// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// Session.swift — actor that owns the input/output FileHandles and brokers
// the Assuan protocol. The actor isolates I/O so blocking reads/writes are
// safe; tests inject `Pipe()` ends instead of stdin/stdout.
//
// Confidentiality: `D`-line payloads and `INQUIRE QUALITY` candidates are
// never logged and never copied through `Swift.String`. They flow through
// `SecureBytes` and the escaped wire form is the only thing that leaves
// the actor.

import Foundation
import Darwin
import SecureMemory

// MARK: - SessionError

public enum SessionError: Error {
    case unexpectedEOF
    case malformedLine(String)
    case unexpectedResponse(String)
    case ioError(errno: Int32)
}

// MARK: - Session

public actor Session {

    // MARK: State

    private let input: FileHandle
    private let output: FileHandle

    /// Pending bytes already read from `input` but not yet consumed as a
    /// complete line. Kept as a `Data` to avoid repeatedly re-allocating.
    private var readBuffer: Data = Data()

    /// Set once `close()` has been called. Subsequent reads return EOF.
    private var isClosed: Bool = false

    // MARK: Init

    public init(input: FileHandle, output: FileHandle) {
        self.input = input
        self.output = output
    }

    // MARK: Greeting

    /// Emit the conventional Assuan greeting line. Format mirrors what
    /// upstream gpg-agent and pinentry both speak.
    public func emitGreeting() async throws {
        let pid = getpid()
        let line = "OK Pleased to meet you, pid \(pid)\n"
        try writeAll(Data(line.utf8))
    }

    // MARK: Command read

    /// Block until the next complete command is available, parse it, and
    /// return it. On EOF the actor returns `.bye` so the caller's loop
    /// terminates cleanly without raising.
    public func nextCommand() async throws -> Command {
        // Skip blank/comment lines: per Assuan, lines starting with '#' are
        // comments and empty lines are tolerated.
        while true {
            guard let line = try readLine() else {
                return .bye
            }
            if line.isEmpty { continue }
            if line.first == "#" { continue }
            do {
                return try Command.parse(line)
            } catch let e as CommandParseError {
                throw SessionError.malformedLine("\(e)")
            }
        }
    }

    // MARK: Send

    /// Write a `Response` to the output file handle. Each wire payload
    /// includes its own LF terminator. Secret payloads are written
    /// directly from their SecureBytes-backed scratch buffer via
    /// `Darwin.write()` (SL-1) so the escaped wire bytes never cross
    /// into Foundation.Data heap on the way out.
    public func send(_ response: Response) async throws {
        let payloads = response.wirePayloads()
        for payload in payloads {
            switch payload {
            case .plain(let data):
                try writeAll(data)
            case .secret(let secure):
                try writeSecure(secure)
            }
        }
    }

    // MARK: Quality inquiry

    /// Maximum source bytes per `INQUIRE QUALITY` candidate (FZ-1
    /// companion). Wire prefix is "INQUIRE QUALITY " (16 bytes), worst-
    /// case escape is 3-for-1, plus LF: 16 + 3*N + 1 ≤ 1001 → N ≤ 328.
    private static let maxQualityCandidateSourceBytes = 328

    /// Maximum number of intervening reply lines we will consume before
    /// the terminal OK/END/ERR (AS-2). A hostile gpg-agent could otherwise
    /// stream `D 0\n` forever and freeze the keystroke-driven quality
    /// path inside a synchronous send-and-wait.
    private static let maxQualityReplyLines = 32

    /// Send `INQUIRE QUALITY <escaped-bytes>` and read back the response.
    /// Returns the integer carried on the resulting `D` line, clamped to
    /// the conventional [-100, 100] range. The `candidate` bytes never
    /// leave `SecureBytes` (SL-1 companion) — the wire payload is built
    /// inside a SecureBytes-backed scratch buffer and written directly
    /// to the file descriptor.
    public func inquireQuality(_ candidate: SecureBytes) async throws -> Int {
        // FZ-1 companion: INQUIRE QUALITY does not support D-line
        // continuation (it's a single-shot prompt), so refuse to even
        // send candidates that would produce a wire line longer than
        // the spec cap. The keystroke-driven quality path is best-effort;
        // returning 0 on overflow is safer than tripping the peer's
        // line-length check.
        let candidateLength = candidate.withUnsafeBytes { $0.count }
        if candidateLength > Self.maxQualityCandidateSourceBytes {
            return 0
        }

        // SL-1 companion: build "INQUIRE QUALITY <escaped>\n" inside a
        // SecureBytes-backed scratch buffer. The intermediate bytes
        // are the *escaped* form, which for ASCII passphrases is byte-
        // identical to the plaintext — keep them mlock'd and deinit-
        // zeroed all the way out.
        try candidate.withUnsafeBytes { (buf: UnsafeBufferPointer<UInt8>) in
            // Worst-case wire size: 16 prefix + 3*N + 1 LF.
            let cap = 16 + buf.count * 3 + 1
            let lineBuf = SecureBytes(capacity: Swift.max(cap, 1))
            for b in "INQUIRE QUALITY ".utf8 {
                lineBuf.append(b)
            }
            // Inline data-line escape — same rules as Response.encodeDataLine
            // so a literal '+' or space in the candidate round-trips
            // through gpg-agent's quality estimator unchanged.
            for b in buf {
                switch b {
                case 0x2B, 0x25, 0..<0x20, 0x7F...0xFF:
                    lineBuf.append(0x25)
                    let hi = b >> 4
                    lineBuf.append(hi < 10 ? (0x30 + hi) : (0x41 + hi - 10))
                    let lo = b & 0x0F
                    lineBuf.append(lo < 10 ? (0x30 + lo) : (0x41 + lo - 10))
                default:
                    lineBuf.append(b)
                }
            }
            lineBuf.append(0x0A)
            try writeSecure(lineBuf)
        }

        // Read until we see ERR/OK/CAN/END. Per upstream, the agent replies
        // with one or more `D` lines plus an OK. We only want the integer
        // from the first D line; later D lines are ignored.
        var gotValue: Int?
        var seenLines = 0
        while true {
            // AS-2: cap intervening lines so a hostile peer cannot pin
            // the dialog inside this loop forever via streamed `D 0\n`.
            if seenLines >= Self.maxQualityReplyLines {
                throw SessionError.unexpectedResponse("INQUIRE QUALITY: too many reply lines")
            }
            seenLines += 1
            guard let reply = try readLine() else {
                throw SessionError.unexpectedEOF
            }
            if reply.isEmpty || reply.first == "#" { continue }

            // Quick verb test on the leading bytes.
            if reply.hasPrefix("D ") {
                if gotValue == nil {
                    let payload = reply.dropFirst(2)
                    // The response is a signed decimal integer. Decode using
                    // the data-line decoder (no '+'↔space) since `D` payloads
                    // carry literal `+` characters by spec; using the
                    // command-arg decoder would silently rewrite any '+' to
                    // space and skew parsing.
                    let bytes = (try? LineCodec.unescapeFromDataLine(String(payload))) ?? []
                    if let s = String(bytes: bytes, encoding: .ascii) {
                        gotValue = Int(s.trimmingCharacters(in: .whitespaces))
                    }
                }
                continue
            }
            if reply == "OK" || reply.hasPrefix("OK ") || reply == "END" || reply.hasPrefix("END ") {
                let v = gotValue ?? 0
                if v < -100 { return -100 }
                if v >  100 { return  100 }
                return v
            }
            if reply.hasPrefix("ERR ") || reply == "ERR" || reply.hasPrefix("CAN") {
                throw SessionError.unexpectedResponse(reply)
            }
            // Anything else: keep looping. Upstream is lenient here.
        }
    }

    // MARK: Close

    public func close() async {
        guard !isClosed else { return }
        isClosed = true
        try? input.close()
        try? output.close()
    }

    // MARK: - Private I/O

    /// Read one LF-terminated line from `input`, returning it without the
    /// trailing LF. Returns `nil` on EOF. Throws `lineTooLong` if a single
    /// logical line exceeds `LineCodec.maxLineLength` bytes (excluding LF).
    private func readLine() throws -> String? {
        if isClosed { return nil }
        while true {
            // Look for an LF in the already-buffered bytes. We index the
            // buffer through a contiguous byte view to avoid any surprises
            // from Data's potentially non-zero startIndex after a previous
            // removeSubrange.
            if let lfOffset = readBuffer.withUnsafeBytes({ buf -> Int? in
                guard let base = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return nil
                }
                for i in 0..<buf.count where base[i] == 0x0A {
                    return i
                }
                return nil
            }) {
                if lfOffset > LineCodec.maxLineLength {
                    throw SessionError.malformedLine("line exceeds \(LineCodec.maxLineLength) bytes")
                }
                // Pull out [0, lfOffset) as the line body, dropping a CR
                // if the terminator was CRLF.
                var endOffset = lfOffset
                if endOffset > 0 {
                    let lastByte: UInt8 = readBuffer.withUnsafeBytes { buf in
                        let base = buf.baseAddress!.assumingMemoryBound(to: UInt8.self)
                        return base[endOffset - 1]
                    }
                    if lastByte == 0x0D {
                        endOffset -= 1
                    }
                }
                let lineData: Data = readBuffer.withUnsafeBytes { buf -> Data in
                    let base = buf.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    return Data(bytes: base, count: endOffset)
                }
                guard let s = String(data: lineData, encoding: .utf8) else {
                    throw SessionError.malformedLine("invalid UTF-8")
                }
                // Drop "line + LF" from the buffer. Use a fresh Data backed
                // by the remaining tail to keep startIndex at zero.
                let consumed = lfOffset + 1
                if consumed >= readBuffer.count {
                    readBuffer = Data()
                } else {
                    let remaining: Data = readBuffer.withUnsafeBytes { buf -> Data in
                        let base = buf.baseAddress!.assumingMemoryBound(to: UInt8.self)
                        return Data(bytes: base.advanced(by: consumed),
                                    count: buf.count - consumed)
                    }
                    readBuffer = remaining
                }
                return s
            }

            // No LF yet. Cap buffer size so a peer that never sends LF
            // can't exhaust memory.
            if readBuffer.count > LineCodec.maxLineLength + 1 {
                throw SessionError.malformedLine("line exceeds \(LineCodec.maxLineLength) bytes")
            }

            // Read more. Foundation's `FileHandle.read(upToCount:)` on a
            // pipe loops internally until the buffer is full or EOF arrives,
            // which deadlocks any line-oriented protocol where the peer
            // sends short bursts and then waits for our reply. Drop down to
            // the raw `read(2)` syscall so one call returns whatever the
            // pipe currently has buffered.
            let bufCap = 4096
            var readData = Data(count: bufCap)
            let nRead = readData.withUnsafeMutableBytes { (ptr: UnsafeMutableRawBufferPointer) -> Int in
                guard let base = ptr.baseAddress else { return -1 }
                return Darwin.read(input.fileDescriptor,
                                   base.assumingMemoryBound(to: UInt8.self),
                                   bufCap)
            }
            if nRead < 0 {
                throw SessionError.ioError(errno: errno)
            }
            let chunk: Data? = nRead == 0 ? nil : readData.prefix(nRead)
            guard let data = chunk, !data.isEmpty else {
                // EOF.
                if readBuffer.isEmpty {
                    return nil
                }
                // Treat trailing-no-LF as a final line.
                if readBuffer.count > LineCodec.maxLineLength {
                    throw SessionError.malformedLine("line exceeds \(LineCodec.maxLineLength) bytes")
                }
                guard let s = String(data: readBuffer, encoding: .utf8) else {
                    throw SessionError.malformedLine("invalid UTF-8")
                }
                readBuffer.removeAll(keepingCapacity: false)
                return s
            }
            readBuffer.append(data)
        }
    }

    /// Write `data` in full to `output`. The Foundation `write(contentsOf:)`
    /// API loops internally on partial writes for regular files; for pipes
    /// it likewise blocks until the buffer is consumed by the peer.
    private func writeAll(_ data: Data) throws {
        do {
            try output.write(contentsOf: data)
        } catch {
            throw SessionError.ioError(errno: errno)
        }
    }

    /// Write secret wire bytes directly from SecureBytes without first
    /// materialising them in Foundation.Data heap.
    private func writeSecure(_ secure: SecureBytes) throws {
        try secure.withUnsafeBytes { (buf: UnsafeBufferPointer<UInt8>) in
            guard let base = buf.baseAddress else { return }
            var written = 0
            while written < buf.count {
                let n = Darwin.write(
                    output.fileDescriptor,
                    base.advanced(by: written),
                    buf.count - written
                )
                if n < 0 {
                    if errno == EINTR {
                        continue
                    }
                    throw SessionError.ioError(errno: errno)
                }
                if n == 0 {
                    throw SessionError.ioError(errno: EPIPE)
                }
                written += n
            }
        }
    }
}
