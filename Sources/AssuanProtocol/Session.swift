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

    /// Write a `Response` to the output file handle. Each wire line includes
    /// its own LF terminator.
    public func send(_ response: Response) async throws {
        let lines = response.wireLines()
        for line in lines {
            try writeAll(line)
        }
    }

    // MARK: Quality inquiry

    /// Send `INQUIRE QUALITY <escaped-bytes>` and read back the response.
    /// Returns the integer carried on the resulting `D` line, clamped to
    /// the conventional [-100, 100] range. The `candidate` bytes never
    /// leave `SecureBytes` except as their escaped wire form — the
    /// escaping is appended directly into the wire-output `Data`, no
    /// intermediate `Swift.String` materialises.
    public func inquireQuality(_ candidate: SecureBytes) async throws -> Int {
        // Build "INQUIRE QUALITY <escaped>\n" inside the secure buffer's
        // unsafe-bytes scope. The intermediate `Data` carries the *escaped*
        // form, which is the value about to be transmitted on the wire.
        let line: Data = candidate.withUnsafeBytes { (buf: UnsafeBufferPointer<UInt8>) -> Data in
            var d = Data()
            d.reserveCapacity(16 + buf.count * 3 + 1)
            d.append(contentsOf: "INQUIRE QUALITY ".utf8)
            LineCodec.escape(buf, into: &d)
            d.append(0x0A)
            return d
        }
        try writeAll(line)

        // Read until we see ERR/OK/CAN/END. Per upstream, the agent replies
        // with one or more `D` lines plus an OK. We only want the integer
        // from the first D line; later D lines are ignored.
        var gotValue: Int?
        while true {
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
}
