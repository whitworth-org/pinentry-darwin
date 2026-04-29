// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SessionQualityProvider.swift — bridge between PinentryUI's QualityProvider
// protocol and AssuanProtocol's `Session.inquireQuality(_:)`.
//
// The candidate `SecureBytes` is round-tripped through the Session actor as
// the escaped wire form (no Swift.String). Errors are swallowed and reported
// as quality 0 — gpg-agent is permitted to refuse INQUIRE if it didn't enable
// SETQUALITYBAR for this session, and we should never leak details.

import Foundation
import AssuanProtocol
import PinentryUI
import SecureMemory

struct SessionQualityProvider: QualityProvider {
    let session: Session

    func quality(for candidate: SecureBytes) async -> Int {
        do {
            return try await session.inquireQuality(candidate)
        } catch {
            // Deliberately silent: an INQUIRE failure can mean the agent
            // disabled the quality bar mid-session, or stdin/stdout were
            // closed. Either way, the UI should just render a neutral bar.
            return 0
        }
    }
}
