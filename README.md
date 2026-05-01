# pinentry-darwin

A SwiftUI passphrase dialog for `gpg-agent` on macOS. Drop-in replacement for `pinentry-mac`: same Assuan protocol, compatible Keychain entries.

Requires macOS 15 (Sequoia) or later on Apple Silicon. This project is arm64-only; universal and legacy x86_64 builds are intentionally out of scope.

## Install

Download `pinentry-darwin-<version>.pkg` from the [latest release](../../releases/latest) and install:

```sh
sudo installer -pkg pinentry-darwin-*.pkg -target /
```

Point `gpg-agent` at the installed binary by adding one line to `~/.gnupg/gpg-agent.conf`:

```
pinentry-program /Applications/pinentry-darwin.app/Contents/MacOS/pinentry-darwin
```

Reload the agent:

```sh
gpgconf --kill gpg-agent
```

The next GPG operation that needs a passphrase will use pinentry-darwin.

## Verify

```sh
spctl -a -vv -t exec /Applications/pinentry-darwin.app
codesign -dvv /Applications/pinentry-darwin.app 2>&1 | grep -E 'TeamIdentifier|Notarization'
```

Expected: `accepted, source=Notarized Developer ID`, `TeamIdentifier=KHJA84J3YW`, and `Notarization Ticket=stapled`.

## Compatibility

- Reads Keychain entries written by `pinentry-mac` (`service=GnuPG`, `account=<fingerprint>`) without migration.
- Honours the `org.gpgtools.common` user defaults (`UseKeychain`, `DisableKeychain`, `ShowPassphrase`) as fallback when its own preferences are unset.
- Implements the Assuan commands required by `gpg-agent` 2.4+: `GETPIN`, `CONFIRM`, `MESSAGE`, `SETREPEAT`, `SETKEYINFO`, `SETQUALITYBAR`, `SETTIMEOUT`, `OPTION`, `GETINFO`, `CLEARPASSPHRASE`, `RESET`, `BYE`.
- Not yet implemented: passphrase generation (`SETGENPIN`), curses TTY fallback, non-English localisation.

## Build from source

```sh
make build         # bundles build/pinentry-darwin.app
make test          # full test suite
make release SIGNER_NAME="<name>" VERSION=<version>
                   # codesign → notarize → pkg → tarball
```

Requires a Swift 6.3 toolchain. The release pipeline additionally requires an Apple Developer ID and a `notarytool` keychain profile (`xcrun notarytool store-credentials`).

Release artifacts are arm64-only.

## Security

- Hardened runtime; `com.apple.security.get-task-allow=false` blocks debugger attach via `task_for_pid`.
- Passphrases never touch `Swift.String`. They live in `mlock`'d, deinit-zeroed buffers and travel from secure memory directly onto the Assuan `D` line — no logging path can reach them.
- No third-party SwiftPM dependencies — standard library and Apple frameworks only.
- App Sandbox is intentionally disabled (it would block `gpg-agent`'s stdio pipe inheritance). Hardened Runtime alone provides the relevant exploit mitigations.

## License

[MIT](LICENSE). Copyright © 2026 Ryan Whitworth.

Window-styling patterns adapted from [Ghostty](https://github.com/ghostty-org/ghostty) (MIT). Assuan protocol semantics conform to the upstream [GnuPG pinentry](https://gnupg.org/related_software/pinentry/) specification — re-implemented from the spec; not derived from GPL sources.
