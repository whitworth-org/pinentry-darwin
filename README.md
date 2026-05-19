# pinentry-darwin

SwiftUI passphrase dialog for `gpg-agent`. Drop-in replacement for `pinentry-mac`: same Assuan protocol, same Keychain layout. macOS 26 (Tahoe) or later, Apple Silicon only.

## Install

Download `pinentry-darwin-<version>.pkg` from the [latest release](../../releases/latest):

```sh
sudo installer -pkg pinentry-darwin-*.pkg -target /
echo 'pinentry-program /Applications/pinentry-darwin.app/Contents/MacOS/pinentry-darwin' \
  >> ~/.gnupg/gpg-agent.conf
gpgconf --kill gpg-agent
```

The next passphrase prompt routes through pinentry-darwin.

## Verify

```sh
spctl -a -vv -t exec /Applications/pinentry-darwin.app
codesign -dvv /Applications/pinentry-darwin.app 2>&1 | grep -E 'TeamIdentifier|Notarization'
```

Expected: `accepted, source=Notarized Developer ID`, `TeamIdentifier=KHJA84J3YW`, `Notarization Ticket=stapled`.

## Compatibility

- Reads existing pinentry-mac Keychain entries (`service=GnuPG`, `account=<fingerprint>`); no migration.
- Honours `org.gpgtools.common` defaults (`UseKeychain`, `DisableKeychain`, `ShowPassphrase`) when its own preferences are unset.
- Implements the Assuan command set used by `gpg-agent` 2.4+: `GETPIN`, `CONFIRM`, `MESSAGE`, `SETREPEAT`, `SETKEYINFO`, `SETQUALITYBAR`, `SETTIMEOUT`, `OPTION`, `GETINFO`, `CLEARPASSPHRASE`, `RESET`, `BYE`.
- Not implemented: `SETGENPIN` (passphrase generation), curses TTY fallback, non-English locales.

## Build

```sh
make build                                           # bundle into build/pinentry-darwin.app
make test                                            # full suite
make release SIGNER_NAME="<name>" VERSION=<version>  # sign, notarize, pkg, tarball
```

Requires Swift 6.3, an Apple Developer ID, and a `notarytool` keychain profile (`xcrun notarytool store-credentials`).

## Security

Passphrases never touch `Swift.String`. They live in `mlock`'d, deinit-zeroed buffers and stream from there onto the Assuan `D` line. No log line reaches them.

Hardened Runtime is enabled; `get-task-allow=false` blocks debugger attach via `task_for_pid`. App Sandbox is deliberately off; it would break `gpg-agent`'s stdio pipe inheritance, and Hardened Runtime covers the relevant exploit mitigations.

No third-party SwiftPM dependencies. Standard library and Apple frameworks only.

## License

[MIT](LICENSE). Copyright © 2026 Ryan Whitworth.

Window styling adapted from [Ghostty](https://github.com/ghostty-org/ghostty) (MIT). Assuan semantics follow the GnuPG pinentry spec; the implementation is original and not derived from GPL sources.
