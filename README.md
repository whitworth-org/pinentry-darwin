# pinentry-darwin

SwiftUI passphrase dialog for `gpg-agent`. A drop-in replacement for `pinentry-mac`: same Assuan protocol, same Keychain entries. macOS 26+, Apple Silicon.

## Install

Download the `.pkg` from the [latest release](../../releases/latest):

```sh
sudo installer -pkg pinentry-darwin-*.pkg -target /
```

Point `gpg-agent` at it and restart the agent:

```sh
/Applications/pinentry-darwin.app/Contents/MacOS/pinentry-darwin --configure-gpg-agent
gpgconf --kill gpg-agent
```

This sets `pinentry-program` in `$GNUPGHOME/gpg-agent.conf` (default `~/.gnupg`), replacing any existing line such as `pinentry-mac`'s. Other options are untouched and a symlinked config is followed. Running it again changes nothing.

## pass

`pass` runs `gpg`, which asks `gpg-agent`, which launches the configured pinentry. After the setup above, `pass show <entry>` prompts through pinentry-darwin.

- With a custom GnuPG home, run the configure command with `GNUPGHOME=<dir>` set (this also covers `PASSWORD_STORE_GPG_OPTS="--homedir <dir>"`).
- The dialog needs a window session. There is no TTY fallback, so `pass` over plain SSH cannot prompt.

## Verify

```sh
spctl -a -vv -t exec /Applications/pinentry-darwin.app
codesign -dvv /Applications/pinentry-darwin.app 2>&1 | grep -E 'TeamIdentifier|Notarization'
```

Expect `source=Notarized Developer ID`, `TeamIdentifier=KHJA84J3YW`, `Notarization Ticket=stapled`.

## Compatibility

- Reads `pinentry-mac` Keychain entries (`service=GnuPG`, `account=<fingerprint>`); no migration.
- Honours `org.gpgtools.common` defaults `UseKeychain`, `DisableKeychain`, `ShowPassphrase` when its own preferences are unset.
- Assuan commands: `GETPIN`, `CONFIRM`, `MESSAGE`, `SETREPEAT`, `SETKEYINFO`, `SETQUALITYBAR`, `SETTIMEOUT`, `OPTION`, `GETINFO`, `CLEARPASSPHRASE`, `RESET`, `BYE` (`gpg-agent` 2.4+).
- Not implemented: `SETGENPIN`, curses TTY fallback, non-English locales.

## Secure Enclave SSH keys

`pinentry-darwin --preferences`, **SSH** tab: creates and manages Secure Enclave-backed keys by running `sc_auth create-ctk-identity -k p-256-ne -t bio` and `ssh-add -K -S /usr/lib/ssh-keychain.dylib`. The private key never leaves the Secure Enclave; the app holds only public hashes, fingerprints and labels.

```sh
export SSH_SK_PROVIDER=/usr/lib/ssh-keychain.dylib   # shell profile
```

`ssh` then prompts for Touch ID on each connection.

## Build

```sh
make build                                           # build/pinentry-darwin.app
make test
make release SIGNER_NAME="<name>" VERSION=<version>  # sign, notarize, pkg, tarball
```

Requires Swift 6.2+ and the macOS 26 SDK. `make release` also needs a Developer ID and a `notarytool` keychain profile (`xcrun notarytool store-credentials`).

## Security

- Passphrases never touch `Swift.String`. They live in `mlock`'d, zero-on-`deinit` buffers and stream straight to the Assuan `D` line; no log line reaches them.
- Hardened Runtime on; `get-task-allow=false` blocks `task_for_pid` debugger attach.
- App Sandbox off by design: it breaks the stdio pipes `gpg-agent` passes to its child.
- No third-party dependencies.

## License

[MIT](LICENSE). Window styling adapted from [Ghostty](https://github.com/ghostty-org/ghostty) (MIT). Assuan behaviour follows the GnuPG pinentry spec; the implementation is original, not derived from GPL sources.
