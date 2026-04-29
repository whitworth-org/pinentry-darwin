# pinentry-darwin

A modern Swift 6 / SwiftUI replacement for pinentry-mac. Drop-in Assuan-protocol passphrase dialog for `gpg-agent` on macOS, designed to look and feel like Ghostty.

## Status

Alpha / pre-1.0. APIs and packaging may change. Not yet recommended for production use.

## Requirements

- macOS 15.0 (Sequoia) or later
- Swift 6 toolchain (Xcode 16+) for development

## Install

Pre-built binaries (coming soon):

```sh
brew install whitworth/tap/pinentry-darwin
```

Manual install: download the notarized `.pkg` from the GitHub releases page and run it. The package installs `pinentry-darwin.app` into `/Applications`.

Build from source:

```sh
make build
```

## Configure gpg-agent

Add the following line to `~/.gnupg/gpg-agent.conf`, substituting the actual path to the installed binary (the Homebrew formula symlinks it into `/opt/homebrew/bin`):

```
pinentry-program /opt/homebrew/bin/pinentry-darwin
```

Then reload the agent so the change takes effect:

```sh
gpgconf --kill gpg-agent
```

## Settings

Open the settings window from a terminal:

```sh
pinentry-darwin --preferences
```

The signed `.pkg` also installs `Pinentry Darwin Settings.app`, which can be opened from Spotlight or the `/Applications` folder. Settings cover appearance (System / Light / Dark), Keychain behavior, and dialog defaults.

## Building from source

```sh
make build           # release build, bundled into build/pinentry-darwin.app
make test            # run the unit tests
make smoke           # build + feed an Assuan transcript to the binary
make check-signing   # verify the Developer ID identity is available
make release         # full pipeline: sign, notarize, pkg, tarball
```

The `Makefile` is the source of truth for the release pipeline. See its `help` target for the full list.

## License

MIT. See `LICENSE`.

This project re-implements the Assuan protocol from scratch; it does not include any GPL-licensed code from the upstream `pinentry` package. UI styling is inspired by Ghostty (MIT). Files derived from Ghostty carry an explicit attribution header naming their source.

## Contributing

Open an issue or pull request on GitHub. There is no DCO or CLA. Please do not add SwiftPM dependencies — this project deliberately ships with zero third-party code on the supply chain.
