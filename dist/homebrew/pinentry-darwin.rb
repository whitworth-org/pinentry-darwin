# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ryan Whitworth.
#
# Homebrew formula for pinentry-darwin.
#
# Place this file in a tap repository (e.g. github.com/whitworth/homebrew-tap)
# at Formula/pinentry-darwin.rb, then:
#
#   brew tap whitworth/tap
#   brew install pinentry-darwin
#
# Two install modes:
#   * Bottle (default once releases are published): downloads the notarized
#     .tar.gz from GitHub releases. Fastest, requires a release artifact.
#   * From source (`brew install --build-from-source pinentry-darwin`):
#     clones, runs `make build`. Useful for development; codesigning is
#     ad-hoc unless DEVELOPER_ID_APPLICATION is set.

class PinentryDarwin < Formula
  desc "Modern Swift 6 / SwiftUI replacement for pinentry-mac"
  homepage "https://github.com/whitworth/pinentry-darwin"
  license "MIT"
  version "0.1.0"

  # These URL/sha256 placeholders are filled in per release.
  on_macos do
    on_arm do
      url "https://github.com/whitworth/pinentry-darwin/releases/download/v#{version}/pinentry-darwin-#{version}-arm64.tar.gz"
      sha256 "REPLACE_WITH_NOTARIZED_TARBALL_SHA256"
    end
    on_intel do
      odie "pinentry-darwin currently ships arm64-only. Build from source on Intel: brew install --build-from-source pinentry-darwin"
    end
  end

  head do
    url "https://github.com/whitworth/pinentry-darwin.git", branch: "main"
  end

  depends_on macos: :sequoia
  depends_on xcode: ["16.0", :build]

  def install
    if build.head?
      system "make", "build"
      app_src = buildpath/"build/pinentry-darwin.app"
    else
      # Bottled tarball ships the notarized .app at its top level.
      app_src = buildpath/"pinentry-darwin.app"
    end

    # Drop the .app where Spotlight / LaunchServices can find it.
    prefix.install app_src => "pinentry-darwin.app"

    # Symlink the binary onto PATH for gpg-agent.conf.
    bin.install_symlink prefix/"pinentry-darwin.app/Contents/MacOS/pinentry-darwin"

    # And a friendlier name for the preferences mode.
    (bin/"pinentry-darwin-prefs").write <<~SH
      #!/bin/sh
      exec "#{prefix}/pinentry-darwin.app/Contents/MacOS/pinentry-darwin" --preferences "$@"
    SH
    chmod 0755, bin/"pinentry-darwin-prefs"
  end

  def caveats
    <<~EOS
      To use pinentry-darwin with gpg-agent, add the following line to
      ~/.gnupg/gpg-agent.conf:

        pinentry-program #{HOMEBREW_PREFIX}/bin/pinentry-darwin

      Then reload the agent:

        gpgconf --kill gpg-agent

      For settings, run:

        pinentry-darwin-prefs
    EOS
  end

  test do
    # Wire smoke: feed a tiny Assuan transcript and assert we get a greeting
    # and the expected D/OK frames back.
    output = pipe_output(
      "#{bin}/pinentry-darwin",
      "GETINFO version\nGETINFO flavor\nBYE\n"
    )
    assert_match(/^OK Pleased to meet you/, output)
    assert_match(/^D #{version}/,            output)
    assert_match(/^D darwin/,                output)
  end
end
