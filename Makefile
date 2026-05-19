# SPDX-License-Identifier: MIT
#
# pinentry-darwin Makefile
#
# Build, sign, notarize, and package the pinentry-darwin .app bundle.
#
# Signing-keychain assumption:
#   All Apple Development / Developer ID certificates for Team KHJA84J3YW live
#   in the System keychain (/Library/Keychains/System.keychain), which is in
#   the default codesigning search list. No `security unlock-keychain` step
#   should be required. If `codesign` cannot find the key, run:
#
#     security list-keychains -d user -s \
#         "$$HOME/Library/Keychains/login.keychain-db" \
#         /Library/Keychains/System.keychain
#
# Required tools: swift, codesign, xcrun (notarytool, stapler), pkgbuild,
# productsign, ditto.

# --- Configuration -----------------------------------------------------------

TEAM_ID         := KHJA84J3YW
BUNDLE_ID       := org.whitworth.pinentry-darwin
APP_NAME        := pinentry-darwin
VERSION         ?= 0.1.0
NOTARY_PROFILE  ?= pinentry-darwin-notary

# SIGNER_NAME is the human-readable common-name from the Developer ID
# Installer certificate, e.g. "Ryan Whitworth". productsign needs the full
# string `Developer ID Installer: <Name> (<TeamID>)`. Supply via env or the
# `pkg` target will fail with a clear message.
SIGNER_NAME     ?=

BUILD_DIR       := build
APP_BUNDLE      := $(BUILD_DIR)/$(APP_NAME).app
APP_CONTENTS    := $(APP_BUNDLE)/Contents
APP_MACOS       := $(APP_CONTENTS)/MacOS
APP_RESOURCES   := $(APP_CONTENTS)/Resources
RELEASE_BIN     := .build/release/$(APP_NAME)

ICON_SRC        := App/Icon.icns
ICON_DEST       := $(APP_RESOURCES)/Icon.icns

ENTITLEMENTS    := App/$(APP_NAME).entitlements
INFO_PLIST      := App/Info.plist

ZIP_PATH        := $(BUILD_DIR)/$(APP_NAME).zip
TARBALL_PATH    := $(BUILD_DIR)/$(APP_NAME)-$(VERSION)-arm64.tar.gz
PKG_UNSIGNED    := $(BUILD_DIR)/$(APP_NAME)-unsigned.pkg
PKG_SIGNED      := $(BUILD_DIR)/$(APP_NAME)-$(VERSION).pkg

.DEFAULT_GOAL := help

.PHONY: help build debug test integration-check audit audit-release check-signing sign notarize pkg tarball release clean icon

# --- Targets -----------------------------------------------------------------

help:
	@echo "pinentry-darwin build targets:"
	@echo ""
	@echo "  build           swift build -c release and bundle into $(APP_BUNDLE)"
	@echo "  debug           swift build (debug, no bundle)"
	@echo "  test            swift test (includes the Assuan smoke test)"
	@echo "  integration-check spawn a real gpg-agent against the binary, probe non-interactively"
	@echo "  audit           static-audit the built .app bundle (Mach-O, plist, entitlements)"
	@echo "  audit-release   like audit, plus require Developer ID + stapled notarization"
	@echo "  check-signing   verify Developer ID identity for Team $(TEAM_ID)"
	@echo "  sign            codesign the .app bundle (depends: build, check-signing)"
	@echo "  notarize        submit to notarytool and staple (depends: sign)"
	@echo "  pkg             build a signed .pkg installer (depends: notarize)"
	@echo "  tarball         build a release .tar.gz of the stapled .app (depends: notarize)"
	@echo "  release         pkg + tarball"
	@echo "  clean           remove .build and build/"
	@echo ""
	@echo "Variables (override on command line or via env):"
	@echo "  VERSION=$(VERSION)"
	@echo "  NOTARY_PROFILE=$(NOTARY_PROFILE)"
	@echo "  SIGNER_NAME=<required for pkg>"

debug:
	swift build

build: $(APP_MACOS)/$(APP_NAME) $(APP_CONTENTS)/Info.plist $(ICON_DEST)
	@echo "Bundled $(APP_BUNDLE)"

# The bundled binary depends on the swift-built artefact; cp -p preserves
# mtime so subsequent `make build` invocations are no-ops once the bundle
# is up to date. Critically, this means `make sign && make audit` does NOT
# re-copy the unsigned binary over the freshly codesigned one — only a
# real source change triggers a rebuild.
#
# NOTE: entitlements file is NOT bundled. It's an INPUT to `codesign`
# (passed via --entitlements), not a runtime resource. Putting it inside
# Contents/ makes codesign treat it as an unsigned subcomponent and fail
# the sign step. Source-of-truth lives at $(ENTITLEMENTS); audit reads
# the embedded entitlements from the signed binary, falling back to the
# source file for unsigned dev builds.
$(APP_MACOS)/$(APP_NAME): $(RELEASE_BIN) | $(APP_MACOS)
	cp -p $< $@

$(APP_CONTENTS)/Info.plist: $(INFO_PLIST) | $(APP_CONTENTS)
	cp -p $< $@

$(ICON_DEST): $(ICON_SRC) | $(APP_RESOURCES)
	cp -p $< $@

$(APP_MACOS) $(APP_CONTENTS) $(APP_RESOURCES):
	install -d $@

$(RELEASE_BIN): FORCE
	swift build -c release

.PHONY: FORCE
FORCE:

test:
	swift test

integration-check: build
	scripts/integration-gpg-agent.sh --check

audit: build
	swift run audit-bundle $(APP_BUNDLE)

audit-release: build
	swift run audit-bundle --release $(APP_BUNDLE)

check-signing:
	@if ! security find-identity -v -p codesigning | grep -F "($(TEAM_ID))" >/dev/null; then \
		echo "ERROR: no codesigning identity for Team $(TEAM_ID) found."; \
		echo "       Run 'security find-identity -v -p codesigning' to inspect."; \
		echo "       The Developer ID Application certificate must be importable"; \
		echo "       from /Library/Keychains/System.keychain."; \
		exit 1; \
	fi
	@echo "Found codesigning identity for Team $(TEAM_ID)."

sign: build check-signing
	@# AMFI's XML parser rejects long XML comments in entitlements files
	@# ("AMFIUnserializeXML: syntax error"). plutil -convert xml1 emits a
	@# normalised, comment-free plist that codesign accepts.
	plutil -convert xml1 -o $(BUILD_DIR)/entitlements.plist $(ENTITLEMENTS)
	codesign --force --options runtime --timestamp \
		--entitlements $(BUILD_DIR)/entitlements.plist \
		--sign $(TEAM_ID) \
		$(APP_BUNDLE)
	@echo "Signed $(APP_BUNDLE)"

notarize: sign
	rm -f $(ZIP_PATH)
	ditto -c -k --keepParent $(APP_BUNDLE) $(ZIP_PATH)
	xcrun notarytool submit $(ZIP_PATH) \
		--keychain-profile $(NOTARY_PROFILE) \
		--wait
	xcrun stapler staple $(APP_BUNDLE)
	@echo "Notarized and stapled $(APP_BUNDLE)"

pkg: notarize
	@if [ -z "$(SIGNER_NAME)" ]; then \
		echo "ERROR: SIGNER_NAME is required for pkg signing."; \
		echo "       Pass the common-name from your Developer ID Installer cert, e.g.:"; \
		echo "         make pkg SIGNER_NAME=\"Ryan Whitworth\""; \
		exit 1; \
	fi
	pkgbuild --root $(APP_BUNDLE) \
		--identifier $(BUNDLE_ID) \
		--version $(VERSION) \
		--install-location /Applications/$(APP_NAME).app \
		$(PKG_UNSIGNED)
	productsign --sign "Developer ID Installer: $(SIGNER_NAME) ($(TEAM_ID))" \
		$(PKG_UNSIGNED) \
		$(PKG_SIGNED)
	@# Gatekeeper rejects signed-but-unnotarized installer packages on
	@# user systems with "Unnotarized Developer ID". Notarize the pkg
	@# itself (separate submission from the .app) and staple the ticket.
	xcrun notarytool submit $(PKG_SIGNED) \
		--keychain-profile $(NOTARY_PROFILE) \
		--wait
	xcrun stapler staple $(PKG_SIGNED)
	@echo "Built, notarized, and stapled $(PKG_SIGNED)"

tarball: notarize
	tar -czf $(TARBALL_PATH) -C $(BUILD_DIR) $(APP_NAME).app
	@echo "Built $(TARBALL_PATH)"

# SC-2: release MUST depend on audit-release. The auditor enforces the
# forbidden-entitlement allow-list, Hardened Runtime, --timestamp, the
# stapled-ticket check, and the TeamIdentifier match — exactly the
# regressions a future bad sign step could introduce that notarisation
# would still accept. `audit-release` runs after the bundle is fully
# notarised and stapled (via pkg → notarize → sign chain), so it sees
# the final artefact rather than an in-progress build.
release: pkg tarball audit-release
	@echo "Release artifacts:"
	@echo "  $(PKG_SIGNED)"
	@echo "  $(TARBALL_PATH)"

clean:
	rm -rf .build $(BUILD_DIR)

# Regenerate App/Icon.icns from the Swift+SF Symbol generator. The .icns
# is committed so normal builds don't depend on swift script execution;
# only run this target when the icon design changes.
icon:
	rm -rf $(BUILD_DIR)/icon.iconset
	mkdir -p $(BUILD_DIR)
	swift scripts/make-icon.swift $(BUILD_DIR)/icon.iconset
	iconutil -c icns -o $(ICON_SRC) $(BUILD_DIR)/icon.iconset
	@echo "Regenerated $(ICON_SRC)"
