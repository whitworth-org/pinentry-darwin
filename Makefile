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
RELEASE_BIN     := .build/release/$(APP_NAME)

ENTITLEMENTS    := App/$(APP_NAME).entitlements
INFO_PLIST      := App/Info.plist

ZIP_PATH        := $(BUILD_DIR)/$(APP_NAME).zip
TARBALL_PATH    := $(BUILD_DIR)/$(APP_NAME)-$(VERSION).tar.gz
PKG_UNSIGNED    := $(BUILD_DIR)/$(APP_NAME)-unsigned.pkg
PKG_SIGNED      := $(BUILD_DIR)/$(APP_NAME)-$(VERSION).pkg

.DEFAULT_GOAL := help

.PHONY: help build debug test smoke check-signing sign notarize pkg tarball release clean

# --- Targets -----------------------------------------------------------------

help:
	@echo "pinentry-darwin build targets:"
	@echo ""
	@echo "  build           swift build -c release and bundle into $(APP_BUNDLE)"
	@echo "  debug           swift build (debug, no bundle)"
	@echo "  test            swift test"
	@echo "  smoke           feed an Assuan transcript to the bundled binary"
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

build:
	swift build -c release
	install -d $(APP_MACOS)
	install -d $(APP_CONTENTS)
	cp $(RELEASE_BIN) $(APP_MACOS)/$(APP_NAME)
	cp $(INFO_PLIST) $(APP_CONTENTS)/Info.plist
	cp $(ENTITLEMENTS) $(APP_CONTENTS)/$(APP_NAME).entitlements
	@echo "Bundled $(APP_BUNDLE)"

test:
	swift test

smoke: build
	scripts/smoke-assuan.sh build/pinentry-darwin.app/Contents/MacOS/pinentry-darwin

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
	codesign --force --options runtime --timestamp \
		--entitlements $(ENTITLEMENTS) \
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
	@echo "Built $(PKG_SIGNED)"

tarball: notarize
	tar -czf $(TARBALL_PATH) -C $(BUILD_DIR) $(APP_NAME).app
	@echo "Built $(TARBALL_PATH)"

release: pkg tarball
	@echo "Release artifacts:"
	@echo "  $(PKG_SIGNED)"
	@echo "  $(TARBALL_PATH)"

clean:
	rm -rf .build $(BUILD_DIR)
