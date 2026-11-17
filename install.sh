#!/bin/bash
# Signal Scan installer for macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/ahmedasad89-design/signal-scan/main/install.sh | bash
#
# It downloads the source, builds the app on your own Mac and opens it. Building locally is what
# lets the app open without a security warning: nothing here is a downloaded program.
#
#   install.sh               install, or update to the latest version
#   install.sh --uninstall   remove the app and everything it stored
#
# What it touches:
#   ~/Library/Application Support/SignalScan/   the source, and the list of device makers
#   /Applications/Signal Scan.app               the app (~/Applications if that is not writable)
#
# For testing, SIGNALSCAN_FROM=<folder> builds from a local copy instead of downloading,
# SIGNALSCAN_APPS=<folder> installs the app there, and SIGNALSCAN_NO_OPEN=1 does not launch it.
set -euo pipefail

REPO="ahmedasad89-design/signal-scan"
BRANCH="main"
APP_NAME="Signal Scan.app"
SUPPORT="$HOME/Library/Application Support/SignalScan"
SRC="$SUPPORT/source"

say()  { printf '%s\n' "$*"; }
fail() { printf '\nSignal Scan was not installed: %s\n' "$*" >&2; exit 1; }

app_dir() {
    if [ -n "${SIGNALSCAN_APPS:-}" ]; then
        printf '%s' "$SIGNALSCAN_APPS"
    elif [ -w /Applications ]; then
        printf '%s' /Applications
    else
        printf '%s' "$HOME/Applications"
    fi
}

uninstall() {
    pkill -x SignalScan 2>/dev/null || true
    rm -rf "/Applications/$APP_NAME" "$HOME/Applications/$APP_NAME"
    rm -rf "$SUPPORT"
    defaults delete dev.local.SignalScan >/dev/null 2>&1 || true
    tccutil reset All dev.local.SignalScan >/dev/null 2>&1 || true
    say "Signal Scan has been removed."
    say "A sleep trial, if you ran one, lives in your browser: clear the site data for 127.0.0.1 to remove it."
}

main() {
    [ "$(uname -s)" = "Darwin" ] || fail "it only runs on macOS."
    if [ "${1:-}" = "--uninstall" ]; then uninstall; return; fi

    local major
    major="$(sw_vers -productVersion | cut -d. -f1)"
    [ "$major" -ge 13 ] || fail "it needs macOS 13 or later (this Mac has $(sw_vers -productVersion))."

    # Asking for the compiler by name on a Mac without it pops up Apple's installer, so check
    # for the tools quietly first.
    if ! xcode-select -p >/dev/null 2>&1; then
        say "Signal Scan is built on your Mac, which needs Apple's free command-line tools."
        say "A window is opening to install them (a few minutes). When it finishes, run this line again."
        xcode-select --install >/dev/null 2>&1 || true
        exit 1
    fi
    xcrun --find swiftc >/dev/null 2>&1 || fail "Apple's command-line tools are present but have no Swift compiler. Run: xcode-select --install"

    local work
    work="$(mktemp -d "${TMPDIR:-/tmp}/signalscan.XXXXXX")"
    trap "rm -rf '$work'" EXIT
    mkdir -p "$work/source"

    if [ -n "${SIGNALSCAN_FROM:-}" ]; then
        say "Copying the source from $SIGNALSCAN_FROM"
        cp -R "$SIGNALSCAN_FROM/." "$work/source/"
        rm -rf "$work/source/build" "$work/source/.git"
    else
        say "Downloading Signal Scan"
        curl -fsSL "https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz" -o "$work/source.tar.gz" \
            || fail "the download failed. Check your connection and try again."
        tar -xzf "$work/source.tar.gz" -C "$work/source" --strip-components 1 \
            || fail "the download could not be unpacked."
    fi
    [ -f "$work/source/build.sh" ] || fail "the source is incomplete."

    # The app reads its page from the source folder, so that folder has to stay where it is.
    mkdir -p "$SUPPORT"
    if [ -z "${SIGNALSCAN_FROM:-}" ] || [ -z "${SIGNALSCAN_APPS:-}" ]; then
        rm -rf "$SRC"
        mv "$work/source" "$SRC"
    else
        SRC="$work/source"          # a test run: leave the installed copy alone
    fi

    say "Building (about a minute)"
    if ! (cd "$SRC" && ./build.sh) >"$work/build.log" 2>&1; then
        tail -n 25 "$work/build.log" >&2
        fail "the build failed. The lines above say why; please report them at https://github.com/$REPO/issues"
    fi

    local apps
    apps="$(app_dir)"
    mkdir -p "$apps"
    rm -rf "$apps/$APP_NAME"
    ditto "$SRC/build/SignalScan.app" "$apps/$APP_NAME"
    rm -rf "$SRC/build"

    # Maker names ("Samsung", "Espressif") come from the public IEEE registry. Optional.
    if [ ! -s "$SUPPORT/oui.csv" ]; then
        say "Fetching the list of device makers"
        curl -fsSL --max-time 90 "https://standards-oui.ieee.org/oui/oui.csv" -o "$work/oui.csv" 2>/dev/null \
            && [ "$(wc -c <"$work/oui.csv")" -gt 1000000 ] && mv "$work/oui.csv" "$SUPPORT/oui.csv" \
            || say "  (could not fetch it; devices will show without maker names. See the README to add it later.)"
    fi

    say ""
    say "Installed: $apps/$APP_NAME"
    if [ -z "${SIGNALSCAN_NO_OPEN:-}" ]; then
        open "$apps/$APP_NAME"
        say "It is opening now, with its page at http://127.0.0.1:8377"
        say "macOS will ask for Location, Bluetooth and Local Network. Allow all three:"
        say "Location is only how macOS lets an app see Wi-Fi names; where you are is never read."
    fi
    say "To update, run the same line again. To remove it: install.sh --uninstall (see the README)."
}

# Everything runs from main, so a download cut off halfway runs nothing.
main "$@"
