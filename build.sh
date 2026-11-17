#!/bin/bash
# Builds build/SignalScan.app with the Xcode command-line tools (no Xcode project needed).
#
#   ./build.sh                     build
#   open build/SignalScan.app      run (opens the dashboard in your browser)
#
# Rebuild only when something in Sources/ or Info.plist changes.
#
# Permissions after a rebuild:
#   - Local Network is remembered by the app's identifier (dev.local.SignalScan) and is not
#     asked again.
#   - Location and Bluetooth are usually asked again. The app is signed "ad hoc", which gives
#     it no lasting identity, so macOS may or may not keep the two grants across a rebuild.
#     After a rebuild, answer the two prompts (including one left on screen by an earlier
#     launch); until then Wi-Fi names and the Bluetooth list are missing.
#
# The dashboard page does not need a rebuild: the app serves Resources/dashboard.html straight
# from this folder (falling back to the copy inside the app if the folder has moved), so edits
# to the page show up on the next browser refresh.
set -euo pipefail
cd "$(dirname "$0")"

APP=build/SignalScan.app

# A copy still running from an earlier build would keep port 8377, and "open" would only bring
# that old copy forward instead of starting this build. Stop it before replacing the app.
pkill -x SignalScan 2>/dev/null || true

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

swiftc -swift-version 5 -O -o "$APP/Contents/MacOS/SignalScan" Sources/*.swift

cp Info.plist "$APP/Contents/Info.plist"
plutil -insert SignalScanWebRoot -string "$PWD/Resources" "$APP/Contents/Info.plist"
cp Resources/dashboard.html "$APP/Contents/Resources/"
codesign --force --sign - "$APP"

"$APP/Contents/MacOS/SignalScan" --selftest
echo "Built $APP"
