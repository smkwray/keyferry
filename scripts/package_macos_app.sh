#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
    echo "usage: package_macos_app.sh CONTROLLER DAEMON PAIRING_HELPER CLI OUTPUT.app" >&2
    exit 2
fi

controller=$1
daemon=$2
pairing_helper=$3
cli=$4
output=$5
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
icon="$project_dir/apps/keyferry/assets/icons/keyferry.icns"

if [ "$(uname -s)" != Darwin ]; then
    echo "package_macos_app.sh must run on macOS" >&2
    exit 1
fi
if [ ! -f "$controller" ] || [ ! -x "$controller" ]; then
    echo "controller is missing or not executable: $controller" >&2
    exit 1
fi
if [ ! -f "$daemon" ] || [ ! -x "$daemon" ]; then
    echo "daemon is missing or not executable: $daemon" >&2
    exit 1
fi
if [ ! -f "$pairing_helper" ] || [ ! -x "$pairing_helper" ]; then
    echo "pairing helper is missing or not executable: $pairing_helper" >&2
    exit 1
fi
if [ ! -f "$cli" ] || [ ! -x "$cli" ]; then
    echo "CLI is missing or not executable: $cli" >&2
    exit 1
fi
if [ ! -f "$icon" ]; then
    echo "application icon is missing: $icon" >&2
    exit 1
fi
case "$output" in
    *.app) ;;
    *) echo "output must end in .app" >&2; exit 2 ;;
esac
if [ -e "$output" ]; then
    echo "refusing to overwrite existing output: $output" >&2
    exit 1
fi

output_parent=$(dirname -- "$output")
mkdir -p "$output_parent"
stage=$(mktemp -d "$output_parent/.keyferry-app.XXXXXX")
cleanup() {
    rm -rf -- "$stage"
}
trap cleanup EXIT HUP INT TERM

bundle="$stage/Keyferry.app"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
install -m 755 "$controller" "$bundle/Contents/MacOS/keyferry"
install -m 755 "$daemon" "$bundle/Contents/MacOS/keyferryd"
install -m 755 "$pairing_helper" "$bundle/Contents/MacOS/keyferry-pairing"
install -m 755 "$cli" "$bundle/Contents/MacOS/keyctl"
install -m 644 "$icon" "$bundle/Contents/Resources/keyferry.icns"

bridge_source="$project_dir/apps/keyferryd/macos/KeyferryBleBridge.swift"
if [ ! -f "$bridge_source" ]; then
    echo "Bluetooth bridge source is missing: $bridge_source" >&2
    exit 1
fi
xcrun swiftc -warnings-as-errors -O \
    -framework CoreBluetooth \
    -framework Foundation \
    "$bridge_source" \
    -o "$bundle/Contents/MacOS/keyferry-ble-bridge"

plist="$bundle/Contents/Info.plist"
plutil -create xml1 "$plist"
plutil -insert CFBundleDevelopmentRegion -string en "$plist"
plutil -insert CFBundleDisplayName -string Keyferry "$plist"
plutil -insert CFBundleExecutable -string keyferry "$plist"
plutil -insert CFBundleIconFile -string keyferry.icns "$plist"
plutil -insert CFBundleIdentifier -string io.github.smkwray.keyferry "$plist"
plutil -insert CFBundleInfoDictionaryVersion -string 6.0 "$plist"
plutil -insert CFBundleName -string Keyferry "$plist"
plutil -insert CFBundlePackageType -string APPL "$plist"
plutil -insert CFBundleShortVersionString -string 0.0.0 "$plist"
plutil -insert CFBundleVersion -string 1 "$plist"
plutil -insert LSMinimumSystemVersion -string 13.0 "$plist"
plutil -insert NSHighResolutionCapable -bool true "$plist"
plutil -insert NSBluetoothAlwaysUsageDescription -string \
    'Keyferry uses Bluetooth to connect securely to a nearby Keyferry USB device.' "$plist"

codesign --force --deep --sign - "$bundle"
codesign --verify --deep --strict "$bundle"
mv -- "$bundle" "$output"
trap - EXIT HUP INT TERM
rmdir -- "$stage"

echo "created $output"
