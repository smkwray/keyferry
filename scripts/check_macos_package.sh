#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
    echo "check_macos_package.sh must run on macOS" >&2
    exit 1
fi

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

logical_cpus=$(sysctl -n hw.logicalcpu)
max_build_jobs=$((logical_cpus * 60 / 100))
[ "$max_build_jobs" -ge 1 ] || max_build_jobs=1
build_jobs=${CARGO_BUILD_JOBS:-$max_build_jobs}
case "$build_jobs" in
    ''|*[!0-9]*) echo "CARGO_BUILD_JOBS must be a positive integer" >&2; exit 1 ;;
esac
[ "$build_jobs" -ge 1 ] || {
    echo "CARGO_BUILD_JOBS must be a positive integer" >&2
    exit 1
}
[ "$build_jobs" -le "$max_build_jobs" ] || build_jobs=$max_build_jobs
export CARGO_BUILD_JOBS=$build_jobs
printf 'build concurrency: %s jobs (cap: 60%% of %s logical CPUs)\n' \
    "$build_jobs" "$logical_cpus"
# Panic locations embed source paths. Map the home, Cargo, and project prefixes (last match wins)
# so no builder's account reaches a release binary; check_public_tree.py rejects any that remain.
cargo_home=${CARGO_HOME:-$HOME/.cargo}
CARGO_ENCODED_RUSTFLAGS=$(printf '%s\037%s\037%s' \
    "--remap-path-prefix=$HOME=~" \
    "--remap-path-prefix=$cargo_home=cargo" \
    "--remap-path-prefix=$project_dir=.")
export CARGO_ENCODED_RUSTFLAGS

# Resolve the checkout's toolchain once, including when Homebrew shadows rustup's shims.
active_toolchain=$(rustup show active-toolchain)
rust_toolchain=${active_toolchain%% *}
RUSTC=$(rustup which --toolchain "$rust_toolchain" rustc)
RUSTDOC=$(rustup which --toolchain "$rust_toolchain" rustdoc)
export RUSTC RUSTDOC

run_cargo() {
    rustup run "$rust_toolchain" cargo "$@"
}

run_cargo test --locked --release \
    -p keyferryd \
    -p keyferry-local-management \
    -p keyferry-pairing
run_cargo build --locked --release \
    -p keyferry \
    -p keyferryd \
    -p keyferry-pairing \
    -p keyctl

stage=$(mktemp -d)
cleanup() {
    cleanup_status=$?
    trap - EXIT HUP INT TERM
    rm -rf -- "$stage"
    exit "$cleanup_status"
}
trap cleanup EXIT HUP INT TERM

app="$stage/Keyferry.app"
cargo_target_dir=${CARGO_TARGET_DIR:-target}
release_dir="$cargo_target_dir/release"
sh scripts/package_macos_app.sh \
    "$release_dir/keyferry" \
    "$release_dir/keyferryd" \
    "$release_dir/keyferry-pairing" \
    "$release_dir/keyctl" \
    "$app"

codesign --verify --deep --strict "$app"
plutil -lint "$app/Contents/Info.plist" >/dev/null
for executable in keyferry keyferryd keyferry-ble-bridge keyferry-pairing keyctl; do
    test -x "$app/Contents/MacOS/$executable"
done

private_identifiers="$stage/private-identifiers.txt"
private_marker=$(uuidgen | tr '[:upper:]' '[:lower:]')
printf '%s\n' "$private_marker" >"$private_identifiers"
release="$stage/keyferry-macos-arm64.zip"
python3 scripts/package_controller_release.py \
    --platform macos \
    --controller "$app" \
    --output "$release" \
    --version 0.0.0-package-gate \
    --private-identifiers "$private_identifiers"
python3 scripts/check_public_tree.py --artifact "$release" \
    --private-identifiers "$private_identifiers" --require-private-registry

usage_description=$(plutil -extract NSBluetoothAlwaysUsageDescription raw \
    "$app/Contents/Info.plist")
[ -n "$usage_description" ]

set +e
"$app/Contents/MacOS/keyferry-pairing" >/dev/null 2>&1
pairing_status=$?
set -e
[ "$pairing_status" -eq 2 ] || {
    echo "packaged pairing helper did not execute with its expected usage status" >&2
    exit 1
}

private_bundle="$stage/pairing-bundle"
mkdir -p "$private_bundle/firmware" "$private_bundle/recovery"
device_id=$(uuidgen | tr '[:upper:]' '[:lower:]')
printf '%s\n' \
    "{\"schema_version\":1,\"device_id\":\"$device_id\",\"link_secret_hex\":\"\",\"host_address\":\"127.0.0.1\",\"host_port\":1,\"host_certificate_der\":\"\",\"host_spki_der\":\"\",\"host_spki_sha256\":\"\"}" \
    >"$private_bundle/firmware/device.json"
dd if=/dev/urandom of="$private_bundle/recovery/secret.bin" bs=32 count=1 2>/dev/null
passphrase=$(openssl rand -hex 32)
owner_kit="$stage/owner-kit.json"
installation="$stage/installation"
printf '%s\n%s\n' "$passphrase" "$passphrase" |
    "$app/Contents/MacOS/keyferry-pairing" --bundle "$private_bundle" \
        create-owner-kit --output "$owner_kit" >/dev/null
printf '%s\n' "$passphrase" |
    "$app/Contents/MacOS/keyferry-pairing" issue-installation \
        --owner-kit "$owner_kit" --output "$installation" >/dev/null
"$app/Contents/MacOS/keyferry-pairing" validate-installation \
    --input "$installation" >/dev/null
new_passphrase="${passphrase}x"
printf '%s\n%s\n%s\n' "$passphrase" "$new_passphrase" "$new_passphrase" |
    "$app/Contents/MacOS/keyferry-pairing" change-owner-kit-passphrase \
        --owner-kit "$owner_kit" >/dev/null
set +e
printf '%s\n' "$passphrase" |
    "$app/Contents/MacOS/keyferry-pairing" issue-installation \
        --owner-kit "$owner_kit" --output "$stage/old-password-installation" \
        >/dev/null 2>&1
old_password_status=$?
set -e
[ "$old_password_status" -ne 0 ] || {
    echo "old owner-kit password remained valid after change" >&2
    exit 1
}
rekeyed_installation="$stage/rekeyed-installation"
printf '%s\n' "$new_passphrase" |
    "$app/Contents/MacOS/keyferry-pairing" issue-installation \
        --owner-kit "$owner_kit" --output "$rekeyed_installation" >/dev/null
"$app/Contents/MacOS/keyferry-pairing" validate-installation \
    --input "$rekeyed_installation" >/dev/null
[ ! -e "${owner_kit%.*}.rekey.lock" ] || {
    echo "owner-kit password change left a stale rekey lock" >&2
    exit 1
}
sh scripts/install_unix_controller.sh --controller "$app" \
    --installation "$installation" --lan-interface en0 --mode Plan >/dev/null

echo "macOS package gate: ok"
