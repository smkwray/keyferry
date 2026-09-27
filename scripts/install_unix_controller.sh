#!/bin/sh
set -eu

usage() {
    echo "usage: install_unix_controller.sh --controller Keyferry.app [--installation DIRECTORY] [--lan-interface NAME]... --mode Plan|Apply|Verify" >&2
    exit 2
}

controller=
installation=
mode=Plan
lan_interfaces=
lan_arguments=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --controller) [ "$#" -ge 2 ] || usage; controller=$2; shift 2 ;;
        --installation) [ "$#" -ge 2 ] || usage; installation=$2; shift 2 ;;
        --lan-interface)
            [ "$#" -ge 2 ] || usage
            name=$2
            case "$name" in ''|*[!A-Za-z0-9._-]*) usage ;; esac
            case "$name" in [A-Za-z0-9]*) ;; *) usage ;; esac
            case " $lan_interfaces " in
                *" $name "*) echo "LAN interface names must be unique" >&2; exit 2 ;;
            esac
            lan_interfaces="${lan_interfaces}${lan_interfaces:+ }$name"
            lan_arguments="$lan_arguments --lan-interface $name"
            shift 2
            ;;
        --mode) [ "$#" -ge 2 ] || usage; mode=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$controller" ] || usage
case "$mode" in Plan|Apply|Verify) ;; *) usage ;; esac
[ "$(uname -s)" = Darwin ] || {
    echo "this milestone installs only the macOS desktop bundle" >&2
    exit 1
}

source_controller="$controller/Contents/MacOS/keyferry"
source_daemon="$controller/Contents/MacOS/keyferryd"
source_ble_bridge="$controller/Contents/MacOS/keyferry-ble-bridge"
source_pairing="$controller/Contents/MacOS/keyferry-pairing"
source_cli="$controller/Contents/MacOS/keyctl"
installed_app="$HOME/Applications/Keyferry.app"
installed_controller="$installed_app/Contents/MacOS/keyferry"
installed_daemon="$installed_app/Contents/MacOS/keyferryd"
installed_ble_bridge="$installed_app/Contents/MacOS/keyferry-ble-bridge"
installed_pairing="$installed_app/Contents/MacOS/keyferry-pairing"
installed_cli="$installed_app/Contents/MacOS/keyctl"
state_root="$HOME/Library/Application Support/keyferry"
installed_installation="$state_root/installation"
launch_agents="$HOME/Library/LaunchAgents"
launch_agent="$launch_agents/io.github.smkwray.keyferryd.plist"
launch_label=io.github.smkwray.keyferryd
launch_domain="gui/$(id -u)"
log_root="$state_root/logs"
daemon_stdout="$log_root/keyferryd.stdout.log"
daemon_stderr="$log_root/keyferryd.stderr.log"
stage=
transaction_rollback=
launch_agent_backup=
credential_stage=
plist_stage=
install_lock=
lock_owned=false
apply_started=false
apply_succeeded=false
old_app_displaced=false
new_app_published=false
had_installed_app=false
had_installed_installation=false
had_launch_agent=false
launch_agent_was_loaded=false
verification_started=false

for executable in "$source_controller" "$source_daemon" "$source_ble_bridge" "$source_pairing" "$source_cli"; do
    [ -f "$executable" ] && [ -x "$executable" ] || {
        echo "application bundle is incomplete: $executable" >&2
        exit 1
    }
done
# Without --installation only the programs are installed; the app then authorizes this computer.
if [ -n "$installation" ]; then
    [ -d "$installation" ] && [ ! -L "$installation" ] || {
        echo "installation credentials are missing or linked" >&2
        exit 1
    }
    find "$installation" -type l -print -quit | grep -q . && {
        echo "installation credentials must not contain links" >&2
        exit 1
    }
fi

if command -v shasum >/dev/null 2>&1; then
    hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    echo "shasum is required" >&2
    exit 1
fi

tree_hash() {
    root=$1
    files=$(find "$root" -type f | LC_ALL=C sort)
    [ -n "$files" ] || return 1
    count=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
    [ "$count" -le 16 ] || return 1
    total=$(find "$root" -type f -exec stat -f '%z' {} \; | awk '{sum += $1} END {print sum + 0}')
    [ "$total" -le 32768 ] || return 1
    (
        cd "$root"
        find . -type f -print | LC_ALL=C sort | while IFS= read -r path; do
            shasum -a 256 "$path"
        done
    ) | shasum -a 256 | awk '{print $1}'
}

stop_verification_daemon() {
    launchctl kill TERM "$launch_domain/$launch_label" 2>/dev/null || true
}

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    [ "$verification_started" != true ] || stop_verification_daemon
    if [ "$apply_started" = true ] && [ "$apply_succeeded" != true ]; then
        launchctl bootout "$launch_domain/$launch_label" 2>/dev/null || true
        pkill -TERM -f "$installed_controller" 2>/dev/null || true
        pkill -TERM -f "$installed_daemon" 2>/dev/null || true
        pkill -TERM -f "$installed_ble_bridge" 2>/dev/null || true
        [ "$installed_app" = "$HOME/Applications/Keyferry.app" ] || exit 90
        if [ "$new_app_published" = true ]; then
            rm -rf -- "$installed_app"
        fi
        if [ "$old_app_displaced" = true ] && [ -d "$transaction_rollback" ]; then
            mv -- "$transaction_rollback" "$installed_app"
        fi
        if [ "$had_launch_agent" = true ] && [ -f "$launch_agent_backup" ]; then
            install -m 600 "$launch_agent_backup" "$launch_agent"
        else
            rm -f -- "$launch_agent"
        fi
        if [ "$had_installed_installation" != true ] && [ -d "$installed_installation" ]; then
            [ "$installed_installation" = "$HOME/Library/Application Support/keyferry/installation" ] || exit 90
            rm -rf -- "$installed_installation"
        fi
        if [ "$launch_agent_was_loaded" = true ] && [ -f "$launch_agent" ]; then
            if ! launchctl bootstrap "$launch_domain" "$launch_agent" 2>/dev/null; then
                echo "rollback failed to restore the previous Keyferry launch agent" >&2
                status=91
            fi
        fi
    fi
    if [ -n "$credential_stage" ] && [ -d "$credential_stage" ]; then
        case "$credential_stage" in "$state_root"/.installation.*) rm -rf -- "$credential_stage" ;; *) exit 90 ;; esac
    fi
    if [ -n "$plist_stage" ] && [ -f "$plist_stage" ]; then
        case "$plist_stage" in "$state_root"/.keyferryd.plist.*) rm -f -- "$plist_stage" ;; *) exit 90 ;; esac
    fi
    if [ -n "$stage" ] && [ -d "$stage" ]; then
        case "$stage" in "$install_parent"/.keyferry-install.*) rm -rf -- "$stage" ;; *) exit 90 ;; esac
    fi
    if [ -n "$transaction_rollback" ] && [ -d "$transaction_rollback" ]; then
        case "$transaction_rollback" in "$install_parent"/.Keyferry.app.rollback.*) rm -rf -- "$transaction_rollback" ;; *) exit 90 ;; esac
    fi
    if [ "$lock_owned" = true ] && [ -d "$install_lock" ]; then
        [ "$install_lock" = "$state_root/.install.lock" ] || exit 90
        rmdir -- "$install_lock" || {
            echo "could not release the Keyferry installer lock" >&2
            status=92
        }
    fi
    exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

installation_hash='authorize this computer in the Keyferry app'
[ ! -d "$installed_installation" ] || installation_hash='existing credentials unchanged'
if [ -n "$installation" ]; then
    "$source_pairing" validate-installation --input "$installation" >/dev/null
    installation_hash=$(tree_hash "$installation")
fi
controller_hash=$(hash_file "$source_controller")
daemon_hash=$(hash_file "$source_daemon")
ble_bridge_hash=$(hash_file "$source_ble_bridge")
pairing_hash=$(hash_file "$source_pairing")
cli_hash=$(hash_file "$source_cli")

if [ "$mode" = Plan ]; then
    printf '%s\n' \
        'role=desktop-and-nearby-gateway' \
        'platform=macos' \
        "controller=$installed_controller" \
        "controller_sha256=$controller_hash" \
        "daemon=$installed_daemon" \
        "daemon_sha256=$daemon_hash" \
        "ble_bridge=$installed_ble_bridge" \
        "ble_bridge_sha256=$ble_bridge_hash" \
        "pairing_helper=$installed_pairing" \
        "pairing_helper_sha256=$pairing_hash" \
        "agent_cli=$installed_cli" \
        "agent_cli_sha256=$cli_hash" \
        "installation=$installed_installation" \
        "installation_tree_sha256=$installation_hash" \
        "lan_interfaces=${lan_interfaces:-none}" \
        "launch_agent=$launch_agent" \
        'daemon_runs=only-while-keyferry-is-open'
    exit 0
fi

[ ! -L "$installed_app" ] || {
    echo "refusing to replace a linked application" >&2
    exit 1
}
[ ! -L "$installed_installation" ] || {
    echo "installed identity must not be linked" >&2
    exit 1
}
lsof_command=$(command -v lsof || true)
[ -n "$lsof_command" ] || {
    echo "lsof is required to verify daemon listener ownership" >&2
    exit 1
}

if [ "$mode" = Apply ]; then
    if [ -n "$installation" ] && [ -d "$installed_installation" ] &&
       [ "$(tree_hash "$installed_installation")" != "$installation_hash" ]; then
        echo "installed identity differs; refusing to replace this computer's authority" >&2
        exit 1
    fi

    install_parent="$HOME/Applications"
    rollback="$install_parent/.Keyferry.app.previous"
    [ "$installed_app" = "$HOME/Applications/Keyferry.app" ] || exit 90
    [ "$rollback" = "$HOME/Applications/.Keyferry.app.previous" ] || exit 90
    mkdir -p "$install_parent" "$state_root" "$launch_agents" "$log_root"
    chmod 700 "$state_root"
    chmod 700 "$log_root"
    install_lock="$state_root/.install.lock"
    if ! mkdir "$install_lock"; then
        echo "another Keyferry installation is already in progress" >&2
        exit 1
    fi
    lock_owned=true
    stage=$(mktemp -d "$install_parent/.keyferry-install.XXXXXX")
    ditto "$controller" "$stage/Keyferry.app"
    codesign --verify --deep --strict "$stage/Keyferry.app"
    [ "$(hash_file "$stage/Keyferry.app/Contents/MacOS/keyferry")" = "$controller_hash" ]
    [ "$(hash_file "$stage/Keyferry.app/Contents/MacOS/keyferryd")" = "$daemon_hash" ]
    [ "$(hash_file "$stage/Keyferry.app/Contents/MacOS/keyferry-ble-bridge")" = "$ble_bridge_hash" ]
    [ "$(hash_file "$stage/Keyferry.app/Contents/MacOS/keyferry-pairing")" = "$pairing_hash" ]
    [ "$(hash_file "$stage/Keyferry.app/Contents/MacOS/keyctl")" = "$cli_hash" ]

    had_installed_app=false
    had_installed_installation=false
    had_launch_agent=false
    launch_agent_was_loaded=false
    [ -d "$installed_app" ] && had_installed_app=true
    [ -d "$installed_installation" ] && had_installed_installation=true
    if [ -f "$launch_agent" ]; then
        had_launch_agent=true
        launch_agent_backup="$stage/launch-agent.previous.plist"
        cp -p -- "$launch_agent" "$launch_agent_backup"
    fi
    if launchctl print "$launch_domain/$launch_label" >/dev/null 2>&1; then
        launch_agent_was_loaded=true
    fi
    if [ "$launch_agent_was_loaded" = true ] && [ "$had_launch_agent" != true ]; then
        echo "the existing loaded Keyferry launch agent has no restorable plist" >&2
        exit 1
    fi
    transaction_rollback="$install_parent/.Keyferry.app.rollback.$$"
    [ ! -e "$transaction_rollback" ] || {
        echo "temporary application rollback path already exists" >&2
        exit 1
    }
    apply_started=true

    launchctl bootout "$launch_domain/$launch_label" 2>/dev/null || true
    pkill -TERM -f "$installed_controller" 2>/dev/null || true
    pkill -TERM -f "$installed_daemon" 2>/dev/null || true
    pkill -TERM -f "$installed_ble_bridge" 2>/dev/null || true
    if [ -d "$installed_app" ]; then
        mv -- "$installed_app" "$transaction_rollback"
        old_app_displaced=true
    fi
    mv -- "$stage/Keyferry.app" "$installed_app"
    new_app_published=true

    if [ -n "$installation" ] && [ ! -d "$installed_installation" ]; then
        credential_stage=$(mktemp -d "$state_root/.installation.XXXXXX")
        ditto "$installation" "$credential_stage/installation"
        mv -- "$credential_stage/installation" "$installed_installation"
        rmdir -- "$credential_stage"
        credential_stage=
    fi
    [ ! -d "$installed_installation" ] || chmod -R go-rwx "$installed_installation"

    plist_stage="$state_root/.keyferryd.plist.$$"
    plutil -create xml1 "$plist_stage"
    plutil -insert Label -string "$launch_label" "$plist_stage"
    plutil -insert ProgramArguments -json '[]' "$plist_stage"
    /usr/libexec/PlistBuddy -c "Add :ProgramArguments:0 string $installed_daemon" "$plist_stage"
    /usr/libexec/PlistBuddy -c 'Add :ProgramArguments:1 string --installation' "$plist_stage"
    /usr/libexec/PlistBuddy -c "Add :ProgramArguments:2 string $installed_installation" "$plist_stage"
    argument_index=3
    for name in $lan_interfaces; do
        /usr/libexec/PlistBuddy -c "Add :ProgramArguments:$argument_index string --lan-interface" "$plist_stage"
        argument_index=$((argument_index + 1))
        /usr/libexec/PlistBuddy -c "Add :ProgramArguments:$argument_index string $name" "$plist_stage"
        argument_index=$((argument_index + 1))
    done
    # The agent defines the daemon's verified command but never starts on its own: the Keyferry
    # app kickstarts it on launch and signals it on exit. It stays loaded between launches.
    plutil -insert RunAtLoad -bool false "$plist_stage"
    plutil -insert KeepAlive -bool false "$plist_stage"
    plutil -insert ProcessType -string Interactive "$plist_stage"
    plutil -insert ThrottleInterval -integer 5 "$plist_stage"
    plutil -insert StandardOutPath -string "$daemon_stdout" "$plist_stage"
    plutil -insert StandardErrorPath -string "$daemon_stderr" "$plist_stage"
    plutil -lint "$plist_stage"
    install -m 600 "$plist_stage" "$launch_agent"
    rm -f -- "$plist_stage"
    plist_stage=
    launchctl bootstrap "$launch_domain" "$launch_agent"
fi

codesign --verify --deep --strict "$installed_app"
[ "$(hash_file "$installed_controller")" = "$controller_hash" ] || exit 1
[ "$(hash_file "$installed_daemon")" = "$daemon_hash" ] || exit 1
[ "$(hash_file "$installed_ble_bridge")" = "$ble_bridge_hash" ] || exit 1
[ "$(hash_file "$installed_pairing")" = "$pairing_hash" ] || exit 1
[ "$(hash_file "$installed_cli")" = "$cli_hash" ] || exit 1
[ -z "$installation" ] || [ "$(tree_hash "$installed_installation")" = "$installation_hash" ] || {
    echo "installed identity does not match the requested installation credentials" >&2
    exit 1
}
# Until the app authorizes this computer, its daemon waits without opening listeners.
authorized=false
[ -d "$installed_installation" ] && authorized=true
plutil -lint "$launch_agent" >/dev/null
expected_command="$installed_daemon --installation $installed_installation$lan_arguments"
[ "$(plutil -extract StandardOutPath raw "$launch_agent")" = "$daemon_stdout" ] || exit 1
[ "$(plutil -extract StandardErrorPath raw "$launch_agent")" = "$daemon_stderr" ] || exit 1
[ "$(plutil -extract RunAtLoad raw "$launch_agent")" = false ] &&
[ "$(plutil -extract KeepAlive raw "$launch_agent")" = false ] || {
    echo "the launch agent must run only when the Keyferry app starts it" >&2
    exit 1
}
# The daemon runs only while the Keyferry app is open. Verification starts it when it is not
# already running, checks it, and stops it again.
launch_state=$(launchctl print "$launch_domain/$launch_label" 2>/dev/null) || {
    echo "the Keyferry launch agent is not loaded" >&2
    exit 1
}
if ! printf '%s\n' "$launch_state" | awk '$1 == "pid" && $2 == "=" {found = 1} END {exit !found}'; then
    verification_started=true
    launchctl kickstart "$launch_domain/$launch_label"
fi

attempts=0
daemon_ready=false
while [ "$attempts" -lt 40 ]; do
    launch_state=$(launchctl print "$launch_domain/$launch_label" 2>/dev/null || true)
    daemon_pid=$(printf '%s\n' "$launch_state" | awk '$1 == "pid" && $2 == "=" {print $3; exit}')
    case "$daemon_pid" in ''|*[!0-9]*) daemon_pid= ;; esac
    if [ -n "$daemon_pid" ]; then
        daemon_command=$(ps -ww -p "$daemon_pid" -o command= 2>/dev/null || true)
        if [ "$daemon_command" = "$expected_command" ] && {
            [ "$authorized" = false ] ||
            "$lsof_command" -nP -a -p "$daemon_pid" -iTCP:8042 -sTCP:LISTEN 2>/dev/null |
                grep -q '127\.0\.0\.1:8042 (LISTEN)'
        }; then
            daemon_ready=true
            break
        fi
    fi
    sleep 0.25
    attempts=$((attempts + 1))
done
[ "$daemon_ready" = true ] || {
    echo "the installed launch agent did not run the requested daemon on its loopback listener" >&2
    exit 1
}
[ "$authorized" = true ] || lan_interfaces=
for name in $lan_interfaces; do
    interface_address=$(ipconfig getifaddr "$name" 2>/dev/null || true)
    [ -n "$interface_address" ] || {
        echo "selected LAN interface is not active: $name" >&2
        exit 1
    }
    "$lsof_command" -nP -a -p "$daemon_pid" -iTCP:7443 -sTCP:LISTEN 2>/dev/null |
        grep -Fq "TCP $interface_address:7443 (LISTEN)" || {
            echo "selected LAN interface did not open its exact device listener: $name" >&2
            exit 1
        }
done

tailscale_command=
for candidate in tailscale \
    /Applications/Tailscale.app/Contents/MacOS/Tailscale \
    /usr/local/bin/tailscale \
    /opt/homebrew/bin/tailscale; do
    if command -v "$candidate" >/dev/null 2>&1; then
        tailscale_command=$(command -v "$candidate")
        break
    fi
done
if [ "$authorized" = true ] && [ -n "$tailscale_command" ]; then
    tailnet_addresses=$($tailscale_command ip -4 2>/dev/null || true)
    if [ -n "$tailnet_addresses" ]; then
        tailnet_count=$(printf '%s\n' "$tailnet_addresses" | awk '/^100\./ {count++} END {print count + 0}')
        [ "$tailnet_count" -eq 1 ] || {
            echo "Tailscale is running without one unambiguous local IPv4 address" >&2
            exit 1
        }
        tailnet_address=$(printf '%s\n' "$tailnet_addresses" | awk '/^100\./ {print; exit}')
        attempts=0
        tailnet_ready=false
        while [ "$attempts" -lt 40 ]; do
            probe_ready=false
            control_ready=false
            "$lsof_command" -nP -a -p "$daemon_pid" -iTCP:18043 -sTCP:LISTEN 2>/dev/null |
                grep -Fq "TCP $tailnet_address:18043 (LISTEN)" && probe_ready=true
            "$lsof_command" -nP -a -p "$daemon_pid" -iTCP:18044 -sTCP:LISTEN 2>/dev/null |
                grep -Fq "TCP $tailnet_address:18044 (LISTEN)" && control_ready=true
            if [ "$probe_ready" = true ] && [ "$control_ready" = true ]; then
                tailnet_ready=true
                break
            fi
            sleep 0.25
            attempts=$((attempts + 1))
        done
        [ "$tailnet_ready" = true ] || {
            echo "the installed daemon did not open both owner-authenticated Tailscale listeners" >&2
            exit 1
        }
    fi
fi

if [ "$verification_started" = true ]; then
    stop_verification_daemon
    attempts=0
    while [ "$attempts" -lt 40 ] && kill -0 "$daemon_pid" 2>/dev/null; do
        sleep 0.25
        attempts=$((attempts + 1))
    done
    kill -0 "$daemon_pid" 2>/dev/null && {
        echo "the installed daemon did not stop after verification" >&2
        exit 1
    }
    verification_started=false
fi

if [ "$mode" = Apply ]; then
    if [ "$had_installed_app" = true ] && [ -d "$transaction_rollback" ]; then
        [ "$rollback" = "$HOME/Applications/.Keyferry.app.previous" ] || exit 90
        rm -rf -- "$rollback"
        mv -- "$transaction_rollback" "$rollback"
    fi
    apply_succeeded=true
fi

echo "Verification OK: Keyferry is installed as a controller and nearby gateway; its service runs only while Keyferry is open."
