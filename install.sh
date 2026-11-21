#!/bin/sh
set -eu
umask 077
box_charset=$(locale charmap 2>/dev/null || true)
LC_ALL=C
export LC_ALL

# Publisher Team ID for signed releases.
readonly BOX_TEAM_ID='94KV3E626L'

box_pretty=0 box_colors=0 box_drawing=0 box_download_pid= box_path_notice=
box_accent= box_dim= box_reset=
clear_progress() {
    [ "$box_drawing" -eq 1 ] || return 0
    printf '\r\033[K\033[?25h' >&2 || true
    box_drawing=0
}
log() { clear_progress; printf '%s\n' "$*" >&2; }
die() { log "install.sh: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
check_width() {
    [ "$box_pretty" -eq 1 ] || return 0
    box_columns=$(stty size <&2 2>/dev/null || true)
    box_columns=${box_columns##* }
    case "$box_columns" in ''|*[!0-9]*) box_columns=0 ;; esac
    if [ "$box_columns" -lt 80 ]; then
        clear_progress
        box_pretty=0 box_accent= box_dim= box_reset=
    fi
}
progress() {
    check_width
    [ "$box_pretty" -eq 1 ] || return 0
    box_on= box_off= box_cell=0
    while [ "$box_cell" -lt 50 ]; do
        if [ "$box_cell" -lt "$(($1 / 2))" ]; then
            box_on="${box_on}■"
        else
            box_off="${box_off}■"
        fi
        box_cell=$((box_cell + 1))
    done
    printf '\033[?25l\r%s%s%s%s%s%s %s%3d%%%s %s%s%s\033[K' \
        "$box_accent" "$box_on" "$box_reset" "$box_dim" "$box_off" "$box_reset" \
        "$box_accent" "$1" "$box_reset" "$box_dim" "$2" "$box_reset" >&2
    box_drawing=1
}
logo() {
    printf '%b\n' \
        '             \033[38;2;222;193;160m▄▄███▄▄\033[0m' \
        '         \033[38;2;154;115;72m▄\033[38;2;222;193;160m▄███████████▄▄\033[0m' \
        '     \033[38;2;222;193;160m▄▄\033[38;2;154;115;72m█████\033[48;2;154;115;72m\033[38;2;222;193;160m▀▀\033[49m████████████▄▄\033[0m' \
        ' \033[38;2;222;193;160m▄▄██████\033[48;2;222;193;160m\033[38;2;154;115;72m▀▀\033[49m█████\033[48;2;154;115;72m\033[38;2;222;193;160m▀▀\033[49m████████████▄▄     \033[39m███\033[38;2;56;166;96m▄\033[0m' \
        '\033[48;2;198;148;92m\033[38;2;242;231;219m▀\033[48;2;242;231;219m\033[38;2;222;193;160m▀▀\033[49m██████████\033[48;2;222;193;160m\033[38;2;154;115;72m▀▀\033[49m█████\033[48;2;154;115;72m\033[38;2;222;193;160m▀▀\033[49m████████\033[48;2;242;231;219m▀▀\033[48;2;115;86;53m\033[38;2;242;231;219m▀\033[49m    \033[39m███\033[38;2;56;166;96m█\033[38;2;30;89;51m█\033[0m' \
        '\033[38;2;198;148;92m█\033[48;2;198;148;92m\033[38;2;42;29;18m▄▖\033[38;2;242;231;219m▀▀\033[48;2;242;231;219m\033[38;2;222;193;160m▀▀\033[49m██████████\033[48;2;222;193;160m\033[38;2;154;115;72m▀▀\033[49m█████\033[48;2;154;115;72m\033[38;2;222;193;160m▀▀\033[48;2;242;231;219m▀▀\033[48;2;115;86;53m\033[38;2;242;231;219m▀▀\033[49m\033[38;2;115;86;53m███    \033[39m█████████▄   ▄████████▄   ███▄  ▄███\033[38;2;56;166;96m▄\033[0m' \
        '\033[38;2;198;148;92m█\033[48;2;198;148;92m\033[38;2;42;29;18m▙▖▜▘▄\033[49m\033[38;2;198;148;92m█\033[48;2;198;148;92m\033[38;2;242;231;219m▀▀\033[48;2;242;231;219m\033[38;2;222;193;160m▀▀\033[49m██████████\033[48;2;222;193;160m\033[38;2;154;115;72m▀\033[48;2;242;231;219m▀▀\033[48;2;75;56;35m\033[38;2;242;231;219m▀▀\033[49m\033[38;2;115;86;53m███████    \033[39m███\033[48;2;56;166;96m▀▀▀▀\033[49m███\033[38;2;56;166;96m█\033[38;2;30;89;51m▄ \033[39m███\033[48;2;56;166;96m▀▀▀▀\033[49m███\033[38;2;56;166;96m█\033[38;2;30;89;51m▄  \033[39m▀██████\033[48;2;56;166;96m▀\033[49m\033[38;2;56;166;96m█\033[48;2;30;89;51m▀\033[49m\033[38;2;30;89;51m█\033[0m' \
        '\033[38;2;198;148;92m█\033[48;2;198;148;92m\033[38;2;42;29;18m▄▌▐\033[49m\033[38;2;198;148;92m█\033[48;2;198;148;92m\033[38;2;42;29;18m▙▘▞▖▖▗\033[38;2;242;231;219m▀▀\033[48;2;242;231;219m\033[38;2;222;193;160m▀▀\033[49m███\033[48;2;242;231;219m▀▀\033[48;2;115;86;53m\033[38;2;242;231;219m▀▀\033[49m\033[38;2;115;86;53m█\033[38;2;75;56;35m███\033[38;2;115;86;53m███████    \033[39m███\033[38;2;56;166;96m█\033[38;2;30;89;51m█▀▀\033[39m███\033[38;2;56;166;96m█\033[38;2;30;89;51m█ \033[39m███\033[38;2;56;166;96m█\033[38;2;30;89;51m█▀▀\033[39m███\033[38;2;56;166;96m█\033[38;2;30;89;51m█    \033[39m████\033[38;2;56;166;96m█\033[48;2;30;89;51m▀\033[49m\033[38;2;30;89;51m█▀\033[0m' \
        '\033[38;2;198;148;92m███\033[48;2;198;148;92m\033[38;2;42;29;18m▝\033[49m\033[38;2;198;148;92m█\033[48;2;198;148;92m\033[38;2;42;29;18m▌▌▛▌▛▟▐▚▗▄\033[38;2;242;231;219m▀\033[49m█\033[48;2;115;86;53m▀\033[49m\033[38;2;115;86;53m█████\033[38;2;75;56;35m█\033[48;2;115;86;53m▀▀\033[49m\033[38;2;115;86;53m███████    \033[39m███\033[48;2;56;166;96m▄\033[48;2;30;89;51m▄\033[49m▄▄███\033[38;2;56;166;96m█\033[38;2;30;89;51m█ \033[39m███\033[48;2;56;166;96m▄\033[48;2;30;89;51m▄\033[49m▄▄███\033[38;2;56;166;96m█\033[38;2;30;89;51m█  \033[39m▄██████\033[48;2;30;89;51m▄\033[0m' \
        '\033[38;2;198;148;92m███████\033[48;2;198;148;92m\033[38;2;42;29;18m▘▘▌▐▐▐▐▄\033[49m\033[38;2;198;148;92m█\033[38;2;242;231;219m█\033[38;2;115;86;53m████████████████    \033[39m█████████\033[48;2;56;166;96m▀\033[49m\033[38;2;56;166;96m█\033[38;2;30;89;51m█ \033[39m▀████████\033[48;2;56;166;96m▀\033[49m\033[38;2;56;166;96m█\033[38;2;30;89;51m█ \033[39m███\033[48;2;56;166;96m▀\033[49m\033[38;2;56;166;96m█\033[48;2;30;89;51m▀\033[39m▀\033[49m███\033[38;2;56;166;96m▄\033[0m' \
        '\033[38;2;198;148;92m▀██████████\033[48;2;198;148;92m\033[38;2;42;29;18m▝▘▗▟\033[49m\033[38;2;198;148;92m█\033[38;2;242;231;219m█\033[38;2;115;86;53m███████████████▀     \033[38;2;56;166;96m▀\033[48;2;30;89;51m▀▀▀▀▀▀▀▀\033[49m\033[38;2;30;89;51m█▀   \033[38;2;56;166;96m▀\033[48;2;30;89;51m▀▀▀▀▀▀▀\033[49m\033[38;2;30;89;51m█▀  \033[38;2;56;166;96m▀\033[48;2;30;89;51m▀▀\033[49m\033[38;2;30;89;51m█▀  \033[38;2;56;166;96m▀\033[48;2;30;89;51m▀▀\033[49m\033[38;2;30;89;51m█\033[0m' \
        '   \033[38;2;198;148;92m▀▀███████████\033[38;2;242;231;219m█\033[38;2;115;86;53m███████████▀▀\033[0m' \
        '       \033[38;2;198;148;92m▀▀███████\033[38;2;242;231;219m█\033[38;2;115;86;53m███████▀▀\033[0m' \
        '           \033[38;2;198;148;92m▀▀███\033[38;2;242;231;219m█\033[38;2;115;86;53m███▀▀\033[0m' \
        '               \033[38;2;198;148;92m▀\033[38;2;242;231;219m▀\033[38;2;115;86;53m▀\033[0m'
}
welcome() {
    check_width
    if [ "$box_pretty" -eq 1 ]; then
        if [ "$box_colors" = 256 ]; then
            logo | sed '
                s/;2;222;193;160m/;5;180m/g
                s/;2;154;115;72m/;5;137m/g
                s/;2;198;148;92m/;5;173m/g
                s/;2;242;231;219m/;5;230m/g
                s/;2;115;86;53m/;5;94m/g
                s/;2;75;56;35m/;5;236m/g
                s/;2;42;29;18m/;5;234m/g
                s/;2;56;166;96m/;5;71m/g
                s/;2;30;89;51m/;5;22m/g
            ' >&2
        else
            logo >&2
        fi
        printf '\n' >&2
    fi
    {
        printf 'box run <profile>       %s# Start an agent in a box, from your project%s\n' "$box_dim" "$box_reset"
        printf 'box profile <command>   %s# Create, show, and remove profiles%s\n\n' "$box_dim" "$box_reset"
        printf '%sExample next steps (Claude Code with Bedrock):%s\n\n' "$box_dim" "$box_reset"
        printf 'box profile create claude --with bedrock   %s# Then set its model and sign in to Bedrock%s\n' "$box_dim" "$box_reset"
        printf 'box run claude                             %s# Run from your project%s\n\n' "$box_dim" "$box_reset"
        if box_telemetry=$("$box_launcher" telemetry status 2>/dev/null); then
            case "$box_telemetry" in
                'Telemetry is on'*)
                    printf '%sbox sends usage telemetry to telemetry.strandsagents.com%s\n' "$box_dim" "$box_reset"
                    printf '%sTo opt out, run:%s box telemetry off\n' "$box_dim" "$box_reset"
                    printf '%sTo learn more:%s https://github.com/strands-agents/box/blob/main/CLI_TELEMETRY.md\n\n' "$box_dim" "$box_reset"
                    ;;
            esac
        fi
    } >&2
}
version() {
    case "$1" in ''|*[!0-9a-z.-]*) die "expected a version such as 0.3.0 or 0.3.0-preview.1: $1" ;; esac
    awk -v value="$1" 'BEGIN {
        exit !(value ~ /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(linux-)?preview\.[1-9][0-9]*)?$/)
    }' || die "expected a version such as 0.3.0 or 0.3.0-preview.1: $1"
}
checksum() {
    case "$box_system" in
        Darwin) shasum -a 256 "$1" ;;
        Linux) sha256sum "$1" ;;
    esac
}
permissions() {
    case "$box_system" in
        Darwin) stat -f '%Sp' "$1" ;;
        Linux) stat -c '%A' "$1" ;;
    esac
}
replace_link() {
    case "$box_system" in
        Darwin) mv -fh "$1" "$2" ;;
        Linux) mv -fT "$1" "$2" ;;
    esac
}
metadata() {
    case "$box_system" in
        Darwin) plutil -extract "release.$1" raw -expect string -o - "$box_metadata" ;;
        Linux)
            python3 -I -c '
import json, sys
try:
    with open(sys.argv[1]) as source:
        value = json.load(source)[sys.argv[2]]
    if not isinstance(value, str):
        raise ValueError("expected a string")
except (OSError, ValueError, KeyError, TypeError):
    sys.exit("install.sh: invalid release.json")
print(value)
' "$box_payload/release.json" "$1"
            ;;
    esac
}
check_directory() {
    box_check=$1
    case "$box_check" in /*) ;; *) die "path must be absolute: $box_check" ;; esac
    while [ "$box_check" != / ]; do
        [ ! -L "$box_check" ] || die "directory is a symbolic link: $box_check"
        if [ -e "$box_check" ]; then
            [ -d "$box_check" ] || die "not a directory: $box_check"
            [ -w "$box_check" ] || die "directory is not writable: $box_check"
            break
        fi
        box_check=${box_check%/*}
        [ -n "$box_check" ] || box_check=/
    done
    while [ "$box_check" != / ]; do
        [ ! -L "$box_check" ] || die "directory is a symbolic link: $box_check"
        box_check=${box_check%/*}
        [ -n "$box_check" ] || box_check=/
    done
}
directory() {
    check_directory "$1"
    [ -d "$1" ] || mkdir "$1" || die "cannot create directory: $1"
}
check_shell_file() {
    check_directory "${1%/*}"
    [ ! -L "$1" ] || die "linked shell file: $1; retry with BOX_NO_MODIFY_PATH=1"
    if [ -e "$1" ]; then
        [ -f "$1" ] && [ -r "$1" ] && [ -w "$1" ] ||
            die "cannot update $1; retry with BOX_NO_MODIFY_PATH=1"
        if grep -q '# [<>][<>][<>] Box PATH' "$1"; then
            sed -n '/^# >>> Box PATH >>>$/,/^# <<< Box PATH <<<$/{p;}' "$1" > "$box_work/path.found"
            cmp -s "$box_work/path.block" "$box_work/path.found" ||
                die "incomplete or changed Box PATH block in $1"
        fi
    fi
}
add_path() {
    check_shell_file "$1"
    if [ -e "$1" ] && grep -q '^# >>> Box PATH >>>$' "$1"; then return; fi
    box_path_temp=$(mktemp "${1%/*}/.box-path.XXXXXXXX") || die "cannot prepare $1"
    box_had_file=0
    if [ -e "$1" ]; then
        cp -p "$1" "$box_work/path.original"
        cp -p "$box_work/path.original" "$box_path_temp"
        box_had_file=1
    fi
    printf '\n' >> "$box_path_temp"
    cat "$box_work/path.block" >> "$box_path_temp"
    check_shell_file "$1"
    if [ "$box_had_file" -eq 1 ]; then
        cmp -s "$1" "$box_work/path.original" || die "shell file changed during installation: $1"
    else
        [ ! -e "$1" ] || die "shell file appeared during installation: $1"
    fi
    mv -f "$box_path_temp" "$1" || die "cannot update $1"
    box_path_temp=
    box_path_notice="${box_path_notice}${box_path_notice:+
}Added box to \$PATH in $1"
}
# Releases download over HTTPS from public GitHub, so the installer needs no GitHub sign-in.
fetch() { curl -fsSL --proto '=https' --tlsv1.2 "$@"; }
release_url() { printf 'https://github.com/%s/releases/download/v%s/%s\n' "$box_repo" "$box_version" "$1"; }
download() {
    if [ "$box_pretty" -eq 1 ] && [ "$1" = "$box_asset" ]; then
        fetch -o "$2" "$(release_url "$1")" > "$box_work/download.log" 2>&1 &
        box_download_pid=$!
        progress 0 Downloading
        while kill -0 "$box_download_pid" 2>/dev/null; do
            if [ -f "$2" ]; then
                box_bytes=$(wc -c < "$2")
                box_mb=$((box_bytes * 10 / 1048576))
                if [ "$box_total" -gt 0 ]; then
                    box_percent=$((box_bytes * 80 / box_total))
                    [ "$box_percent" -le 80 ] || box_percent=80
                    box_of=$((box_total * 10 / 1048576))
                    progress "$box_percent" "$((box_mb / 10)).$((box_mb % 10)) / $((box_of / 10)).$((box_of % 10)) MB"
                else
                    progress 0 "Downloading $((box_mb / 10)).$((box_mb % 10)) MB"
                fi
            fi
            sleep 0.1
        done
        if wait "$box_download_pid"; then
            box_download_pid=
            return
        fi
        box_download_pid=
        clear_progress
        cat "$box_work/download.log" >&2
        die "cannot download $1 from release v$box_version of $box_repo"
    fi
    fetch -o "$2" "$(release_url "$1")" ||
        die "cannot download $1 from release v$box_version of $box_repo"
}
native_alias() {
    case "$1" in
        strands-box-sock-alias|strands-box-contain-trampoline) printf 'Box.app/Contents/MacOS/%s\n' "$1" ;;
        resources|release.json) printf 'Box.app/Contents/Resources/%s\n' "$1" ;;
        *) return 1 ;;
    esac
}
check_links() {
    find "$1" ! -type f ! -type d ! -type l -print > "$box_work/special"
    [ ! -s "$box_work/special" ] || die "$2 contains special files"
    find "$1" -type l -print > "$box_work/links"
    while IFS= read -r box_link; do
        box_name=${box_link#"$1/"}
        box_target=$(native_alias "$box_name") || die "$2 contains an unexpected link: $box_name"
        [ "$box_native" -eq 1 ] && [ "$(readlink "$box_link")" = "$box_target" ] &&
            [ -e "$1/$box_target" ] || die "$2 contains an unsafe alias: $box_name"
    done < "$box_work/links"
}
managed_metadata() {
    [ -f "$1/release.json" ] || return 1
    [ -L "$1/release.json" ] || return 0
    [ "$box_system" = Darwin ] &&
        [ "$(readlink "$1/release.json")" = Box.app/Contents/Resources/release.json ] || return 1
    for box_part in Box.app Box.app/Contents Box.app/Contents/Resources Box.app/Contents/Resources/release.json; do
        [ ! -L "$1/$box_part" ] || return 1
    done
}
check_installation() {
    box_earlier_launcher=0
    if [ -L "$box_launcher" ]; then
        box_link=$(readlink "$box_launcher")
        # box 0.2.2 and earlier installed into ~/.box/packages; this installer takes its launcher over.
        if [ "$box_link" = "$box_earlier_target" ]; then
            box_earlier_launcher=1
        else
            [ "$box_link" = "$box_launcher_target" ] ||
                die "another launcher exists at $box_launcher"
        fi
    elif [ -e "$box_launcher" ]; then
        die "another file exists at $box_launcher"
    fi
    box_previous=
    if [ -L "$box_current" ]; then
        box_previous=$(readlink "$box_current")
        case "$box_previous" in *-"$box_triple") ;; *) die "current is not a managed release" ;; esac
        version "${box_previous%-$box_triple}"
        [ ! -L "$box_root/$box_previous" ] && [ -d "$box_root/$box_previous" ] &&
            managed_metadata "$box_root/$box_previous" || die "current is not a managed release"
    elif [ -e "$box_current" ]; then
        die "current is not a symbolic link: $box_current"
    fi
    if [ -n "${box_destination-}" ]; then
        [ ! -L "$box_destination" ] || die "release directory is a symbolic link"
        if [ -e "$box_destination" ]; then
            [ -d "$box_destination" ] || die "release path is not a directory"
        fi
    fi
}

box_work= box_stage= box_unpack= box_path_temp= box_lock= box_made_strands=0 box_made_box=0 box_made_root=0
box_previous= box_activating=0 box_created_launcher=0 box_replaced_launcher=0
cleanup() {
    box_status=$?
    trap - 0 HUP INT TERM
    if [ -n "$box_download_pid" ]; then
        kill "$box_download_pid" 2>/dev/null || true
        wait "$box_download_pid" 2>/dev/null || true
    fi
    clear_progress
    if [ "$box_status" -ne 0 ] && [ "$box_activating" -eq 1 ] &&
        [ -L "$box_current" ] && [ "$(readlink "$box_current")" = "$box_release" ]; then
        if [ -n "$box_previous" ]; then
            if ln -s "$box_previous" "$box_stage/current.rollback" &&
                replace_link "$box_stage/current.rollback" "$box_current"; then
                log "Restored $box_previous."
            else
                log "Cannot restore $box_current to $box_previous."
            fi
        else
            rm -f "$box_current"
        fi
    fi
    if [ "$box_status" -ne 0 ] && [ "$box_created_launcher" -eq 1 ] &&
        [ -L "$box_launcher" ] && [ "$(readlink "$box_launcher")" = "$box_launcher_target" ]; then
        rm -f "$box_launcher"
    fi
    if [ "$box_status" -ne 0 ] && [ "$box_replaced_launcher" -eq 1 ] &&
        [ -L "$box_launcher" ] && [ "$(readlink "$box_launcher")" = "$box_launcher_target" ]; then
        if ln -s "$box_earlier_target" "$box_stage/launcher.rollback" &&
            replace_link "$box_stage/launcher.rollback" "$box_launcher"; then
            log "Restored the launcher of the earlier box in ~/.box."
        else
            log "Cannot restore $box_launcher to $box_earlier_target."
        fi
    fi
    [ -z "$box_path_temp" ] || rm -f "$box_path_temp"
    [ -z "$box_stage" ] || rm -rf "$box_stage"
    [ -z "$box_unpack" ] || rm -rf "$box_unpack"
    # A failed install removes the folders it created to unpack in, while they are still empty.
    if [ "$box_status" -ne 0 ]; then
        [ "$box_made_root" -eq 0 ] || rmdir "$box_root" 2>/dev/null || true
        [ "$box_made_box" -eq 0 ] || rmdir "$box_home/.strands/box" 2>/dev/null || true
        [ "$box_made_strands" -eq 0 ] || rmdir "$box_home/.strands" 2>/dev/null || true
    fi
    [ -z "$box_work" ] || rm -rf "$box_work"
    [ -z "$box_lock" ] || rmdir "$box_lock"
    exit "$box_status"
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$#" -eq 0 ] ||
    die "use BOX_VERSION, BOX_NO_MODIFY_PATH, BOX_GITHUB_REPO, and BOX_ALLOW_UNSIGNED through the environment"
box_repo=${BOX_GITHUB_REPO-strands-agents/box}
case "$box_repo" in ''|*[!A-Za-z0-9._/-]*) die "BOX_GITHUB_REPO must be owner/repo" ;; esac
awk -v repo="$box_repo" 'BEGIN {
    split(repo, parts, "/")
    exit !(repo ~ /^[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9._-]+$/ && parts[2] != "." && parts[2] != "..")
}' || die "BOX_GITHUB_REPO must be owner/repo"
box_unsigned=${BOX_ALLOW_UNSIGNED-0}
case "$box_unsigned" in 0|1) ;; *) die "BOX_ALLOW_UNSIGNED must be 0 or 1" ;; esac
box_no_path=${BOX_NO_MODIFY_PATH-0}
case "$box_no_path" in 0|1) ;; *) die "BOX_NO_MODIFY_PATH must be 0 or 1" ;; esac
# BOX_VERSION takes the release tag too (v0.3.0), as download.sh does.
if [ "${BOX_VERSION+x}" = x ]; then BOX_VERSION=${BOX_VERSION#v}; version "$BOX_VERSION"; fi
for box_tool in uname awk tar mktemp mkdir rmdir mv ln rm readlink find \
    sort cmp stat chmod sed grep cat cp curl dirname wc sleep; do
    need "$box_tool"
done
box_system=$(uname -s)
case "$box_system" in
    Darwin)
        need sw_vers
        box_os=$(sw_vers -productVersion)
        case "$box_os" in ''|*[!0-9.]*) die "cannot read the macOS version" ;; esac
        [ "${box_os%%.*}" -ge 15 ] || die "macOS 15 or later is required"
        case "$(uname -m)" in
            arm64|aarch64) ;;
            x86_64)
                need sysctl
                [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ] ||
                    die "Intel Macs are unsupported"
                ;;
            *) die "Apple Silicon is required" ;;
        esac
        box_triple=aarch64-apple-darwin
        box_default_shell=/bin/zsh
        need shasum
        need plutil
        if [ "$box_unsigned" -eq 0 ]; then
            [ -n "$BOX_TEAM_ID" ] ||
                die "the release publisher must configure the signing Team ID, or set BOX_ALLOW_UNSIGNED=1 for an unsigned release"
            case "$BOX_TEAM_ID" in *[!A-Z0-9]*) die "invalid publisher Team ID" ;; esac
            [ "${#BOX_TEAM_ID}" -eq 10 ] || die "invalid publisher Team ID"
            need codesign
            need spctl
        fi
        ;;
    Linux)
        box_machine=$(uname -m)
        case "$box_machine" in
            arm64|aarch64) box_triple=aarch64-unknown-linux-gnu ;;
            x86_64|amd64) box_triple=x86_64-unknown-linux-gnu ;;
            *) die "unsupported Linux architecture: $box_machine; use macOS on Apple silicon, or Linux on ARM64 or x86-64" ;;
        esac
        need getconf
        box_libc=$(getconf GNU_LIBC_VERSION 2>/dev/null) || die "Linux requires glibc 2.34 or later"
        awk -v value="$box_libc" 'BEGIN {
            if (value !~ /^glibc [0-9]+\.[0-9]+$/) exit 1
            split(substr(value, 7), parts, ".")
            exit !(parts[1] > 2 || (parts[1] == 2 && parts[2] >= 34))
        }' || die "Linux requires glibc 2.34 or later"
        box_default_shell=/bin/bash
        need sha256sum
        need python3
        ;;
    *) die "unsupported operating system: $box_system; use macOS on Apple silicon, or Linux on ARM64 or x86-64" ;;
esac
case "${HOME-}" in /*) ;; *) die "HOME must be an absolute directory" ;; esac
box_home=$(cd "$HOME" && pwd -P) || die "cannot open HOME"
box_root="$box_home/.strands/box/packages"
box_bin="$box_home/.local/bin"
box_current="$box_root/current"
box_launcher="$box_bin/box"
box_launcher_target="$box_root/current/box"
box_earlier_target="$box_home/.box/packages/current/box"
check_directory "$box_root"
check_directory "$box_bin"
[ ! -e "$box_root/.install-lock" ] && [ ! -L "$box_root/.install-lock" ] ||
    die "Another Box installation is in progress. Remove $box_root/.install-lock only after confirming it has stopped."
check_installation

box_work=$(mktemp -d /var/tmp/box-download.XXXXXXXX) || die "cannot create temporary storage"
cat > "$box_work/path.block" <<'BOX_PATH'
# >>> Box PATH >>>
case ":${PATH-}:" in
    *":$HOME/.local/bin:"*) ;;
    *) export PATH="$HOME/.local/bin${PATH:+:$PATH}" ;;
esac
# <<< Box PATH <<<
BOX_PATH
box_path_first= box_path_second= box_fish_config=
box_need_path=$((1 - box_no_path))
case ":${PATH-}:" in *":$box_bin:"*|*":$HOME/.local/bin:"*) box_need_path=0 ;; esac
if [ "$box_need_path" -eq 1 ]; then
    case "${SHELL-$box_default_shell}" in
        */zsh) box_path_first="${ZDOTDIR:-$box_home}/.zshrc" ;;
        */bash)
            box_path_first="$box_home/.bash_profile"
            for box_file in "$box_home/.bash_profile" "$box_home/.bash_login" "$box_home/.profile"; do
                if [ -e "$box_file" ] || [ -L "$box_file" ]; then box_path_first=$box_file; break; fi
            done
            box_path_second="$box_home/.bashrc"
            ;;
        */fish)
            box_fish_config="${XDG_CONFIG_HOME:-$box_home/.config}/fish"
            box_path_first="$box_fish_config/conf.d/box.fish"
            cat > "$box_work/path.block" <<'BOX_FISH_PATH'
# >>> Box PATH >>>
fish_add_path --global --prepend "$HOME/.local/bin"
# <<< Box PATH <<<
BOX_FISH_PATH
            ;;
        *) die "unsupported shell; retry with BOX_NO_MODIFY_PATH=1" ;;
    esac
    for box_file in "$box_path_first" "$box_path_second"; do
        if [ -n "$box_file" ]; then
            check_shell_file "$box_file"
            [ -n "$box_fish_config" ] || [ -d "${box_file%/*}" ] ||
                die "shell directory is missing; retry with BOX_NO_MODIFY_PATH=1"
        fi
    done
fi

if [ "${BOX_VERSION+x}" = x ]; then
    box_version=$BOX_VERSION
else
    # GitHub redirects releases/latest to the latest release's tag page, never to a pre-release.
    box_latest=$(fetch -I -o /dev/null -w '%{url_effective}' "https://github.com/$box_repo/releases/latest") ||
        die "cannot find the latest release in $box_repo"
    box_tag=${box_latest#"https://github.com/$box_repo/releases/tag/"}
    [ "$box_tag" != "$box_latest" ] || die "cannot find the latest release in $box_repo"
    case "$box_tag" in v*) box_version=${box_tag#v} ;; *) die "expected a release tag such as v0.1.0" ;; esac
    version "$box_version"
fi
box_release="$box_version-$box_triple"
box_destination="$box_root/$box_release"
[ ! -L "$box_destination" ] || die "release directory is a symbolic link"
if [ -e "$box_destination" ]; then
    [ -d "$box_destination" ] || die "release path is not a directory"
fi
box_asset=
download SHA256SUMS.txt "$box_work/checksums"
# A release names its archive box-cli-v<version>-<triple>.tar.gz. Earlier releases named it
# box-v<version>-<triple>.tar.gz, so take that name when the release lists only it. In
# strands-agents/box that name is Box Core's archive, never box, so it is not a fallback there.
box_names="box-cli-v$box_version-$box_triple.tar.gz"
[ "$(awk -v repo="$box_repo" 'BEGIN { print tolower(repo) }')" = strands-agents/box ] || box_names="$box_names box-v$box_version-$box_triple.tar.gz"
for box_name in $box_names; do
    if awk -v asset="$box_name" '$2 == asset { found = 1 } END { exit !found }' "$box_work/checksums"; then
        box_asset=$box_name
        break
    fi
done
if [ -z "$box_asset" ]; then
    [ "${BOX_VERSION+x}" = x ] ||
        die "release v$box_version has no box for $box_triple; set BOX_VERSION to a release that has one, such as a pre-release"
    die "SHA256SUMS.txt in release v$box_version lists no box-cli-v$box_version-$box_triple.tar.gz"
fi
if [ -t 2 ] && [ -z "${NO_COLOR-}" ] && [ -n "${TERM-}" ] && [ "$TERM" != dumb ]; then
    case "$box_charset" in
        UTF-8|UTF8|utf-8|utf8)
            case "${COLORTERM-}" in
                truecolor|24bit) box_colors=16777216 ;;
                *) box_colors=$(tput colors 2>/dev/null || true) ;;
            esac
            ;;
    esac
    case "$box_colors" in
        16777216) box_accent=$(printf '\033[38;2;74;222;128m') ;;
        256) box_accent=$(printf '\033[38;5;78m') ;;
        *) box_colors=0 ;;
    esac
    if [ "$box_colors" != 0 ]; then
        box_pretty=1
        box_dim=$(printf '\033[2m')
        box_reset=$(printf '\033[0m')
        check_width
    fi
fi
if [ "$box_pretty" -eq 1 ]; then
    box_total=$(fetch -I "$(release_url "$box_asset")" 2>/dev/null |
        awk 'tolower($1) == "content-length:" { size = $2 } END { sub(/\r$/, "", size); print size }') ||
        box_total=0
    case "$box_total" in ''|0*|*[!0-9]*) box_total=0 ;; esac
    [ "${#box_total}" -le 12 ] || box_total=0
    printf '\n%sInstalling%s box %sversion:%s %s\n' "$box_dim" "$box_reset" \
        "$box_dim" "$box_reset" "$box_version" >&2
elif [ -z "$box_previous" ]; then
    log "Downloading $box_asset..."
fi
download "$box_asset" "$box_work/archive"
progress 80 Verifying
box_expected=$(awk -v asset="$box_asset" '
    $2 == asset {
        count++
        if (NF != 2 || length($1) != 64 || $1 !~ /^[0-9A-Fa-f]+$/) bad = 1
        digest = tolower($1)
    }
    END { if (count != 1 || bad) exit 1; print digest }
' "$box_work/checksums") || die "SHA256SUMS.txt must have one valid entry for $box_asset"
checksum "$box_work/archive" > "$box_work/digest"
[ "$(awk '{print tolower($1)}' "$box_work/digest")" = "$box_expected" ] ||
    die "checksum mismatch for $box_asset"
tar -tzf "$box_work/archive" > "$box_work/names" || die "cannot list archive"
tar -tvzf "$box_work/archive" > "$box_work/types" || die "cannot inspect archive"
box_native=0
if grep -Eq '^(\./)*Box[.]app/Contents/MacOS/box$' "$box_work/names"; then
    [ "$box_system" = Darwin ] || die "native app bundles require macOS"
    box_native=1
fi
awk -v native="$box_native" '
    BEGIN {
        alias["strands-box-sock-alias"] = "Box.app/Contents/MacOS/strands-box-sock-alias"
        alias["strands-box-contain-trampoline"] = "Box.app/Contents/MacOS/strands-box-contain-trampoline"
        alias["resources"] = "Box.app/Contents/Resources/resources"
        alias["release.json"] = "Box.app/Contents/Resources/release.json"
    }
    NR == FNR {
        kind[FNR] = substr($0, 1, 1)
        if (kind[FNR] == "l" && native) {
            target[FNR] = $0
            if (!sub(/^.* -> /, "", target[FNR])) bad = 1
        } else {
            if (kind[FNR] != "-" && kind[FNR] != "d") bad = 1
            if ($1 ~ /[sStT]/ || substr($1, 6, 1) == "w" || substr($1, 9, 1) == "w") bad = 1
        }
        entries++
        next
    }
    {
        name = $0
        while (sub(/^\.\//, "", name)) {}
        sub(/\/$/, "", name)
        if (name == "." || name == "") { if (kind[FNR] != "d") bad = 1; next }
        if (name !~ /^[A-Za-z0-9_.\/-]+$/ || seen[tolower(name)]++) bad = 1
        count = split(name, parts, "/")
        for (i = 1; i <= count; i++) if (parts[i] == "" || parts[i] == "." || parts[i] == "..") bad = 1
        path = name
        if (native) {
            if (name in alias) {
                if (kind[FNR] != "l" || target[FNR] != alias[name]) bad = 1
                aliases++
                next
            }
            if (name == "box") {
                if (kind[FNR] != "-") bad = 1
            } else if (name ~ /^Box[.]app(\/Contents(\/(MacOS|Resources|_CodeSignature))?)?$/) {
                if (kind[FNR] != "d") bad = 1
            } else if (name ~ /^Box[.]app\/Contents\/(Info[.]plist|embedded[.]provisionprofile|CodeResources|_CodeSignature\/CodeResources|MacOS\/(box|strands-box-sock-alias|strands-box-contain-trampoline))$/) {
                if (kind[FNR] != "-") bad = 1
            } else if (sub(/^Box[.]app\/Contents\/Resources\//, "", path)) {
                if (path == "release.json" || path == "resources/config.toml" || path == "resources/editing-box-profile.md") {
                    if (kind[FNR] != "-") bad = 1
                } else if (path == "resources" || path == "resources/packs" || path == "resources/plugins" || path == "resources/policies" || path == "resources/starters") {
                    if (kind[FNR] != "d") bad = 1
                } else if (path !~ /^resources\/(packs|plugins|policies|starters)\// || (kind[FNR] != "-" && kind[FNR] != "d")) bad = 1
            } else bad = 1
        } else if (name ~ /^(box|strands-box-sock-alias|strands-box-contain-trampoline|release[.]json)$/ || name == "resources/config.toml" || name == "resources/editing-box-profile.md") {
            if (kind[FNR] != "-") bad = 1
        } else if (name == "resources" || name == "resources/packs" || name == "resources/shared" || name == "resources/plugins" || name == "resources/policies" || name == "resources/starters") {
            if (kind[FNR] != "d") bad = 1
        } else if (name !~ /^resources\/(packs|shared|plugins|policies|starters)\//) bad = 1
        if (kind[FNR] == "-") print name
    }
    END { if (bad || entries != FNR || entries == 0 || (native && aliases != 4)) exit 1 }
' "$box_work/types" "$box_work/names" > "$box_work/expected-files" ||
    die "archive contains unsafe paths, links, permissions, or duplicate entries"
# Linux hosts may mount /var/tmp noexec, so on Linux the checked archive unpacks on the
# filesystem it installs to, as download.sh does, and its programs run from there.
if [ "$box_system" = Linux ]; then
    [ -d "$box_home/.strands" ] || box_made_strands=1
    [ -d "$box_home/.strands/box" ] || box_made_box=1
    [ -d "$box_root" ] || box_made_root=1
    for box_dir in "$box_home/.strands" "$box_home/.strands/box" "$box_root"; do directory "$box_dir"; done
    box_unpack=$(mktemp -d "$box_root/.unpack.XXXXXXXX") || die "cannot prepare $box_root"
    box_payload="$box_unpack/payload"
else
    box_payload="$box_work/payload"
fi
mkdir "$box_payload"
tar -xzf "$box_work/archive" -C "$box_payload" --no-same-owner --no-same-permissions ||
    die "cannot extract archive"
check_links "$box_payload" "archive"
(cd "$box_payload" && find . -type f -print | sed 's|^\./||' | sort) > "$box_work/actual-files"
sort "$box_work/expected-files" > "$box_work/sorted-files"
cmp -s "$box_work/actual-files" "$box_work/sorted-files" || die "extracted files differ from archive"
for box_required in box strands-box-sock-alias strands-box-contain-trampoline release.json resources/config.toml resources/policies/open/policy.toml resources/policies/open/policy.dw; do
    [ -f "$box_payload/$box_required" ] || die "bundle is missing $box_required"
done
# Releases up to v0.1.11 hold their packs in resources/shared/, keep their starters inside the
# agent packs, and ship the open and project policies. Only a packs/ release has the rest.
# The profile guide is not required: packs/ releases before it ship without it.
if [ -f "$box_payload/resources/packs/base/pack.toml" ]; then
    for box_required in resources/policies/scoped/policy.toml resources/policies/scoped/policy.dw resources/policies/locked/policy.toml resources/policies/locked/policy.dw resources/starters/claude/starter.toml; do
        [ -f "$box_payload/$box_required" ] || die "bundle is missing $box_required"
    done
else
    [ -f "$box_payload/resources/shared/base/pack.toml" ] ||
        die "bundle is missing resources/packs/base/pack.toml"
fi
if [ "$box_native" -eq 1 ]; then
    for box_required in Box.app/Contents/Info.plist Box.app/Contents/embedded.provisionprofile Box.app/Contents/CodeResources Box.app/Contents/_CodeSignature/CodeResources; do
        [ -f "$box_payload/$box_required" ] || die "bundle is missing $box_required"
    done
    cat > "$box_work/launcher" <<'BOX_NATIVE_LAUNCHER'
#!/bin/sh
set -eu
path=$0
count=0
while [ -L "$path" ]; do
    count=$((count + 1))
    [ "$count" -le 40 ] || { echo "box: installation link loop" >&2; exit 1; }
    directory=$(CDPATH= cd -P -- "$(/usr/bin/dirname -- "$path")" && pwd)
    target=$(/usr/bin/readlink "$path")
    case "$target" in
        /*) path=$target ;;
        *) path=$directory/$target ;;
    esac
done
root=$(CDPATH= cd -P -- "$(/usr/bin/dirname -- "$path")" && pwd)
exec "$root/Box.app/Contents/MacOS/box" "$@"
BOX_NATIVE_LAUNCHER
    cmp -s "$box_work/launcher" "$box_payload/box" || die "native bundle launcher differs"
fi
if [ "$box_system" = Darwin ]; then
    box_metadata="$box_work/metadata.plist"
    plutil -create xml1 "$box_metadata"
    plutil -insert release -json "$(cat "$box_payload/release.json")" "$box_metadata" || die "invalid release.json"
fi
[ "$(metadata box_version)" = "$box_version" ] ||
    die "metadata version does not match $box_version"
[ "$(metadata target)" = "$box_triple" ] || die "metadata target does not match"
version "$(metadata core_version)"
for box_field in box_commit core_commit; do
    box_commit=$(metadata "$box_field") || die "missing $box_field"
    case "$box_commit" in *[!0-9a-f]*) die "invalid $box_field" ;; esac
    [ "${#box_commit}" -eq 40 ] || die "invalid $box_field"
done
if [ "$box_system" = Darwin ] && [ "$box_unsigned" -eq 1 ]; then
    log "Allowing unsigned release; Apple signature and Gatekeeper checks are skipped."
fi
box_programs="box strands-box-sock-alias strands-box-contain-trampoline"
if [ "$box_native" -eq 1 ]; then
    [ -x "$box_payload/box" ] && [ -x "$box_payload/Box.app/Contents/MacOS/box" ] ||
        die "native bundle launcher or executable is not executable"
    box_programs="Box.app Box.app/Contents/MacOS/strands-box-sock-alias Box.app/Contents/MacOS/strands-box-contain-trampoline"
fi
for box_binary in $box_programs; do
    [ -x "$box_payload/$box_binary" ] || die "not executable: $box_binary"
    [ "$box_system" = Darwin ] && [ "$box_unsigned" -eq 0 ] || continue
    codesign --display --verbose=4 -r- "$box_payload/$box_binary" > "$box_work/signature" 2>&1 ||
        die "cannot read signing identity: $box_binary"
    box_identifier=com.amazon.strands.box
    case "$box_binary" in
        box|Box.app)
            box_identifier=$(sed -n 's/^Identifier=//p' "$box_work/signature")
            case "$box_identifier" in
                com.amazon.strands.box|com.amazon.strands.box-cli) ;;
                *) die "unexpected publisher or signing options: $box_binary" ;;
            esac ;;
    esac
    awk -v identifier="$box_identifier" -v team="$BOX_TEAM_ID" '
        /^Identifier=/ { identities++; if ($0 != "Identifier=" identifier) bad = 1 }
        /^Authority=/ { authorities++; if (authorities == 1 && $0 !~ /^Authority=Developer ID Application: /) bad = 1 }
        /^Authority=Developer ID Application: / { developers++ }
        /^TeamIdentifier=/ { teams++; if ($0 != "TeamIdentifier=" team) bad = 1 }
        /^CodeDirectory / {
            directories++
            if ($0 !~ /flags=0x[0-9a-fA-F]+\(.*runtime.*\)/ || $0 ~ /adhoc/) bad = 1
        }
        /^Timestamp=/ { timestamps++; if ($0 !~ /^Timestamp=./) bad = 1 }
        /^designated => / { requirements++ }
        /^Signature=adhoc/ { bad = 1 }
        END { exit (bad || identities != 1 || developers != 1 || teams != 1 ||
                    directories != 1 || timestamps != 1 || requirements != 1) }
    ' "$box_work/signature" || die "unexpected publisher or signing options: $box_binary"
    box_requirement="=identifier \"$box_identifier\" and anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$BOX_TEAM_ID\""
    codesign --verify --strict --verbose=2 --test-requirement "$box_requirement" "$box_payload/$box_binary" > "$box_work/verify" 2>&1 ||
        { clear_progress; cat "$box_work/verify" >&2; die "signature verification failed: $box_binary"; }
    box_assessment=install
    [ "$box_binary" != Box.app ] || box_assessment=execute
    spctl --assess --type "$box_assessment" "$box_payload/$box_binary" > "$box_work/gatekeeper" 2>&1 ||
        { clear_progress; cat "$box_work/gatekeeper" >&2; die "Gatekeeper assessment failed: $box_binary"; }
done
box_reported=$("$box_payload/box" --version) || die "staged box --version failed"
[ "$box_reported" = "box $box_version" ] || die "binary version does not match $box_version"
find "$box_payload" -type d -exec chmod 0755 {} +
find "$box_payload" -type f -exec chmod 0644 {} +
chmod 0755 "$box_payload/box" "$box_payload/strands-box-sock-alias" "$box_payload/strands-box-contain-trampoline"
if [ "$box_native" -eq 1 ]; then chmod 0755 "$box_payload/Box.app/Contents/MacOS/box"; fi

progress 99 Installing
for box_dir in "$box_home/.strands" "$box_home/.strands/box" "$box_root" "$box_home/.local" "$box_bin"; do directory "$box_dir"; done
mkdir "$box_root/.install-lock" 2>/dev/null || die "Another Box installation is in progress."
box_lock="$box_root/.install-lock"
check_installation
box_stage=$(mktemp -d "$box_root/.staging.XXXXXXXX") || die "cannot stage release"
if [ -d "$box_destination" ]; then
    check_links "$box_destination" "installed release"
    (cd "$box_payload" && find . -print | sort) > "$box_work/new-tree"
    (cd "$box_destination" && find . -print | sort) > "$box_work/old-tree"
    cmp -s "$box_work/new-tree" "$box_work/old-tree" || die "installed release contents differ"
    while IFS= read -r box_entry; do
        [ "$(permissions "$box_payload/$box_entry")" = "$(permissions "$box_destination/$box_entry")" ] ||
            die "installed release permissions differ: $box_entry"
        if [ -L "$box_payload/$box_entry" ]; then
            [ -L "$box_destination/$box_entry" ] &&
                [ "$(readlink "$box_payload/$box_entry")" = "$(readlink "$box_destination/$box_entry")" ] ||
                die "installed release aliases differ: $box_entry"
        elif [ -f "$box_payload/$box_entry" ]; then
            cmp -s "$box_payload/$box_entry" "$box_destination/$box_entry" ||
                die "installed release contents differ: $box_entry"
        fi
    done < "$box_work/new-tree"
else
    cp -Rp "$box_payload" "$box_stage/payload"
    mv "$box_stage/payload" "$box_destination" || die "cannot install release"
fi
if [ "$box_earlier_launcher" -eq 1 ]; then
    ln -s "$box_launcher_target" "$box_stage/launcher.next" &&
        replace_link "$box_stage/launcher.next" "$box_launcher" || die "cannot replace the earlier launcher"
    box_replaced_launcher=1
elif [ ! -L "$box_launcher" ]; then
    ln -s "$box_launcher_target" "$box_launcher" || die "cannot create launcher"
    box_created_launcher=1
fi
if [ -n "$box_fish_config" ]; then
    for box_dir in "${box_fish_config%/*}" "$box_fish_config" "$box_fish_config/conf.d"; do
        directory "$box_dir"
    done
fi
for box_file in "$box_path_first" "$box_path_second"; do
    [ -z "$box_file" ] || add_path "$box_file"
done
ln -s "$box_release" "$box_stage/current.next"
box_activating=1
replace_link "$box_stage/current.next" "$box_current" || die "cannot activate release"
box_reported=$("$box_launcher" --version) || die "installed box --version failed"
[ "$box_reported" = "box $box_version" ] || die "installed version does not match"
box_activating=0
box_created_launcher=0
[ "$box_replaced_launcher" -eq 0 ] ||
    log "Replaced the launcher of an earlier box in ~/.box. box now keeps its files in ~/.strands/box, and ~/.box is unchanged."
box_replaced_launcher=0
progress 100 ''
if [ "$box_drawing" -eq 1 ]; then
    printf '\n\033[?25h' >&2
    box_drawing=0
fi
box_welcome=1
if [ -n "$box_previous" ]; then
    box_old_version=${box_previous%-$box_triple}
    if [ "$box_old_version" = "$box_version" ]; then
        box_welcome=0
        log "box $box_version is already installed."
    else
        log "Updated box $box_old_version to $box_version."
    fi
else
    box_verified="Verified checksum and archive"
    if [ "$box_system" = Darwin ] && [ "$box_unsigned" -eq 0 ]; then
        box_verified="Verified checksum, archive, and Apple signature"
    fi
    printf '%s%s%s\n' "$box_dim" "$box_verified" "$box_reset" >&2
    [ "$box_pretty" -eq 1 ] || log "Installed box $box_version."
fi
[ -z "$box_path_notice" ] || log "$box_path_notice"
case ":${PATH-}:" in
    *":$box_bin:"*|*":$HOME/.local/bin:"*) ;;
    *)
        case "${SHELL-}" in
            */fish) log 'Open a new terminal, or run: fish_add_path "$HOME/.local/bin"' ;;
            *) log 'Open a new terminal, or run: export PATH="$HOME/.local/bin:$PATH"' ;;
        esac
        ;;
esac
# Installs and updates both welcome, so an update also shows the commands and the telemetry
# notice. A rerun of the installed version changes nothing and says only that.
if [ "$box_welcome" -eq 1 ]; then
    printf '\n' >&2
    welcome
fi
