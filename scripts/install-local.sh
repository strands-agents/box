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
die() { log "install-local.sh: $*"; exit 1; }
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
        printf 'box profile <command>   %s# Create, list, show, and reset profiles%s\n\n' "$box_dim" "$box_reset"
        printf '%sExample next steps (Claude Code with Bedrock):%s\n\n' "$box_dim" "$box_reset"
        printf 'box profile create claude --with bedrock   %s# Then configure its model and key%s\n' "$box_dim" "$box_reset"
        printf 'box run claude                             %s# Run from your project%s\n\n' "$box_dim" "$box_reset"
    } >&2
}
version() {
    release_version "$1" || die "expected a version such as 0.1.0 or 0.1.1-linux-preview.1: $1"
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
    sys.exit("install-local.sh: invalid release.json")
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
download() {
    [ -f "$box_local/$1" ] && [ ! -L "$box_local/$1" ] || die "missing file: $box_local/$1"
    cp "$box_local/$1" "$2" || die "cannot copy $1"
}
release_version() {
    case "$1" in ''|*[!0-9a-z.-]*) return 1 ;; esac
    awk -v value="$1" 'BEGIN {
        exit !(value ~ /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-linux-preview\.[1-9][0-9]*)?$/)
    }'
}
managed_release() {
    case "$1" in *-"$box_triple") ;; *) return 1 ;; esac
    release_version "${1%-"$box_triple"}" || return 1
    [ ! -L "$box_root/$1" ] && [ -d "$box_root/$1" ] &&
        [ -f "$box_root/$1/release.json" ] && [ ! -L "$box_root/$1/release.json" ]
}
check_installation() {
    if [ -L "$box_launcher" ]; then
        [ "$(readlink "$box_launcher")" = "$box_launcher_target" ] ||
            die "another launcher exists at $box_launcher"
    elif [ -e "$box_launcher" ]; then
        die "another file exists at $box_launcher"
    fi
    box_previous= box_replaced=
    if [ -L "$box_current" ]; then
        box_previous=$(readlink "$box_current")
        if ! managed_release "$box_previous"; then
            box_replaced=$box_previous
            box_previous=
        fi
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

box_work= box_stage= box_path_temp= box_lock=
box_previous= box_replaced= box_activating=0 box_created_launcher=0
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
        box_restore=${box_previous:-$box_replaced}
        if [ -n "$box_restore" ]; then
            if ln -s "$box_restore" "$box_stage/current.rollback" &&
                replace_link "$box_stage/current.rollback" "$box_current"; then
                log "Restored $box_restore."
            else
                log "Cannot restore $box_current to $box_restore."
            fi
        else
            rm -f "$box_current"
        fi
    fi
    if [ "$box_status" -ne 0 ] && [ "$box_created_launcher" -eq 1 ] &&
        [ -L "$box_launcher" ] && [ "$(readlink "$box_launcher")" = "$box_launcher_target" ]; then
        rm -f "$box_launcher"
    fi
    [ -z "$box_path_temp" ] || rm -f "$box_path_temp"
    [ -z "$box_stage" ] || rm -rf "$box_stage"
    [ -z "$box_work" ] || rm -rf "$box_work"
    [ -z "$box_lock" ] || rmdir "$box_lock"
    exit "$box_status"
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

box_file=${BOX_LOCAL_FILE-}
case "$#" in
    0) ;;
    2) [ "$1" = --from ] || die "usage: install-local.sh --from PATH"; box_file=$2 ;;
    *) die "usage: install-local.sh --from PATH" ;;
esac
[ -n "$box_file" ] || die "pass --from PATH to the downloaded box-v<version>-<platform>.tar.gz, or set BOX_LOCAL_FILE"
{ [ -f "$box_file" ] && [ ! -L "$box_file" ]; } || die "not a regular file: $box_file"
box_name=${box_file##*/}
box_local=$(cd "$(dirname "$box_file")" && pwd -P) || die "cannot read the folder of $box_file"
box_unsigned=${BOX_ALLOW_UNSIGNED-0}
case "$box_unsigned" in 0|1) ;; *) die "BOX_ALLOW_UNSIGNED must be 0 or 1" ;; esac
box_no_path=${BOX_NO_MODIFY_PATH-0}
case "$box_no_path" in 0|1) ;; *) die "BOX_NO_MODIFY_PATH must be 0 or 1" ;; esac
if [ "${BOX_VERSION+x}" = x ]; then version "$BOX_VERSION"; fi
for box_tool in uname awk tar mktemp mkdir rmdir mv ln rm readlink find \
    sort cmp stat chmod sed grep cat cp dirname wc sleep; do
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
        case "$(uname -m)" in
            arm64|aarch64) ;;
            *) die "only ARM64 Linux is supported" ;;
        esac
        need getconf
        box_libc=$(getconf GNU_LIBC_VERSION 2>/dev/null) || die "Linux requires glibc 2.34 or later"
        awk -v value="$box_libc" 'BEGIN {
            if (value !~ /^glibc [0-9]+\.[0-9]+$/) exit 1
            split(substr(value, 7), parts, ".")
            exit !(parts[1] > 2 || (parts[1] == 2 && parts[2] >= 34))
        }' || die "Linux requires glibc 2.34 or later"
        box_triple=aarch64-unknown-linux-gnu
        box_default_shell=/bin/bash
        need sha256sum
        need python3
        ;;
    *) die "unsupported operating system: $box_system; use macOS or ARM64 Linux" ;;
esac
case "${HOME-}" in /*) ;; *) die "HOME must be an absolute directory" ;; esac
box_home=$(cd "$HOME" && pwd -P) || die "cannot open HOME"
box_root="$box_home/.box/packages"
box_bin="$box_home/.local/bin"
box_current="$box_root/current"
box_launcher="$box_bin/box"
box_launcher_target="$box_root/current/box"
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

case "$box_name" in
    box-v*-"$box_triple".tar.gz) ;;
    *) die "expected a file named box-v<version>-$box_triple.tar.gz, got $box_name" ;;
esac
box_version=${box_name#box-v}
box_version=${box_version%-"$box_triple".tar.gz}
version "$box_version"
if [ "${BOX_VERSION+x}" = x ] && [ "$BOX_VERSION" != "$box_version" ]; then
    die "BOX_VERSION $BOX_VERSION does not match $box_name"
fi
box_release="$box_version-$box_triple"
box_destination="$box_root/$box_release"
[ ! -L "$box_destination" ] || die "release directory is a symbolic link"
if [ -e "$box_destination" ]; then
    [ -d "$box_destination" ] || die "release path is not a directory"
fi
box_asset="box-v$box_version-$box_triple.tar.gz"
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
download SHA256SUMS.txt "$box_work/checksums"
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
awk '
    NR == FNR {
        kind[FNR] = substr($0, 1, 1)
        if (kind[FNR] != "-" && kind[FNR] != "d") bad = 1
        if ($1 ~ /[sStT]/ || substr($1, 6, 1) == "w" || substr($1, 9, 1) == "w") bad = 1
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
        if (name ~ /^(box|strands-box-sock-alias|strands-box-contain-trampoline|release[.]json)$/ || name == "resources/config.toml") {
            if (kind[FNR] != "-") bad = 1
        } else if (name == "resources" || name == "resources/packs" || name == "resources/shared" || name == "resources/policies" || name == "resources/starters") {
            if (kind[FNR] != "d") bad = 1
        } else if (name !~ /^resources\/(packs|shared|policies|starters)\//) bad = 1
        if (kind[FNR] == "-") print name
    }
    END { if (bad || entries != FNR || entries == 0) exit 1 }
' "$box_work/types" "$box_work/names" > "$box_work/expected-files" ||
    die "archive contains unsafe paths, links, permissions, or duplicate entries"
box_payload="$box_work/payload"
mkdir "$box_payload"
tar -xzf "$box_work/archive" -C "$box_payload" --no-same-owner --no-same-permissions ||
    die "cannot extract archive"
find "$box_payload" ! -type f ! -type d -print > "$box_work/special"
[ ! -s "$box_work/special" ] || die "archive extracts links or special files"
(cd "$box_payload" && find . -type f -print | sed 's|^\./||' | sort) > "$box_work/actual-files"
sort "$box_work/expected-files" > "$box_work/sorted-files"
cmp -s "$box_work/actual-files" "$box_work/sorted-files" || die "extracted files differ from archive"
for box_required in box strands-box-sock-alias strands-box-contain-trampoline release.json resources/config.toml resources/policies/open/policy.toml resources/policies/open/policy.dw; do
    [ -f "$box_payload/$box_required" ] || die "bundle is missing $box_required"
done
# Releases up to v0.1.11 hold their packs in resources/shared/, keep their starters inside the
# agent packs, and ship the open and project policies. Only a packs/ release has the rest.
if [ -f "$box_payload/resources/packs/base/pack.toml" ]; then
    for box_required in resources/policies/scoped/policy.toml resources/policies/scoped/policy.dw resources/policies/locked/policy.toml resources/policies/locked/policy.dw resources/starters/claude/starter.toml; do
        [ -f "$box_payload/$box_required" ] || die "bundle is missing $box_required"
    done
else
    [ -f "$box_payload/resources/shared/base/pack.toml" ] ||
        die "bundle is missing resources/packs/base/pack.toml"
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
for box_binary in box strands-box-sock-alias strands-box-contain-trampoline; do
    [ -x "$box_payload/$box_binary" ] || die "not executable: $box_binary"
    [ "$box_system" = Darwin ] && [ "$box_unsigned" -eq 0 ] || continue
    case "$box_binary" in
        box) box_identifier=com.amazon.strands.box-cli ;;
        *) box_identifier=com.amazon.strands.box ;;
    esac
    codesign --display --verbose=4 -r- "$box_payload/$box_binary" > "$box_work/signature" 2>&1 ||
        die "cannot read signing identity: $box_binary"
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
    spctl --assess --type install "$box_payload/$box_binary" > "$box_work/gatekeeper" 2>&1 ||
        { clear_progress; cat "$box_work/gatekeeper" >&2; die "Gatekeeper assessment failed: $box_binary"; }
done
box_reported=$("$box_payload/box" --version) || die "staged box --version failed"
[ "$box_reported" = "box $box_version" ] || die "binary version does not match $box_version"
find "$box_payload" -type d -exec chmod 0755 {} +
find "$box_payload" -type f -exec chmod 0644 {} +
chmod 0755 "$box_payload/box" "$box_payload/strands-box-sock-alias" "$box_payload/strands-box-contain-trampoline"

progress 99 Installing
for box_dir in "$box_home/.box" "$box_root" "$box_home/.local" "$box_bin"; do directory "$box_dir"; done
mkdir "$box_root/.install-lock" 2>/dev/null || die "Another Box installation is in progress."
box_lock="$box_root/.install-lock"
check_installation
box_stage=$(mktemp -d "$box_root/.staging.XXXXXXXX") || die "cannot stage release"
if [ -d "$box_destination" ]; then
    find "$box_destination" ! -type f ! -type d -print > "$box_work/installed-special"
    [ ! -s "$box_work/installed-special" ] || die "installed release contains links or special files"
    (cd "$box_payload" && find . -print | sort) > "$box_work/new-tree"
    (cd "$box_destination" && find . -print | sort) > "$box_work/old-tree"
    cmp -s "$box_work/new-tree" "$box_work/old-tree" || die "installed release contents differ"
    while IFS= read -r box_entry; do
        [ "$(permissions "$box_payload/$box_entry")" = "$(permissions "$box_destination/$box_entry")" ] ||
            die "installed release permissions differ: $box_entry"
        if [ -f "$box_payload/$box_entry" ]; then
            cmp -s "$box_payload/$box_entry" "$box_destination/$box_entry" ||
                die "installed release contents differ: $box_entry"
        fi
    done < "$box_work/new-tree"
else
    cp -Rp "$box_payload" "$box_stage/payload"
    mv "$box_stage/payload" "$box_destination" || die "cannot install release"
fi
if [ ! -L "$box_launcher" ]; then
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
progress 100 ''
if [ "$box_drawing" -eq 1 ]; then
    printf '\n\033[?25h' >&2
    box_drawing=0
fi
if [ -n "$box_previous" ]; then
    box_old_version=${box_previous%-$box_triple}
    if [ "$box_old_version" = "$box_version" ]; then
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
[ -z "$box_replaced" ] ||
    log "Replaced $box_current, which pointed to $box_replaced. This installer does not manage $box_replaced and left it in place."
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
if [ -z "$box_previous" ]; then
    printf '\n' >&2
    welcome
fi
