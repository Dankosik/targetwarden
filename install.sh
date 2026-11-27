#!/bin/sh
# Install or upgrade targetwarden from GitHub Releases (macOS Apple Silicon & Intel).
# Usage:
#   curl -fsSL https://github.com/Dankosik/targetwarden/releases/latest/download/install.sh | sh
#   TARGETWARDEN_VERSION=v0.1.0 sh install.sh
#   TARGETWARDEN_INSTALL_DIR=/usr/local/bin sh install.sh

set -eu

REPO="Dankosik/targetwarden"
BIN_NAME="targetwarden"
INSTALL_DIR="${TARGETWARDEN_INSTALL_DIR:-${HOME}/.local/bin}"
VERSION="${TARGETWARDEN_VERSION:-}"
DOWNLOAD_BASE="${TARGETWARDEN_DOWNLOAD_BASE:-}"

die() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

detect_target() {
    os_name="${TARGETWARDEN_OS:-$(uname -s)}"
    arch_name="${TARGETWARDEN_ARCH:-$(uname -m)}"

    if [ "$os_name" != "Darwin" ]; then
        die "targetwarden supports macOS only (detected OS: $os_name)"
    fi

    case "$arch_name" in
        arm64|aarch64)
            printf '%s\n' "aarch64-apple-darwin"
            ;;
        x86_64|amd64)
            printf '%s\n' "x86_64-apple-darwin"
            ;;
        *)
            die "unsupported macOS architecture: $arch_name"
            ;;
    esac
}

validate_version() {
    case "$1" in
        v[0-9]*.[0-9]*.[0-9]*)
            ;;
        *)
            die "invalid TARGETWARDEN_VERSION '$1' (expected vX.Y.Z)"
            ;;
    esac
    case "$1" in
        */*|*\\*|*..*|*" "*|*"	"*)
            die "invalid characters in TARGETWARDEN_VERSION '$1'"
            ;;
    esac
}

resolve_latest_version() {
    latest_url="https://github.com/${REPO}/releases/latest"
    final_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "$latest_url")" \
        || die "failed to resolve latest release from $latest_url"
    tag="${final_url##*/}"
    if [ -z "$tag" ] || [ "$tag" = "releases" ] || [ "$tag" = "latest" ]; then
        die "could not determine latest release tag from $final_url"
    fi
    printf '%s\n' "$tag"
}

sha256_file() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        die "neither shasum nor sha256sum is available for checksum verification"
    fi
}

main() {
    need_cmd curl
    need_cmd tar
    need_cmd awk
    need_cmd mktemp

    target="$(detect_target)"

    if [ -z "$VERSION" ]; then
        if [ -n "$DOWNLOAD_BASE" ]; then
            die "TARGETWARDEN_VERSION must be set when TARGETWARDEN_DOWNLOAD_BASE is used"
        fi
        VERSION="$(resolve_latest_version)"
    fi
    validate_version "$VERSION"

    bare_version="${VERSION#v}"
    archive_root="${BIN_NAME}-${bare_version}-${target}"
    archive_name="${archive_root}.tar.gz"

    if [ -n "$DOWNLOAD_BASE" ]; then
        base_url="${DOWNLOAD_BASE%/}"
    else
        base_url="https://github.com/${REPO}/releases/download/${VERSION}"
    fi

    tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/targetwarden-install.XXXXXX")"
    cleanup() {
        rm -rf "$tmp_dir"
    }
    trap cleanup EXIT INT TERM

    archive_path="${tmp_dir}/${archive_name}"
    sums_path="${tmp_dir}/SHA256SUMS"

    printf 'Downloading %s (%s)...\n' "$archive_name" "$VERSION"
    curl -fsSL "${base_url}/${archive_name}" -o "$archive_path" \
        || die "failed to download ${base_url}/${archive_name}"
    curl -fsSL "${base_url}/SHA256SUMS" -o "$sums_path" \
        || die "failed to download ${base_url}/SHA256SUMS"

    expected_sum="$(awk -v name="$archive_name" '$2 == name { print $1; exit }' "$sums_path")"
    if [ -z "$expected_sum" ]; then
        die "SHA256SUMS does not contain an entry for $archive_name"
    fi

    actual_sum="$(sha256_file "$archive_path")"
    if [ "$actual_sum" != "$expected_sum" ]; then
        die "checksum mismatch for $archive_name (expected $expected_sum, got $actual_sum)"
    fi

    tar -xzf "$archive_path" -C "$tmp_dir" "${archive_root}/${BIN_NAME}" \
        || die "failed to extract ${archive_root}/${BIN_NAME} from $archive_name"

    extracted_bin="${tmp_dir}/${archive_root}/${BIN_NAME}"
    [ -f "$extracted_bin" ] || die "extracted binary missing: $extracted_bin"
    chmod 755 "$extracted_bin"

    if command -v xattr >/dev/null 2>&1; then
        xattr -d com.apple.quarantine "$extracted_bin" >/dev/null 2>&1 || true
    fi

    mkdir -p "$INSTALL_DIR"
    dest_tmp="${INSTALL_DIR}/.${BIN_NAME}.install.$$"
    dest_bin="${INSTALL_DIR}/${BIN_NAME}"
    cp "$extracted_bin" "$dest_tmp"
    chmod 755 "$dest_tmp"
    mv -f "$dest_tmp" "$dest_bin"

    installed_version="$("$dest_bin" --version)" \
        || die "installed binary failed --version smoke check"
    printf 'Installed %s -> %s\n' "$installed_version" "$dest_bin"

    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*)
            ;;
        *)
            printf 'Note: add %s to your PATH to run %s directly.\n' "$INSTALL_DIR" "$BIN_NAME"
            ;;
    esac
}

main "$@"
