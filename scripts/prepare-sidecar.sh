#!/bin/sh
set -eu

profile="${1:-release}"
case "$profile" in
  debug|release) ;;
  *) echo "usage: $0 [debug|release]" >&2; exit 2 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
host=$(rustc -vV | awk '/^host:/ { print $2 }')

if [ "$profile" = "release" ]; then
  cargo build --manifest-path "$repo_root/Cargo.toml" -p miaovps-cli --release
else
  cargo build --manifest-path "$repo_root/Cargo.toml" -p miaovps-cli
fi

extension=""
case "$host" in
  *-windows-*) extension=".exe" ;;
esac

source_bin="$repo_root/target/$profile/miaovps$extension"
sidecar_dir="$repo_root/apps/desktop/src-tauri/binaries"
sidecar_bin="$sidecar_dir/miaovps-$host$extension"

mkdir -p "$sidecar_dir"
cp "$source_bin" "$sidecar_bin"
chmod 755 "$sidecar_bin"
echo "prepared sidecar: $sidecar_bin"
