#!/bin/sh
set -eu

profile="${1:-release}"
case "$profile" in
  debug|release) ;;
  *) echo "usage: $0 [debug|release]" >&2; exit 2 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
target="${MIAOVPS_SIDECAR_TARGET:-$(rustc -vV | awk '/^host:/ { print $2 }')}"
cargo_bin="${CARGO:-cargo}"
cargo_target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"

if [ "$profile" = "release" ]; then
  "$cargo_bin" build --manifest-path "$repo_root/Cargo.toml" -p miaovps-cli --release --target "$target"
else
  "$cargo_bin" build --manifest-path "$repo_root/Cargo.toml" -p miaovps-cli --target "$target"
fi

extension=""
case "$target" in
  *-windows-*) extension=".exe" ;;
esac

source_bin="$cargo_target_dir/$target/$profile/miaovps$extension"
sidecar_dir="$repo_root/apps/desktop/src-tauri/binaries"
sidecar_bin="$sidecar_dir/miaovps-$target$extension"

mkdir -p "$sidecar_dir"
cp "$source_bin" "$sidecar_bin"
chmod 755 "$sidecar_bin"
echo "prepared sidecar: $sidecar_bin"
