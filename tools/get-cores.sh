#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:?android or windows}"
CACHE="${CORES_CACHE:-$ROOT/build/cores}"

digest() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'
}

fetch() {
  local name=$1 asset=$2 repo tag dir base want
  read -r repo tag < <(awk -v n="$name" '$1 == n { print $2, $3 }' "$ROOT/tools/cores.txt")
  [ -n "${tag:-}" ] || { echo "$name is not in tools/cores.txt" >&2; exit 1; }
  dir="$CACHE/$repo/$tag"
  base="https://github.com/$repo/releases/download/$tag"
  mkdir -p "$dir"
  [ -s "$dir/SHA256SUMS" ] || curl -fsSL --retry 3 -o "$dir/SHA256SUMS" "$base/SHA256SUMS"
  want=$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1 }' "$dir/SHA256SUMS")
  [ -n "$want" ] || { echo "$asset is not in $repo $tag" >&2; exit 1; }
  if [ ! -s "$dir/$asset" ] || [ "$(digest "$dir/$asset")" != "$want" ]; then
    curl -fsSL --retry 3 -o "$dir/$asset" "$base/$asset"
    [ "$(digest "$dir/$asset")" = "$want" ] || { echo "$asset from $repo $tag does not match its checksum" >&2; exit 1; }
  fi
  printf '%s\n' "$dir/$asset"
}

unpack() {
  local zip=$1 dest=$2
  rm -rf "$dest"
  mkdir -p "$dest"
  unzip -q -o "$zip" -d "$dest"
}

tor_tree() {
  unpack "$1" "$2"
  cp "$ROOT/app/src/main/assets/tor/bridges_default.lst" "$2/"
  ( cd "$2" && find . -type f ! -name files.txt | sed 's#^\./##' | sort > files.txt )
}

pick() {
  local from=$1 name=$2 to=$3 src
  src=$(find "$from" -type f -name "$name" | head -1)
  [ -n "$src" ] || { echo "$name is missing from $from" >&2; exit 1; }
  cp "$src" "$to"
}

case "$TARGET" in
  android)
    jni="$ROOT/app/src/main/jniLibs"
    mkdir -p "$ROOT/app/libs" "$jni"
    cp "$(fetch zedcore zedcore.aar)" "$ROOT/app/libs/zedcore.aar"
    for abi in arm64-v8a armeabi-v7a x86_64; do
      mkdir -p "$jni/$abi"
      for core in tor snispoof hev; do
        unzip -q -o "$(fetch "$core" "$core-android-$abi.zip")" -d "$jni/$abi"
      done
    done
    unpack "$(fetch zeptun zeptun-android-jniLibs.zip)" "$CACHE/zeptun-android"
    cp -r "$CACHE/zeptun-android/jniLibs/." "$jni/"
    find "$jni" -name '*.so' -exec chmod +x {} +
    ;;
  *)
    echo "unknown target $TARGET" >&2
    exit 1
    ;;
esac
echo "cores for $TARGET are in place"
