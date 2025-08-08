#!/usr/bin/env bash
set -euo pipefail

# =========================
# Secure IPFS binaries fetcher
# - Download from primary CDN with retry
# - Fallback mirror if primary fails
# - Verify SHA256 checksums
# - Mark binaries executable
# =========================

OUT_DIR="./client/ipfs-manager/src"
mkdir -p "$OUT_DIR"

PRIMARY_BASE="https://storage.uomi.ai"
# TODO: ganti ke mirror resmi tim Uomi jika tersedia
FALLBACK_BASE="https://storage.backup.uomi.ai"

# Mapping: local filename => remote path (relative to *_BASE)
declare -A FILES=(
  ["ipfs_linux_amd64"]="ipfs_linux_amd64"
  ["ipfs_linux_arm64"]="ipfs_linux_arm64"
  ["ipfs_macOS"]="ipfs_macOS"
)

# SHA256 resmi (per 2025-08-08)
declare -A SHA256=(
  ["ipfs_linux_amd64"]="bd864e195542658f8df89d9a2085c116d6af91f0ef9fb5c34a2ea7163f189e17"
  ["ipfs_linux_arm64"]="105c62c2ee26774214cda334c8d24ef98c6eeba3e07cfffa0a4bfc73e9867505"
  ["ipfs_macOS"]="0a43dabd38373295d10112b8782fb7c968e104b9898dcf529d3c3a43c31a186b"
)

curl_get () {
  local url="$1"
  local out="$2"
  echo "-> Downloading $url"
  # -f fail on HTTP errors; -L follow redirects; retry 3x; sensible timeouts
  curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 300 -o "$out.part" "$url"
  mv "$out.part" "$out"
}

verify_sha256 () {
  local file="$1"
  local expected="$2"
  echo "-> Verifying SHA256 for $(basename "$file")"
  local actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$file" | awk '{print $1}')
  else
    actual=$(shasum -a 256 "$file" | awk '{print $1}')
  fi
  if [[ "$actual" != "$expected" ]]; then
    echo "!! SHA256 mismatch for $(basename "$file")"
    echo "   expected: $expected"
    echo "   actual  : $actual"
    return 1
  fi
}

for fname in "${!FILES[@]}"; do
  dest="$OUT_DIR/$fname"
  url_primary="$PRIMARY_BASE/${FILES[$fname]}"
  url_fallback="$FALLBACK_BASE/${FILES[$fname]}"

  # Try primary first
  if ! curl_get "$url_primary" "$dest"; then
    echo "-> Primary failed, trying fallback..."
    curl_get "$url_fallback" "$dest"
  fi

  # Verify checksum; if fail, retry from fallback once
  expected_sha="${SHA256[$fname]}"
  if ! verify_sha256 "$dest" "$expected_sha"; then
    echo "-> Checksum failed. Retrying from fallback…"
    rm -f "$dest"
    curl_get "$url_fallback" "$dest"
    verify_sha256 "$dest" "$expected_sha"
  fi

  chmod +x "$dest" || true
  echo "-> Done: $dest"
done

echo "All IPFS binaries downloaded & verified."
