#!/usr/bin/env sh
# Construit Jalon pour windows/linux/darwin × amd64/arm64, sans cgo.
# Usage : scripts/build.sh [version]   → binaires et sommes SHA-256 dans dist/
set -eu
cd "$(dirname "$0")/.."
VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
VERSION="${VERSION#v}"
LDFLAGS="-s -w -X github.com/maxb1906/jalon/internal/model.Version=${VERSION}"
rm -rf dist && mkdir -p dist
for os in windows linux darwin; do
  for arch in amd64 arm64; do
    ext=""; [ "$os" = windows ] && ext=".exe"
    out="dist/jalon-${VERSION}-${os}-${arch}${ext}"
    echo "→ ${out}"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "$out" ./cmd/jalon
  done
done
(cd dist && sha256sum jalon-* > SHA256SUMS)
ls -l dist
