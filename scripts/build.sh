#!/usr/bin/env sh
# Construit Jalon pour windows/linux/darwin × amd64/arm64, sans cgo.
# Sous Windows, l'exe embarque l'interface graphique Wails (frontend/dist,
# compilé ici avec Node.js) ; ailleurs : CLI, TUI et interface web.
# Usage : scripts/build.sh [version]   → binaires et sommes SHA-256 dans dist/
# JALON_SKIP_FRONTEND=1 réutilise frontend/dist tel quel.
set -eu
cd "$(dirname "$0")/.."
VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
VERSION="${VERSION#v}"
LDFLAGS="-s -w -X github.com/maxb1906/jalon/internal/model.Version=${VERSION}"

if [ "${JALON_SKIP_FRONTEND:-0}" != 1 ]; then
  echo "→ interface graphique (frontend/dist)"
  (cd frontend && npm ci --no-audit --no-fund && npm run check && npm run build)
fi
[ -f frontend/dist/index.html ] || { echo "frontend/dist/index.html absent : interface graphique non compilée" >&2; exit 1; }
# Icône, manifeste et version de l'exe Windows (cmd/jalon/rsrc_windows_*.syso).
go run ./tools/winres -version "$VERSION"

rm -rf dist && mkdir -p dist
for os in windows linux darwin; do
  for arch in amd64 arm64; do
    ext="" tags=""
    # Balises exigées par Wails pour une fenêtre de production.
    [ "$os" = windows ] && ext=".exe" tags="desktop,production"
    out="dist/jalon-${VERSION}-${os}-${arch}${ext}"
    echo "→ ${out}"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -tags "$tags" -ldflags "$LDFLAGS" -o "$out" ./cmd/jalon
  done
done
(cd dist && sha256sum jalon-* > SHA256SUMS)
ls -l dist
