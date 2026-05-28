#!/bin/sh

set -eu

WORKSPACE="${1:?Usage: $0 <workspace-dir> [dist-dir]}"
DIST_DIR="${2:-$WORKSPACE/frontend/dist}"

MARKER="$DIST_DIR/index.html"

# Rebuild when the dist is missing/empty.
if [ ! -d "$DIST_DIR" ] || [ ! -f "$MARKER" ]; then
    sh "$WORKSPACE/build_scripts/build-frontend.sh" "$WORKSPACE" "$DIST_DIR"
    exit 0
fi

# Rebuild when the dist is STALE: any tracked frontend source newer than the
# built marker means the existing dist no longer reflects the sources. This
# guards against shipping a stale bundle (e.g. a leftover dist from before a
# UI change), which silently put removed pages back into a release once.
SRC="$WORKSPACE/frontend"
if [ -n "$(find "$SRC/src" "$SRC/index.html" "$SRC/package.json" "$SRC/vite.config.ts" "$SRC/components.json" \
            -newer "$MARKER" -print 2>/dev/null -quit)" ]; then
    echo "ensure-frontend-dist: sources newer than $MARKER — rebuilding frontend"
    sh "$WORKSPACE/build_scripts/build-frontend.sh" "$WORKSPACE" "$DIST_DIR"
    exit 0
fi

echo "ensure-frontend-dist: $DIST_DIR is up to date — skipping rebuild"
exit 0
