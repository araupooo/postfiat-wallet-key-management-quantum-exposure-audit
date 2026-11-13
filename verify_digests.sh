#!/bin/sh
# verify_digests.sh — SHA-256 manifest for this pack.
#   ./verify_digests.sh          regenerate SHA256SUMS over all pack files
#                                 (except SHA256SUMS itself) and verify it
#   ./verify_digests.sh --check  verify the existing SHA256SUMS only
set -eu
PACK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$PACK_DIR"

if [ "${1:-}" = "--check" ]; then
    sha256sum -c SHA256SUMS
    exit 0
fi

# Regenerate: every regular file in the pack except SHA256SUMS itself,
# sorted, paths relative to the pack root.
find . -type f ! -name SHA256SUMS ! -path './.git/*' -print0 \
  | sort -z \
  | xargs -0 sha256sum > SHA256SUMS
sha256sum -c SHA256SUMS
echo "verify_digests.sh: SHA256SUMS regenerated and verified"
