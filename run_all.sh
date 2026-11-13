#!/bin/sh
# Regenerate every derived output of this pack from scratch (offline).
#   1. harness.py (offline) -> results/summary.json, results/*.csv,
#                              results/summary.txt
#                              (from the vendored
#                              results/sample_ledger_data.json; no
#                              network access)
#   2. build_derived.py     -> docs/index.html
#   3. verify_digests.sh    -> SHA256SUMS (over every other pack file)
#
# To fetch a fresh live sample instead, run `python3 harness.py --live`
# first (public read-only endpoint, no credentials), then this script.
# The tree to check defaults to the pinned worktree used at authoring time;
# override with POSTFIATD_TREE=/path/to/postfiatd-tree.
set -eu
PACK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TREE=${POSTFIATD_TREE:-/home/hatch/workspace/postfiatd-amendment/worktree-0085a1ff}

cd "$PACK_DIR"
python3 harness.py --tree "$TREE" --out-dir "$PACK_DIR/results"
python3 build_derived.py
./verify_digests.sh
echo "run_all.sh: OK"
