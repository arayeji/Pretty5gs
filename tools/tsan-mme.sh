#!/bin/sh
# TSAN soak rig for the MME SMP offloads (s1ap_rx_workers / s1ap_tx_workers /
# s1ap_io_thread / mme.workers). Builds a separate ThreadSanitizer tree,
# injects the worker knobs into the test config, and runs the EPC test
# suites under TSAN.
#
# Usage:
#   ./tools/tsan-mme.sh                # build + run default suites
#   ./tools/tsan-mme.sh build          # build only
#   ./tools/tsan-mme.sh test [suite]   # run one meson test (default: all EPC)
#
# Prereqs (Ubuntu): meson ninja-build gcc libtalloc-dev ... (same as normal
# build) — TSAN comes with gcc/clang, no extra package.

set -eu

BUILDDIR="${BUILDDIR:-build-tsan}"
# EPC (MME-exercising) suites from tests/meson.build
SUITES="${SUITES:-attach volte csfb handover transfer}"

cd "$(dirname "$0")/.."

do_build() {
    if [ ! -d "$BUILDDIR" ]; then
        meson setup "$BUILDDIR" \
            -Dbuildtype=debugoptimized \
            -Db_sanitize=thread \
            -Db_lundef=false
    fi
    ninja -C "$BUILDDIR"

    # tests read <builddir>/configs/sample.yaml (see tests/meson.build);
    # inject the SMP knobs right under its top-level `mme:` key. Sample
    # config indentation is 2 spaces.
    f="$BUILDDIR/configs/sample.yaml"
    if [ -f "$f" ] && ! grep -q 's1ap_rx_workers' "$f"; then
        awk '
            { print }
            /^mme:/ && !done {
                print "  s1ap_rx_workers: 4"
                print "  s1ap_tx_workers: 4"
                print "  s1ap_io_thread: 1"
                print "  workers: 4"
                done = 1
            }
        ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
        echo "injected SMP knobs -> $f"
    elif [ -f "$f" ] && ! grep -q 'workers:' "$f"; then
        # Older TSAN trees already had rx/tx/io; add Stage A UE shards.
        awk '
            { print }
            /^mme:/ && !done {
                print "  workers: 4"
                done = 1
            }
        ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
        echo "injected mme.workers:4 -> $f"
    fi
}

do_test() {
    suite="${1:-}"
    export TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=0 history_size=7 second_deadlock_stack=1 log_path=tsan-mme}"
    if [ -n "$suite" ]; then
        meson test -C "$BUILDDIR" "$suite" --timeout-multiplier 4 \
            --print-errorlogs
    else
        for s in $SUITES; do
            echo "==== TSAN suite: $s ===="
            meson test -C "$BUILDDIR" "$s" --timeout-multiplier 4 \
                --print-errorlogs || true
        done
    fi
    echo
    echo "TSAN reports (if any):"
    ls -la tsan-mme.* 2>/dev/null || echo "  none - clean run"
}

case "${1:-all}" in
    build) do_build ;;
    test)  shift || true; do_test "${1:-}" ;;
    all)   do_build; do_test "" ;;
    *)     echo "usage: $0 [build|test [suite]|all]"; exit 1 ;;
esac
