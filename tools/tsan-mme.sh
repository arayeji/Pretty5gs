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

    # SGWC shard workers (rehome / TEID shard-bit routing) under `sgwc:`.
    if [ -f "$f" ] && ! awk '/^sgwc:/{s=1;next} /^[a-z]/{s=0} s&&/workers:/{f=1} END{exit !f}' "$f"; then
        awk '
            { print }
            /^sgwc:/ && !done {
                print "  workers: 4"
                done = 1
            }
        ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
        echo "injected sgwc.workers:4 -> $f"
    fi

    # Lab-only address relocation: the production AMF on this host owns
    # 127.0.0.5 (SBI/NGAP/metrics). Move the lab AMF to 127.0.0.105 in
    # every suite config (tests connect using the same yaml, so both
    # sides stay consistent).
    for cf in "$BUILDDIR"/configs/*.yaml; do
        [ -f "$cf" ] || continue
        if grep -qE '127\.0\.0\.5([^0-9]|$)' "$cf"; then
            sed -Ei 's/127\.0\.0\.5([^0-9]|$)/127.0.0.105\1/g' "$cf"
            echo "relocated 127.0.0.5 -> 127.0.0.105 in $cf"
        fi
    done
}

# Failed suites leave sibling daemons running (the harness aborts when
# one child dies); they then hold the loopback ports and break the next
# suite. Kill anything spawned from this build tree.
cleanup_lab() {
    pkill -f "$BUILDDIR/[s]rc/" 2>/dev/null || true
    sleep 1
}

do_test() {
    suite="${1:-}"
    export TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=0 history_size=7 second_deadlock_stack=1 log_path=tsan-mme}"
    if [ -n "$suite" ]; then
        cleanup_lab
        meson test -C "$BUILDDIR" "$suite" --timeout-multiplier 4 \
            --print-errorlogs
    else
        for s in $SUITES; do
            echo "==== TSAN suite: $s ===="
            cleanup_lab
            meson test -C "$BUILDDIR" "$s" --timeout-multiplier 4 \
                --print-errorlogs || true
        done
    fi
    cleanup_lab
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
