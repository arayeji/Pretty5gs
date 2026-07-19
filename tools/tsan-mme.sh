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

    # Each test suite reads its own <builddir>/configs/<suite>.yaml (see
    # tests/*/abts-main.c: sample.yaml, attach.yaml, csfb.yaml, volte.yaml,
    # ...). Inject the SMP knobs into every config with a top-level `mme:`
    # key so all suites exercise the worker paths. Indentation is 2 spaces.
    for f in "$BUILDDIR"/configs/*.yaml; do
        [ -f "$f" ] || continue
        grep -q '^mme:' "$f" || continue
        if ! grep -q 's1ap_rx_workers' "$f"; then
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
        elif ! grep -q 'workers:' "$f"; then
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
        if grep -q '^sgwc:' "$f" && \
           ! awk '/^sgwc:/{s=1;next} /^[a-z]/{s=0} s&&/workers:/{f=1} END{exit !f}' "$f"; then
            awk '
                { print }
                /^sgwc:/ && !done {
                    print "  workers: 4"
                    done = 1
                }
            ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
            echo "injected sgwc.workers:4 -> $f"
        fi
    done

    # Lab-only relocations, applied to every generated suite config
    # (tests connect using the same yaml, so both sides stay consistent):
    #  - production AMF owns 127.0.0.5  -> lab AMF to 127.0.0.105
    #  - production SMF owns 127.0.0.4  -> lab SMF to 127.0.0.104
    #    (NOT .14: that is the stock NSSF address; 5GC suites collide)
    #  - production owns ogstun/10.45.* -> lab uses ogstun2/10.46.*
    # All rules are idempotent on a second pass.
    for cf in "$BUILDDIR"/configs/*.yaml; do
        [ -f "$cf" ] || continue
        sed -Ei \
            -e 's/127\.0\.0\.5([^0-9]|$)/127.0.0.105\1/g' \
            -e 's/127\.0\.0\.4([^0-9]|$)/127.0.0.104\1/g' \
            -e 's/\bogstun\b/ogstun2/g' \
            -e 's/10\.45\./10.46./g' \
            -e 's/db8:cafe/db8:babe/g' \
            "$cf"
    done

    # Stock session subnets carry no `dev:` -> NFs default to ogstun,
    # which production owns. Pin every session subnet to ogstun2 (the
    # superadmin-owned lab tun with 10.46/16 + 2001:db8:babe::/48).
    for cf in "$BUILDDIR"/configs/*.yaml; do
        [ -f "$cf" ] || continue
        if grep -q -- '- subnet:' "$cf" && ! grep -q 'dev: ogstun2' "$cf"; then
            awk '
                { print }
                /- subnet: / { print "      dev: ogstun2" }
            ' "$cf" > "$cf.tmp" && mv "$cf.tmp" "$cf"
        fi
    done
    echo "lab address/tun relocations applied -> $BUILDDIR/configs/*.yaml"
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
    # exitcode=0: TSAN reports (freeDiameter shutdown races in the lab
    # daemons) must not turn into nonzero exits, or the test harness's
    # child_main asserts during teardown and aborts the whole suite.
    export TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=0 exitcode=0 history_size=7 second_deadlock_stack=1 log_path=tsan-mme}"
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
