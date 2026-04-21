# Open5GS Admin Watcher (C)

A small C library that NFs link against to consume the Open5GS Admin API.

Responsibilities:

1. Periodically poll the admin API's list endpoints.
2. Detect rows whose `revision` is higher than anything we've applied so far.
3. Invoke NF-provided callbacks for each new row — these callbacks append
   the config into whatever static arrays / lists the NF uses.
4. POST `/api/v1/apply-status/heartbeat` with the highest revision
   successfully applied, plus any error string from the last apply.

## Design notes

* **Single-threaded by design.** The watcher does blocking libcurl requests
  on its own thread; callbacks are marshalled onto the NF's event loop by
  the integrator using `ogs_queue_push` or an equivalent. Do not call
  libogs from the watcher thread.
* **List vs settings resources.** List rows (PLMN/TAC/DNN/UPF-peer/subnet)
  are append-only; the watcher only forwards rows whose `revision` is
  higher than the one we last applied, and there are no delete callbacks.
  Settings rows (currently just `smf/cdr`) are singletons; the watcher
  refetches them on every tick and only fires `on_smf_cdr_update` when
  their revision changes. A `DELETE` on a settings row fires
  `on_settings_clear` so the NF can revert.
* **No retries of state.** The watcher only forwards rows whose revision
  exceeds the last-seen value. Replays across NF restarts are handled by
  reading Mongo from revision 0 and applying everything (idempotent).

## Files

```
watcher-c/
├── include/open5gs_admin_watcher.h   # public API
├── src/open5gs_admin_watcher.c       # impl (libcurl + cJSON)
└── meson.build                        # static library target
```

## Dependencies

* libcurl (already required by Open5GS)
* cJSON (already pulled in by `ogs-sbi`)
* pthreads

## Integration outline (MME TAC, first proof)

```c
#include "open5gs_admin_watcher.h"

static void on_tac_add(const char *mcc, const char *mnc, int tac, void *ud)
{
    /* Append to mme_self()->served_tai[0].list0 / list1 / list2.
       Bail silently if already present (idempotent). */
}

static ogs_admin_watcher_t *g_watcher;

void mme_admin_watcher_init(void) {
    ogs_admin_watcher_cfg_t cfg = {
        .base_url = "http://127.0.0.1:9998",
        .bearer_token = getenv("OPEN5GS_ADMIN_TOKEN"),
        .nf_type = "mme",
        .nf_id = "mme-1",
        .poll_interval_ms = 5000,
    };
    ogs_admin_watcher_cbs_t cbs = {
        .on_tac_add = on_tac_add,
    };
    g_watcher = ogs_admin_watcher_new(&cfg, &cbs);
}
```

The MME TAC applier must take care **not** to:

* Reallocate or shift existing `served_tai` entries (eNBs hold pointers).
* Advertise the TAI change to already-connected eNBs via S1 Reset. UEs
  attaching afterwards will pick up the new TAI naturally.
