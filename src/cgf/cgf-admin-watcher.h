/*
 * CGF integration for the Open5GS Admin API C watcher.
 *
 * Compiled and wired in ONLY when meson is configured with
 *   -Dadmin_watcher=true
 *
 * Covers:
 *   - cgfd/gtpp settings (peer list, echo/RTO tunables) → live applied
 *     via cgf_gtpp_apply_runtime().
 *
 * See tools/admin-api/README.md for the operational contract.
 */

#ifndef CGF_ADMIN_WATCHER_H
#define CGF_ADMIN_WATCHER_H

#ifdef __cplusplus
extern "C" {
#endif

int  cgf_admin_watcher_init(void);
void cgf_admin_watcher_final(void);

#ifdef __cplusplus
}
#endif

#endif /* CGF_ADMIN_WATCHER_H */
