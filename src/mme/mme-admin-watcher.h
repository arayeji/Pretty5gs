/*
 * MME integration for the Open5GS Admin API C watcher.
 *
 * Compiled and wired in ONLY when meson is configured with
 *   -Dadmin_watcher=true
 *
 * See tools/admin-api/README.md for the operational contract.
 */

#ifndef MME_ADMIN_WATCHER_H
#define MME_ADMIN_WATCHER_H

#ifdef __cplusplus
extern "C" {
#endif

/* No-ops at runtime when admin_watcher is off — also guarded in mme-init.c
 * behind #ifdef OPEN5GS_ADMIN_WATCHER. */
int  mme_admin_watcher_init(void);
void mme_admin_watcher_final(void);

#ifdef __cplusplus
}
#endif

#endif /* MME_ADMIN_WATCHER_H */
