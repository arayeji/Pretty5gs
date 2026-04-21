/*
 * UPF integration for the Open5GS Admin API C watcher.
 *
 * Compiled and wired in ONLY when meson is configured with
 *   -Dadmin_watcher=true
 *
 * Scope: subnet (IP-pool) hot-add via ogs_pfcp_subnet_add. All other
 * callbacks are tolerated but ignored — they are not meaningful at the
 * UPF layer in the Open5GS architecture.
 */

#ifndef UPF_ADMIN_WATCHER_H
#define UPF_ADMIN_WATCHER_H

#ifdef __cplusplus
extern "C" {
#endif

int  upf_admin_watcher_init(void);
void upf_admin_watcher_final(void);

#ifdef __cplusplus
}
#endif

#endif /* UPF_ADMIN_WATCHER_H */
