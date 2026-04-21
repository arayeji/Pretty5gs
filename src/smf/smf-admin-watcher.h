/*
 * SMF integration for the Open5GS Admin API C watcher.
 *
 * Compiled and wired in ONLY when meson is configured with
 *   -Dadmin_watcher=true
 *
 * Covers:
 *   - UPF-peer hot-add  → ogs_pfcp_self()->pfcp_peer_list
 *   - Subnet    hot-add → ogs_pfcp_self()->subnet_list
 *   - DNN       hot-add → informational log only (DNNs in Open5GS are
 *                         metadata attached to subnets / subscriber
 *                         profiles; there is no separate global list).
 *
 * See tools/admin-api/README.md for the operational contract.
 */

#ifndef SMF_ADMIN_WATCHER_H
#define SMF_ADMIN_WATCHER_H

#ifdef __cplusplus
extern "C" {
#endif

int  smf_admin_watcher_init(void);
void smf_admin_watcher_final(void);

#ifdef __cplusplus
}
#endif

#endif /* SMF_ADMIN_WATCHER_H */
