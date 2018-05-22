/* Copyright (c) 2015, 2016, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "ovn-controller.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "bfd.h"
#include "binding.h"
#include "chassis.h"
#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "encaps.h"
#include "fatal-signal.h"
#include "openvswitch/hmap.h"
#include "lflow.h"
#include "lib/vswitch-idl.h"
#include "lport.h"
#include "ofctrl.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "ovn/actions.h"
#include "ovn/lib/chassis-index.h"
#include "ovn/lib/extend-table.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn/lib/ovn-util.h"
#include "patch.h"
#include "physical.h"
#include "pinctrl.h"
#include "openvswitch/poll-loop.h"
#include "lib/bitmap.h"
#include "lib/hash.h"
#include "smap.h"
#include "sset.h"
#include "stream-ssl.h"
#include "stream.h"
#include "unixctl.h"
#include "util.h"
#include "timeval.h"
#include "timer.h"
#include "stopwatch.h"
#include "ovn/lib/inc-proc-eng.h"

VLOG_DEFINE_THIS_MODULE(main);

static unixctl_cb_func ovn_controller_exit;
static unixctl_cb_func ct_zone_list;
static unixctl_cb_func inject_pkt;

#define DEFAULT_BRIDGE_NAME "br-int"
#define DEFAULT_PROBE_INTERVAL_MSEC 5000

#define CONTROLLER_LOOP_STOPWATCH_NAME "ovn-controller-flow-generation"

static void update_probe_interval(struct controller_ctx *,
                                  const char *ovnsb_remote);
static char *parse_options(int argc, char *argv[]);
OVS_NO_RETURN static void usage(void);

/* Pending packet to be injected into connected OVS. */
struct pending_pkt {
    /* Setting 'conn' indicates that a request is pending. */
    struct unixctl_conn *conn;
    char *flow_s;
};

struct local_datapath *
get_local_datapath(const struct hmap *local_datapaths, uint32_t tunnel_key)
{
    struct hmap_node *node = hmap_first_with_hash(local_datapaths, tunnel_key);
    return (node
            ? CONTAINER_OF(node, struct local_datapath, hmap_node)
            : NULL);
}

const struct sbrec_chassis *
get_chassis(struct ovsdb_idl *ovnsb_idl, const char *chassis_id)
{
    const struct sbrec_chassis *chassis_rec;

    SBREC_CHASSIS_FOR_EACH(chassis_rec, ovnsb_idl) {
        if (!strcmp(chassis_rec->name, chassis_id)) {
            break;
        }
    }

    return chassis_rec;
}

uint32_t
get_tunnel_type(const char *name)
{
    if (!strcmp(name, "geneve")) {
        return GENEVE;
    } else if (!strcmp(name, "stt")) {
        return STT;
    } else if (!strcmp(name, "vxlan")) {
        return VXLAN;
    }

    return 0;
}

const struct ovsrec_bridge *
get_bridge(struct ovsdb_idl *ovs_idl, const char *br_name)
{
    const struct ovsrec_bridge *br;
    OVSREC_BRIDGE_FOR_EACH (br, ovs_idl) {
        if (!strcmp(br->name, br_name)) {
            return br;
        }
    }
    return NULL;
}

static void
update_sb_monitors(struct ovsdb_idl *ovnsb_idl,
                   const struct sbrec_chassis *chassis,
                   const struct sset *local_ifaces,
                   struct hmap *local_datapaths)
{
    /* Monitor Port_Bindings rows for local interfaces and local datapaths.
     *
     * Monitor Logical_Flow, MAC_Binding, Multicast_Group, and DNS tables for
     * local datapaths.
     *
     * We always monitor patch ports because they allow us to see the linkages
     * between related logical datapaths.  That way, when we know that we have
     * a VIF on a particular logical switch, we immediately know to monitor all
     * the connected logical routers and logical switches. */
    struct ovsdb_idl_condition pb = OVSDB_IDL_CONDITION_INIT(&pb);
    struct ovsdb_idl_condition lf = OVSDB_IDL_CONDITION_INIT(&lf);
    struct ovsdb_idl_condition mb = OVSDB_IDL_CONDITION_INIT(&mb);
    struct ovsdb_idl_condition mg = OVSDB_IDL_CONDITION_INIT(&mg);
    struct ovsdb_idl_condition dns = OVSDB_IDL_CONDITION_INIT(&dns);
    sbrec_port_binding_add_clause_type(&pb, OVSDB_F_EQ, "patch");
    /* XXX: We can optimize this, if we find a way to only monitor
     * ports that have a Gateway_Chassis that point's to our own
     * chassis */
    sbrec_port_binding_add_clause_type(&pb, OVSDB_F_EQ, "chassisredirect");
    if (chassis) {
        /* This should be mostly redundant with the other clauses for port
         * bindings, but it allows us to catch any ports that are assigned to
         * us but should not be.  That way, we can clear their chassis
         * assignments. */
        sbrec_port_binding_add_clause_chassis(&pb, OVSDB_F_EQ,
                                              &chassis->header_.uuid);

        /* Ensure that we find out about l2gateway and l3gateway ports that
         * should be present on this chassis.  Otherwise, we might never find
         * out about those ports, if their datapaths don't otherwise have a VIF
         * in this chassis. */
        const char *id = chassis->name;
        const struct smap l2 = SMAP_CONST1(&l2, "l2gateway-chassis", id);
        sbrec_port_binding_add_clause_options(&pb, OVSDB_F_INCLUDES, &l2);
        const struct smap l3 = SMAP_CONST1(&l3, "l3gateway-chassis", id);
        sbrec_port_binding_add_clause_options(&pb, OVSDB_F_INCLUDES, &l3);
    }
    if (local_ifaces) {
        const char *name;
        SSET_FOR_EACH (name, local_ifaces) {
            sbrec_port_binding_add_clause_logical_port(&pb, OVSDB_F_EQ, name);
            sbrec_port_binding_add_clause_parent_port(&pb, OVSDB_F_EQ, name);
        }
    }
    if (local_datapaths) {
        const struct local_datapath *ld;
        HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
            struct uuid *uuid = CONST_CAST(struct uuid *,
                                           &ld->datapath->header_.uuid);
            sbrec_port_binding_add_clause_datapath(&pb, OVSDB_F_EQ, uuid);
            sbrec_logical_flow_add_clause_logical_datapath(&lf, OVSDB_F_EQ,
                                                           uuid);
            sbrec_mac_binding_add_clause_datapath(&mb, OVSDB_F_EQ, uuid);
            sbrec_multicast_group_add_clause_datapath(&mg, OVSDB_F_EQ, uuid);
            sbrec_dns_add_clause_datapaths(&dns, OVSDB_F_INCLUDES, &uuid, 1);
        }
    }
    sbrec_port_binding_set_condition(ovnsb_idl, &pb);
    sbrec_logical_flow_set_condition(ovnsb_idl, &lf);
    sbrec_mac_binding_set_condition(ovnsb_idl, &mb);
    sbrec_multicast_group_set_condition(ovnsb_idl, &mg);
    sbrec_dns_set_condition(ovnsb_idl, &dns);
    ovsdb_idl_condition_destroy(&pb);
    ovsdb_idl_condition_destroy(&lf);
    ovsdb_idl_condition_destroy(&mb);
    ovsdb_idl_condition_destroy(&mg);
    ovsdb_idl_condition_destroy(&dns);
}

static const char *
br_int_name(const struct ovsrec_open_vswitch *cfg)
{
    return smap_get_def(&cfg->external_ids, "ovn-bridge", DEFAULT_BRIDGE_NAME);
}

static const struct ovsrec_bridge *
create_br_int(struct controller_ctx *ctx)
{
    if (!ctx->ovs_idl_txn) {
        return NULL;
    }

    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_first(ctx->ovs_idl);
    if (!cfg) {
        return NULL;
    }
    const char *bridge_name = br_int_name(cfg);

    ovsdb_idl_txn_add_comment(ctx->ovs_idl_txn,
            "ovn-controller: creating integration bridge '%s'", bridge_name);

    struct ovsrec_interface *iface;
    iface = ovsrec_interface_insert(ctx->ovs_idl_txn);
    ovsrec_interface_set_name(iface, bridge_name);
    ovsrec_interface_set_type(iface, "internal");

    struct ovsrec_port *port;
    port = ovsrec_port_insert(ctx->ovs_idl_txn);
    ovsrec_port_set_name(port, bridge_name);
    ovsrec_port_set_interfaces(port, &iface, 1);

    struct ovsrec_bridge *bridge;
    bridge = ovsrec_bridge_insert(ctx->ovs_idl_txn);
    ovsrec_bridge_set_name(bridge, bridge_name);
    ovsrec_bridge_set_fail_mode(bridge, "secure");
    const struct smap oc = SMAP_CONST1(&oc, "disable-in-band", "true");
    ovsrec_bridge_set_other_config(bridge, &oc);
    ovsrec_bridge_set_ports(bridge, &port, 1);

    struct ovsrec_bridge **bridges;
    size_t bytes = sizeof *bridges * cfg->n_bridges;
    bridges = xmalloc(bytes + sizeof *bridges);
    memcpy(bridges, cfg->bridges, bytes);
    bridges[cfg->n_bridges] = bridge;
    ovsrec_open_vswitch_verify_bridges(cfg);
    ovsrec_open_vswitch_set_bridges(cfg, bridges, cfg->n_bridges + 1);
    free(bridges);

    return bridge;
}

static const struct ovsrec_bridge *
get_br_int(struct controller_ctx *ctx)
{
    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_first(ctx->ovs_idl);
    if (!cfg) {
        return NULL;
    }

    return get_bridge(ctx->ovs_idl, br_int_name(cfg));
}

static const char *
get_chassis_id(const struct ovsdb_idl *ovs_idl)
{
    const struct ovsrec_open_vswitch *cfg = ovsrec_open_vswitch_first(ovs_idl);
    const char *chassis_id = cfg ? smap_get(&cfg->external_ids, "system-id") : NULL;

    if (!chassis_id) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "'system-id' in Open_vSwitch database is missing.");
    }

    return chassis_id;
}

/* Iterate address sets in the southbound database.  Create and update the
 * corresponding symtab entries as necessary. */
static void
addr_sets_update(struct controller_ctx *ctx, struct shash *addr_sets,
                 struct sset *new, struct sset *deleted, struct sset *updated)
{
    const struct sbrec_address_set *as;
    SBREC_ADDRESS_SET_FOR_EACH_TRACKED (as, ctx->ovnsb_idl) {
        if (sbrec_address_set_is_deleted(as)) {
            expr_const_sets_remove(addr_sets, as->name);
            sset_add(deleted, as->name);
        } else {
            expr_const_sets_add(addr_sets, as->name,
                                (const char *const *) as->addresses,
                                as->n_addresses, true);
            if (sbrec_address_set_is_new(as)) {
                sset_add(new, as->name);
            } else {
                sset_add(updated, as->name);
            }
        }
    }
}

/* Iterate port groups in the southbound database.  Create and update the
 * corresponding symtab entries as necessary. */
static void
port_groups_init(struct controller_ctx *ctx, struct shash *port_groups)
{
    const struct sbrec_port_group *pg;
    SBREC_PORT_GROUP_FOR_EACH (pg, ctx->ovnsb_idl) {
        expr_const_sets_add(port_groups, pg->name,
                            (const char *const *) pg->ports,
                            pg->n_ports, false);
    }
}

static void
update_ssl_config(const struct ovsdb_idl *ovs_idl)
{
    const struct ovsrec_ssl *ssl = ovsrec_ssl_first(ovs_idl);

    if (ssl) {
        stream_ssl_set_key_and_cert(ssl->private_key, ssl->certificate);
        stream_ssl_set_ca_cert_file(ssl->ca_cert, ssl->bootstrap_ca_cert);
    }
}

/* Retrieves the OVN Southbound remote location from the
 * "external-ids:ovn-remote" key in 'ovs_idl' and returns a copy of it. */
static char *
get_ovnsb_remote(struct ovsdb_idl *ovs_idl)
{
    while (1) {
        ovsdb_idl_run(ovs_idl);

        const struct ovsrec_open_vswitch *cfg
            = ovsrec_open_vswitch_first(ovs_idl);
        if (cfg) {
            const char *remote = smap_get(&cfg->external_ids, "ovn-remote");
            if (remote) {
                update_ssl_config(ovs_idl);
                return xstrdup(remote);
            }
        }

        VLOG_INFO("OVN OVSDB remote not specified.  Waiting...");
        ovsdb_idl_wait(ovs_idl);
        poll_block();
    }
}

static void
update_ct_zones(struct sset *lports, const struct hmap *local_datapaths,
                struct simap *ct_zones, unsigned long *ct_zone_bitmap,
                struct shash *pending_ct_zones)
{
    struct simap_node *ct_zone, *ct_zone_next;
    int scan_start = 1;
    const char *user;
    struct sset all_users = SSET_INITIALIZER(&all_users);

    SSET_FOR_EACH(user, lports) {
        sset_add(&all_users, user);
    }

    /* Local patched datapath (gateway routers) need zones assigned. */
    const struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
        /* XXX Add method to limit zone assignment to logical router
         * datapaths with NAT */
        char *dnat = alloc_nat_zone_key(&ld->datapath->header_.uuid, "dnat");
        char *snat = alloc_nat_zone_key(&ld->datapath->header_.uuid, "snat");
        sset_add(&all_users, dnat);
        sset_add(&all_users, snat);
        free(dnat);
        free(snat);
    }

    /* Delete zones that do not exist in above sset. */
    SIMAP_FOR_EACH_SAFE(ct_zone, ct_zone_next, ct_zones) {
        if (!sset_contains(&all_users, ct_zone->name)) {
            VLOG_DBG("removing ct zone %"PRId32" for '%s'",
                     ct_zone->data, ct_zone->name);

            struct ct_zone_pending_entry *pending = xmalloc(sizeof *pending);
            pending->state = CT_ZONE_DB_QUEUED; /* Skip flushing zone. */
            pending->zone = ct_zone->data;
            pending->add = false;
            shash_add(pending_ct_zones, ct_zone->name, pending);

            bitmap_set0(ct_zone_bitmap, ct_zone->data);
            simap_delete(ct_zones, ct_zone);
        }
    }

    /* xxx This is wasteful to assign a zone to each port--even if no
     * xxx security policy is applied. */

    /* Assign a unique zone id for each logical port and two zones
     * to a gateway router. */
    SSET_FOR_EACH(user, &all_users) {
        int zone;

        if (simap_contains(ct_zones, user)) {
            continue;
        }

        /* We assume that there are 64K zones and that we own them all. */
        zone = bitmap_scan(ct_zone_bitmap, 0, scan_start, MAX_CT_ZONES + 1);
        if (zone == MAX_CT_ZONES + 1) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "exhausted all ct zones");
            return;
        }
        scan_start = zone + 1;

        VLOG_DBG("assigning ct zone %"PRId32" to '%s'", zone, user);

        struct ct_zone_pending_entry *pending = xmalloc(sizeof *pending);
        pending->state = CT_ZONE_OF_QUEUED;
        pending->zone = zone;
        pending->add = true;
        shash_add(pending_ct_zones, user, pending);

        bitmap_set1(ct_zone_bitmap, zone);
        simap_put(ct_zones, user, zone);
    }

    sset_destroy(&all_users);
}

static void
commit_ct_zones(const struct ovsrec_bridge *br_int,
                struct shash *pending_ct_zones)
{
    struct smap new_ids;
    smap_clone(&new_ids, &br_int->external_ids);

    bool updated = false;
    struct shash_node *iter;
    SHASH_FOR_EACH(iter, pending_ct_zones) {
        struct ct_zone_pending_entry *ctzpe = iter->data;

        /* The transaction is open, so any pending entries in the
         * CT_ZONE_DB_QUEUED must be sent and any in CT_ZONE_DB_QUEUED
         * need to be retried. */
        if (ctzpe->state != CT_ZONE_DB_QUEUED
            && ctzpe->state != CT_ZONE_DB_SENT) {
            continue;
        }

        char *user_str = xasprintf("ct-zone-%s", iter->name);
        if (ctzpe->add) {
            char *zone_str = xasprintf("%"PRId32, ctzpe->zone);
            smap_replace(&new_ids, user_str, zone_str);
            free(zone_str);
        } else {
            smap_remove(&new_ids, user_str);
        }
        free(user_str);

        ctzpe->state = CT_ZONE_DB_SENT;
        updated = true;
    }

    if (updated) {
        ovsrec_bridge_verify_external_ids(br_int);
        ovsrec_bridge_set_external_ids(br_int, &new_ids);
    }
    smap_destroy(&new_ids);
}

static void
restore_ct_zones(struct ovsdb_idl *ovs_idl,
                 struct simap *ct_zones, unsigned long *ct_zone_bitmap)
{
    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_first(ovs_idl);
    if (!cfg) {
        return;
    }

    const struct ovsrec_bridge *br_int;
    br_int = get_bridge(ovs_idl, br_int_name(cfg));
    if (!br_int) {
        /* If the integration bridge hasn't been defined, assume that
         * any existing ct-zone definitions aren't valid. */
        return;
    }

    struct smap_node *node;
    SMAP_FOR_EACH(node, &br_int->external_ids) {
        if (strncmp(node->key, "ct-zone-", 8)) {
            continue;
        }

        const char *user = node->key + 8;
        int zone = atoi(node->value);

        if (user[0] && zone) {
            VLOG_DBG("restoring ct zone %"PRId32" for '%s'", zone, user);
            bitmap_set1(ct_zone_bitmap, zone);
            simap_put(ct_zones, user, zone);
        }
    }
}

static int64_t
get_nb_cfg(struct ovsdb_idl *idl)
{
    const struct sbrec_sb_global *sb = sbrec_sb_global_first(idl);
    return sb ? sb->nb_cfg : 0;
}

static void
ctrl_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    /* We do not monitor all tables by default, so modules must register
     * their interest explicitly. */
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_external_ids);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_bridges);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_bfd);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_bfd_status);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_type);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_options);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_external_ids);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_fail_mode);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_other_config);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_external_ids);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_ssl);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_bootstrap_ca_cert);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_ca_cert);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_certificate);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_private_key);
    chassis_register_ovs_idl(ovs_idl);
    encaps_register_ovs_idl(ovs_idl);
    binding_register_ovs_idl(ovs_idl);
    bfd_register_ovs_idl(ovs_idl);
    physical_register_ovs_idl(ovs_idl);
}

static void
create_ovnsb_indexes(struct ovsdb_idl *ovnsb_idl)
{
    struct ovsdb_idl_index *index;

    /* Index multicast group table by name and datapath. */
    index = ovsdb_idl_create_index(ovnsb_idl, &sbrec_table_multicast_group,
                                   "multicast-group-by-dp-name");
    ovsdb_idl_index_add_column(index, &sbrec_multicast_group_col_name,
                               OVSDB_INDEX_ASC, NULL);
    ovsdb_idl_index_add_column(index, &sbrec_multicast_group_col_datapath,
                               OVSDB_INDEX_ASC, NULL);

    /* Index logical port table by name. */
    index = ovsdb_idl_create_index(ovnsb_idl, &sbrec_table_port_binding,
                                   "lport-by-name");
    ovsdb_idl_index_add_column(index, &sbrec_port_binding_col_logical_port,
                               OVSDB_INDEX_ASC, NULL);

    /* Index logical port table by tunnel key and datapath. */
    index = ovsdb_idl_create_index(ovnsb_idl, &sbrec_table_port_binding,
                                   "lport-by-key");
    ovsdb_idl_index_add_column(index, &sbrec_port_binding_col_tunnel_key,
                               OVSDB_INDEX_ASC, NULL);
    ovsdb_idl_index_add_column(index, &sbrec_port_binding_col_datapath,
                               OVSDB_INDEX_ASC, NULL);

    /* Index logical port table by datapath. */
    index = ovsdb_idl_create_index(ovnsb_idl, &sbrec_table_port_binding,
                                   "lport-by-datapath");
    ovsdb_idl_index_add_column(index, &sbrec_port_binding_col_datapath,
                               OVSDB_INDEX_ASC, NULL);

    /* Index datapath binding table by tunnel key. */
    index = ovsdb_idl_create_index(ovnsb_idl, &sbrec_table_datapath_binding,
                                   "dpath-by-key");
    ovsdb_idl_index_add_column(index, &sbrec_datapath_binding_col_tunnel_key,
                               OVSDB_INDEX_ASC, NULL);
}

ENGINE_FUNC_SB(chassis);
ENGINE_FUNC_SB(encap);
ENGINE_FUNC_SB(address_set);
ENGINE_FUNC_SB(port_group);
ENGINE_FUNC_SB(multicast_group);
ENGINE_FUNC_SB(datapath_binding);
ENGINE_FUNC_SB(port_binding);
ENGINE_FUNC_SB(mac_binding);
ENGINE_FUNC_SB(logical_flow);
ENGINE_FUNC_SB(dhcp_options);
ENGINE_FUNC_SB(dhcpv6_options);
ENGINE_FUNC_SB(dns);
ENGINE_FUNC_SB(gateway_chassis);

ENGINE_FUNC_OVS(port);
ENGINE_FUNC_OVS(interface);

struct ed_type_addr_sets {
    struct shash addr_sets;
    struct sset new;
    struct sset deleted;
    struct sset updated;
};

static void
en_addr_sets_init(struct engine_node *node)
{
    struct ed_type_addr_sets *as = (struct ed_type_addr_sets *)node->data;
    shash_init(&as->addr_sets);
    sset_init(&as->new);
    sset_init(&as->deleted);
    sset_init(&as->updated);
}

static void
en_addr_sets_cleanup(struct engine_node *node)
{
    struct ed_type_addr_sets *as = (struct ed_type_addr_sets *)node->data;
    expr_const_sets_destroy(&as->addr_sets);
    shash_destroy(&as->addr_sets);
    sset_destroy(&as->new);
    sset_destroy(&as->deleted);
    sset_destroy(&as->updated);
}

/* For en_addr_sets, the run function handles changes since there is only
 * one input */
static void
en_addr_sets_run(struct engine_node *node)
{
    struct controller_ctx *ctx = (struct controller_ctx *)node->context;
    struct ed_type_addr_sets *as = (struct ed_type_addr_sets *)node->data;

    sset_clear(&as->new);
    sset_clear(&as->deleted);
    sset_clear(&as->updated);

    addr_sets_update(ctx, &as->addr_sets, &as->new,
                     &as->deleted, &as->updated);

    node->changed = !sset_is_empty(&as->new) || !sset_is_empty(&as->deleted)
                    || !sset_is_empty(&as->updated);
}

struct ed_type_runtime_data {
    struct chassis_index chassis_index;

    /* Contains "struct local_datapath" nodes. */
    struct hmap local_datapaths;

    /* Contains the name of each logical port resident on the local
     * hypervisor.  These logical ports include the VIFs (and their child
     * logical ports, if any) that belong to VMs running on the hypervisor,
     * l2gateway ports for which options:l2gateway-chassis designates the
     * local hypervisor, and localnet ports. */
    struct sset local_lports;

    /* Contains the same ports as local_lports, but in the format:
     * <datapath-tunnel-key>_<port-tunnel-key> */
    struct sset local_lport_ids;
    struct sset active_tunnels;
    struct shash port_groups;

    /* connection tracking zones. */
    unsigned long ct_zone_bitmap[BITMAP_N_LONGS(MAX_CT_ZONES)];
    struct shash pending_ct_zones;
    struct simap ct_zones;
};

static void
en_runtime_data_init(struct engine_node *node)
{
    struct controller_ctx *ctx = (struct controller_ctx *)node->context;
    struct ed_type_runtime_data *data =
        (struct ed_type_runtime_data *)node->data;
    hmap_init(&data->local_datapaths);
    sset_init(&data->local_lports);
    sset_init(&data->local_lport_ids);
    sset_init(&data->active_tunnels);
    shash_init(&data->port_groups);
    shash_init(&data->pending_ct_zones);
    simap_init(&data->ct_zones);

    /* Initialize connection tracking zones. */
    memset(data->ct_zone_bitmap, 0, sizeof data->ct_zone_bitmap);
    bitmap_set1(data->ct_zone_bitmap, 0); /* Zone 0 is reserved. */
    restore_ct_zones(ctx->ovs_idl, &data->ct_zones, data->ct_zone_bitmap);
}

static void
en_runtime_data_cleanup(struct engine_node *node)
{
    struct ed_type_runtime_data *data =
        (struct ed_type_runtime_data *)node->data;

    expr_const_sets_destroy(&data->port_groups);
    shash_destroy(&data->port_groups);

    chassis_index_destroy(&data->chassis_index);

    sset_destroy(&data->local_lports);
    sset_destroy(&data->local_lport_ids);
    sset_destroy(&data->active_tunnels);
    struct local_datapath *cur_node, *next_node;
    HMAP_FOR_EACH_SAFE (cur_node, next_node, hmap_node,
                        &data->local_datapaths) {
        free(cur_node->peer_dps);
        hmap_remove(&data->local_datapaths, &cur_node->hmap_node);
        free(cur_node);
    }
    hmap_destroy(&data->local_datapaths);

    simap_destroy(&data->ct_zones);
    shash_destroy(&data->pending_ct_zones);
}

static void
en_runtime_data_run(struct engine_node *node)
{
    struct controller_ctx *ctx = (struct controller_ctx *)node->context;
    struct ed_type_runtime_data *data =
        (struct ed_type_runtime_data *)node->data;
    struct hmap *local_datapaths = &data->local_datapaths;
    struct sset *local_lports = &data->local_lports;
    struct sset *local_lport_ids = &data->local_lport_ids;
    struct sset *active_tunnels = &data->active_tunnels;
    struct chassis_index *chassis_index = &data->chassis_index;
    struct shash *port_groups = &data->port_groups;
    unsigned long *ct_zone_bitmap = data->ct_zone_bitmap;
    struct shash *pending_ct_zones = &data->pending_ct_zones;
    struct simap *ct_zones = &data->ct_zones;

    static bool first_run = true;
    if (first_run) {
        /* don't cleanup since there is no data yet */
        first_run = false;
    } else {
        struct local_datapath *cur_node, *next_node;
        HMAP_FOR_EACH_SAFE (cur_node, next_node, hmap_node, local_datapaths) {
            free(cur_node->peer_dps);
            hmap_remove(local_datapaths, &cur_node->hmap_node);
            free(cur_node);
        }
        hmap_clear(local_datapaths);
        sset_destroy(local_lports);
        sset_destroy(local_lport_ids);
        sset_destroy(active_tunnels);
        chassis_index_destroy(chassis_index);
        expr_const_sets_destroy(port_groups);
        sset_init(local_lports);
        sset_init(local_lport_ids);
        sset_init(active_tunnels);
    }

    const char *chassis_id = get_chassis_id(ctx->ovs_idl);
    const struct ovsrec_bridge *br_int = get_br_int(ctx);

    ovs_assert(br_int && chassis_id);
    const struct sbrec_chassis *chassis = NULL;
    chassis = get_chassis(ctx->ovnsb_idl, chassis_id);
    ovs_assert(chassis);

    chassis_index_init(chassis_index, ctx->ovnsb_idl);
    bfd_calculate_active_tunnels(br_int, active_tunnels);
    /* requires ctx->ovnsb_idl_txn */
    binding_run(ctx, br_int, chassis,
                chassis_index, active_tunnels, local_datapaths,
                local_lports, local_lport_ids);

    port_groups_init(ctx, port_groups);
    update_ct_zones(local_lports, local_datapaths, ct_zones,
                    ct_zone_bitmap, pending_ct_zones);

    node->changed = true;
}

static bool
runtime_data_sb_port_binding_handler(struct engine_node *node)
{
    struct controller_ctx *ctx = (struct controller_ctx *)node->context;
    struct ed_type_runtime_data *data =
        (struct ed_type_runtime_data *)node->data;
    struct sset *local_lports = &data->local_lports;
    struct sset *active_tunnels = &data->active_tunnels;
    struct chassis_index *chassis_index = &data->chassis_index;

    const char *chassis_id = get_chassis_id(ctx->ovs_idl);
    const struct ovsrec_bridge *br_int = get_br_int(ctx);

    ovs_assert(br_int && chassis_id);
    const struct sbrec_chassis *chassis = NULL;
    chassis = get_chassis(ctx->ovnsb_idl, chassis_id);
    ovs_assert(chassis);

    bool changed = binding_evaluate_port_binding_changes(
                ctx, br_int, chassis,
                chassis_index, active_tunnels,
                local_lports);

    return !changed;
}

struct ed_type_flow_output {
    /* desired flows */
    struct ovn_desired_flow_table flow_table;
    /* group ids for load balancing */
    struct ovn_extend_table group_table;
    /* meter ids for QoS */
    struct ovn_extend_table meter_table;
    /* conjunction id offset */
    uint32_t conj_id_ofs;
};

static void
en_flow_output_init(struct engine_node *node)
{
    struct ed_type_flow_output *data =
        (struct ed_type_flow_output *)node->data;
    ovn_desired_flow_table_init(&data->flow_table);
    ovn_extend_table_init(&data->group_table);
    ovn_extend_table_init(&data->meter_table);
    data->conj_id_ofs = 1;
}

static void
en_flow_output_cleanup(struct engine_node *node)
{
    struct ed_type_flow_output *data =
        (struct ed_type_flow_output *)node->data;
    ovn_desired_flow_table_destroy(&data->flow_table);
    ovn_extend_table_destroy(&data->group_table);
    ovn_extend_table_destroy(&data->meter_table);
}

static void
en_flow_output_run(struct engine_node *node)
{
    struct controller_ctx *ctx = (struct controller_ctx *)node->context;
    struct ed_type_runtime_data *rt_data =
        (struct ed_type_runtime_data *)engine_get_input(
            "runtime_data", node)->data;
    struct hmap *local_datapaths = &rt_data->local_datapaths;
    struct sset *local_lports = &rt_data->local_lports;
    struct sset *local_lport_ids = &rt_data->local_lport_ids;
    struct sset *active_tunnels = &rt_data->active_tunnels;
    struct chassis_index *chassis_index = &rt_data->chassis_index;
    struct shash *port_groups = &rt_data->port_groups;
    struct simap *ct_zones = &rt_data->ct_zones;

    struct ed_type_addr_sets *as_data =
        (struct ed_type_addr_sets *)engine_get_input("addr_sets", node)->data;
    struct shash *addr_sets = &as_data->addr_sets;

    const struct ovsrec_bridge *br_int = get_br_int(ctx);

    const char *chassis_id = get_chassis_id(ctx->ovs_idl);

    const struct sbrec_chassis *chassis = NULL;
    if (chassis_id) {
        chassis = get_chassis(ctx->ovnsb_idl, chassis_id);
    }

    ovs_assert(br_int && chassis);

    struct ed_type_flow_output *fo =
        (struct ed_type_flow_output *)node->data;
    struct ovn_desired_flow_table *flow_table = &fo->flow_table;
    struct ovn_extend_table *group_table = &fo->group_table;
    struct ovn_extend_table *meter_table = &fo->meter_table;
    uint32_t *conj_id_ofs = &fo->conj_id_ofs;

    static bool first_run = true;
    if (first_run) {
        first_run = false;
    } else {
        ovn_desired_flow_table_clear(flow_table);
        ovn_extend_table_clear(group_table, false /* desired */);
        ovn_extend_table_clear(meter_table, false /* desired */);
    }

    *conj_id_ofs = 1;
    lflow_run(flow_table, ctx, chassis,
              chassis_index, local_datapaths, group_table,
              meter_table, addr_sets, port_groups, active_tunnels,
              local_lport_ids, conj_id_ofs);

    enum mf_field_id mff_ovn_geneve = ofctrl_get_mf_field_id();

    physical_run(flow_table, ctx, mff_ovn_geneve,
                 br_int, chassis, ct_zones,
                 local_datapaths, local_lports,
                 chassis_index, active_tunnels);

    node->changed = true;
}

static bool
flow_output_sb_logical_flow_handler(struct engine_node *node)
{
    struct controller_ctx *ctx = (struct controller_ctx *)node->context;
    struct ed_type_runtime_data *data =
        (struct ed_type_runtime_data *)engine_get_input(
                "runtime_data", node)->data;
    struct hmap *local_datapaths = &data->local_datapaths;
    struct sset *local_lport_ids = &data->local_lport_ids;
    struct sset *active_tunnels = &data->active_tunnels;
    struct chassis_index *chassis_index = &data->chassis_index;
    struct shash *port_groups = &data->port_groups;
    struct ed_type_addr_sets *as_data =
        (struct ed_type_addr_sets *)engine_get_input("addr_sets", node)->data;
    struct shash *addr_sets = &as_data->addr_sets;

    const struct ovsrec_bridge *br_int = get_br_int(ctx);

    const char *chassis_id = get_chassis_id(ctx->ovs_idl);


    const struct sbrec_chassis *chassis = NULL;
    if (chassis_id) {
        chassis = get_chassis(ctx->ovnsb_idl, chassis_id);
    }

    ovs_assert(br_int && chassis);

    struct ed_type_flow_output *fo =
        (struct ed_type_flow_output *)node->data;
    struct ovn_desired_flow_table *flow_table = &fo->flow_table;
    struct ovn_extend_table *group_table = &fo->group_table;
    struct ovn_extend_table *meter_table = &fo->meter_table;
    uint32_t *conj_id_ofs = &fo->conj_id_ofs;

    bool handled = lflow_handle_changed_flows(flow_table, ctx, chassis,
              chassis_index, local_datapaths, group_table, meter_table,
              addr_sets, port_groups, active_tunnels, local_lport_ids,
              conj_id_ofs);

    node->changed = true;
    return handled;
}

static bool
flow_output_sb_port_binding_handler(struct engine_node *node)
{
    struct controller_ctx *ctx = (struct controller_ctx *)node->context;
    struct ed_type_runtime_data *data =
        (struct ed_type_runtime_data *)engine_get_input(
                "runtime_data", node)->data;
    struct hmap *local_datapaths = &data->local_datapaths;
    struct sset *active_tunnels = &data->active_tunnels;
    struct chassis_index *chassis_index = &data->chassis_index;
    struct simap *ct_zones = &data->ct_zones;
    const struct ovsrec_bridge *br_int = get_br_int(ctx);

    const char *chassis_id = get_chassis_id(ctx->ovs_idl);


    const struct sbrec_chassis *chassis = NULL;
    if (chassis_id) {
        chassis = get_chassis(ctx->ovnsb_idl, chassis_id);
    }

    ovs_assert(br_int && chassis);

    struct ed_type_flow_output *fo =
        (struct ed_type_flow_output *)node->data;
    struct ovn_desired_flow_table *flow_table = &fo->flow_table;

    /* XXX: now we handles port-binding changes for physical flow processing
     * only, but port-binding change can have impact to logical flow
     * processing, too, in below circumstances:
     *
     *  - When a port-binding for a lport is inserted/deleted but the lflow
     *    using that lport doesn't change.
     *
     *    This is likely to happen only when the lport name is used by ACL
     *    match condition, which is specified by user. Even in that case, when
     *    port is actually bound on the chassis it will trigger recompute on
     *    that chassis since ovs interface is updated. So the only situation
     *    this would have real impact is when user defines an ACL that includes
     *    lport that is not the ingress/egress lport, e.g.:
     *
     *    to-lport 1000 'outport=="A" && inport=="B"' allow-related
     *
     *    If "B" is created and bound after the ACL is created, the ACL may not
     *    take effect on the chassis where "A" is bound, until a recompute is
     *    triggered there later.
     *
     *  - When is_chassis_resident is used in lflow. In this case the port
     *    binding is patch type, since this condition is used only for lrouter
     *    ports. In current "runtime_data" handling, port-binding changes of
     *    patch ports always trigger recomputing. So it is fine even if we do
     *    not handle it here.
     *
     *  - When a mac-binding doesn't change but the port-binding related to
     *    that mac-binding is deleted. In this case the neighbor flow generated
     *    for the mac-binding should be deleted. This would not cause any real
     *    issue for now, since mac-binding change triggers recomputing.
     *
     * To address the above issues, we will need to maintain a mapping between
     * lport names and the lflows that uses them, and reprocess the related
     * lflows when a port-binding corresponding to a lport name changes.
     */

    enum mf_field_id mff_ovn_geneve = ofctrl_get_mf_field_id();
    physical_handle_port_binding_changes(flow_table,
                                         ctx, mff_ovn_geneve,
                                         chassis, ct_zones,
                                         local_datapaths,
                                         chassis_index, active_tunnels);

    node->changed = true;
    return true;
}

static bool
flow_output_sb_multicast_group_handler(struct engine_node *node)
{
    struct controller_ctx *ctx = (struct controller_ctx *)node->context;
    struct ed_type_runtime_data *data =
        (struct ed_type_runtime_data *)engine_get_input(
                "runtime_data", node)->data;
    struct hmap *local_datapaths = &data->local_datapaths;
    struct simap *ct_zones = &data->ct_zones;
    const struct ovsrec_bridge *br_int = get_br_int(ctx);

    const char *chassis_id = get_chassis_id(ctx->ovs_idl);


    const struct sbrec_chassis *chassis = NULL;
    if (chassis_id) {
        chassis = get_chassis(ctx->ovnsb_idl, chassis_id);
    }

    ovs_assert(br_int && chassis);

    struct ed_type_flow_output *fo =
        (struct ed_type_flow_output *)node->data;
    struct ovn_desired_flow_table *flow_table = &fo->flow_table;

    enum mf_field_id mff_ovn_geneve = ofctrl_get_mf_field_id();
    physical_handle_mc_group_changes(flow_table,
                                     ctx, mff_ovn_geneve,
                                     chassis, ct_zones,
                                     local_datapaths);
    node->changed = true;
    return true;

}

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    bool exiting;
    int retval;

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    char *ovs_remote = parse_options(argc, argv);
    fatal_ignore_sigpipe();

    daemonize_start(false);

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_controller_exit, &exiting);


    daemonize_complete();

    pinctrl_init();
    lflow_init();

    /* Connect to OVS OVSDB instance. */
    struct ovsdb_idl_loop ovs_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovs_remote, &ovsrec_idl_class, false, true));
    ctrl_register_ovs_idl(ovs_idl_loop.idl);
    ovsdb_idl_get_initial_snapshot(ovs_idl_loop.idl);

    /* Connect to OVN SB database and get a snapshot. */
    char *ovnsb_remote = get_ovnsb_remote(ovs_idl_loop.idl);
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnsb_remote, &sbrec_idl_class, true, true));
    ovsdb_idl_set_leader_only(ovnsb_idl_loop.idl, false);

    create_ovnsb_indexes(ovnsb_idl_loop.idl);
    lport_init(ovnsb_idl_loop.idl);

    ovsdb_idl_track_add_all(ovnsb_idl_loop.idl);
    ovsdb_idl_omit_alert(ovnsb_idl_loop.idl, &sbrec_chassis_col_nb_cfg);
    update_sb_monitors(ovnsb_idl_loop.idl, NULL, NULL, NULL);
    ovsdb_idl_get_initial_snapshot(ovnsb_idl_loop.idl);


    stopwatch_create(CONTROLLER_LOOP_STOPWATCH_NAME, SW_MS);

    struct controller_ctx ctx = {
        .ovs_idl = ovs_idl_loop.idl,
        .ovnsb_idl = ovnsb_idl_loop.idl
    };
    struct ed_type_runtime_data ed_runtime_data;
    struct ed_type_flow_output ed_flow_output;
    struct ed_type_addr_sets ed_addr_sets;

    ENGINE_NODE_SB(chassis, "chassis", &ctx);
    ENGINE_NODE_SB(encap, "encap", &ctx);
    ENGINE_NODE_SB(address_set, "address_set", &ctx);
    ENGINE_NODE_SB(port_group, "port_group", &ctx);
    ENGINE_NODE_SB(multicast_group, "multicast_group", &ctx);
    ENGINE_NODE_SB(datapath_binding, "datapath_binding", &ctx);
    ENGINE_NODE_SB(port_binding, "port_binding", &ctx);
    ENGINE_NODE_SB(mac_binding, "mac_binding", &ctx);
    ENGINE_NODE_SB(logical_flow, "logical_flow", &ctx);
    ENGINE_NODE_SB(dhcp_options, "dhcp_options", &ctx);
    ENGINE_NODE_SB(dhcpv6_options, "dhcpv6_options", &ctx);
    ENGINE_NODE_SB(dns, "dns", &ctx);
    ENGINE_NODE_SB(gateway_chassis, "gateway_chassis", &ctx);

    ENGINE_NODE_OVS(port, "ovs_table_port", &ctx);
    ENGINE_NODE_OVS(interface, "ovs_table_interface", &ctx);

    ENGINE_NODE(addr_sets, "addr_sets", &ctx);
    ENGINE_NODE(runtime_data, "runtime_data", &ctx);
    ENGINE_NODE(flow_output, "flow_output", &ctx);

    engine_add_input(&en_addr_sets, &en_sb_address_set, NULL);

    engine_add_input(&en_flow_output, &en_addr_sets, NULL);
    engine_add_input(&en_flow_output, &en_runtime_data, NULL);

    engine_add_input(&en_flow_output, &en_ovs_port, NULL);
    engine_add_input(&en_flow_output, &en_ovs_interface, NULL);

    engine_add_input(&en_flow_output, &en_sb_chassis, NULL);
    engine_add_input(&en_flow_output, &en_sb_encap, NULL);
    engine_add_input(&en_flow_output, &en_sb_multicast_group, flow_output_sb_multicast_group_handler);
    engine_add_input(&en_flow_output, &en_sb_datapath_binding, NULL);
    engine_add_input(&en_flow_output, &en_sb_port_binding, flow_output_sb_port_binding_handler);
    engine_add_input(&en_flow_output, &en_sb_mac_binding, NULL);
    engine_add_input(&en_flow_output, &en_sb_logical_flow, flow_output_sb_logical_flow_handler);
    engine_add_input(&en_flow_output, &en_sb_dhcp_options, NULL);
    engine_add_input(&en_flow_output, &en_sb_dhcpv6_options, NULL);
    engine_add_input(&en_flow_output, &en_sb_dns, NULL);
    engine_add_input(&en_flow_output, &en_sb_gateway_chassis, NULL);

    engine_add_input(&en_runtime_data, &en_ovs_port, NULL);
    engine_add_input(&en_runtime_data, &en_ovs_interface, NULL);

    engine_add_input(&en_runtime_data, &en_sb_chassis, NULL);
    engine_add_input(&en_runtime_data, &en_sb_port_group, NULL);
    engine_add_input(&en_runtime_data, &en_sb_datapath_binding, NULL);
    engine_add_input(&en_runtime_data, &en_sb_port_binding, runtime_data_sb_port_binding_handler);
    engine_add_input(&en_runtime_data, &en_sb_gateway_chassis, NULL);

    engine_init(&en_flow_output);

    ofctrl_init(&ed_flow_output.group_table,
                &ed_flow_output.meter_table);
    unixctl_command_register("ct-zone-list", "", 0, 0,
                             ct_zone_list, &ed_runtime_data.ct_zones);

    struct pending_pkt pending_pkt = { .conn = NULL };
    unixctl_command_register("inject-pkt", "MICROFLOW", 1, 1, inject_pkt,
                             &pending_pkt);

    uint64_t engine_run_id = 0;
    uint64_t old_engine_run_id = 0;

    /* Main loop. */
    exiting = false;
    while (!exiting) {
        old_engine_run_id = engine_run_id;
        /* Check OVN SB database. */
        char *new_ovnsb_remote = get_ovnsb_remote(ovs_idl_loop.idl);
        if (strcmp(ovnsb_remote, new_ovnsb_remote)) {
            free(ovnsb_remote);
            ovnsb_remote = new_ovnsb_remote;
            ovsdb_idl_set_remote(ovnsb_idl_loop.idl, ovnsb_remote, true);
        } else {
            free(new_ovnsb_remote);
        }

        ctx.ovs_idl = ovs_idl_loop.idl;
        ctx.ovs_idl_txn = ovsdb_idl_loop_run(&ovs_idl_loop);
        ctx.ovnsb_idl = ovnsb_idl_loop.idl;
        ctx.ovnsb_idl_txn = ovsdb_idl_loop_run(&ovnsb_idl_loop);

        update_probe_interval(&ctx, ovnsb_remote);

        update_ssl_config(ctx.ovs_idl);

        const struct ovsrec_bridge *br_int = get_br_int(&ctx);
        if (!br_int) {
            br_int = create_br_int(&ctx);
        }
        const char *chassis_id = get_chassis_id(ctx.ovs_idl);
        const struct sbrec_chassis *chassis
            = chassis_id ? chassis_run(&ctx, chassis_id, br_int) : NULL;

        if (br_int && chassis) {
            ofctrl_run(br_int, &ed_runtime_data.pending_ct_zones);
            patch_run(&ctx, br_int, chassis);
            encaps_run(&ctx, br_int, chassis_id);

            stopwatch_start(CONTROLLER_LOOP_STOPWATCH_NAME,
                            time_msec());
            engine_run(&en_flow_output, ++engine_run_id);
            stopwatch_stop(CONTROLLER_LOOP_STOPWATCH_NAME,
                           time_msec());
            if (ctx.ovs_idl_txn) {
                commit_ct_zones(br_int, &ed_runtime_data.pending_ct_zones);
                bfd_run(&ctx, br_int, chassis,
                        &ed_runtime_data.local_datapaths,
                        &ed_runtime_data.chassis_index);
            }
            ofctrl_put(&ed_flow_output.flow_table,
                       &ed_runtime_data.pending_ct_zones,
                       get_nb_cfg(ctx.ovnsb_idl),
                       en_flow_output.changed);
            pinctrl_run(&ctx, br_int, chassis, &ed_runtime_data.chassis_index,
                        &ed_runtime_data.local_datapaths,
                        &ed_runtime_data.active_tunnels);

            if (en_runtime_data.changed) {
                update_sb_monitors(ctx.ovnsb_idl, chassis,
                                   &ed_runtime_data.local_lports,
                                   &ed_runtime_data.local_datapaths);
            }

        }
        if (old_engine_run_id == engine_run_id) {
            if (engine_need_run(&en_flow_output)) {
                VLOG_DBG("engine did not run, force recompute next time: "
                         "br_int %p, chassis %p", br_int, chassis);
                engine_set_force_recompute(true);
                poll_immediate_wake();
            } else {
                VLOG_DBG("engine did not run, and it was not needed either: "
                         "br_int %p, chassis %p", br_int, chassis);
            }
        } else {
            engine_set_force_recompute(false);
        }

        if (ctx.ovnsb_idl_txn) {
            int64_t cur_cfg = ofctrl_get_cur_cfg();
            if (cur_cfg && cur_cfg != chassis->nb_cfg) {
                sbrec_chassis_set_nb_cfg(chassis, cur_cfg);
            }
        }


        if (pending_pkt.conn) {
            if (br_int && chassis) {
                char *error = ofctrl_inject_pkt(br_int, pending_pkt.flow_s,
                                                &ed_runtime_data.port_groups,
                                                &ed_addr_sets.addr_sets);
                if (error) {
                    unixctl_command_reply_error(pending_pkt.conn, error);
                    free(error);
                } else {
                    unixctl_command_reply(pending_pkt.conn, NULL);
                }
            } else {
                unixctl_command_reply_error(pending_pkt.conn,
                                            "ovn-controller not ready.");
            }
            pending_pkt.conn = NULL;
            free(pending_pkt.flow_s);
        }

        unixctl_server_run(unixctl);

        unixctl_server_wait(unixctl);
        if (exiting || pending_pkt.conn) {
            poll_immediate_wake();
        }

        if (br_int) {
            ofctrl_wait();
            pinctrl_wait(&ctx);
        }

        ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);

        if (ovsdb_idl_loop_commit_and_wait(&ovs_idl_loop) == 1) {
            struct shash_node *iter, *iter_next;
            SHASH_FOR_EACH_SAFE (iter, iter_next,
                                 &ed_runtime_data.pending_ct_zones) {
                struct ct_zone_pending_entry *ctzpe = iter->data;
                if (ctzpe->state == CT_ZONE_DB_SENT) {
                    shash_delete(&ed_runtime_data.pending_ct_zones, iter);
                    free(ctzpe);
                }
            }
        }

        ovsdb_idl_track_clear(ctx.ovnsb_idl);
        ovsdb_idl_track_clear(ctx.ovs_idl);
        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
    }

    engine_cleanup(&en_flow_output);

    /* It's time to exit.  Clean up the databases. */
    bool done = false;
    while (!done) {
        struct controller_ctx ctx_ = {
            .ovs_idl = ovs_idl_loop.idl,
            .ovs_idl_txn = ovsdb_idl_loop_run(&ovs_idl_loop),
            .ovnsb_idl = ovnsb_idl_loop.idl,
            .ovnsb_idl_txn = ovsdb_idl_loop_run(&ovnsb_idl_loop),
        };

        const struct ovsrec_bridge *br_int = get_br_int(&ctx_);
        const char *chassis_id = get_chassis_id(ctx_.ovs_idl);
        const struct sbrec_chassis *chassis
            = chassis_id ? get_chassis(ctx_.ovnsb_idl, chassis_id) : NULL;

        /* Run all of the cleanup functions, even if one of them returns false.
         * We're done if all of them return true. */
        done = binding_cleanup(&ctx_, chassis);
        done = chassis_cleanup(&ctx_, chassis) && done;
        done = encaps_cleanup(&ctx_, br_int) && done;
        if (done) {
            poll_immediate_wake();
        }

        ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);
        ovsdb_idl_loop_commit_and_wait(&ovs_idl_loop);
        poll_block();
    }

    unixctl_server_destroy(unixctl);
    lflow_destroy();
    ofctrl_destroy();
    pinctrl_destroy();

    ovsdb_idl_loop_destroy(&ovs_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);

    free(ovnsb_remote);
    free(ovs_remote);
    service_stop();

    exit(retval);
}

static char *
parse_options(int argc, char *argv[])
{
    enum {
        OPT_PEER_CA_CERT = UCHAR_MAX + 1,
        OPT_BOOTSTRAP_CA_CERT,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };

    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        DAEMON_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        {NULL, 0, NULL, 0}
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(OFP13_VERSION, OFP13_VERSION);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS
        STREAM_SSL_OPTION_HANDLERS

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    char *ovs_remote;
    if (argc == 0) {
        ovs_remote = xasprintf("unix:%s/db.sock", ovs_rundir());
    } else if (argc == 1) {
        ovs_remote = xstrdup(argv[0]);
    } else {
        VLOG_FATAL("exactly zero or one non-option argument required; "
                   "use --help for usage");
    }
    return ovs_remote;
}

static void
usage(void)
{
    printf("%s: OVN controller\n"
           "usage %s [OPTIONS] [OVS-DATABASE]\n"
           "where OVS-DATABASE is a socket on which the OVS OVSDB server is listening.\n",
               program_name, program_name);
    stream_usage("OVS-DATABASE", true, false, true);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}

static void
ovn_controller_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
             const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}

static void
ct_zone_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
             const char *argv[] OVS_UNUSED, void *ct_zones_)
{
    struct simap *ct_zones = ct_zones_;
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct simap_node *zone;

    SIMAP_FOR_EACH(zone, ct_zones) {
        ds_put_format(&ds, "%s %d\n", zone->name, zone->data);
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
inject_pkt(struct unixctl_conn *conn, int argc OVS_UNUSED,
           const char *argv[], void *pending_pkt_)
{
    struct pending_pkt *pending_pkt = pending_pkt_;

    if (pending_pkt->conn) {
        unixctl_command_reply_error(conn, "already pending packet injection");
        return;
    }
    pending_pkt->conn = conn;
    pending_pkt->flow_s = xstrdup(argv[1]);
}

/* Get the desired SB probe timer from the OVS database and configure it into
 * the SB database. */
static void
update_probe_interval(struct controller_ctx *ctx, const char *ovnsb_remote)
{
    const struct ovsrec_open_vswitch *cfg
        = ovsrec_open_vswitch_first(ctx->ovs_idl);
    int interval = -1;
    if (cfg) {
        interval = smap_get_int(&cfg->external_ids,
                                "ovn-remote-probe-interval",
                                -1);
    }
    if (interval == -1) {
        interval = stream_or_pstream_needs_probes(ovnsb_remote)
                   ? DEFAULT_PROBE_INTERVAL_MSEC
                   : 0;
    }

    ovsdb_idl_set_probe_interval(ctx->ovnsb_idl, interval);
}
