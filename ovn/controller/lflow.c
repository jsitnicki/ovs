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
#include "lflow.h"
#include "coverage.h"
#include "gchassis.h"
#include "lport.h"
#include "ofctrl.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovn-controller.h"
#include "ovn/actions.h"
#include "ovn/expr.h"
#include "ovn/lib/ovn-l7.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn/lib/extend-table.h"
#include "packets.h"
#include "physical.h"
#include "simap.h"
#include "sset.h"

VLOG_DEFINE_THIS_MODULE(lflow);

COVERAGE_DEFINE(lflow_run);

/* Symbol table. */

/* Contains "struct expr_symbol"s for fields supported by OVN lflows. */
static struct shash symtab;

void
lflow_init(void)
{
    ovn_init_symtab(&symtab);
}

struct lookup_port_aux {
    struct ovsdb_idl *ovnsb_idl;
    const struct sbrec_datapath_binding *dp;
};

struct condition_aux {
    struct ovsdb_idl *ovnsb_idl;
    const struct sbrec_chassis *chassis;
    const struct sset *active_tunnels;
    const struct chassis_index *chassis_index;
};

static bool consider_logical_flow(struct ovn_desired_flow_table *flow_table,
                                  struct lflow_resource_ref *lfrr,
                                  struct controller_ctx *ctx,
                                  const struct chassis_index *chassis_index,
                                  const struct sbrec_logical_flow *lflow,
                                  const struct hmap *local_datapaths,
                                  struct ovn_extend_table *group_table,
                                  struct ovn_extend_table *meter_table,
                                  const struct sbrec_chassis *chassis,
                                  struct hmap *dhcp_opts,
                                  struct hmap *dhcpv6_opts,
                                  struct hmap *nd_ra_opts,
                                  uint32_t *conj_id_ofs,
                                  const struct shash *addr_sets,
                                  const struct shash *port_groups,
                                  struct sset *active_tunnels,
                                  struct sset *local_lport_ids);

static bool
lookup_port_cb(const void *aux_, const char *port_name, unsigned int *portp)
{
    const struct lookup_port_aux *aux = aux_;

    const struct sbrec_port_binding *pb
        = lport_lookup_by_name(aux->ovnsb_idl, port_name);
    if (pb && pb->datapath == aux->dp) {
        *portp = pb->tunnel_key;
        return true;
    }

    const struct sbrec_multicast_group *mg
        = mcgroup_lookup_by_dp_name(aux->ovnsb_idl, aux->dp, port_name);
    if (mg) {
        *portp = mg->tunnel_key;
        return true;
    }

    return false;
}

static bool
is_chassis_resident_cb(const void *c_aux_, const char *port_name)
{
    const struct condition_aux *c_aux = c_aux_;

    const struct sbrec_port_binding *pb
        = lport_lookup_by_name(c_aux->ovnsb_idl, port_name);
    if (!pb) {
        return false;
    }
    if (strcmp(pb->type, "chassisredirect")) {
        /* for non-chassisredirect ports */
        return pb->chassis && pb->chassis == c_aux->chassis;
    } else {
        struct ovs_list *gateway_chassis;
        gateway_chassis = gateway_chassis_get_ordered(pb,
                                                      c_aux->chassis_index);
        if (gateway_chassis) {
            bool active = gateway_chassis_is_active(gateway_chassis,
                                                    c_aux->chassis,
                                                    c_aux->active_tunnels);
            gateway_chassis_destroy(gateway_chassis);
            return active;
        }
        return false;
    }
}

static bool
is_switch(const struct sbrec_datapath_binding *ldp)
{
    return smap_get(&ldp->external_ids, "logical-switch") != NULL;

}

void
lflow_resource_init(struct lflow_resource_ref *lfrr)
{
    hmap_init(&lfrr->ref_lflow_table);
    hmap_init(&lfrr->lflow_ref_table);
}

void
lflow_resource_destroy(struct lflow_resource_ref *lfrr)
{
    struct ref_lflow_node *rlfn, *rlfn_next;
    HMAP_FOR_EACH_SAFE (rlfn, rlfn_next, node, &lfrr->ref_lflow_table) {
        free(rlfn->ref_name);
        struct lflow_ref_list_node *lrln, *next;
        LIST_FOR_EACH_SAFE (lrln, next, ref_list, &rlfn->ref_lflow_head) {
            ovs_list_remove(&lrln->ref_list);
            ovs_list_remove(&lrln->lflow_list);
            free(lrln);
        }
        hmap_remove(&lfrr->ref_lflow_table, &rlfn->node);
        free(rlfn);
    }
    hmap_destroy(&lfrr->ref_lflow_table);

    struct lflow_ref_node *lfrn, *lfrn_next;
    HMAP_FOR_EACH_SAFE (lfrn, lfrn_next, node, &lfrr->lflow_ref_table) {
        hmap_remove(&lfrr->lflow_ref_table, &lfrn->node);
        free(lfrn);
    }
    hmap_destroy(&lfrr->lflow_ref_table);
}

void
lflow_resource_clear(struct lflow_resource_ref *lfrr)
{
    lflow_resource_destroy(lfrr);
    lflow_resource_init(lfrr);
}

static struct ref_lflow_node*
ref_lflow_lookup(struct hmap *ref_lflow_table,
                 enum ref_type type, const char *ref_name)
{
    struct ref_lflow_node *rlfn;

    HMAP_FOR_EACH_WITH_HASH (rlfn, node, hash_string(ref_name, type),
                             ref_lflow_table) {
        if (rlfn->type == type && !strcmp(rlfn->ref_name, ref_name)) {
            return rlfn;
        }
    }
    return NULL;
}

static struct lflow_ref_node*
lflow_ref_lookup(struct hmap *lflow_ref_table,
                 const struct uuid *lflow_uuid)
{
    struct lflow_ref_node *lfrn;

    HMAP_FOR_EACH_WITH_HASH (lfrn, node, uuid_hash(lflow_uuid),
                             lflow_ref_table) {
        if (uuid_equals(&lfrn->lflow_uuid, lflow_uuid)) {
            return lfrn;
        }
    }
    return NULL;
}

static void
lflow_resource_add(struct lflow_resource_ref *lfrr, enum ref_type type,
                   const char *ref_name, const struct uuid *lflow_uuid)
{
    struct ref_lflow_node *rlfn = ref_lflow_lookup(&lfrr->ref_lflow_table,
                                                   type, ref_name);
    if (!rlfn) {
        rlfn = xzalloc(sizeof *rlfn);
        rlfn->node.hash = hash_string(ref_name, type);
        rlfn->type = type;
        rlfn->ref_name = xstrdup(ref_name);
        ovs_list_init(&rlfn->ref_lflow_head);
        hmap_insert(&lfrr->ref_lflow_table, &rlfn->node, rlfn->node.hash);
    }

    struct lflow_ref_node *lfrn = lflow_ref_lookup(&lfrr->lflow_ref_table,
                                                   lflow_uuid);
    if (!lfrn) {
        lfrn = xzalloc(sizeof *lfrn);
        lfrn->node.hash = uuid_hash(lflow_uuid);
        lfrn->lflow_uuid = *lflow_uuid;
        ovs_list_init(&lfrn->lflow_ref_head);
        hmap_insert(&lfrr->lflow_ref_table, &lfrn->node, lfrn->node.hash);
    }

    struct lflow_ref_list_node *lrln = xzalloc(sizeof *lrln);
    lrln->type = type;
    lrln->ref_name = xstrdup(ref_name);
    lrln->lflow_uuid = *lflow_uuid;
    ovs_list_push_back(&rlfn->ref_lflow_head, &lrln->ref_list);
    ovs_list_push_back(&lfrn->lflow_ref_head, &lrln->lflow_list);
}

static void
lflow_resource_destroy_lflow(struct lflow_resource_ref *lfrr,
                            const struct uuid *lflow_uuid)
{
    struct lflow_ref_node *lfrn = lflow_ref_lookup(&lfrr->lflow_ref_table,
                                                   lflow_uuid);
    if (!lfrn) {
        return;
    }

    hmap_remove(&lfrr->lflow_ref_table, &lfrn->node);
    struct lflow_ref_list_node *lrln, *next;
    LIST_FOR_EACH_SAFE (lrln, next, lflow_list, &lfrn->lflow_ref_head) {
        ovs_list_remove(&lrln->ref_list);
        ovs_list_remove(&lrln->lflow_list);
        free(lrln);
    }
    free(lfrn);
}

/* Adds the logical flows from the Logical_Flow table to flow tables. */
static void
add_logical_flows(struct ovn_desired_flow_table *flow_table,
                  struct lflow_resource_ref *lfrr,
                  struct controller_ctx *ctx,
                  const struct chassis_index *chassis_index,
                  const struct hmap *local_datapaths,
                  struct ovn_extend_table *group_table,
                  struct ovn_extend_table *meter_table,
                  const struct sbrec_chassis *chassis,
                  const struct shash *addr_sets,
                  const struct shash *port_groups,
                  struct sset *active_tunnels,
                  struct sset *local_lport_ids,
                  uint32_t *conj_id_ofs)
{
    const struct sbrec_logical_flow *lflow;

    struct hmap dhcp_opts = HMAP_INITIALIZER(&dhcp_opts);
    struct hmap dhcpv6_opts = HMAP_INITIALIZER(&dhcpv6_opts);
    const struct sbrec_dhcp_options *dhcp_opt_row;
    SBREC_DHCP_OPTIONS_FOR_EACH(dhcp_opt_row, ctx->ovnsb_idl) {
        dhcp_opt_add(&dhcp_opts, dhcp_opt_row->name, dhcp_opt_row->code,
                     dhcp_opt_row->type);
    }


    const struct sbrec_dhcpv6_options *dhcpv6_opt_row;
    SBREC_DHCPV6_OPTIONS_FOR_EACH(dhcpv6_opt_row, ctx->ovnsb_idl) {
       dhcp_opt_add(&dhcpv6_opts, dhcpv6_opt_row->name, dhcpv6_opt_row->code,
                    dhcpv6_opt_row->type);
    }

    struct hmap nd_ra_opts = HMAP_INITIALIZER(&nd_ra_opts);
    nd_ra_opts_init(&nd_ra_opts);

    SBREC_LOGICAL_FLOW_FOR_EACH (lflow, ctx->ovnsb_idl) {
        if (!consider_logical_flow(flow_table, lfrr, ctx, chassis_index,
                                   lflow, local_datapaths,
                                   group_table, meter_table, chassis,
                                   &dhcp_opts, &dhcpv6_opts, &nd_ra_opts,
                                   conj_id_ofs, addr_sets, port_groups,
                                   active_tunnels, local_lport_ids)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
            VLOG_ERR_RL(&rl, "Conjunction id overflow when processing lflow "
                        UUID_FMT, UUID_ARGS(&lflow->header_.uuid));
        }
    }

    dhcp_opts_destroy(&dhcp_opts);
    dhcp_opts_destroy(&dhcpv6_opts);
    nd_ra_opts_destroy(&nd_ra_opts);
}

bool
lflow_handle_changed_flows(struct ovn_desired_flow_table *flow_table,
                           struct lflow_resource_ref *lfrr,
                           struct controller_ctx *ctx,
                           const struct sbrec_chassis *chassis,
                           const struct chassis_index *chassis_index,
                           const struct hmap *local_datapaths,
                           struct ovn_extend_table *group_table,
                           struct ovn_extend_table *meter_table,
                           const struct shash *addr_sets,
                           const struct shash *port_groups,
                           struct sset *active_tunnels,
                           struct sset *local_lport_ids,
                           uint32_t *conj_id_ofs)
{
    bool ret = true;
    const struct sbrec_logical_flow *lflow;

    struct hmap dhcp_opts = HMAP_INITIALIZER(&dhcp_opts);
    struct hmap dhcpv6_opts = HMAP_INITIALIZER(&dhcpv6_opts);
    const struct sbrec_dhcp_options *dhcp_opt_row;
    SBREC_DHCP_OPTIONS_FOR_EACH (dhcp_opt_row, ctx->ovnsb_idl) {
        dhcp_opt_add(&dhcp_opts, dhcp_opt_row->name, dhcp_opt_row->code,
                     dhcp_opt_row->type);
    }


    const struct sbrec_dhcpv6_options *dhcpv6_opt_row;
    SBREC_DHCPV6_OPTIONS_FOR_EACH(dhcpv6_opt_row, ctx->ovnsb_idl) {
       dhcp_opt_add(&dhcpv6_opts, dhcpv6_opt_row->name, dhcpv6_opt_row->code,
                    dhcpv6_opt_row->type);
    }

    struct hmap nd_ra_opts = HMAP_INITIALIZER(&nd_ra_opts);
    nd_ra_opts_init(&nd_ra_opts);

    /* Handle removed flows first, and then other flows, so that when
     * the flows being added and removed have same match conditions
     * can be processed in the proper order */
    SBREC_LOGICAL_FLOW_FOR_EACH_TRACKED (lflow, ctx->ovnsb_idl) {
        /* Remove any flows that should be removed. */
        if (sbrec_logical_flow_is_deleted(lflow)) {
            VLOG_DBG("handle deleted lflow "UUID_FMT,
                     UUID_ARGS(&lflow->header_.uuid));
            ofctrl_remove_flows(flow_table, &lflow->header_.uuid);
            /* Delete entries from lflow resource reference. */
            lflow_resource_destroy_lflow(lfrr, &lflow->header_.uuid);
        }
    }
    SBREC_LOGICAL_FLOW_FOR_EACH_TRACKED (lflow, ctx->ovnsb_idl) {
        if (!sbrec_logical_flow_is_deleted(lflow)) {
            /* Now, add/modify existing flows. If the logical
             * flow is a modification, just remove the flows
             * for this row, and then add new flows. */
            if (!sbrec_logical_flow_is_new(lflow)) {
                VLOG_DBG("handle updated lflow "UUID_FMT,
                         UUID_ARGS(&lflow->header_.uuid));
                ofctrl_remove_flows(flow_table, &lflow->header_.uuid);
                /* Delete entries from lflow resource reference. */
                lflow_resource_destroy_lflow(lfrr, &lflow->header_.uuid);
            }
            VLOG_DBG("handle new lflow "UUID_FMT,
                     UUID_ARGS(&lflow->header_.uuid));
            if (!consider_logical_flow(flow_table, lfrr, ctx, chassis_index,
                                       lflow, local_datapaths,
                                       group_table, meter_table, chassis,
                                       &dhcp_opts, &dhcpv6_opts, &nd_ra_opts,
                                       conj_id_ofs, addr_sets, port_groups,
                                       active_tunnels, local_lport_ids)) {
                ret = false;
                break;
            }
        }
    }
    dhcp_opts_destroy(&dhcp_opts);
    dhcp_opts_destroy(&dhcpv6_opts);
    nd_ra_opts_destroy(&nd_ra_opts);
    return ret;
}

static bool
update_conj_id_ofs(uint32_t *conj_id_ofs, uint32_t n_conjs)
{
    if (*conj_id_ofs + n_conjs < *conj_id_ofs) {
        /* overflow */
        return false;
    }
    *conj_id_ofs += n_conjs;
    return true;
}

static bool
consider_logical_flow(struct ovn_desired_flow_table *flow_table,
                      struct lflow_resource_ref *lfrr,
                      struct controller_ctx *ctx,
                      const struct chassis_index *chassis_index,
                      const struct sbrec_logical_flow *lflow,
                      const struct hmap *local_datapaths,
                      struct ovn_extend_table *group_table,
                      struct ovn_extend_table *meter_table,
                      const struct sbrec_chassis *chassis,
                      struct hmap *dhcp_opts,
                      struct hmap *dhcpv6_opts,
                      struct hmap *nd_ra_opts,
                      uint32_t *conj_id_ofs,
                      const struct shash *addr_sets,
                      const struct shash *port_groups,
                      struct sset *active_tunnels,
                      struct sset *local_lport_ids)
{
    /* Determine translation of logical table IDs to physical table IDs. */
    bool ingress = !strcmp(lflow->pipeline, "ingress");

    const struct sbrec_datapath_binding *ldp = lflow->logical_datapath;
    if (!ldp) {
        VLOG_DBG("lflow "UUID_FMT" has no datapath binding, skip",
                 UUID_ARGS(&lflow->header_.uuid));
        return true;
    }
    if (!get_local_datapath(local_datapaths, ldp->tunnel_key)) {
        VLOG_DBG("lflow "UUID_FMT" is not for local datapath, skip",
                 UUID_ARGS(&lflow->header_.uuid));
        return true;
    }

    /* Determine translation of logical table IDs to physical table IDs. */
    uint8_t first_ptable = (ingress
                            ? OFTABLE_LOG_INGRESS_PIPELINE
                            : OFTABLE_LOG_EGRESS_PIPELINE);
    uint8_t ptable = first_ptable + lflow->table_id;
    uint8_t output_ptable = (ingress
                             ? OFTABLE_REMOTE_OUTPUT
                             : OFTABLE_SAVE_INPORT);

    /* Parse OVN logical actions.
     *
     * XXX Deny changes to 'outport' in egress pipeline. */
    uint64_t ovnacts_stub[1024 / 8];
    struct ofpbuf ovnacts = OFPBUF_STUB_INITIALIZER(ovnacts_stub);
    struct ovnact_parse_params pp = {
        .symtab = &symtab,
        .dhcp_opts = dhcp_opts,
        .dhcpv6_opts = dhcpv6_opts,
        .nd_ra_opts = nd_ra_opts,

        .pipeline = ingress ? OVNACT_P_INGRESS : OVNACT_P_EGRESS,
        .n_tables = LOG_PIPELINE_LEN,
        .cur_ltable = lflow->table_id,
    };
    struct expr *prereqs;
    char *error;

    error = ovnacts_parse_string(lflow->actions, &pp, &ovnacts, &prereqs);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "error parsing actions \"%s\": %s",
                     lflow->actions, error);
        free(error);
        ovnacts_free(ovnacts.data, ovnacts.size);
        ofpbuf_uninit(&ovnacts);
        return true;
    }

    /* Translate OVN match into table of OpenFlow matches. */
    struct hmap matches;
    struct expr *expr;

    struct sset addr_sets_ref = SSET_INITIALIZER(&addr_sets_ref);
    expr = expr_parse_string(lflow->match, &symtab, addr_sets, port_groups,
                             &addr_sets_ref, &error);
    const char *addr_set_name;
    SSET_FOR_EACH (addr_set_name, &addr_sets_ref) {
        lflow_resource_add(lfrr, REF_TYPE_ADDRSET, addr_set_name,
                           &lflow->header_.uuid);
    }
    sset_destroy(&addr_sets_ref);

    if (!error) {
        if (prereqs) {
            expr = expr_combine(EXPR_T_AND, expr, prereqs);
            prereqs = NULL;
        }
        expr = expr_annotate(expr, &symtab, &error);
    }
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "error parsing match \"%s\": %s",
                     lflow->match, error);
        expr_destroy(prereqs);
        free(error);
        ovnacts_free(ovnacts.data, ovnacts.size);
        ofpbuf_uninit(&ovnacts);
        return true;
    }

    struct lookup_port_aux aux = {
        .ovnsb_idl = ctx->ovnsb_idl,
        .dp = lflow->logical_datapath
    };
    struct condition_aux cond_aux = { ctx->ovnsb_idl, chassis, active_tunnels,
                                      chassis_index};
    expr = expr_simplify(expr, is_chassis_resident_cb, &cond_aux);
    expr = expr_normalize(expr);
    uint32_t n_conjs = expr_to_matches(expr, lookup_port_cb, &aux,
                                       &matches);
    expr_destroy(expr);

    if (hmap_is_empty(&matches)) {
        VLOG_DBG("lflow "UUID_FMT" matches are empty, skip",
                 UUID_ARGS(&lflow->header_.uuid));
        ovnacts_free(ovnacts.data, ovnacts.size);
        ofpbuf_uninit(&ovnacts);
        expr_matches_destroy(&matches);
        return true;
    }

    /* Encode OVN logical actions into OpenFlow. */
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    struct ovnact_encode_params ep = {
        .lookup_port = lookup_port_cb,
        .aux = &aux,
        .is_switch = is_switch(ldp),
        .group_table = group_table,
        .meter_table = meter_table,
        .lflow_uuid = lflow->header_.uuid,

        .pipeline = ingress ? OVNACT_P_INGRESS : OVNACT_P_EGRESS,
        .ingress_ptable = OFTABLE_LOG_INGRESS_PIPELINE,
        .egress_ptable = OFTABLE_LOG_EGRESS_PIPELINE,
        .output_ptable = output_ptable,
        .mac_bind_ptable = OFTABLE_MAC_BINDING,
    };
    ovnacts_encode(ovnacts.data, ovnacts.size, &ep, &ofpacts);
    ovnacts_free(ovnacts.data, ovnacts.size);
    ofpbuf_uninit(&ovnacts);

    /* Prepare the OpenFlow matches for adding to the flow table. */
    struct expr_match *m;
    HMAP_FOR_EACH (m, hmap_node, &matches) {
        match_set_metadata(&m->match,
                           htonll(lflow->logical_datapath->tunnel_key));
        if (m->match.wc.masks.conj_id) {
            m->match.flow.conj_id += *conj_id_ofs;
        }
        if (is_switch(ldp)) {
            unsigned int reg_index
                = (ingress ? MFF_LOG_INPORT : MFF_LOG_OUTPORT) - MFF_REG0;
            int64_t port_id = m->match.flow.regs[reg_index];
            if (port_id) {
                int64_t dp_id = lflow->logical_datapath->tunnel_key;
                char buf[16];
                snprintf(buf, sizeof(buf), "%"PRId64"_%"PRId64, dp_id, port_id);
                if (!sset_contains(local_lport_ids, buf)) {
                    VLOG_DBG("lflow "UUID_FMT
                             " port %s in match is not local, skip",
                             UUID_ARGS(&lflow->header_.uuid),
                             buf);
                    continue;
                }
            }
        }
        if (!m->n) {
            ofctrl_add_flow(flow_table, ptable, lflow->priority,
                            lflow->header_.uuid.parts[0], &m->match, &ofpacts,
                            &lflow->header_.uuid);
        } else {
            uint64_t conj_stubs[64 / 8];
            struct ofpbuf conj;

            ofpbuf_use_stub(&conj, conj_stubs, sizeof conj_stubs);
            for (int i = 0; i < m->n; i++) {
                const struct cls_conjunction *src = &m->conjunctions[i];
                struct ofpact_conjunction *dst;

                dst = ofpact_put_CONJUNCTION(&conj);
                dst->id = src->id + *conj_id_ofs;
                dst->clause = src->clause;
                dst->n_clauses = src->n_clauses;
            }
            ofctrl_add_flow(flow_table, ptable, lflow->priority, 0, &m->match,
                            &conj, &lflow->header_.uuid);
            ofpbuf_uninit(&conj);
        }
    }

    /* Clean up. */
    expr_matches_destroy(&matches);
    ofpbuf_uninit(&ofpacts);
    return update_conj_id_ofs(conj_id_ofs, n_conjs);
}

static void
put_load(const uint8_t *data, size_t len,
         enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts,
                                                       mf_from_id(dst), NULL,
                                                       NULL);
    bitwise_copy(data, len, 0, sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(ofpact_set_field_mask(sf), sf->field->n_bytes, ofs, n_bits);
}

static void
consider_neighbor_flow(struct ovn_desired_flow_table *flow_table,
                       struct controller_ctx *ctx,
                       const struct sbrec_mac_binding *b)
{
    const struct sbrec_port_binding *pb
        = lport_lookup_by_name(ctx->ovnsb_idl, b->logical_port);
    if (!pb) {
        return;
    }

    struct eth_addr mac;
    if (!eth_addr_from_string(b->mac, &mac)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad 'mac' %s", b->mac);
        return;
    }

    struct match match = MATCH_CATCHALL_INITIALIZER;
    if (strchr(b->ip, '.')) {
        ovs_be32 ip;
        if (!ip_parse(b->ip, &ip)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad 'ip' %s", b->ip);
            return;
        }
        match_set_reg(&match, 0, ntohl(ip));
    } else {
        struct in6_addr ip6;
        if (!ipv6_parse(b->ip, &ip6)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad 'ip' %s", b->ip);
            return;
        }
        ovs_be128 value;
        memcpy(&value, &ip6, sizeof(value));
        match_set_xxreg(&match, 0, ntoh128(value));
    }

    match_set_metadata(&match, htonll(pb->datapath->tunnel_key));
    match_set_reg(&match, MFF_LOG_OUTPORT - MFF_REG0, pb->tunnel_key);

    uint64_t stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);
    put_load(mac.ea, sizeof mac.ea, MFF_ETH_DST, 0, 48, &ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_MAC_BINDING, 100, 0, &match, &ofpacts,
                    &b->header_.uuid);
    ofpbuf_uninit(&ofpacts);
}

/* Adds an OpenFlow flow to flow tables for each MAC binding in the OVN
 * southbound database. */
static void
add_neighbor_flows(struct ovn_desired_flow_table *flow_table,
                   struct controller_ctx *ctx)
{
    const struct sbrec_mac_binding *b;
    SBREC_MAC_BINDING_FOR_EACH (b, ctx->ovnsb_idl) {
        consider_neighbor_flow(flow_table, ctx, b);
    }
}

/* Translates logical flows in the Logical_Flow table in the OVN_SB database
 * into OpenFlow flows.  See ovn-architecture(7) for more information. */
void
lflow_run(struct ovn_desired_flow_table *flow_table,
          struct lflow_resource_ref *lfrr,
          struct controller_ctx *ctx,
          const struct sbrec_chassis *chassis,
          const struct chassis_index *chassis_index,
          const struct hmap *local_datapaths,
          struct ovn_extend_table *group_table,
          struct ovn_extend_table *meter_table,
          const struct shash *addr_sets,
          const struct shash *port_groups,
          struct sset *active_tunnels,
          struct sset *local_lport_ids,
          uint32_t *conj_id_ofs)
{
    COVERAGE_INC(lflow_run);

    add_logical_flows(flow_table, lfrr, ctx, chassis_index, local_datapaths,
                      group_table, meter_table, chassis, addr_sets,
                      port_groups, active_tunnels, local_lport_ids,
                      conj_id_ofs);
    add_neighbor_flows(flow_table, ctx);
}

void
lflow_destroy(void)
{
    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
}
