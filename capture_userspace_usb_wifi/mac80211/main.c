/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* hw allocation and registration, monitor bring-up, channel contexts and the mac80211
 * calls a monitor-only driver makes.  Station, TX, scan and power-save paths are inert:
 * no station or data interface ever exists. */

#include "local.h"

static pthread_mutex_t kc_locals_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t kc_locals_cond = PTHREAD_COND_INITIALIZER;
static LIST_HEAD(kc_locals);
static int kc_phy_idx;

struct ieee80211_hw *ieee80211_alloc_hw_nm(size_t priv_data_len, const struct ieee80211_ops *ops,
        const char *requested_name) {
    struct ieee80211_local *local;
    struct wiphy *wiphy;
    size_t priv_size = ALIGN(sizeof(*local), NETDEV_ALIGN) + priv_data_len;
    char name[32];

    if ((wiphy = calloc(1, sizeof(*wiphy) + priv_size)) == NULL)
        return NULL;

    pthread_mutex_lock(&kc_locals_lock);
    snprintf(name, sizeof(name), "%s", requested_name ? requested_name : "");
    if (name[0] == 0)
        snprintf(name, sizeof(name), "phy%d", kc_phy_idx);
    kc_phy_idx++;
    pthread_mutex_unlock(&kc_locals_lock);

    kc_device_init(&wiphy->dev, NULL, name);
    mutex_init(&wiphy->mtx);
    wiphy->retry_short = 7;
    wiphy->retry_long = 4;

    local = wiphy_priv(wiphy);
    local->ops = ops;
    local->hw.wiphy = wiphy;
    local->hw.priv = (char *) local + ALIGN(sizeof(*local), NETDEV_ALIGN);
    local->hw.queues = 1;
    local->hw.max_rates = 1;
    local->hw.max_rx_aggregation_subframes = IEEE80211_MAX_AMPDU_BUF_HT;
    local->hw.max_tx_aggregation_subframes = IEEE80211_MAX_AMPDU_BUF_HT;
    local->hw.offchannel_tx_hw_queue = IEEE80211_INVAL_HW_QUEUE;
    local->hw.conf.long_frame_max_tx_count = wiphy->retry_long;
    local->hw.conf.short_frame_max_tx_count = wiphy->retry_short;
    local->hw.radiotap_mcs_details = IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_GI |
        IEEE80211_RADIOTAP_MCS_HAVE_BW;
    local->hw.radiotap_vht_details = IEEE80211_RADIOTAP_VHT_KNOWN_GI |
        IEEE80211_RADIOTAP_VHT_KNOWN_BANDWIDTH;
    local->hw.uapsd_queues = IEEE80211_DEFAULT_UAPSD_QUEUES;
    local->hw.uapsd_max_sp_len = IEEE80211_DEFAULT_MAX_SP_LEN;
    local->hw.max_mtu = IEEE80211_MAX_DATA_LEN;
    local->hw.radiotap_timestamp.units_pos = -1;
    local->hw.radiotap_timestamp.accuracy = -1;
    snprintf(local->alpha2, sizeof(local->alpha2), "00");

    local->emulate_chanctx = ops->add_chanctx == ieee80211_emulate_add_chanctx;

    if ((local->workqueue = alloc_ordered_workqueue("%s", 0, name)) == NULL) {
        free(wiphy);
        return NULL;
    }

    INIT_LIST_HEAD(&local->list);
    return &local->hw;
}

void ieee80211_free_hw(struct ieee80211_hw *hw) {
    struct ieee80211_local *local = hw_to_local(hw);
    struct wiphy *wiphy = hw->wiphy;

    destroy_workqueue(local->workqueue);
    kc_device_release(&wiphy->dev);
    free(wiphy);
}

struct ieee80211_hw *wiphy_to_ieee80211_hw(struct wiphy *wiphy) {
    struct ieee80211_local *local = wiphy_priv(wiphy);
    return &local->hw;
}

/* The first enabled channel of the first band is the default, as in mac80211 */
static void kc_default_chandef(struct ieee80211_local *local) {
    struct wiphy *wiphy = local->hw.wiphy;

    for (int b = 0; b < NUM_NL80211_BANDS; b++) {
        struct ieee80211_supported_band *sband = wiphy->bands[b];

        if (sband == NULL)
            continue;

        for (int c = 0; c < sband->n_channels; c++) {
            if (sband->channels[c].flags & IEEE80211_CHAN_DISABLED)
                continue;
            cfg80211_chandef_create(&local->default_chandef, &sband->channels[c], NL80211_CHAN_NO_HT);
            return;
        }
    }
}

static void kc_reg_notify(struct ieee80211_local *local) {
    struct wiphy *wiphy = local->hw.wiphy;
    struct regulatory_request req;

    if (wiphy->reg_notifier == NULL)
        return;

    memset(&req, 0, sizeof(req));
    req.initiator = NL80211_REGDOM_SET_BY_USER;
    req.user_reg_hint_type = NL80211_USER_REG_HINT_USER;
    memcpy(req.alpha2, local->alpha2, sizeof(req.alpha2));
    req.dfs_region = NL80211_DFS_UNSET;

    wiphy->reg_notifier(wiphy, &req);
}

int ieee80211_register_hw(struct ieee80211_hw *hw) {
    struct ieee80211_local *local = hw_to_local(hw);

    for (int b = 0; b < NUM_NL80211_BANDS; b++) {
        struct ieee80211_supported_band *sband = hw->wiphy->bands[b];
        if (sband == NULL)
            continue;
        sband->band = b;
        for (int c = 0; c < sband->n_channels; c++)
            sband->channels[c].band = b;
    }

    kc_default_chandef(local);
    hw->conf.chandef = local->default_chandef;
    hw->wiphy->registered = true;

    pthread_mutex_lock(&kc_locals_lock);
    local->registered = true;
    list_add_tail(&local->list, &kc_locals);
    pthread_cond_broadcast(&kc_locals_cond);
    pthread_mutex_unlock(&kc_locals_lock);

    dev_info(&hw->wiphy->dev, "registered %s", dev_name(hw->wiphy->dev.parent));
    return 0;
}

void ieee80211_unregister_hw(struct ieee80211_hw *hw) {
    struct ieee80211_local *local = hw_to_local(hw);

    kc_mac80211_stop(hw);

    pthread_mutex_lock(&kc_locals_lock);
    if (local->registered)
        list_del_init(&local->list);
    local->registered = false;
    pthread_mutex_unlock(&kc_locals_lock);

    flush_workqueue(local->workqueue);
}

struct ieee80211_hw *kc_mac80211_wait_hw(struct device *parent, unsigned int timeout_ms) {
    u64 deadline = kc_jiffies_now() + timeout_ms;
    struct ieee80211_hw *hw = NULL;

    pthread_mutex_lock(&kc_locals_lock);
    for (;;) {
        struct ieee80211_local *local;

        list_for_each_entry(local, &kc_locals, list) {
            if (local->hw.wiphy->dev.parent == parent) {
                hw = &local->hw;
                break;
            }
        }

        long rem = __kc_jiffies_remaining(deadline);
        if (hw != NULL || rem <= 0)
            break;
        __kc_cond_timedwait_ms(&kc_locals_cond, &kc_locals_lock, rem);
    }
    pthread_mutex_unlock(&kc_locals_lock);

    return hw;
}

int kc_mac80211_set_regdomain(struct ieee80211_hw *hw, const char *alpha2) {
    struct ieee80211_local *local = hw_to_local(hw);

    if (alpha2 == NULL || strlen(alpha2) != 2)
        return -EINVAL;

    memcpy(local->alpha2, alpha2, 2);
    local->alpha2[2] = 0;
    kc_reg_notify(local);
    return 0;
}

/* Work queued by the driver runs on the hw's ordered workqueue */
void ieee80211_queue_work(struct ieee80211_hw *hw, struct work_struct *work) {
    queue_work(hw_to_local(hw)->workqueue, work);
}

void ieee80211_queue_delayed_work(struct ieee80211_hw *hw, struct delayed_work *dwork, unsigned long delay) {
    queue_delayed_work(hw_to_local(hw)->workqueue, dwork, delay);
}

void ieee80211_iterate_interfaces(struct ieee80211_hw *hw, u32 iter_flags,
        void (*iterator)(void *data, u8 *mac, struct ieee80211_vif *vif), void *data) {
    struct ieee80211_vif *vif = hw_to_local(hw)->monitor_vif;
    (void) iter_flags;

    if (vif)
        iterator(data, vif->addr, vif);
}

void ieee80211_iterate_active_interfaces_atomic(struct ieee80211_hw *hw, u32 iter_flags,
        void (*iterator)(void *data, u8 *mac, struct ieee80211_vif *vif), void *data) {
    ieee80211_iterate_interfaces(hw, iter_flags, iterator, data);
}

void ieee80211_iterate_stations_atomic(struct ieee80211_hw *hw,
        void (*iterator)(void *data, struct ieee80211_sta *sta), void *data) {
    (void) hw; (void) iterator; (void) data;
}

/* Channel contexts emulated through config(), as mac80211's _ieee80211_hw_conf_chan */
static int kc_hw_conf_chan(struct ieee80211_local *local, struct ieee80211_chanctx_conf *ctx) {
    const struct cfg80211_chan_def *def = ctx ? &ctx->def : &local->default_chandef;

    if (!local->open_count)
        return 0;

    if (cfg80211_chandef_identical(&local->hw.conf.chandef, def))
        return 0;

    local->hw.conf.chandef = *def;
    return local->ops->config(&local->hw, -1, IEEE80211_CONF_CHANGE_CHANNEL);
}

int ieee80211_emulate_add_chanctx(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx) {
    hw->conf.radar_enabled = ctx->radar_enabled;
    return kc_hw_conf_chan(hw_to_local(hw), ctx);
}

void ieee80211_emulate_remove_chanctx(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx) {
    (void) ctx;
    hw->conf.radar_enabled = false;
    kc_hw_conf_chan(hw_to_local(hw), NULL);
}

void ieee80211_emulate_change_chanctx(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx,
        u32 changed) {
    (void) changed;
    hw->conf.radar_enabled = ctx->radar_enabled;
    kc_hw_conf_chan(hw_to_local(hw), ctx);
}

int ieee80211_emulate_switch_vif_chanctx(struct ieee80211_hw *hw, struct ieee80211_vif_chanctx_switch *vifs,
        int n_vifs, enum ieee80211_chanctx_switch_mode mode) {
    (void) mode;
    if (n_vifs <= 0)
        return -EINVAL;
    hw->conf.radar_enabled = vifs[0].new_ctx->radar_enabled;
    return kc_hw_conf_chan(hw_to_local(hw), vifs[0].new_ctx);
}

/* Monitor interface bring-up, in the order mac80211's ieee80211_do_open() uses */
int kc_mac80211_start_monitor(struct ieee80211_hw *hw, kc_mac80211_rx_cb_t cb, void *ctx) {
    struct ieee80211_local *local = hw_to_local(hw);
    struct ieee80211_vif *vif;
    struct ieee80211_chanctx_conf *chanctx;
    unsigned int total_flags;
    int r;

    guard(mutex)(&hw->wiphy->mtx);

    if (local->started)
        return -EBUSY;

    local->rx_cb = cb;
    local->rx_ctx = ctx;

    if ((r = local->ops->start(hw)) < 0) {
        dev_err(&hw->wiphy->dev, "driver start failed: %d", r);
        return r;
    }

    local->started = true;
    local->open_count = 1;

    /* ieee80211_hw_conf_init() */
    u32 changed = ~(IEEE80211_CONF_CHANGE_CHANNEL | IEEE80211_CONF_CHANGE_POWER |
            IEEE80211_CONF_CHANGE_SMPS);
    if (local->emulate_chanctx) {
        hw->conf.chandef = local->default_chandef;
        changed |= IEEE80211_CONF_CHANGE_CHANNEL;
    }
    if ((r = local->ops->config(hw, -1, changed)) < 0)
        dev_warn(&hw->wiphy->dev, "initial config failed: %d", r);

    /* ieee80211_add_virtual_monitor() */
    if ((vif = calloc(1, sizeof(*vif) + (size_t) hw->vif_data_size)) == NULL)
        return -ENOMEM;

    vif->type = NL80211_IFTYPE_MONITOR;
    memcpy(vif->addr, hw->wiphy->perm_addr, ETH_ALEN);
    vif->addr_valid = true;
    vif->bss_conf.vif = vif;
    rcu_assign_pointer(vif->link_conf[0], &vif->bss_conf);
    for (int ac = 0; ac < IEEE80211_NUM_ACS; ac++)
        vif->hw_queue[ac] = (u8) ac;
    vif->cab_queue = IEEE80211_INVAL_HW_QUEUE;

    if ((vif->txq = calloc(1, sizeof(*vif->txq) + (size_t) hw->txq_data_size)) == NULL) {
        free(vif);
        return -ENOMEM;
    }
    vif->txq->vif = vif;
    vif->txq->tid = IEEE80211_NUM_TIDS;
    vif->txq->ac = IEEE80211_AC_BE;

    if ((r = local->ops->add_interface(hw, vif)) < 0) {
        dev_err(&hw->wiphy->dev, "add monitor interface failed: %d", r);
        free(vif->txq);
        free(vif);
        return r;
    }
    local->monitor_vif = vif;

    /* ieee80211_link_use_channel() */
    if ((chanctx = calloc(1, sizeof(*chanctx) + (size_t) hw->chanctx_data_size)) == NULL)
        return -ENOMEM;

    chanctx->def = local->default_chandef;
    chanctx->min_def = local->default_chandef;
    chanctx->rx_chains_static = 1;
    chanctx->rx_chains_dynamic = 1;
    chanctx->radio_idx = -1;
    vif->bss_conf.chanreq.oper = local->default_chandef;

    if (local->ops->add_chanctx && (r = local->ops->add_chanctx(hw, chanctx)) < 0) {
        dev_err(&hw->wiphy->dev, "add channel context failed: %d", r);
        free(chanctx);
        return r;
    }
    local->chanctx = chanctx;

    if (local->ops->assign_vif_chanctx &&
            (r = local->ops->assign_vif_chanctx(hw, vif, &vif->bss_conf, chanctx)) < 0) {
        dev_err(&hw->wiphy->dev, "assign channel context failed: %d", r);
        return r;
    }
    rcu_assign_pointer(vif->bss_conf.chanctx_conf, chanctx);

    /* ieee80211_configure_filter() for a monitor interface */
    total_flags = FIF_ALLMULTI | FIF_FCSFAIL | FIF_PLCPFAIL | FIF_CONTROL | FIF_OTHER_BSS |
        FIF_PSPOLL | FIF_PROBE_REQ | FIF_BCN_PRBRESP_PROMISC;
    local->ops->configure_filter(hw, total_flags, &total_flags, 0);

    hw->conf.flags |= IEEE80211_CONF_MONITOR;
    if ((r = local->ops->config(hw, -1, IEEE80211_CONF_CHANGE_MONITOR)) < 0)
        dev_warn(&hw->wiphy->dev, "monitor config failed: %d", r);

    return 0;
}

int kc_mac80211_set_chandef(struct ieee80211_hw *hw, const struct cfg80211_chan_def *def) {
    struct ieee80211_local *local = hw_to_local(hw);
    struct ieee80211_chanctx_conf *ctx = local->chanctx;
    u32 changed = 0;

    guard(mutex)(&hw->wiphy->mtx);

    if (ctx == NULL || local->monitor_vif == NULL)
        return -ENODEV;

    if (def->chan != ctx->def.chan)
        changed |= IEEE80211_CHANCTX_CHANGE_CHANNEL;
    if (def->width != ctx->def.width || def->center_freq1 != ctx->def.center_freq1 ||
            def->center_freq2 != ctx->def.center_freq2)
        changed |= IEEE80211_CHANCTX_CHANGE_WIDTH;

    if (!changed)
        return 0;

    ctx->def = *def;
    ctx->min_def = *def;
    local->monitor_vif->bss_conf.chanreq.oper = *def;

    if (local->ops->change_chanctx)
        local->ops->change_chanctx(hw, ctx, changed | IEEE80211_CHANCTX_CHANGE_MIN_DEF);

    return 0;
}

void kc_mac80211_stop(struct ieee80211_hw *hw) {
    struct ieee80211_local *local = hw_to_local(hw);
    struct ieee80211_vif *vif = local->monitor_vif;

    guard(mutex)(&hw->wiphy->mtx);

    if (!local->started)
        return;

    if (vif) {
        if (local->chanctx) {
            if (local->ops->unassign_vif_chanctx)
                local->ops->unassign_vif_chanctx(hw, vif, &vif->bss_conf, local->chanctx);
            rcu_assign_pointer(vif->bss_conf.chanctx_conf, NULL);
            if (local->ops->remove_chanctx)
                local->ops->remove_chanctx(hw, local->chanctx);
            free(local->chanctx);
            local->chanctx = NULL;
        }

        local->ops->remove_interface(hw, vif);
        local->monitor_vif = NULL;
        synchronize_rcu();
        free(vif->txq);
        free(vif);
    }

    hw->conf.flags &= ~IEEE80211_CONF_MONITOR;
    local->ops->stop(hw, false);
    local->started = false;
    local->open_count = 0;
    local->rx_cb = NULL;
}

int kc_mac80211_chandef(struct ieee80211_hw *hw, enum nl80211_band band, int channel,
        enum nl80211_chan_width width, u32 center_freq1, struct cfg80211_chan_def *def) {
    struct ieee80211_supported_band *sband;
    u32 freq = ieee80211_channel_to_frequency(channel, band);

    if (band >= NUM_NL80211_BANDS || (sband = hw->wiphy->bands[band]) == NULL || freq == 0)
        return -EINVAL;

    for (int c = 0; c < sband->n_channels; c++) {
        if (sband->channels[c].center_freq != freq)
            continue;

        memset(def, 0, sizeof(*def));
        def->chan = &sband->channels[c];
        def->width = width;
        def->center_freq1 = center_freq1 ? center_freq1 : freq;
        return 0;
    }

    return -ENOENT;
}

/* Calls a monitor-only device makes which have nothing to act on */
void ieee80211_stop_queues(struct ieee80211_hw *hw) { (void) hw; }
void ieee80211_wake_queues(struct ieee80211_hw *hw) { (void) hw; }
void ieee80211_txq_schedule_start(struct ieee80211_hw *hw, u8 ac) { (void) hw; (void) ac; }
void __ieee80211_schedule_txq(struct ieee80211_hw *hw, struct ieee80211_txq *txq, bool force) {
    (void) hw; (void) txq; (void) force;
}
struct ieee80211_txq *ieee80211_next_txq(struct ieee80211_hw *hw, u8 ac) { (void) hw; (void) ac; return NULL; }
struct sk_buff *ieee80211_tx_dequeue(struct ieee80211_hw *hw, struct ieee80211_txq *txq) {
    (void) hw; (void) txq; return NULL;
}
u32 ieee80211_txq_aql_pending(struct ieee80211_hw *hw, struct ieee80211_txq *txq) { (void) hw; (void) txq; return 0; }
bool ieee80211_tx_prepare_skb(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct sk_buff *skb,
        int band, struct ieee80211_sta **sta) {
    (void) hw; (void) vif; (void) skb; (void) band; (void) sta; return false;
}
void ieee80211_free_txskb(struct ieee80211_hw *hw, struct sk_buff *skb) { (void) hw; kfree_skb(skb); }
void ieee80211_tx_status_ext(struct ieee80211_hw *hw, struct ieee80211_tx_status *status) {
    (void) hw;
    if (status->skb)
        kfree_skb(status->skb);
}
void ieee80211_get_tx_rates(struct ieee80211_vif *vif, struct ieee80211_sta *sta, struct sk_buff *skb,
        struct ieee80211_tx_rate *dest, int max_rates) {
    (void) vif; (void) sta; (void) skb;
    for (int i = 0; i < max_rates; i++) {
        dest[i].idx = -1;
        dest[i].count = 0;
    }
}
struct sk_buff *ieee80211_nullfunc_get(struct ieee80211_hw *hw, struct ieee80211_vif *vif, int link_id,
        bool qos_ok) {
    (void) hw; (void) vif; (void) link_id; (void) qos_ok; return NULL;
}
struct sk_buff *ieee80211_beacon_get_template(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
        struct ieee80211_mutable_offsets *offs, unsigned int link_id) {
    (void) hw; (void) vif; (void) offs; (void) link_id; return NULL;
}
bool ieee80211_beacon_cntdwn_is_complete(struct ieee80211_vif *vif, unsigned int link_id) {
    (void) vif; (void) link_id; return false;
}
void ieee80211_csa_finish(struct ieee80211_vif *vif, unsigned int link_id) { (void) vif; (void) link_id; }
void ieee80211_chswitch_done(struct ieee80211_vif *vif, bool success, unsigned int link_id) {
    (void) vif; (void) success; (void) link_id;
}
void ieee80211_beacon_loss(struct ieee80211_vif *vif) { (void) vif; }
void ieee80211_connection_loss(struct ieee80211_vif *vif) { (void) vif; }
void ieee80211_disconnect(struct ieee80211_vif *vif, bool reconnect) { (void) vif; (void) reconnect; }
void ieee80211_cqm_rssi_notify(struct ieee80211_vif *vif, enum nl80211_cqm_rssi_threshold_event e,
        s32 rssi_level, gfp_t gfp) {
    (void) vif; (void) e; (void) rssi_level; (void) gfp;
}
struct ieee80211_sta *ieee80211_find_sta(struct ieee80211_vif *vif, const u8 *addr) {
    (void) vif; (void) addr; return NULL;
}
struct ieee80211_sta *ieee80211_find_sta_by_ifaddr(struct ieee80211_hw *hw, const u8 *addr, const u8 *localaddr) {
    (void) hw; (void) addr; (void) localaddr; return NULL;
}
void ieee80211_sta_eosp(struct ieee80211_sta *pubsta) { (void) pubsta; }
int ieee80211_sta_ps_transition(struct ieee80211_sta *sta, bool start) { (void) sta; (void) start; return 0; }
void ieee80211_sta_pspoll(struct ieee80211_sta *sta) { (void) sta; }
void ieee80211_sta_uapsd_trigger(struct ieee80211_sta *sta, u8 tid) { (void) sta; (void) tid; }
void ieee80211_sta_register_airtime(struct ieee80211_sta *pubsta, u8 tid, u32 tx_airtime, u32 rx_airtime) {
    (void) pubsta; (void) tid; (void) tx_airtime; (void) rx_airtime;
}
int ieee80211_start_tx_ba_session(struct ieee80211_sta *sta, u16 tid, u16 timeout) {
    (void) sta; (void) tid; (void) timeout; return -EOPNOTSUPP;
}
void ieee80211_stop_tx_ba_cb_irqsafe(struct ieee80211_vif *vif, const u8 *ra, u16 tid) {
    (void) vif; (void) ra; (void) tid;
}
void ieee80211_send_bar(struct ieee80211_vif *vif, u8 *ra, u16 tid, u16 ssn) {
    (void) vif; (void) ra; (void) tid; (void) ssn;
}
void ieee80211_get_key_rx_seq(struct ieee80211_key_conf *keyconf, int tid, struct ieee80211_key_seq *seq) {
    (void) keyconf; (void) tid;
    memset(seq, 0, sizeof(*seq));
}
void ieee80211_scan_completed(struct ieee80211_hw *hw, struct cfg80211_scan_info *info) { (void) hw; (void) info; }
void ieee80211_sched_scan_results(struct ieee80211_hw *hw) { (void) hw; }
void ieee80211_ready_on_channel(struct ieee80211_hw *hw) { (void) hw; }
void ieee80211_remain_on_channel_expired(struct ieee80211_hw *hw) { (void) hw; }
u32 ieee80211_calc_rx_airtime(struct ieee80211_hw *hw, struct ieee80211_rx_status *status, int len) {
    (void) hw; (void) status; (void) len; return 0;
}
struct sk_buff *ieee80211_probereq_get(struct ieee80211_hw *hw, const u8 *src_addr, const u8 *ssid,
        size_t ssid_len, size_t tailroom) {
    (void) hw; (void) src_addr; (void) ssid; (void) ssid_len; (void) tailroom; return NULL;
}
