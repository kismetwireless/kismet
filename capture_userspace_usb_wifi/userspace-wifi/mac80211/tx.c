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

/* Transmit: frames injected on the monitor interface, handed to the driver as mac80211's
 * ieee80211_monitor_start_xmit() and the TX handlers that apply to a monitor interface
 * hand them, with queue stop/wake and TX status.
 *
 * ieee80211_validate_radiotap_len(), ieee80211_rate_bw_usable(),
 * ieee80211_parse_tx_radiotap() (as kc_parse_tx_radiotap(), taking local rather than a
 * net_device) and ieee80211_duration() are from Linux net/mac80211/tx.c,
 * ieee80211_frame_duration() from net/mac80211/util.c, and __rate_control_send_low(),
 * rate_control_fill_sta_table() and ieee80211_get_tx_rates() from net/mac80211/rate.c (GPL-2.0, Copyright 2002-2005 Instant802 Networks, 2005-2006
 * Devicescape Software, 2006-2007 Jiri Benc, 2007 Johannes Berg, 2013-2014 Intel Mobile
 * Communications GmbH, 2018-2026 Intel Corporation), adapted only where they reach into
 * mac80211 internals: there are no stations, the monitor interface has no basic rates,
 * short preamble or 11g mode, and the rate mask is every rate. */

#include "local.h"

#define FCS_LEN 4

/* From net/mac80211/ieee80211_i.h */
#define IEEE80211_ENCRYPT_HEADROOM 8
#define IEEE80211_ENCRYPT_TAILROOM 18

/* Frames held while the driver has its queues stopped, before the host is told to wait */
#define KC_TX_PENDING_MAX 256

static bool ieee80211_validate_radiotap_len(struct sk_buff *skb)
{
	struct ieee80211_radiotap_header *rthdr =
		(struct ieee80211_radiotap_header *)skb->data;

	/* check for not even having the fixed radiotap header part */
	if (unlikely(skb_headlen(skb) < sizeof(struct ieee80211_radiotap_header)))
		return false; /* too short to be possibly valid */

	/* is it a header version we can trust to find length from? */
	if (unlikely(rthdr->it_version))
		return false; /* only version 0 is supported */

	/* does the skb contain enough to deliver on the alleged length? */
	if (unlikely(skb_headlen(skb) < ieee80211_get_radiotap_len((const char *) skb->data)))
		return false; /* skb too short for claimed rt header extent */

	return true;
}

static bool ieee80211_rate_bw_usable(u16 rate_flags,
				     const struct cfg80211_chan_def *chandef)
{
	int width;

	if (!chandef)
		return true;

	width = cfg80211_chandef_get_width(chandef);

	if (rate_flags & IEEE80211_TX_RC_40_MHZ_WIDTH && width < 40)
		return false;
	if (rate_flags & IEEE80211_TX_RC_80_MHZ_WIDTH && width < 80)
		return false;
	if (rate_flags & IEEE80211_TX_RC_160_MHZ_WIDTH && width < 160)
		return false;

	return true;
}

static bool kc_parse_tx_radiotap(struct ieee80211_local *local,
				 struct sk_buff *skb,
				 const struct cfg80211_chan_def *chandef)
{
	struct ieee80211_radiotap_iterator iterator;
	struct ieee80211_radiotap_header *rthdr =
		(struct ieee80211_radiotap_header *) skb->data;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	int ret = ieee80211_radiotap_iterator_init(&iterator, rthdr, skb->len,
						   NULL);
	u16 txflags;
	u16 rate = 0;
	bool rate_found = false;
	u8 rate_retries = 0;
	u16 rate_flags = 0;
	u8 mcs_known, mcs_flags, mcs_bw;
	u16 vht_known;
	u8 vht_mcs = 0, vht_nss = 0;
	int i;

	if (!ieee80211_validate_radiotap_len(skb))
		return false;

	info->flags |= IEEE80211_TX_INTFL_DONT_ENCRYPT |
		       IEEE80211_TX_CTL_DONTFRAG;

	while (!ret) {
		ret = ieee80211_radiotap_iterator_next(&iterator);

		if (ret)
			continue;

		switch (iterator.this_arg_index) {
		case IEEE80211_RADIOTAP_FLAGS:
			if (*iterator.this_arg & IEEE80211_RADIOTAP_F_FCS) {
				if (skb->len < (iterator._max_length + FCS_LEN))
					return false;

				skb_trim(skb, skb->len - FCS_LEN);
			}
			if (*iterator.this_arg & IEEE80211_RADIOTAP_F_WEP)
				info->flags &= ~IEEE80211_TX_INTFL_DONT_ENCRYPT;
			if (*iterator.this_arg & IEEE80211_RADIOTAP_F_FRAG)
				info->flags &= ~IEEE80211_TX_CTL_DONTFRAG;
			break;

		case IEEE80211_RADIOTAP_TX_FLAGS:
			txflags = get_unaligned_le16(iterator.this_arg);
			if (txflags & IEEE80211_RADIOTAP_F_TX_NOACK)
				info->flags |= IEEE80211_TX_CTL_NO_ACK;
			if (txflags & IEEE80211_RADIOTAP_F_TX_NOSEQNO)
				info->control.flags |= IEEE80211_TX_CTRL_NO_SEQNO;
			if (txflags & IEEE80211_RADIOTAP_F_TX_ORDER)
				info->control.flags |=
					IEEE80211_TX_CTRL_DONT_REORDER;
			break;

		case IEEE80211_RADIOTAP_RATE:
			rate = *iterator.this_arg;
			rate_flags = 0;
			rate_found = true;
			break;

		case IEEE80211_RADIOTAP_ANTENNA:
			/* this can appear multiple times, keep a bitmap */
			/* control.antennas is only a 2-bit bitmap */
			if (*iterator.this_arg < 2)
				info->control.antennas |= BIT(*iterator.this_arg);
			break;

		case IEEE80211_RADIOTAP_DATA_RETRIES:
			rate_retries = *iterator.this_arg;
			break;

		case IEEE80211_RADIOTAP_MCS:
			mcs_known = iterator.this_arg[0];
			mcs_flags = iterator.this_arg[1];
			if (!(mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_MCS))
				break;

			rate_found = true;
			rate = iterator.this_arg[2];
			rate_flags = IEEE80211_TX_RC_MCS;

			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_GI &&
			    mcs_flags & IEEE80211_RADIOTAP_MCS_SGI)
				rate_flags |= IEEE80211_TX_RC_SHORT_GI;

			mcs_bw = mcs_flags & IEEE80211_RADIOTAP_MCS_BW_MASK;
			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_BW &&
			    mcs_bw == IEEE80211_RADIOTAP_MCS_BW_40)
				rate_flags |= IEEE80211_TX_RC_40_MHZ_WIDTH;

			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_FEC &&
			    mcs_flags & IEEE80211_RADIOTAP_MCS_FEC_LDPC)
				info->flags |= IEEE80211_TX_CTL_LDPC;

			if (mcs_known & IEEE80211_RADIOTAP_MCS_HAVE_STBC) {
				u8 stbc = u8_get_bits(mcs_flags,
						      IEEE80211_RADIOTAP_MCS_STBC_MASK);

				info->flags |=
					u32_encode_bits(stbc,
							IEEE80211_TX_CTL_STBC);
			}
			break;

		case IEEE80211_RADIOTAP_VHT:
			vht_known = get_unaligned_le16(iterator.this_arg);
			rate_found = true;

			rate_flags = IEEE80211_TX_RC_VHT_MCS;
			if ((vht_known & IEEE80211_RADIOTAP_VHT_KNOWN_GI) &&
			    (iterator.this_arg[2] &
			     IEEE80211_RADIOTAP_VHT_FLAG_SGI))
				rate_flags |= IEEE80211_TX_RC_SHORT_GI;
			if (vht_known &
			    IEEE80211_RADIOTAP_VHT_KNOWN_BANDWIDTH) {
				if (iterator.this_arg[3] == 1)
					rate_flags |=
						IEEE80211_TX_RC_40_MHZ_WIDTH;
				else if (iterator.this_arg[3] == 4)
					rate_flags |=
						IEEE80211_TX_RC_80_MHZ_WIDTH;
				else if (iterator.this_arg[3] == 11)
					rate_flags |=
						IEEE80211_TX_RC_160_MHZ_WIDTH;
			}

			vht_mcs = iterator.this_arg[4] >> 4;
			if (vht_mcs > 11)
				vht_mcs = 0;
			vht_nss = iterator.this_arg[4] & 0xF;
			if (!vht_nss || vht_nss > 8)
				vht_nss = 1;
			break;

		default:
			break;
		}
	}

	if (ret != -ENOENT) /* ie, if we didn't simply run out of fields */
		return false;

	if (rate_found) {
		struct ieee80211_supported_band *sband =
			local->hw.wiphy->bands[info->band];

		if (!ieee80211_rate_bw_usable(rate_flags, chandef))
			return false;

		info->control.flags |= IEEE80211_TX_CTRL_RATE_INJECT;

		for (i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
			info->control.rates[i].idx = -1;
			info->control.rates[i].flags = 0;
			info->control.rates[i].count = 0;
		}

		if (rate_flags & IEEE80211_TX_RC_MCS) {
			/* reset antennas if not enough */
			if (IEEE80211_HT_MCS_CHAINS(rate) >
					hweight8(info->control.antennas))
				info->control.antennas = 0;

			info->control.rates[0].idx = rate;
		} else if (rate_flags & IEEE80211_TX_RC_VHT_MCS) {
			/* reset antennas if not enough */
			if (vht_nss > hweight8(info->control.antennas))
				info->control.antennas = 0;

			ieee80211_rate_set_vht(info->control.rates, vht_mcs,
					       vht_nss);
		} else if (sband) {
			for (i = 0; i < sband->n_bitrates; i++) {
				if (rate * 5 != sband->bitrates[i].bitrate)
					continue;

				info->control.rates[0].idx = i;
				break;
			}
		}

		if (info->control.rates[0].idx < 0)
			info->control.flags &= ~IEEE80211_TX_CTRL_RATE_INJECT;

		info->control.rates[0].flags = rate_flags;
		info->control.rates[0].count = min_t(u8, rate_retries + 1,
						     local->hw.max_rate_tries);
	}

	return true;
}

static void __rate_control_send_low(struct ieee80211_hw *hw,
				    struct ieee80211_supported_band *sband,
				    struct ieee80211_tx_info *info,
				    u32 rate_mask)
{
	u32 rate_flags = 0;
	int i;

	if ((sband->band == NL80211_BAND_2GHZ) &&
	    (info->flags & IEEE80211_TX_CTL_NO_CCK_RATE))
		rate_flags |= IEEE80211_RATE_ERP_G;

	info->control.rates[0].idx = 0;
	for (i = 0; i < sband->n_bitrates; i++) {
		if (!(rate_mask & BIT(i)))
			continue;

		if ((rate_flags & sband->bitrates[i].flags) != rate_flags)
			continue;

		info->control.rates[0].idx = i;
		break;
	}

	info->control.rates[0].count =
		(info->flags & IEEE80211_TX_CTL_NO_ACK) ?
		1 : hw->max_rate_tries;

	info->control.skip_table = 1;
}

static void rate_control_fill_sta_table(struct ieee80211_tx_info *info,
					struct ieee80211_tx_rate *rates,
					int max_rates)
{
	int i;

	/* Fill remaining rate slots with data from the sta rate table. */
	max_rates = min_t(int, max_rates, IEEE80211_TX_RATE_TABLE_SIZE);
	for (i = 0; i < max_rates; i++) {
		if (i < ARRAY_SIZE(info->control.rates) &&
		    info->control.rates[i].idx >= 0 &&
		    info->control.rates[i].count) {
			if (rates != info->control.rates)
				rates[i] = info->control.rates[i];
		} else {
			rates[i].idx = -1;
			rates[i].count = 0;
		}

		if (rates[i].idx < 0 || !rates[i].count)
			break;
	}
}

void ieee80211_get_tx_rates(struct ieee80211_vif *vif,
			    struct ieee80211_sta *sta,
			    struct sk_buff *skb,
			    struct ieee80211_tx_rate *dest,
			    int max_rates)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_supported_band *sband;
	struct ieee80211_local *local;

	(void) sta;

	rate_control_fill_sta_table(info, dest, max_rates);

	if (!vif || (local = kc_vif_to_local(vif)) == NULL)
		return;

	if (info->band >= NUM_NL80211_BANDS)
		return;

	sband = local->hw.wiphy->bands[info->band];

	if (dest[0].idx < 0 && sband)
		__rate_control_send_low(&local->hw, sband, info, ~0u);
}

static int ieee80211_frame_duration(enum nl80211_band band, size_t len,
				    int rate, int erp, int short_preamble)
{
	int dur;

	if (band == NL80211_BAND_5GHZ || erp) {
		dur = 16; /* SIFS + signal ext */
		dur += 16; /* IEEE 802.11-2012 18.3.2.4: T_PREAMBLE = 16 usec */
		dur += 4; /* IEEE 802.11-2012 18.3.2.4: T_SIGNAL = 4 usec */

		dur += 4 * DIV_ROUND_UP((16 + 8 * (len + 4) + 6) * 10,
					4 * rate); /* T_SYM x N_SYM */
	} else {
		dur = 10; /* aSIFSTime = 10 usec */
		dur += short_preamble ? (72 + 24) : (144 + 48);

		dur += DIV_ROUND_UP(8 * (len + 4) * 10, rate);
	}

	return dur;
}

static __le16 ieee80211_duration(struct ieee80211_local *local,
				 struct sk_buff *skb,
				 const struct ieee80211_tx_rate *tx_rate)
{
	int rate, mrate, erp, dur, i;
	struct ieee80211_rate *txrate;
	struct ieee80211_supported_band *sband;
	struct ieee80211_hdr *hdr;
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	/* assume HW handles this */
	if (tx_rate->flags & (IEEE80211_TX_RC_MCS | IEEE80211_TX_RC_VHT_MCS))
		return 0;

	if (tx_rate->idx < 0 || info->band >= NUM_NL80211_BANDS)
		return 0;

	sband = local->hw.wiphy->bands[info->band];
	txrate = &sband->bitrates[tx_rate->idx];

	erp = txrate->flags & IEEE80211_RATE_ERP_G;

	hdr = (struct ieee80211_hdr *)skb->data;
	if (ieee80211_is_ctl(hdr->frame_control))
		return 0;

	if (is_multicast_ether_addr(hdr->addr1))
		return 0;

	/* The monitor interface has no basic rates and isn't in 11g mode, so the ACK goes at
	 * the highest mandatory rate no faster than this frame's */
	rate = -1;
	mrate = sband->bitrates[0].bitrate;
	for (i = 0; i < sband->n_bitrates; i++) {
		struct ieee80211_rate *r = &sband->bitrates[i];
		u32 flag;

		if (r->bitrate > txrate->bitrate)
			break;

		switch (sband->band) {
		case NL80211_BAND_2GHZ:
			flag = IEEE80211_RATE_MANDATORY_B;
			break;
		case NL80211_BAND_5GHZ:
		case NL80211_BAND_6GHZ:
			flag = IEEE80211_RATE_MANDATORY_A;
			break;
		default:
			flag = 0;
			break;
		}

		if (r->flags & flag)
			mrate = r->bitrate;
	}
	if (rate == -1)
		rate = mrate;

	/* Don't calculate ACKs for QoS Frames with NoAck Policy set */
	if (ieee80211_is_data_qos(hdr->frame_control) &&
	    *(ieee80211_get_qos_ctl(hdr)) & IEEE80211_QOS_CTL_ACK_POLICY_NOACK)
		dur = 0;
	else
		dur = ieee80211_frame_duration(sband->band, 10, rate, erp, 0);

	return cpu_to_le16(dur);
}

/* From net/wireless/util.c */
static const u8 ieee802_1d_to_ac[8] = {
    IEEE80211_AC_BE, IEEE80211_AC_BK, IEEE80211_AC_BK, IEEE80211_AC_BE,
    IEEE80211_AC_VI, IEEE80211_AC_VI, IEEE80211_AC_VO, IEEE80211_AC_VO,
};

/* ieee80211_select_queue_80211(), for a device with no WMM admission control */
static u16 kc_select_queue(struct ieee80211_local *local, struct sk_buff *skb, struct ieee80211_hdr *hdr) {
    struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

    if (local->hw.queues < IEEE80211_NUM_ACS)
        return 0;

    if (!ieee80211_is_data_qos(hdr->frame_control)) {
        skb->priority = 7;
        return ieee802_1d_to_ac[skb->priority & 7];
    }

    if (!(info->control.flags & IEEE80211_TX_CTRL_DONT_REORDER))
        skb->priority = *ieee80211_get_qos_ctl(hdr) & IEEE80211_QOS_CTL_TAG1D_MASK;

    return ieee802_1d_to_ac[skb->priority & 7];
}

/* The vif a monitor frame is sent with, as __ieee80211_tx() picks it */
static struct ieee80211_vif *kc_tx_vif(struct ieee80211_local *local) {
    return local->monitor_in_driver ? local->monitor_vif : NULL;
}

static void kc_drv_tx(struct ieee80211_local *local, struct sk_buff *skb) {
    struct ieee80211_tx_control control = { 0 };
    struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

    info->control.vif = kc_tx_vif(local);
    local->ops->tx(&local->hw, &control, skb);
}

/* Sends held frames once the driver wakes its queues; the tx-pending tasklet */
static void kc_tx_pending_work(struct work_struct *work) {
    struct ieee80211_local *local = container_of(work, struct ieee80211_local, tx_pending_work);
    struct sk_buff *skb;

    for (;;) {
        spin_lock_bh(&local->queue_stop_reason_lock);
        if (local->queue_stop_reasons ||
                (skb = __skb_dequeue(&local->pending)) == NULL) {
            spin_unlock_bh(&local->queue_stop_reason_lock);
            return;
        }
        spin_unlock_bh(&local->queue_stop_reason_lock);

        kc_drv_tx(local, skb);
    }
}

void kc_mac80211_tx_init(struct ieee80211_local *local) {
    spin_lock_init(&local->queue_stop_reason_lock);
    __skb_queue_head_init(&local->pending);
    INIT_WORK(&local->tx_pending_work, kc_tx_pending_work);
}

void kc_mac80211_tx_flush(struct ieee80211_local *local) {
    struct sk_buff *skb;

    cancel_work_sync(&local->tx_pending_work);

    spin_lock_bh(&local->queue_stop_reason_lock);
    while ((skb = __skb_dequeue(&local->pending)) != NULL)
        kfree_skb(skb);
    local->queue_stop_reasons = 0;
    spin_unlock_bh(&local->queue_stop_reason_lock);
}

void kc_mac80211_set_tx_status_cb(struct ieee80211_hw *hw, kc_mac80211_tx_status_cb_t cb, void *ctx) {
    struct ieee80211_local *local = hw_to_local(hw);

    local->tx_status_ctx = ctx;
    local->tx_status_cb = cb;
}

int kc_mac80211_tx(struct ieee80211_hw *hw, const u8 *data, size_t len) {
    struct ieee80211_local *local = hw_to_local(hw);
    const struct cfg80211_chan_def *chandef;
    struct ieee80211_tx_info *info;
    struct ieee80211_hdr *hdr;
    struct sk_buff *skb;
    unsigned int headroom;
    u16 len_rthdr;
    int hdrlen;

    if (!local->started || local->monitor_vif == NULL || local->ops->tx == NULL)
        return -ENETDOWN;

    chandef = local->chanctx ? &local->chanctx->def : &hw->conf.chandef;
    if (chandef->chan == NULL)
        return -ENETDOWN;

    /* cfg80211_reg_can_beacon(): no injection where the channel forbids initiating radiation */
    if (chandef->chan->flags & (IEEE80211_CHAN_DISABLED | IEEE80211_CHAN_NO_IR | IEEE80211_CHAN_RADAR))
        return -EPERM;

    headroom = max_t(unsigned int, hw->extra_tx_headroom, IEEE80211_TX_STATUS_HEADROOM) +
        IEEE80211_ENCRYPT_HEADROOM;
    if ((skb = dev_alloc_skb(headroom + len + IEEE80211_ENCRYPT_TAILROOM)) == NULL)
        return -ENOMEM;
    skb_reserve(skb, headroom);
    skb_put_data(skb, data, len);

    info = IEEE80211_SKB_CB(skb);
    memset(info, 0, sizeof(*info));
    info->flags = IEEE80211_TX_CTL_REQ_TX_STATUS | IEEE80211_TX_CTL_INJECTED;

    if (!ieee80211_validate_radiotap_len(skb))
        goto invalid;

    len_rthdr = ieee80211_get_radiotap_len((const char *) skb->data);
    if (skb_headlen(skb) < len_rthdr + 2)
        goto invalid;

    hdr = (struct ieee80211_hdr *) (skb->data + len_rthdr);
    hdrlen = ieee80211_hdrlen(hdr->frame_control);
    if (skb_headlen(skb) < len_rthdr + hdrlen)
        goto invalid;

    info->band = chandef->chan->band;
    skb_set_queue_mapping(skb, kc_select_queue(local, skb, hdr));

    if (!kc_parse_tx_radiotap(local, skb, chandef))
        goto invalid;

    skb_pull(skb, len_rthdr);
    hdr = (struct ieee80211_hdr *) skb->data;

    /* ieee80211_tx_prepare() */
    if (is_multicast_ether_addr(hdr->addr1))
        info->flags |= IEEE80211_TX_CTL_NO_ACK;
    info->flags |= IEEE80211_TX_CTL_CLEAR_PS_FILT | IEEE80211_TX_CTL_FIRST_FRAGMENT;
    info->hw_queue = local->monitor_vif->hw_queue[skb_get_queue_mapping(skb)];

    /* ieee80211_tx_h_rate_ctrl() and ieee80211_tx_h_calculate_duration(); there is no
     * station, so rate control sends at the lowest rate.  The monitor interface assigns no
     * sequence numbers. */
    if (!ieee80211_hw_check(hw, HAS_RATE_CONTROL)) {
        struct ieee80211_supported_band *sband = hw->wiphy->bands[info->band];
        struct ieee80211_tx_rate tx_rate = { 0 };

        if (sband == NULL)
            goto invalid;

        if (!(info->control.flags & IEEE80211_TX_CTRL_RATE_INJECT)) {
            for (int i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
                info->control.rates[i].idx = -1;
                info->control.rates[i].flags = 0;
                info->control.rates[i].count = 0;
            }
            __rate_control_send_low(hw, sband, info, ~0u);
            tx_rate = info->control.rates[0];
        }

        if (!ieee80211_is_pspoll(hdr->frame_control))
            hdr->duration_id = ieee80211_duration(local, skb, &tx_rate);
    }

    /* ieee80211_tx_frags(): queue behind held frames or while the driver has stopped */
    spin_lock_bh(&local->queue_stop_reason_lock);
    if (local->queue_stop_reasons || !skb_queue_empty(&local->pending)) {
        if (skb_queue_len(&local->pending) >= KC_TX_PENDING_MAX) {
            spin_unlock_bh(&local->queue_stop_reason_lock);
            kfree_skb(skb);
            return -EBUSY;
        }
        __skb_queue_tail(&local->pending, skb);
        spin_unlock_bh(&local->queue_stop_reason_lock);
        return 0;
    }
    spin_unlock_bh(&local->queue_stop_reason_lock);

    kc_drv_tx(local, skb);
    return 0;

invalid:
    kfree_skb(skb);
    return -EINVAL;
}

/* Queue control */
void ieee80211_stop_queue(struct ieee80211_hw *hw, int queue) {
    struct ieee80211_local *local = hw_to_local(hw);

    spin_lock_bh(&local->queue_stop_reason_lock);
    local->queue_stop_reasons |= BIT(queue);
    spin_unlock_bh(&local->queue_stop_reason_lock);
}

void ieee80211_wake_queue(struct ieee80211_hw *hw, int queue) {
    struct ieee80211_local *local = hw_to_local(hw);
    bool run;

    spin_lock_bh(&local->queue_stop_reason_lock);
    local->queue_stop_reasons &= ~BIT(queue);
    run = !local->queue_stop_reasons && !skb_queue_empty(&local->pending);
    spin_unlock_bh(&local->queue_stop_reason_lock);

    if (run)
        queue_work(local->workqueue, &local->tx_pending_work);
}

void ieee80211_stop_queues(struct ieee80211_hw *hw) {
    struct ieee80211_local *local = hw_to_local(hw);

    spin_lock_bh(&local->queue_stop_reason_lock);
    local->queue_stop_reasons = BIT(hw->queues) - 1;
    spin_unlock_bh(&local->queue_stop_reason_lock);
}

void ieee80211_wake_queues(struct ieee80211_hw *hw) {
    struct ieee80211_local *local = hw_to_local(hw);
    bool run;

    spin_lock_bh(&local->queue_stop_reason_lock);
    local->queue_stop_reasons = 0;
    run = !skb_queue_empty(&local->pending);
    spin_unlock_bh(&local->queue_stop_reason_lock);

    if (run)
        queue_work(local->workqueue, &local->tx_pending_work);
}

int ieee80211_queue_stopped(struct ieee80211_hw *hw, int queue) {
    struct ieee80211_local *local = hw_to_local(hw);
    int r;

    spin_lock_bh(&local->queue_stop_reason_lock);
    r = !!(local->queue_stop_reasons & BIT(queue));
    spin_unlock_bh(&local->queue_stop_reason_lock);
    return r;
}

/* TX status: injected frames which asked for it are reported to the host, as mac80211
 * reports them to monitor interfaces */
static void kc_tx_status(struct ieee80211_hw *hw, struct sk_buff *skb, struct ieee80211_tx_info *info) {
    struct ieee80211_local *local = hw_to_local(hw);
    kc_mac80211_tx_status_cb_t cb = local->tx_status_cb;

    if (cb && info && (info->flags & IEEE80211_TX_CTL_INJECTED) &&
            (info->flags & IEEE80211_TX_CTL_REQ_TX_STATUS))
        cb(local->tx_status_ctx, hw, skb->data, skb->len, !!(info->flags & IEEE80211_TX_STAT_ACK));
}

void ieee80211_tx_status_skb(struct ieee80211_hw *hw, struct sk_buff *skb) {
    kc_tx_status(hw, skb, IEEE80211_SKB_CB(skb));
    kfree_skb(skb);
}

void ieee80211_tx_status_irqsafe(struct ieee80211_hw *hw, struct sk_buff *skb) {
    ieee80211_tx_status_skb(hw, skb);
}

void ieee80211_tx_status_ext(struct ieee80211_hw *hw, struct ieee80211_tx_status *status) {
    if (status->skb == NULL)
        return;

    kc_tx_status(hw, status->skb, status->info ? status->info : IEEE80211_SKB_CB(status->skb));
    kfree_skb(status->skb);
}

void ieee80211_free_txskb(struct ieee80211_hw *hw, struct sk_buff *skb) {
    (void) hw;
    kfree_skb(skb);
}

void ieee80211_purge_tx_queue(struct ieee80211_hw *hw, struct sk_buff_head *skbs) {
    struct sk_buff *skb;

    while ((skb = __skb_dequeue(skbs)) != NULL)
        ieee80211_free_txskb(hw, skb);
}
