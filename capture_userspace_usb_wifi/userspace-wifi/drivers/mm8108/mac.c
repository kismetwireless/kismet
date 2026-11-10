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

/* The MM8108 as a mac80211 driver.
 *
 * mac80211 has no usable 802.11ah band, so, as morse_driver does, the region's S1G channels
 * are registered as 5GHz channels: each 1, 2, 4 and 8MHz S1G channel is a 20, 40, 80 and
 * 160MHz 5GHz channel (mm_channels.h).  A 20MHz channel tunes its 1MHz channel as the
 * primary of the widest channel containing it, so wider BSSs with that primary are heard;
 * wider channels tune the S1G channel itself.
 *
 * With a station interface, frames are converted between 802.11ah and the 802.11n/ac
 * frames mac80211 expects (mm_s1g.h); a monitor interface alone gets the frames as sent,
 * with radiotap TLVs for the S1G PHY and the frequency in kHz, as morse_driver's monitor
 * interface reports them.  NDP frames carry SIG fields rather than a frame and are dropped.
 * A thread services the chip: interrupts, received frames, TX status and the TX queue. */

#include <dirent.h>

#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/usb.h>
#include <net/mac80211.h>

#include <kc_mac80211.h>

#include "mm8108.h"
#include "mm_channels.h"
#include "mm_s1g.h"
#include "mm_util.h"

#define MM_MAC_TXQ_MAX      64
#define MM_MAC_TXQ_WAKE     16
#define MM_MAC_PENDING_MAX  64
#define MM_MAC_STATUS_MS    500
#define MM_MAC_MAX_FRAME    2400
#define MM_MAC_SERVICE_MS   20

struct mm_mac_pending {
    struct sk_buff *skb;
    uint32_t pkt_id;
    unsigned long sent;
};

struct mm_mac {
    struct mm8108_dev dev;
    struct ieee80211_hw *hw;
    struct usb_interface *intf;

    const struct mm_s1g_region *region;
    /* Per region channel, false where the board config disables it */
    bool *usable;
    struct ieee80211_supported_band sband;
    struct ieee80211_channel *channels;

    /* Device access: commands, the TX queue and servicing */
    struct mutex lock;
    struct task_struct *thread;
    bool started;
    bool dead;

    struct sk_buff_head txq;
    bool queues_stopped;
    /* The chip's queue was full; wait for it to free pages */
    bool tx_blocked;
    struct mm_mac_pending pending[MM_MAC_PENDING_MAX];
    uint32_t pkt_id;

    struct ieee80211_vif *sta_vif;
    /* mac80211 has a monitor interface; the chip's is removed while a station exists */
    bool want_monitor;
    uint8_t bssid[6];
    struct mm_s1g_conv conv;

    /* The tuned channel */
    const struct mm_s1g_channel *op;
    const struct mm_s1g_channel *pri1;
    uint8_t pri_bw;
    u32 rx_freq;

    uint8_t rx_buf[MM_MAC_MAX_FRAME + MM_S1G_RX_GROWTH];
    uint8_t tx_buf[MM_MAC_MAX_FRAME];
};

static struct ieee80211_rate mm_mac_bitrates[] = {
    { .bitrate = 60, .hw_value = 0 },
    { .bitrate = 90, .hw_value = 1 },
    { .bitrate = 120, .hw_value = 2 },
    { .bitrate = 180, .hw_value = 3 },
    { .bitrate = 240, .hw_value = 4 },
    { .bitrate = 360, .hw_value = 5 },
    { .bitrate = 480, .hw_value = 6 },
    { .bitrate = 540, .hw_value = 7 },
};

static bool mm_mac_usable(const struct mm_mac *m, const struct mm_s1g_channel *ch) {
    return ch != NULL && m->usable[ch - m->region->channels];
}

static u32 mm_mac_5g_freq(unsigned int chan) {
    return 5000 + 5 * chan;
}

/* A usable channel of a width containing ch */
static const struct mm_s1g_channel *mm_mac_containing(const struct mm_mac *m,
        const struct mm_s1g_channel *ch, unsigned int bw) {
    const struct mm_s1g_channel *c = mm_s1g_containing(m->region, ch, bw, NULL);

    return mm_mac_usable(m, c) ? c : NULL;
}

static const struct mm_s1g_channel *mm_mac_by_5g(const struct mm_mac *m, unsigned int chan,
        unsigned int bw) {
    const struct mm_s1g_channel *c = mm_s1g_channel_by_5g(m->region, chan, bw);

    return mm_mac_usable(m, c) ? c : NULL;
}

static unsigned int mm_mac_width_mhz(enum nl80211_chan_width width) {
    switch (width) {
        case NL80211_CHAN_WIDTH_20_NOHT:
        case NL80211_CHAN_WIDTH_20:
            return 1;
        case NL80211_CHAN_WIDTH_40:
            return 2;
        case NL80211_CHAN_WIDTH_80:
            return 4;
        case NL80211_CHAN_WIDTH_160:
            return 8;
        default:
            return 0;
    }
}

static int mm_mac_tune(struct mm_mac *m, const struct cfg80211_chan_def *def) {
    const unsigned int bw = mm_mac_width_mhz(def->width);
    const struct mm_s1g_channel *pri1, *op = NULL;
    const struct mm_s1g_bss *bss;
    uint8_t pri_bw, idx;
    int r;

    if (def->chan == NULL || bw == 0)
        return -EINVAL;

    if ((pri1 = mm_mac_by_5g(m, def->chan->hw_value, 1)) == NULL)
        return -EINVAL;

    if (bw == 1) {
        /* A known 1MHz BSS here is tuned exactly, as it would be associated */
        bss = mm_s1g_find_bss_on(&m->conv, pri1, pri1);
        for (unsigned int w = 8; bss == NULL && op == NULL && w >= 2; w /= 2)
            op = mm_mac_containing(m, pri1, w);
        if (op == NULL)
            op = pri1;
    } else {
        op = mm_mac_by_5g(m, ieee80211_frequency_to_channel(def->center_freq1), bw);
        if (op == NULL || mm_s1g_containing(m->region, pri1, bw, NULL) != op)
            return -EINVAL;
    }

    pri_bw = op->bw_mhz == 1 ? 1 : 2;
    if (op->bw_mhz > 1 && (bss = mm_s1g_find_bss_on(&m->conv, op, pri1)) != NULL) {
        struct mm_s1g_op o;

        if (mm_s1g_parse_op(m->region, bss->s1g_op, &o))
            pri_bw = o.pri_bw;
    }

    idx = (uint8_t) ((pri1->freq_khz - (op->freq_khz - op->bw_mhz * 500u)) / 1000);

    if ((r = mm_cmd_set_channel(&m->dev, op->freq_khz, op->bw_mhz, pri_bw, idx)) < 0)
        return r;

    m->op = op;
    m->pri1 = pri1;
    m->pri_bw = pri_bw;
    m->rx_freq = def->chan->center_freq;

    mm_log(&m->dev, 2, "tuned S1G channel %u (%uMHz, primary %u at %uMHz) for 5GHz %u",
            op->channel, op->bw_mhz, pri1->channel, pri_bw, def->chan->hw_value);
    return 0;
}

static void mm_mac_complete(struct mm_mac *m, struct sk_buff *skb, bool acked) {
    struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

    ieee80211_tx_info_clear_status(info);
    if (acked && !(info->flags & IEEE80211_TX_CTL_NO_ACK))
        info->flags |= IEEE80211_TX_STAT_ACK;
    ieee80211_tx_status_irqsafe(m->hw, skb);
}

static void mm_mac_tx_status(void *ctx, uint32_t pkt_id, bool acked, uint32_t flags) {
    struct mm_mac *m = ctx;
    (void) flags;

    for (size_t i = 0; i < MM_MAC_PENDING_MAX; i++) {
        struct mm_mac_pending *p = &m->pending[i];

        if (p->skb != NULL && p->pkt_id == pkt_id) {
            struct sk_buff *skb = p->skb;

            p->skb = NULL;
            mm_mac_complete(m, skb, acked);
            return;
        }
    }
}

static void mm_mac_tx_expire(struct mm_mac *m, bool all) {
    for (size_t i = 0; i < MM_MAC_PENDING_MAX; i++) {
        struct mm_mac_pending *p = &m->pending[i];

        if (p->skb != NULL && (all || time_after(jiffies, p->sent + msecs_to_jiffies(MM_MAC_STATUS_MS)))) {
            struct sk_buff *skb = p->skb;

            p->skb = NULL;
            mm_mac_complete(m, skb, false);
        }
    }
}

/* The kernel's rate as an S1G rate at the matching width: 20/40/80/160 is 1/2/4/8MHz.
 * Management frames and legacy rates go at 1MHz MCS0, which every S1G station receives. */
static void mm_mac_rates(const struct mm_mac *m, const struct ieee80211_tx_info *info, bool mgmt,
        struct mm_tx_info *ti) {
    const struct ieee80211_tx_rate *r = &info->control.rates[0];
    unsigned int bw = 1, mcs = 0, count = r->count ? r->count : 4;
    bool sgi = false;

    if (!mgmt && r->idx >= 0 && (r->flags & (IEEE80211_TX_RC_VHT_MCS | IEEE80211_TX_RC_MCS))) {
        if (r->flags & IEEE80211_TX_RC_VHT_MCS)
            mcs = ieee80211_rate_get_vht_mcs(r);
        else
            mcs = (unsigned int) r->idx % 8;

        if (r->flags & IEEE80211_TX_RC_160_MHZ_WIDTH)
            bw = 8;
        else if (r->flags & IEEE80211_TX_RC_80_MHZ_WIDTH)
            bw = 4;
        else if (r->flags & IEEE80211_TX_RC_40_MHZ_WIDTH)
            bw = 2;

        sgi = (r->flags & IEEE80211_TX_RC_SHORT_GI) != 0;
    }

    if (m->op != NULL && bw > m->op->bw_mhz)
        bw = m->op->bw_mhz;
    if (mcs > 9)
        mcs = 9;
    if (count > 8)
        count = 8;

    memset(ti->rates, 0, sizeof(ti->rates));
    ti->rates[0].ratecode = MM_RATECODE_INIT(mm_bw_idx(bw), 0, mcs, bw == 1 ? 2 : 1) |
        (sgi ? MM_RATECODE_SGI_FLAG : 0);
    ti->rates[0].count = (uint8_t) count;

    if (bw != 1 || mcs != 0) {
        ti->rates[1].ratecode = MM_RATECODE_INIT(0, 0, 0, 2);
        ti->rates[1].count = 2;
    }
}

/* Writes one frame to the chip; -EAGAIN leaves it for when the chip has room */
static int mm_mac_tx_one(struct mm_mac *m, struct sk_buff *skb) {
    struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
    const struct ieee80211_hdr *hdr = (const void *) skb->data;
    const bool mgmt = ieee80211_is_mgmt(hdr->frame_control);
    struct mm_mac_pending *slot = NULL;
    struct mm_tx_info ti = { 0 };
    const uint8_t *frame = skb->data;
    int len = (int) skb->len;
    int r;

    for (size_t i = 0; i < MM_MAC_PENDING_MAX && slot == NULL; i++)
        if (m->pending[i].skb == NULL)
            slot = &m->pending[i];
    if (slot == NULL)
        return -EAGAIN;

    if (m->sta_vif != NULL) {
        if ((len = mm_s1g_tx(&m->conv, skb->data, skb->len, m->tx_buf, sizeof(m->tx_buf))) <= 0) {
            mm_mac_complete(m, skb, false);
            return 0;
        }
        frame = m->tx_buf;

        /* The S1G duration differs; the chip sets it */
        m->tx_buf[2] = m->tx_buf[3] = 0;

        /* The station interface accepts its BSS's frames once it knows the BSSID */
        if (ieee80211_is_auth(hdr->frame_control) && skb->len >= 24 &&
                memcmp(m->bssid, hdr->addr3, 6) != 0 &&
                mm_cmd_set_bssid(&m->dev, m->dev.sta_vif_id, hdr->addr3) == 0)
            memcpy(m->bssid, hdr->addr3, 6);
    }

    ti.flags = MM_TX_FLAG_IMMEDIATE_REPORT |
        MM_TX_FLAG_VIF_ID(m->dev.sta_added ? m->dev.sta_vif_id : m->dev.mon_vif_id);
    if ((info->flags & IEEE80211_TX_CTL_NO_ACK) || is_multicast_ether_addr(hdr->addr1))
        ti.flags |= MM_TX_FLAG_NO_ACK;
    if (ieee80211_is_data_qos(hdr->frame_control))
        ti.tid = *ieee80211_get_qos_ctl((struct ieee80211_hdr *) skb->data) & IEEE80211_QOS_CTL_TID_MASK;
    ti.pkt_id = ++m->pkt_id;
    mm_mac_rates(m, info, mgmt, &ti);

    r = mm_yaps_write_frame(&m->dev, mgmt ? MM_SKB_CHAN_MGMT : MM_SKB_CHAN_DATA, &ti, frame,
            (size_t) len);
    if (r == -EAGAIN)
        return r;

    if (r < 0) {
        mm_mac_complete(m, skb, false);
        return 0;
    }

    if (mgmt)
        mm_log(&m->dev, 2, "TX packet %u: management subtype %u, seq %u%s, %d bytes", ti.pkt_id,
                (le16_to_cpu(hdr->frame_control) >> 4) & 0xf, le16_to_cpu(hdr->seq_ctrl) >> 4,
                ieee80211_has_retry(hdr->frame_control) ? " (retry)" : "", len);

    slot->skb = skb;
    slot->pkt_id = ti.pkt_id;
    slot->sent = jiffies;
    return 0;
}

static void mm_mac_tx_drain(struct mm_mac *m) {
    struct sk_buff *skb;

    while ((skb = skb_dequeue(&m->txq)) != NULL) {
        if (mm_mac_tx_one(m, skb) == -EAGAIN) {
            skb_queue_head(&m->txq, skb);
            m->tx_blocked = true;
            break;
        }
    }

    if (m->queues_stopped && skb_queue_len(&m->txq) < MM_MAC_TXQ_WAKE) {
        m->queues_stopped = false;
        ieee80211_wake_queues(m->hw);
    }
}

/* Radiotap TLVs, from morse_driver s1g_radiotap.h and vendor.h */
#define MM_RT_TLV_S1G           32
#define MM_RT_TLV_VENDOR        30
#define MM_RT_S1G_LEN           6
#define MM_RT_VENDOR_LEN        12
#define MM_RT_TLVS_LEN          (4 + 8 + 4 + MM_RT_VENDOR_LEN)

#define MM_S1G_KNOWN_PPDU       0x0001
#define MM_S1G_KNOWN_RI         0x0002
#define MM_S1G_KNOWN_GI         0x0004
#define MM_S1G_KNOWN_NSS        0x0008
#define MM_S1G_KNOWN_BW         0x0010
#define MM_S1G_KNOWN_MCS        0x0020
#define MM_S1G_KNOWN_COLOR      0x0040
#define MM_S1G_KNOWN_UPLINK     0x0080

#define MM_S1G_PPDU_1M          0
#define MM_S1G_PPDU_SHORT       1
#define MM_S1G_PPDU_LONG        2

static const uint8_t mm_morse_oui[3] = { 0x0C, 0xBF, 0x74 };
#define MM_MORSE_VENDOR_FREQ_KHZ 35

/* The S1G TLV and Morse Micro's frequency TLV, padded to 4 */
static void mm_mac_rx_tlvs(const struct mm_rx_status *st, uint8_t *p) {
    const unsigned int preamble = MM_RATECODE_PREAMBLE(st->ratecode);
    uint16_t known = MM_S1G_KNOWN_RI | MM_S1G_KNOWN_COLOR | MM_S1G_KNOWN_UPLINK;
    uint16_t data1 = (uint16_t) (MM_RX_FLAG_RI(st->flags) << 2);
    const uint16_t data2 = (uint16_t) ((st->bss_color & 0x7) |
            ((st->flags & MM_RX_FLAG_UPLINK) ? 0x8 : 0) | ((uint16_t) (uint8_t) st->rssi << 8));

    memset(p, 0, MM_RT_TLVS_LEN);

    /* Rate details only apply to S1G preambles */
    if (preamble == MM_PREAMBLE_S1G_LONG || preamble == MM_PREAMBLE_S1G_SHORT ||
            preamble == MM_PREAMBLE_S1G_1M) {
        const unsigned int ppdu = preamble == MM_PREAMBLE_S1G_LONG ? MM_S1G_PPDU_LONG :
            preamble == MM_PREAMBLE_S1G_1M ? MM_S1G_PPDU_1M : MM_S1G_PPDU_SHORT;
        const unsigned int bw = MM_RATECODE_BW_IDX(st->ratecode);

        known |= MM_S1G_KNOWN_PPDU | MM_S1G_KNOWN_GI | MM_S1G_KNOWN_NSS | MM_S1G_KNOWN_MCS;
        data1 |= (uint16_t) (ppdu & 0x3);
        data1 |= (uint16_t) (MM_RATECODE_SGI(st->ratecode) << 5);
        data1 |= (uint16_t) (((MM_RATECODE_NSS(st->ratecode) - 1) & 0x3) << 6);
        data1 |= (uint16_t) (MM_RATECODE_MCS(st->ratecode) << 12);

        /* 1, 2, 4, 8 and 16 MHz */
        if (bw <= 4) {
            known |= MM_S1G_KNOWN_BW;
            data1 |= (uint16_t) (bw << 8);
        }
    }

    mm_put_le16(p, MM_RT_TLV_S1G);
    mm_put_le16(p + 2, MM_RT_S1G_LEN);
    mm_put_le16(p + 4, known);
    mm_put_le16(p + 6, data1);
    mm_put_le16(p + 8, data2);

    /* OUI, sub-namespace 0, vendor type, reserved, then the frequency */
    p += 12;
    mm_put_le16(p, MM_RT_TLV_VENDOR);
    mm_put_le16(p + 2, MM_RT_VENDOR_LEN);
    memcpy(p + 4, mm_morse_oui, sizeof(mm_morse_oui));
    mm_put_le16(p + 8, MM_MORSE_VENDOR_FREQ_KHZ);
    mm_put_le32(p + 12, st->freq_khz);
}

static void mm_mac_rx(void *ctx, const struct mm_rx_status *st, const uint8_t *frame, size_t len) {
    struct mm_mac *m = ctx;
    struct ieee80211_rx_status *status;
    const bool bad = (st->flags & (MM_RX_FLAG_ERROR | MM_RX_FLAG_CRC_ERROR)) != 0;
    const unsigned int bw_idx = MM_RATECODE_BW_IDX(st->ratecode);
    struct sk_buff *skb;
    int n = (int) len;

    if (!m->started || m->rx_freq == 0 || (st->flags & MM_RX_FLAG_NDP))
        return;

    if (st->flags & MM_RX_FLAG_FCS_INCLUDED) {
        if (len < 4)
            return;
        n -= 4;
    }

    if (m->sta_vif != NULL) {
        if (bad || (n = mm_s1g_rx(&m->conv, m->pri1, frame, (size_t) n, m->rx_buf,
                        sizeof(m->rx_buf))) <= 0)
            return;
        frame = m->rx_buf;
    }

    if ((skb = dev_alloc_skb((unsigned int) n + 64)) == NULL)
        return;
    skb_reserve(skb, 64);
    skb_put_data(skb, frame, (unsigned int) n);

    status = IEEE80211_SKB_RXCB(skb);
    memset(status, 0, sizeof(*status));

    /* As sent, the frame is S1G; say so, in front of the 802.11 header */
    if (m->sta_vif == NULL) {
        skb_reset_mac_header(skb);
        mm_mac_rx_tlvs(st, skb_push(skb, MM_RT_TLVS_LEN));
        status->flag |= RX_FLAG_RADIOTAP_TLV_AT_END;
    }

    /* The chip's timer at frame detection */
    status->mactime = st->timestamp_us;
    status->flag |= RX_FLAG_MACTIME_START;
    status->band = NL80211_BAND_5GHZ;
    /* A BSS heard off its primary is reported on its primary, as the frame describes it */
    status->freq = (u16) (m->sta_vif != NULL && m->conv.rx_pri_5g ?
            mm_mac_5g_freq(m->conv.rx_pri_5g) : m->rx_freq);
    status->signal = st->rssi;
    status->encoding = RX_ENC_VHT;
    status->rate_idx = (u8) min_t(unsigned int, MM_RATECODE_MCS(st->ratecode), 9);
    status->nss = (u8) MM_RATECODE_NSS(st->ratecode);
    status->bw = bw_idx >= 3 ? RATE_INFO_BW_160 : bw_idx == 2 ? RATE_INFO_BW_80 :
        bw_idx == 1 ? RATE_INFO_BW_40 : RATE_INFO_BW_20;
    if (MM_RATECODE_SGI(st->ratecode))
        status->enc_flags |= RX_ENC_FLAG_SHORT_GI;
    if (bad)
        status->flag |= RX_FLAG_FAILED_FCS_CRC;

    ieee80211_rx_irqsafe(m->hw, skb);
}

static int mm_mac_thread(void *data) {
    struct mm_mac *m = data;
    struct mm8108_dev *dev = &m->dev;
    int r;

    while (!kthread_should_stop()) {
        wait_event_timeout(dev->irq_wq, kthread_should_stop() || dev->irq_pending ||
                dev->int_error != 0 || (!m->tx_blocked && !skb_queue_empty(&m->txq)),
                msecs_to_jiffies(MM_MAC_SERVICE_MS));

        if (kthread_should_stop())
            break;

        mutex_lock(&m->lock);

        if (!m->dead) {
            if (dev->irq_pending)
                m->tx_blocked = false;

            if ((r = mm8108_poll(dev, 0)) < 0) {
                dev_err(&m->intf->dev, "chip stopped responding: %d", r);
                m->dead = true;
            } else {
                mm_mac_tx_drain(m);
            }
        }

        mm_mac_tx_expire(m, m->dead);
        mutex_unlock(&m->lock);

        if (m->dead)
            msleep(MM_MAC_SERVICE_MS);
    }

    return 0;
}

static void mm_mac_op_tx(struct ieee80211_hw *hw, struct ieee80211_tx_control *control,
        struct sk_buff *skb) {
    struct mm_mac *m = hw->priv;
    (void) control;

    if (skb->len < 10 || skb->len > MM_MAC_MAX_FRAME - 64 || skb_queue_len(&m->txq) >= MM_MAC_TXQ_MAX) {
        mm_mac_complete(m, skb, false);
        return;
    }

    skb_queue_tail(&m->txq, skb);

    if (skb_queue_len(&m->txq) >= MM_MAC_TXQ_MAX / 2 && !m->queues_stopped) {
        m->queues_stopped = true;
        ieee80211_stop_queues(hw);
    }

    wake_up(&m->dev.irq_wq);
}

static int mm_mac_op_start(struct ieee80211_hw *hw) {
    struct mm_mac *m = hw->priv;
    struct task_struct *t;

    m->tx_blocked = false;
    m->started = true;

    t = kthread_run(mm_mac_thread, m, "mm8108");
    if (IS_ERR(t)) {
        m->started = false;
        return PTR_ERR(t);
    }
    m->thread = t;

    return 0;
}

static void mm_mac_op_stop(struct ieee80211_hw *hw, bool suspend) {
    struct mm_mac *m = hw->priv;
    struct sk_buff *skb;
    (void) suspend;

    if (m->thread != NULL) {
        kthread_stop(m->thread);
        m->thread = NULL;
    }

    mutex_lock(&m->lock);
    m->started = false;
    mm_mac_tx_expire(m, true);
    while ((skb = skb_dequeue(&m->txq)) != NULL)
        mm_mac_complete(m, skb, false);
    mutex_unlock(&m->lock);
}

static int mm_mac_op_add_interface(struct ieee80211_hw *hw, struct ieee80211_vif *vif) {
    struct mm_mac *m = hw->priv;
    int r;

    guard(mutex)(&m->lock);

    switch (vif->type) {
        case NL80211_IFTYPE_MONITOR:
            m->want_monitor = true;
            return m->sta_vif != NULL ? 0 : mm_cmd_add_monitor(&m->dev);

        case NL80211_IFTYPE_STATION:
            if (m->sta_vif != NULL)
                return -EBUSY;
            /* With its monitor interface the chip doesn't acknowledge frames to the
             * station, so the station takes its place, scanning so it still passes on every
             * BSS's beacons */
            mm_cmd_remove_monitor(&m->dev);
            if ((r = mm_cmd_add_station(&m->dev, vif->addr)) < 0) {
                if (m->want_monitor)
                    mm_cmd_add_monitor(&m->dev);
                return r;
            }
            mm_cmd_scan_config(&m->dev, m->dev.sta_vif_id, true);
            memset(m->bssid, 0, sizeof(m->bssid));
            mm_s1g_conv_init(&m->conv, m->region);
            m->sta_vif = vif;
            return 0;

        default:
            return -EOPNOTSUPP;
    }
}

static void mm_mac_op_remove_interface(struct ieee80211_hw *hw, struct ieee80211_vif *vif) {
    struct mm_mac *m = hw->priv;

    guard(mutex)(&m->lock);

    if (vif->type == NL80211_IFTYPE_MONITOR) {
        m->want_monitor = false;
        mm_cmd_remove_monitor(&m->dev);
    } else if (vif == m->sta_vif) {
        mm_cmd_remove_station(&m->dev);
        m->sta_vif = NULL;
        if (m->want_monitor)
            mm_cmd_add_monitor(&m->dev);
    }
}

static int mm_mac_op_config(struct ieee80211_hw *hw, int radio_idx, u32 changed) {
    struct mm_mac *m = hw->priv;
    (void) radio_idx;

    if (!(changed & IEEE80211_CONF_CHANGE_CHANNEL))
        return 0;

    guard(mutex)(&m->lock);
    return mm_mac_tune(m, &hw->conf.chandef);
}

static void mm_mac_op_configure_filter(struct ieee80211_hw *hw, unsigned int changed,
        unsigned int *total, u64 multicast) {
    (void) hw; (void) changed; (void) multicast;
    *total &= FIF_ALLMULTI | FIF_FCSFAIL | FIF_CONTROL | FIF_OTHER_BSS | FIF_BCN_PRBRESP_PROMISC |
        FIF_PROBE_REQ;
}

static const struct ieee80211_ops mm_mac_ops = {
    .tx = mm_mac_op_tx,
    .start = mm_mac_op_start,
    .stop = mm_mac_op_stop,
    .add_interface = mm_mac_op_add_interface,
    .remove_interface = mm_mac_op_remove_interface,
    .config = mm_mac_op_config,
    .configure_filter = mm_mac_op_configure_filter,
    .add_chanctx = ieee80211_emulate_add_chanctx,
    .remove_chanctx = ieee80211_emulate_remove_chanctx,
    .change_chanctx = ieee80211_emulate_change_chanctx,
    .switch_vif_chanctx = ieee80211_emulate_switch_vif_chanctx,
};

static void mm_mac_print_chanmap(struct ieee80211_hw *hw, FILE *out) {
    struct mm_mac *m = hw->priv;

    fprintf(out, "\n802.11ah channels (%s) as 5GHz channels: 1/2/4/8MHz S1G is 20/40/80/160MHz\n",
            m->region->country);
    fprintf(out, "  %-7s %-6s %-10s %-8s %s\n", "S1G ch", "Width", "Center", "5GHz ch", "5GHz center");

    for (unsigned int bw = 1; bw <= 8; bw *= 2) {
        for (size_t i = 0; i < m->region->num_channels; i++) {
            const struct mm_s1g_channel *c = &m->region->channels[i];

            if (c->bw_mhz != bw)
                continue;

            fprintf(out, "  %-7u %uMHz   %3u.%u MHz  %-8u %u MHz%s\n", c->channel, c->bw_mhz,
                    c->freq_khz / 1000, (c->freq_khz % 1000) / 100, c->chan_5g,
                    mm_mac_5g_freq(c->chan_5g), m->usable[i] ? "" : " (disabled by board config)");
        }
    }
}

static bool mm_mac_disabled(const struct mm_s1g_channel *c, const struct mm_disabled_channel *dis,
        size_t num) {
    for (size_t i = 0; i < num; i++)
        if (dis[i].freq_khz == c->freq_khz && dis[i].bw_mhz == c->bw_mhz)
            return true;
    return false;
}

/* The region's 1MHz channels as 5GHz channels, flagged with the widths they can't use */
static int mm_mac_init_band(struct mm_mac *m) {
    struct ieee80211_supported_band *sband = &m->sband;
    bool has_2 = false, has_8 = false;
    int n = 0;

    if ((m->channels = kcalloc(m->region->num_channels, sizeof(*m->channels), GFP_KERNEL)) == NULL)
        return -ENOMEM;

    for (size_t i = 0; i < m->region->num_channels; i++) {
        const struct mm_s1g_channel *c = &m->region->channels[i];
        struct ieee80211_channel *ch;
        const struct mm_s1g_channel *w;
        int pos;

        has_2 |= m->usable[i] && c->bw_mhz == 2;
        has_8 |= m->usable[i] && c->bw_mhz == 8;

        if (c->bw_mhz != 1 || !m->usable[i])
            continue;

        for (pos = n; pos > 0 && m->channels[pos - 1].hw_value > c->chan_5g; pos--)
            m->channels[pos] = m->channels[pos - 1];

        ch = &m->channels[pos];
        memset(ch, 0, sizeof(*ch));
        ch->band = NL80211_BAND_5GHZ;
        ch->center_freq = mm_mac_5g_freq(c->chan_5g);
        ch->hw_value = c->chan_5g;
        ch->max_power = 20;
        ch->max_reg_power = 20;

        w = mm_mac_containing(m, c, 2);
        if (w == NULL || w->chan_5g < c->chan_5g)
            ch->flags |= IEEE80211_CHAN_NO_HT40PLUS;
        if (w == NULL || w->chan_5g > c->chan_5g)
            ch->flags |= IEEE80211_CHAN_NO_HT40MINUS;
        if (mm_mac_containing(m, c, 4) == NULL)
            ch->flags |= IEEE80211_CHAN_NO_80MHZ;
        if (mm_mac_containing(m, c, 8) == NULL)
            ch->flags |= IEEE80211_CHAN_NO_160MHZ;
        ch->orig_flags = ch->flags;
        n++;
    }

    if (n == 0)
        return -ENODEV;

    sband->band = NL80211_BAND_5GHZ;
    sband->channels = m->channels;
    sband->n_channels = n;
    sband->bitrates = mm_mac_bitrates;
    sband->n_bitrates = ARRAY_SIZE(mm_mac_bitrates);

    sband->ht_cap.ht_supported = true;
    sband->ht_cap.cap = IEEE80211_HT_CAP_SGI_20 |
        (has_2 ? IEEE80211_HT_CAP_SUP_WIDTH_20_40 | IEEE80211_HT_CAP_SGI_40 : 0);
    sband->ht_cap.ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K;
    sband->ht_cap.mcs.rx_mask[0] = 0xff;
    sband->ht_cap.mcs.tx_params = IEEE80211_HT_MCS_TX_DEFINED;

    sband->vht_cap.vht_supported = true;
    sband->vht_cap.cap = IEEE80211_VHT_CAP_SHORT_GI_80 |
        (has_8 ? IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ | IEEE80211_VHT_CAP_SHORT_GI_160 : 0);
    sband->vht_cap.vht_mcs.rx_mcs_map = cpu_to_le16(0xfffe);
    sband->vht_cap.vht_mcs.tx_mcs_map = cpu_to_le16(0xfffe);

    return 0;
}

/* name in the host program's directories, in the layout of this project or of a morse-firmware
 * checkout, then in the system's, in the linux-firmware layout and morse_driver's */
static const char *const mm_fw_host_dirs[] = { "morse/", "", "firmware/", "bcf/morsemicro/" };
static const char *const mm_fw_system_dirs[] = { "morsemicro/mm81x/v" __stringify(MM8108_FW_SEMVER_MAJOR) "/",
    "morse/" };

#define MM_FW_NAME_LEN 128

static int mm_mac_find_in(struct mm_mac *m, const char *name, enum kc_fw_dirs which,
        const struct firmware **fw) {
    const char *const *dirs = which == KC_FW_DIRS_SYSTEM ? mm_fw_system_dirs : mm_fw_host_dirs;
    const size_t num = which == KC_FW_DIRS_SYSTEM ? ARRAY_SIZE(mm_fw_system_dirs) :
        ARRAY_SIZE(mm_fw_host_dirs);
    char paths[ARRAY_SIZE(mm_fw_host_dirs)][MM_FW_NAME_LEN + 32];
    const char *names[ARRAY_SIZE(mm_fw_host_dirs)];

    for (size_t i = 0; i < num; i++) {
        snprintf(paths[i], sizeof(paths[i]), "%s%s", dirs[i], name);
        names[i] = paths[i];
    }

    return kc_firmware_request_in(fw, names, num, &m->intf->dev, which);
}

static int mm_mac_find(struct mm_mac *m, const char *name, const struct firmware **fw) {
    if (mm_mac_find_in(m, name, KC_FW_DIRS_HOST, fw) == 0)
        return 0;
    return mm_mac_find_in(m, name, KC_FW_DIRS_SYSTEM, fw);
}

/* linux-firmware firmware for a firmware interface version this driver can't use, as a hint */
static bool mm_mac_other_fw_version(char *out, size_t out_len) {
    const char *const *paths;
    const size_t num = kc_firmware_get_paths(KC_FW_DIRS_SYSTEM, &paths);
    char dirpath[512];

    for (size_t i = 0; i < num; i++) {
        struct dirent *de;
        DIR *dir;

        snprintf(dirpath, sizeof(dirpath), "%s/morsemicro/mm81x", paths[i]);
        if ((dir = opendir(dirpath)) == NULL)
            continue;

        while ((de = readdir(dir)) != NULL) {
            unsigned int v;
            char tail;

            if (sscanf(de->d_name, "v%u%c", &v, &tail) == 1 && v != MM8108_FW_SEMVER_MAJOR) {
                snprintf(out, out_len, "%s/%s", dirpath, de->d_name);
                closedir(dir);
                return true;
            }
        }

        closedir(dir);
    }

    return false;
}

/* The chosen firmware, or the chip revision's, then the name linux-firmware uses */
static int mm_mac_load_firmware(struct mm_mac *m, const struct firmware **fw, char *name,
        size_t name_len) {
    const char *chosen = kc_firmware_choice();
    const char *rev = mm_chip_rev_string(m->dev.chip_id);
    char other[512];

    if (chosen != NULL)
        snprintf(name, name_len, "%s", chosen);
    else
        snprintf(name, name_len, "mm8108%s-rl.bin", rev ? rev : "");

    if (mm_mac_find(m, name, fw) == 0)
        return 0;

    if (chosen == NULL && mm_mac_find(m, "mm8108.bin", fw) == 0) {
        snprintf(name, name_len, "mm8108.bin");
        return 0;
    }

    if (mm_mac_other_fw_version(other, sizeof(other)))
        dev_err(&m->intf->dev, "no firmware %s; %s is for another firmware interface version, "
                "this driver needs v%u.  Firmware is at https://github.com/MorseMicro/morse-firmware",
                name, other, MM8108_FW_SEMVER_MAJOR);
    else
        dev_err(&m->intf->dev, "no firmware %s in the firmware directories; Morse Micro's is at "
                "https://github.com/MorseMicro/morse-firmware", name);
    return -ENOENT;
}

/* The chosen board config, or the board type's own, then the MM8108 reference module's that
 * this project ships (which the MM8108 board types in morse-firmware all use), and only then
 * the system's choice, as morse_driver would make it */
static int mm_mac_load_bcf(struct mm_mac *m, const struct firmware **bcf, char *name,
        size_t name_len) {
    static const char *const reference[] = { "bcf_mf15457.bin", "bcf_mm8108_mf15457.bin" };
    char names[MM_BCF_MAX_NAMES][MM_BCF_NAME_LEN];
    const size_t num = mm_bcf_default_names(&m->dev, names);
    const char *chosen = kc_firmware_board_choice();

    if (chosen != NULL) {
        snprintf(name, name_len, "%s", chosen);
        if (mm_mac_find(m, chosen, bcf) == 0)
            return 0;

        dev_err(&m->intf->dev, "no board config %s in the firmware directories; Morse Micro's are "
                "at https://github.com/MorseMicro/morse-firmware", chosen);
        return -ENOENT;
    }

    if (m->dev.board_type != 0 && mm_mac_find(m, names[0], bcf) == 0) {
        chosen = names[0];
    } else {
        for (size_t i = 0; i < ARRAY_SIZE(reference) && chosen == NULL; i++)
            if (mm_mac_find_in(m, reference[i], KC_FW_DIRS_HOST, bcf) == 0)
                chosen = reference[i];

        for (size_t i = m->dev.board_type != 0 ? 1 : 0; i < num && chosen == NULL; i++)
            if (mm_mac_find_in(m, names[i], KC_FW_DIRS_SYSTEM, bcf) == 0)
                chosen = names[i];
    }

    if (chosen == NULL) {
        dev_err(&m->intf->dev, "no board config for board type 0x%04x; they're at "
                "https://github.com/MorseMicro/morse-firmware, or choose one with the board "
                "config option (uwifi --boardfile, Kismet boardfile=)",
                m->dev.board_type);
        return -ENOENT;
    }

    /* Only the board type's own config is known to match the adapter */
    if (m->dev.board_type == 0 || chosen != names[0])
        dev_warn(&m->intf->dev, "%s; using board config %s.  If the adapter needs a different "
                "one, choose it with the board config option (uwifi --boardfile, Kismet "
                "boardfile=)", m->dev.board_type == 0 ?
                "no board type in OTP" : "unknown board type", chosen);

    snprintf(name, name_len, "%s", chosen);
    return 0;
}

static int mm_mac_boot(struct mm_mac *m) {
    struct mm_disabled_channel dis[128];
    const struct firmware *fw = NULL, *bcf = NULL;
    struct mm8108_boot_config boot = { 0 };
    const char *country;
    char version[64], fw_name[MM_FW_NAME_LEN], bcf_name[MM_FW_NAME_LEN];
    size_t num_dis = 0;
    int r;

    if ((r = mm_read_chip_id(&m->dev)) < 0 || (r = mm_read_otp(&m->dev)) < 0)
        return r;

    /* The OTP country locks the regulatory domain; without one, the user's choice or US */
    country = m->dev.otp_country[0] ? m->dev.otp_country :
        kc_country_choice() ? kc_country_choice() : "US";
    if ((m->region = mm_s1g_region(country)) == NULL) {
        dev_err(&m->intf->dev, "no 802.11ah channels for country %s", country);
        return -EINVAL;
    }

    if ((r = mm_mac_load_firmware(m, &fw, fw_name, sizeof(fw_name))) < 0 ||
            (r = mm_mac_load_bcf(m, &bcf, bcf_name, sizeof(bcf_name))) < 0)
        goto out;

    boot.firmware = fw->data;
    boot.firmware_len = fw->size;
    boot.bcf = bcf->data;
    boot.bcf_len = bcf->size;
    boot.country = m->region->country;

    if ((r = mm_boot(&m->dev, &boot)) < 0 ||
            (r = mm_cmd_get_version(&m->dev, version, sizeof(version))) < 0)
        goto out;

    if (mm_cmd_get_disabled_channels(&m->dev, dis, ARRAY_SIZE(dis), &num_dis) < 0)
        num_dis = 0;

    if ((m->usable = kcalloc(m->region->num_channels, sizeof(*m->usable), GFP_KERNEL)) == NULL) {
        r = -ENOMEM;
        goto out;
    }
    for (size_t i = 0; i < m->region->num_channels; i++)
        m->usable[i] = !mm_mac_disabled(&m->region->channels[i], dis, num_dis);

    snprintf(m->hw->wiphy->fw_version, sizeof(m->hw->wiphy->fw_version), "%s", version);
    dev_info(&m->intf->dev, "%s, board 0x%04x%s%s, firmware %s (%s), board config %s, region %s",
            mm_chip_name(m->dev.chip_id), m->dev.board_type, m->dev.bcf_module[0] ? " " : "",
            m->dev.bcf_module, version, fw_name, bcf_name, m->region->country);

out:
    release_firmware(fw);
    release_firmware(bcf);
    return r;
}

static void mm_mac_free(struct mm_mac *m) {
    mm8108_stop(&m->dev);
    mm8108_free(&m->dev);
    kfree(m->usable);
    kfree(m->channels);
    ieee80211_free_hw(m->hw);
}

static int mm_mac_probe(struct usb_interface *intf, const struct usb_device_id *id) {
    struct ieee80211_hw *hw;
    struct mm_mac *m;
    int r;
    (void) id;

    if ((hw = ieee80211_alloc_hw(sizeof(*m), &mm_mac_ops)) == NULL)
        return -ENOMEM;

    m = hw->priv;
    m->hw = hw;
    m->intf = intf;
    mutex_init(&m->lock);
    skb_queue_head_init(&m->txq);

    if ((r = mm8108_init(&m->dev, 2)) < 0) {
        ieee80211_free_hw(hw);
        return r;
    }

    mm8108_set_rx_cb(&m->dev, mm_mac_rx, m);
    mm8108_set_tx_status_cb(&m->dev, mm_mac_tx_status, m);

    if ((r = mm_usb_open(&m->dev, intf)) < 0 || (r = mm_mac_boot(m)) < 0 ||
            (r = mm_mac_init_band(m)) < 0) {
        if (m->dev.errstr[0])
            dev_err(&intf->dev, "%s", m->dev.errstr);
        mm_mac_free(m);
        return r;
    }

    SET_IEEE80211_DEV(hw, &intf->dev);
    SET_IEEE80211_PERM_ADDR(hw, m->dev.mac);
    hw->queues = 4;
    hw->extra_tx_headroom = 0;
    ieee80211_hw_set(hw, SIGNAL_DBM);
    ieee80211_hw_set(hw, HAS_RATE_CONTROL);
    ieee80211_hw_set(hw, WANT_MONITOR_VIF);
    ieee80211_hw_set(hw, REPORTS_TX_ACK_STATUS);
    hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_MONITOR) | BIT(NL80211_IFTYPE_STATION);
    hw->wiphy->bands[NL80211_BAND_5GHZ] = &m->sband;
    hw->wiphy->available_antennas_tx = 1;
    hw->wiphy->available_antennas_rx = 1;

    usb_set_intfdata(intf, m);

    if ((r = ieee80211_register_hw(hw)) < 0) {
        usb_set_intfdata(intf, NULL);
        mm_mac_free(m);
        return r;
    }

    kc_mac80211_set_chanmap_cb(hw, mm_mac_print_chanmap);
    /* The region the chip booted with, which a later regulatory change doesn't move */
    kc_mac80211_set_regdomain(hw, m->region->country);
    return 0;
}

static void mm_mac_disconnect(struct usb_interface *intf) {
    struct mm_mac *m = usb_get_intfdata(intf);

    if (m == NULL)
        return;

    ieee80211_unregister_hw(m->hw);
    usb_set_intfdata(intf, NULL);
    mm_mac_free(m);
}

static const struct usb_device_id mm_mac_table[] = {
    { USB_DEVICE(0x325b, 0x8100) },
    { },
};
MODULE_DEVICE_TABLE(usb, mm_mac_table);

static struct usb_driver mm_mac_driver = {
    .name = "mm8108",
    .id_table = mm_mac_table,
    .probe = mm_mac_probe,
    .disconnect = mm_mac_disconnect,
};

module_usb_driver(mm_mac_driver);
