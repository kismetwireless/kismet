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

#include <poll.h>

#include "genl.h"
#include "hwsim.h"
#include "mac80211_hwsim.h"

/* Unicast frames wait this long for the driver's TX status or an ACK seen on air */
#define TX_STATUS_WAIT_MS 60
#define TX_PENDING_MAX 256
/* The radio's operating channel is checked this often, and followed once the radio hasn't
 * sent on another channel for TX_CHANNEL_HOLD_MS */
#define CHANNEL_POLL_MS 250
#define TX_CHANNEL_HOLD_MS 400

/* Until the radio has an operating channel the adapter hops its own channels this often, and
 * the beacons and probe responses it hears are replayed to the radio, which takes those on
 * whichever channel it is scanning: a passive scan sends nothing to follow */
#define IDLE_HOP_MS 300
#define BSS_REPLAY_MS 20
#define BSS_CACHE_MAX 32
#define BSS_CACHE_AGE_MS 30000

/* mac80211_hwsim's legacy rates; 5 and 6GHz start at 6 Mbps */
static const u16 hwsim_bitrates[] = { 10, 20, 55, 110, 60, 90, 120, 180, 240, 360, 480, 540 };
#define HWSIM_OFDM_OFFSET 4

struct tx_pending {
    u64 cookie;
    u32 flags;
    u8 addr1[ETH_ALEN];
    __le16 fc;
    __le16 seq_ctrl;
    struct hwsim_tx_rate rates[IEEE80211_TX_MAX_RATES];
    u64 sent_ms;
    bool driver_status;
    bool acked;
};

struct bss_entry {
    u8 bssid[ETH_ALEN];
    u32 freq;
    __le16 fc;
    u32 rx_rate;
    s32 signal;
    u64 seen_ms;
    size_t len;
    u8 *frame;
};

struct hwsim_bridge {
    struct uwifi_dev *dev;
    struct ieee80211_hw *hw;
    u8 mac[ETH_ALEN];
    char name[64];

    struct uwifi_genl *hwsim;
    struct uwifi_genl *nl80211;
    u32 wiphy;
    bool have_wiphy;
    char ifname[32];

    /* Tuned channel; changed only from the main loop */
    u32 freq;
    enum nl80211_chan_width width;
    u32 center_freq1;
    u64 last_tx_other_ms;
    u64 last_tx_ms;

    /* No operating channel: hop and replay (see IDLE_HOP_MS) */
    bool connected;
    u32 *hop_freqs;
    size_t n_hops, hop_idx;
    u64 next_hop_ms, next_replay_ms;
    struct bss_entry bss[BSS_CACHE_MAX];

    pthread_mutex_t lock;
    struct tx_pending pending[TX_PENDING_MAX];
    size_t n_pending;
    u64 last_ack_ms;

    unsigned long tx_frames, tx_errors, tx_acked, rx_frames, retunes;
};

static enum nl80211_band freq_band(u32 freq) {
    if (freq < 3000)
        return NL80211_BAND_2GHZ;
    if (freq >= 5955 && freq <= 7115)
        return NL80211_BAND_6GHZ;
    return NL80211_BAND_5GHZ;
}

static int bridge_tune(struct hwsim_bridge *b, u32 freq, enum nl80211_chan_width width, u32 center_freq1) {
    enum nl80211_band band = freq_band(freq);
    int chan = ieee80211_frequency_to_channel(freq);
    struct cfg80211_chan_def def;
    int r;

    if (width == NL80211_CHAN_WIDTH_20_NOHT)
        width = NL80211_CHAN_WIDTH_20;

    if (freq == b->freq && width == b->width && (width == NL80211_CHAN_WIDTH_20 || center_freq1 == b->center_freq1))
        return 0;

    if (width != NL80211_CHAN_WIDTH_20 && !uwifi_band_width_ok(b->dev, band, width))
        width = NL80211_CHAN_WIDTH_20;
    if (width == NL80211_CHAN_WIDTH_20)
        center_freq1 = 0;

    if ((r = kc_mac80211_chandef(b->hw, band, chan, width, center_freq1, &def)) < 0 ||
            (r = kc_mac80211_set_chandef(b->hw, &def)) < 0) {
        if (width == NL80211_CHAN_WIDTH_20)
            return r;
        return bridge_tune(b, freq, NL80211_CHAN_WIDTH_20, 0);
    }

    b->freq = freq;
    b->width = width;
    b->center_freq1 = center_freq1;
    b->retunes++;
    return 0;
}

/* TX status back to the radio; mac80211 learns the ACK and the rates tried */
static void bridge_tx_info(struct hwsim_bridge *b, const struct tx_pending *p, bool acked) {
    struct uwifi_genl_msg *m = malloc(sizeof(*m));
    struct hwsim_tx_rate rates[IEEE80211_TX_MAX_RATES];

    if (m == NULL)
        return;

    memcpy(rates, p->rates, sizeof(rates));
    /* As wmediumd reports: an acknowledged frame got through on its first rate's tries */
    if (acked) {
        if (rates[0].count == 0)
            rates[0].count = 1;
        for (int i = 1; i < IEEE80211_TX_MAX_RATES; i++)
            rates[i].idx = -1;
    }

    uwifi_genl_msg_init(b->hwsim, m, HWSIM_CMD_TX_INFO_FRAME, 0);
    uwifi_genl_put(m, HWSIM_ATTR_ADDR_TRANSMITTER, b->mac, ETH_ALEN);
    uwifi_genl_put_u32(m, HWSIM_ATTR_FLAGS, p->flags | (acked ? HWSIM_TX_STAT_ACK : 0));
    uwifi_genl_put_u32(m, HWSIM_ATTR_SIGNAL, (u32) -50);
    uwifi_genl_put(m, HWSIM_ATTR_TX_INFO, rates, sizeof(rates));
    uwifi_genl_put_u64(m, HWSIM_ATTR_COOKIE, p->cookie);
    uwifi_genl_send(b->hwsim, m);
    free(m);

    if (acked)
        b->tx_acked++;
}

/* Answers frames whose status is in, or which have waited long enough */
static void bridge_resolve(struct hwsim_bridge *b, u64 now) {
    struct tx_pending done[TX_PENDING_MAX];
    bool acked[TX_PENDING_MAX];
    size_t n_done = 0, keep = 0;

    pthread_mutex_lock(&b->lock);
    for (size_t i = 0; i < b->n_pending; i++) {
        struct tx_pending *p = &b->pending[i];
        bool ack_seen = b->last_ack_ms >= p->sent_ms;

        if (p->driver_status || ack_seen || now - p->sent_ms >= TX_STATUS_WAIT_MS) {
            acked[n_done] = p->acked || ack_seen;
            done[n_done++] = *p;
        } else {
            b->pending[keep++] = *p;
        }
    }
    b->n_pending = keep;
    pthread_mutex_unlock(&b->lock);

    for (size_t i = 0; i < n_done; i++)
        bridge_tx_info(b, &done[i], acked[i]);
}

/* Radiotap for a frame from the radio: its first rate, retries and no-ACK */
static size_t bridge_radiotap(u8 *buf, const struct hwsim_tx_rate *rate, const struct hwsim_tx_rate_flag *rflag,
        enum nl80211_band band, bool noack) {
    u32 present = BIT(IEEE80211_RADIOTAP_TX_FLAGS) | BIT(IEEE80211_RADIOTAP_DATA_RETRIES);
    u16 flags = rflag ? rflag->flags : 0;
    size_t len = 8;

    if (rate->idx >= 0 && (flags & MAC80211_HWSIM_TX_RC_VHT_MCS))
        present |= BIT(IEEE80211_RADIOTAP_VHT);
    else if (rate->idx >= 0 && (flags & MAC80211_HWSIM_TX_RC_MCS))
        present |= BIT(IEEE80211_RADIOTAP_MCS);
    else if (rate->idx >= 0)
        present |= BIT(IEEE80211_RADIOTAP_RATE);

    if (present & BIT(IEEE80211_RADIOTAP_RATE)) {
        int idx = rate->idx + (band == NL80211_BAND_2GHZ ? 0 : HWSIM_OFDM_OFFSET);
        buf[len++] = idx < (int) ARRAY_SIZE(hwsim_bitrates) ? (u8) (hwsim_bitrates[idx] / 5) : 2;
    }

    len = ALIGN(len, 2);
    put_unaligned_le16(noack ? IEEE80211_RADIOTAP_F_TX_NOACK : 0, buf + len);
    len += 2;

    buf[len++] = rate->count > 1 ? (u8) (rate->count - 1) : 0;

    if (present & BIT(IEEE80211_RADIOTAP_MCS)) {
        buf[len++] = IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI;
        buf[len++] = ((flags & MAC80211_HWSIM_TX_RC_40_MHZ_WIDTH) ? IEEE80211_RADIOTAP_MCS_BW_40 : 0) |
            ((flags & MAC80211_HWSIM_TX_RC_SHORT_GI) ? IEEE80211_RADIOTAP_MCS_SGI : 0);
        buf[len++] = (u8) rate->idx;
    }

    if (present & BIT(IEEE80211_RADIOTAP_VHT)) {
        u8 bw = 0;

        if (flags & MAC80211_HWSIM_TX_RC_160_MHZ_WIDTH)
            bw = 11;
        else if (flags & MAC80211_HWSIM_TX_RC_80_MHZ_WIDTH)
            bw = 4;
        else if (flags & MAC80211_HWSIM_TX_RC_40_MHZ_WIDTH)
            bw = 1;

        len = ALIGN(len, 2);
        put_unaligned_le16(IEEE80211_RADIOTAP_VHT_KNOWN_GI | IEEE80211_RADIOTAP_VHT_KNOWN_BANDWIDTH, buf + len);
        buf[len + 2] = (flags & MAC80211_HWSIM_TX_RC_SHORT_GI) ? IEEE80211_RADIOTAP_VHT_FLAG_SGI : 0;
        buf[len + 3] = bw;
        /* hwsim's idx is NSS - 1 in the high nibble and the MCS in the low */
        buf[len + 4] = (u8) (((rate->idx & 0xf) << 4) | (((rate->idx >> 4) & 0xf) + 1));
        memset(buf + len + 5, 0, 7);
        len += 12;
    }

    buf[0] = 0;
    buf[1] = 0;
    put_unaligned_le16((u16) len, buf + 2);
    put_unaligned_le32(present, buf + 4);
    return len;
}

/* A frame the kernel sent on the radio */
static void bridge_frame_from_radio(struct hwsim_bridge *b, const struct uwifi_genl_attr *attrs) {
    const struct uwifi_genl_attr *frame = &attrs[HWSIM_ATTR_FRAME];
    struct hwsim_tx_rate rates[IEEE80211_TX_MAX_RATES];
    const struct hwsim_tx_rate_flag *rflags = NULL;
    struct tx_pending p = { 0 };
    u8 buf[64 + IEEE80211_MAX_DATA_LEN];
    u32 freq = uwifi_genl_u32(&attrs[HWSIM_ATTR_FREQ]);
    size_t rt;
    int r;

    if (attrs[HWSIM_ATTR_ADDR_TRANSMITTER].len != ETH_ALEN ||
            memcmp(attrs[HWSIM_ATTR_ADDR_TRANSMITTER].data, b->mac, ETH_ALEN) != 0)
        return;

    if (frame->data == NULL || frame->len < 10 || frame->len > IEEE80211_MAX_DATA_LEN ||
            attrs[HWSIM_ATTR_COOKIE].data == NULL)
        return;

    for (int i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
        rates[i].idx = -1;
        rates[i].count = 0;
    }
    if (attrs[HWSIM_ATTR_TX_INFO].data)
        memcpy(rates, attrs[HWSIM_ATTR_TX_INFO].data, min_t(size_t, sizeof(rates), attrs[HWSIM_ATTR_TX_INFO].len));
    if (attrs[HWSIM_ATTR_TX_INFO_FLAGS].len >= sizeof(*rflags))
        rflags = attrs[HWSIM_ATTR_TX_INFO_FLAGS].data;

    p.cookie = uwifi_genl_u64(&attrs[HWSIM_ATTR_COOKIE]);
    p.flags = uwifi_genl_u32(&attrs[HWSIM_ATTR_FLAGS]);
    memcpy(p.rates, rates, sizeof(rates));

    const struct ieee80211_hdr *hdr = frame->data;
    p.fc = hdr->frame_control;
    memcpy(p.addr1, hdr->addr1, ETH_ALEN);
    if (frame->len >= 24)
        p.seq_ctrl = hdr->seq_ctrl;

    if (freq) {
        if (freq != b->freq)
            b->last_tx_other_ms = kc_jiffies_now();
        /* Keep the operating width when sending on its primary channel */
        if (freq != b->freq || b->width == NL80211_CHAN_WIDTH_20)
            bridge_tune(b, freq, NL80211_CHAN_WIDTH_20, 0);
    }

    bool noack = (p.flags & HWSIM_TX_CTL_NO_ACK) || is_multicast_ether_addr(hdr->addr1);

    rt = bridge_radiotap(buf, &rates[0], rflags, freq_band(b->freq), noack);
    memcpy(buf + rt, frame->data, frame->len);

    p.sent_ms = kc_jiffies_now();
    b->last_tx_ms = p.sent_ms;

    /* Register before sending, so a quick status finds it */
    if (!noack) {
        pthread_mutex_lock(&b->lock);
        if (b->n_pending < TX_PENDING_MAX)
            b->pending[b->n_pending++] = p;
        else
            noack = true;
        pthread_mutex_unlock(&b->lock);
    }

    while ((r = uwifi_tx(b->dev, buf, rt + frame->len)) == -EBUSY)
        msleep(1);

    if (r < 0) {
        b->tx_errors++;
        if (!noack) {
            pthread_mutex_lock(&b->lock);
            for (size_t i = 0; i < b->n_pending; i++) {
                if (b->pending[i].cookie == p.cookie) {
                    b->pending[i] = b->pending[--b->n_pending];
                    break;
                }
            }
            pthread_mutex_unlock(&b->lock);
        }
        bridge_tx_info(b, &p, false);
        return;
    }

    b->tx_frames++;
    if (noack)
        bridge_tx_info(b, &p, false);
}

static void bridge_hwsim_cb(void *ctx, u8 cmd, const struct uwifi_genl_attr *attrs, int max) {
    (void) max;
    if (cmd == HWSIM_CMD_FRAME)
        bridge_frame_from_radio(ctx, attrs);
}

/* TX status from the adapter's driver, matched to the radio's frame by address and sequence */
static void bridge_tx_status(void *ctx, struct ieee80211_hw *hw, const u8 *data, size_t len, bool acked) {
    struct hwsim_bridge *b = ctx;
    const struct ieee80211_hdr *hdr = (const void *) data;
    (void) hw;

    if (len < 24)
        return;

    pthread_mutex_lock(&b->lock);
    for (size_t i = 0; i < b->n_pending; i++) {
        struct tx_pending *p = &b->pending[i];

        if (p->driver_status || p->fc != hdr->frame_control || p->seq_ctrl != hdr->seq_ctrl ||
                memcmp(p->addr1, hdr->addr1, ETH_ALEN) != 0)
            continue;

        p->driver_status = true;
        p->acked = acked;
        break;
    }
    pthread_mutex_unlock(&b->lock);
}

static u32 bridge_rx_rate(struct hwsim_bridge *b, const struct ieee80211_rx_status *status) {
    const struct ieee80211_supported_band *sband = b->hw->wiphy->bands[status->band];
    size_t first = status->band == NL80211_BAND_2GHZ ? 0 : HWSIM_OFDM_OFFSET;

    if (status->encoding != RX_ENC_LEGACY || sband == NULL || status->rate_idx >= sband->n_bitrates)
        return 0;

    for (size_t i = first; i < ARRAY_SIZE(hwsim_bitrates); i++)
        if (hwsim_bitrates[i] == sband->bitrates[status->rate_idx].bitrate)
            return (u32) (i - first);

    return 0;
}

/* The latest beacon and probe response of each BSS on each channel */
static void bridge_cache_bss(struct hwsim_bridge *b, const struct ieee80211_hdr *hdr, size_t len, u32 freq,
        u32 rx_rate, s32 signal) {
    struct bss_entry *e = NULL, *oldest = &b->bss[0];
    u64 now = kc_jiffies_now();
    u8 *copy;

    if ((copy = malloc(len)) == NULL)
        return;
    memcpy(copy, hdr, len);

    pthread_mutex_lock(&b->lock);
    for (size_t i = 0; i < BSS_CACHE_MAX && e == NULL; i++) {
        struct bss_entry *c = &b->bss[i];

        if (c->frame && c->freq == freq && c->fc == hdr->frame_control && ether_addr_equal(c->bssid, hdr->addr3))
            e = c;
        else if (c->frame == NULL || (oldest->frame && c->seen_ms < oldest->seen_ms))
            oldest = c;
    }
    if (e == NULL)
        e = oldest;

    free(e->frame);
    memcpy(e->bssid, hdr->addr3, ETH_ALEN);
    e->freq = freq;
    e->fc = hdr->frame_control;
    e->rx_rate = rx_rate;
    e->signal = signal;
    e->seen_ms = now;
    e->len = len;
    e->frame = copy;
    pthread_mutex_unlock(&b->lock);
}

static void bridge_replay_bss(struct hwsim_bridge *b, u64 now) {
    struct uwifi_genl_msg *m = malloc(sizeof(*m));

    if (m == NULL)
        return;

    pthread_mutex_lock(&b->lock);
    for (size_t i = 0; i < BSS_CACHE_MAX; i++) {
        struct bss_entry *e = &b->bss[i];

        if (e->frame == NULL)
            continue;

        if (now - e->seen_ms >= BSS_CACHE_AGE_MS) {
            free(e->frame);
            e->frame = NULL;
            continue;
        }

        uwifi_genl_msg_init(b->hwsim, m, HWSIM_CMD_FRAME, 0);
        uwifi_genl_put(m, HWSIM_ATTR_ADDR_RECEIVER, b->mac, ETH_ALEN);
        uwifi_genl_put(m, HWSIM_ATTR_FRAME, e->frame, e->len);
        uwifi_genl_put_u32(m, HWSIM_ATTR_RX_RATE, e->rx_rate);
        uwifi_genl_put_u32(m, HWSIM_ATTR_SIGNAL, (u32) e->signal);
        uwifi_genl_put_u32(m, HWSIM_ATTR_FREQ, e->freq);
        uwifi_genl_send(b->hwsim, m);
    }
    pthread_mutex_unlock(&b->lock);
    free(m);
}

static void bridge_clear_bss(struct hwsim_bridge *b) {
    pthread_mutex_lock(&b->lock);
    for (size_t i = 0; i < BSS_CACHE_MAX; i++) {
        free(b->bss[i].frame);
        b->bss[i].frame = NULL;
    }
    pthread_mutex_unlock(&b->lock);
}

/* Every enabled 20MHz channel the adapter has */
static void bridge_build_hops(struct hwsim_bridge *b) {
    struct wiphy *wiphy = b->hw->wiphy;
    size_t n = 0;

    for (int band = 0; band < NUM_NL80211_BANDS; band++)
        if (wiphy->bands[band])
            n += wiphy->bands[band]->n_channels;

    if ((b->hop_freqs = calloc(n ? n : 1, sizeof(*b->hop_freqs))) == NULL)
        return;

    for (int band = 0; band < NUM_NL80211_BANDS; band++) {
        const struct ieee80211_supported_band *sband = wiphy->bands[band];

        for (int c = 0; sband && c < sband->n_channels; c++)
            if (!(sband->channels[c].flags & IEEE80211_CHAN_DISABLED))
                b->hop_freqs[b->n_hops++] = sband->channels[c].center_freq;
    }
}

static void bridge_idle(struct hwsim_bridge *b, u64 now) {
    if (b->connected)
        return;

    if (now >= b->next_replay_ms) {
        bridge_replay_bss(b, now);
        b->next_replay_ms = now + BSS_REPLAY_MS;
    }

    /* Frames from the radio set the channel for a while */
    if (b->n_hops && now >= b->next_hop_ms && now - b->last_tx_ms >= TX_CHANNEL_HOLD_MS) {
        bridge_tune(b, b->hop_freqs[b->hop_idx], NL80211_CHAN_WIDTH_20, 0);
        b->hop_idx = (b->hop_idx + 1) % b->n_hops;
        b->next_hop_ms = now + IDLE_HOP_MS;
    }
}

/* A frame the adapter received, passed to the radio */
static void bridge_rx(void *ctx, struct ieee80211_hw *hw, const struct ieee80211_rx_status *status,
        const u8 *data, size_t len) {
    struct hwsim_bridge *b = ctx;
    struct ieee80211_radiotap_iterator it;
    struct uwifi_genl_msg *m;
    const struct ieee80211_hdr *hdr;
    bool fcs = false;
    u16 rtlen;
    (void) hw;

    if (status->flag & RX_FLAG_FAILED_FCS_CRC)
        return;

    if (len < sizeof(struct ieee80211_radiotap_header) ||
            ieee80211_radiotap_iterator_init(&it, (struct ieee80211_radiotap_header *) data, (int) len, NULL) < 0)
        return;
    rtlen = ieee80211_get_radiotap_len((const char *) data);

    while (ieee80211_radiotap_iterator_next(&it) == 0) {
        if (it.this_arg_index == IEEE80211_RADIOTAP_FLAGS) {
            if (*it.this_arg & IEEE80211_RADIOTAP_F_BADFCS)
                return;
            fcs = *it.this_arg & IEEE80211_RADIOTAP_F_FCS;
        }
    }

    if (len < rtlen + (fcs ? 4u : 0u) + 10)
        return;
    data += rtlen;
    len -= rtlen + (fcs ? 4 : 0);
    hdr = (const void *) data;

    /* ACKs to the radio's address settle its frames' TX status */
    if (ieee80211_is_ack(hdr->frame_control)) {
        if (ether_addr_equal(hdr->addr1, b->mac)) {
            pthread_mutex_lock(&b->lock);
            b->last_ack_ms = kc_jiffies_now();
            pthread_mutex_unlock(&b->lock);
        }
        return;
    }

    /* hwsim takes nothing shorter than a 3-address header, so no other control frames */
    if (len < 24 || ether_addr_equal(hdr->addr2, b->mac))
        return;

    if ((m = malloc(sizeof(*m))) == NULL)
        return;

    s32 signal = status->signal ? status->signal : -50;
    u32 rx_rate = bridge_rx_rate(b, status);

    if (ieee80211_is_beacon(hdr->frame_control) || ieee80211_is_probe_resp(hdr->frame_control))
        bridge_cache_bss(b, hdr, len, status->freq, rx_rate, signal);

    uwifi_genl_msg_init(b->hwsim, m, HWSIM_CMD_FRAME, 0);
    uwifi_genl_put(m, HWSIM_ATTR_ADDR_RECEIVER, b->mac, ETH_ALEN);
    uwifi_genl_put(m, HWSIM_ATTR_FRAME, data, len);
    uwifi_genl_put_u32(m, HWSIM_ATTR_RX_RATE, rx_rate);
    uwifi_genl_put_u32(m, HWSIM_ATTR_SIGNAL, (u32) signal);
    uwifi_genl_put_u32(m, HWSIM_ATTR_FREQ, status->freq);
    if (uwifi_genl_send(b->hwsim, m) == 0)
        __atomic_add_fetch(&b->rx_frames, 1, __ATOMIC_RELAXED);
    free(m);
}

/* nl80211: the radio's wiphy index, then its interfaces and their channel */
static void bridge_wiphy_cb(void *ctx, u8 cmd, const struct uwifi_genl_attr *attrs, int max) {
    struct hwsim_bridge *b = ctx;
    const struct uwifi_genl_attr *name = &attrs[NL80211_ATTR_WIPHY_NAME];
    (void) cmd;
    (void) max;

    if (name->data && attrs[NL80211_ATTR_WIPHY].data &&
            strncmp(name->data, b->name, name->len) == 0 && strlen(b->name) + 1 == name->len) {
        b->wiphy = uwifi_genl_u32(&attrs[NL80211_ATTR_WIPHY]);
        b->have_wiphy = true;
    }
}

struct chan_poll {
    struct hwsim_bridge *b;
    u32 freq;
    enum nl80211_chan_width width;
    u32 center_freq1;
};

static void bridge_iface_cb(void *ctx, u8 cmd, const struct uwifi_genl_attr *attrs, int max) {
    struct chan_poll *cp = ctx;
    (void) cmd;
    (void) max;

    if (!attrs[NL80211_ATTR_WIPHY].data || uwifi_genl_u32(&attrs[NL80211_ATTR_WIPHY]) != cp->b->wiphy)
        return;

    if (cp->b->ifname[0] == 0 && attrs[NL80211_ATTR_IFNAME].data)
        snprintf(cp->b->ifname, sizeof(cp->b->ifname), "%.*s", (int) attrs[NL80211_ATTR_IFNAME].len,
                (const char *) attrs[NL80211_ATTR_IFNAME].data);

    if (cp->freq == 0 && attrs[NL80211_ATTR_WIPHY_FREQ].data) {
        cp->freq = uwifi_genl_u32(&attrs[NL80211_ATTR_WIPHY_FREQ]);
        cp->width = attrs[NL80211_ATTR_CHANNEL_WIDTH].data ?
            (enum nl80211_chan_width) uwifi_genl_u32(&attrs[NL80211_ATTR_CHANNEL_WIDTH]) : NL80211_CHAN_WIDTH_20;
        cp->center_freq1 = uwifi_genl_u32(&attrs[NL80211_ATTR_CENTER_FREQ1]);
    }
}

static int bridge_find_wiphy(struct hwsim_bridge *b) {
    struct uwifi_genl_msg *m = malloc(sizeof(*m));
    int r;

    if (m == NULL)
        return -ENOMEM;

    uwifi_genl_msg_init(b->nl80211, m, NL80211_CMD_GET_WIPHY, 0);
    r = uwifi_genl_request(b->nl80211, m, true, bridge_wiphy_cb, b, NL80211_ATTR_MAX);
    free(m);

    if (r < 0)
        return r;
    return b->have_wiphy ? 0 : -ENOENT;
}

/* Follows the radio's operating channel once it isn't sending elsewhere */
static void bridge_poll_channel(struct hwsim_bridge *b) {
    struct uwifi_genl_msg *m = malloc(sizeof(*m));
    struct chan_poll cp = { .b = b };

    if (m == NULL)
        return;

    uwifi_genl_msg_init(b->nl80211, m, NL80211_CMD_GET_INTERFACE, 0);
    uwifi_genl_request(b->nl80211, m, true, bridge_iface_cb, &cp, NL80211_ATTR_MAX);
    free(m);

    if (cp.freq && !b->connected)
        bridge_clear_bss(b);
    b->connected = cp.freq != 0;

    if (cp.freq && kc_jiffies_now() - b->last_tx_other_ms >= TX_CHANNEL_HOLD_MS)
        bridge_tune(b, cp.freq, cp.width, cp.center_freq1);
}

static int bridge_new_radio(struct hwsim_bridge *b, const struct uwifi_hwsim_opts *opts) {
    struct uwifi_genl_msg *m = malloc(sizeof(*m));
    int r;

    if (m == NULL)
        return -ENOMEM;

    /* A radio from a run just ended is destroyed asynchronously, and its address or name
     * can be refused until it's gone */
    for (int tries = 0; tries < 10; tries++) {
        uwifi_genl_msg_init(b->hwsim, m, HWSIM_CMD_NEW_RADIO, 0);
        uwifi_genl_put(m, HWSIM_ATTR_PERM_ADDR, b->mac, ETH_ALEN);
        uwifi_genl_put_str(m, HWSIM_ATTR_RADIO_NAME, b->name);
        uwifi_genl_put_flag(m, HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE);
        if (opts->country)
            uwifi_genl_put(m, HWSIM_ATTR_REG_HINT_ALPHA2, opts->country, 2);

        if ((r = uwifi_genl_request(b->hwsim, m, false, NULL, NULL, HWSIM_ATTR_MAX)) != -EINVAL &&
                r != -EEXIST)
            break;
        msleep(500);
    }

    /* Then become the medium for the radio's frames */
    if (r >= 0) {
        uwifi_genl_msg_init(b->hwsim, m, HWSIM_CMD_REGISTER, 0);
        r = uwifi_genl_request(b->hwsim, m, false, NULL, NULL, HWSIM_ATTR_MAX);
    }

    free(m);
    return r;
}

int uwifi_hwsim_run(struct uwifi_dev *dev, const struct uwifi_hwsim_opts *opts, volatile sig_atomic_t *stop,
        FILE *out) {
    struct hwsim_bridge *b;
    u64 next_poll = 0, next_stats;
    int r;

    if ((b = calloc(1, sizeof(*b))) == NULL)
        return -ENOMEM;

    b->dev = dev;
    b->hw = uwifi_hw(dev);
    memcpy(b->mac, uwifi_mac(dev), ETH_ALEN);
    snprintf(b->name, sizeof(b->name), "%s", opts->name ? opts->name : uwifi_info(dev)->ifname);
    pthread_mutex_init(&b->lock, NULL);

    if ((b->hwsim = uwifi_genl_open("MAC80211_HWSIM")) == NULL) {
        r = -errno;
        fprintf(stderr, "mac80211_hwsim is not available (modprobe mac80211_hwsim radios=0): %s\n",
                strerror(errno));
        goto out;
    }
    if ((b->nl80211 = uwifi_genl_open("nl80211")) == NULL) {
        r = -errno;
        fprintf(stderr, "nl80211 is not available: %s\n", strerror(errno));
        goto out;
    }

    /* The adapter must be receiving before the medium is registered */
    uwifi_set_tx_status_cb(dev, bridge_tx_status, b);
    if ((r = uwifi_start_monitor(dev, bridge_rx, b)) < 0) {
        fprintf(stderr, "could not start the adapter: %s\n", strerror(-r));
        goto out;
    }
    bridge_build_hops(b);
    if (b->n_hops)
        bridge_tune(b, b->hop_freqs[0], NL80211_CHAN_WIDTH_20, 0);

    /* Frames to the radio are acknowledged by the adapter, which sends them on its own */
    if ((r = kc_mac80211_add_station_vif(b->hw, b->mac)) < 0)
        fprintf(stderr, "the adapter can't acknowledge frames to %02x:%02x:%02x:%02x:%02x:%02x (%s); "
                "peers will retry and may give up\n", b->mac[0], b->mac[1], b->mac[2], b->mac[3], b->mac[4],
                b->mac[5], strerror(-r));

    if ((r = bridge_new_radio(b, opts)) < 0) {
        fprintf(stderr, "could not create the hwsim radio %s: %s\n", b->name,
                r == -EBUSY ? "another medium (wmediumd) is registered" : strerror(-r));
        goto out;
    }

    if ((r = bridge_find_wiphy(b)) < 0) {
        fprintf(stderr, "could not find wiphy %s: %s\n", b->name, strerror(-r));
        goto out;
    }

    bridge_poll_channel(b);
    fprintf(out, "Radio %s (phy index %u) on %s, address %02x:%02x:%02x:%02x:%02x:%02x\n", b->name, b->wiphy,
            b->ifname[0] ? b->ifname : "no interface", b->mac[0], b->mac[1], b->mac[2], b->mac[3], b->mac[4],
            b->mac[5]);
    fflush(out);

    next_stats = kc_jiffies_now() + opts->stats_interval_s * 1000ull;

    while (!*stop && uwifi_alive(dev)) {
        struct pollfd pfd = { .fd = uwifi_genl_fd(b->hwsim), .events = POLLIN };
        u64 now;

        if (poll(&pfd, 1, 10) > 0 && (pfd.revents & POLLIN)) {
            /* Errors the kernel returns are for frames the radio dropped, as when idle */
            if ((r = uwifi_genl_recv(b->hwsim, bridge_hwsim_cb, b, HWSIM_ATTR_MAX)) < 0 && r != -EAGAIN &&
                    r != -EINTR && r != -ENOBUFS) {
                fprintf(stderr, "hwsim netlink: %s\n", strerror(-r));
                break;
            }
        }

        now = kc_jiffies_now();
        bridge_resolve(b, now);
        bridge_idle(b, now);

        if (now >= next_poll) {
            bridge_poll_channel(b);
            next_poll = now + CHANNEL_POLL_MS;
        }

        if (opts->stats_interval_s && now >= next_stats) {
            fprintf(out, "%s: %u MHz, sent %lu (%lu acked, %lu failed), received %lu, %lu retunes\n",
                    b->ifname[0] ? b->ifname : b->name, b->freq, b->tx_frames, b->tx_acked, b->tx_errors,
                    __atomic_load_n(&b->rx_frames, __ATOMIC_RELAXED), b->retunes);
            fflush(out);
            next_stats = now + opts->stats_interval_s * 1000ull;
        }
    }

    if (!uwifi_alive(dev))
        fprintf(stderr, "adapter lost\n");
    r = 0;

out:
    /* Closing the socket removes the radio */
    kc_mac80211_stop(b->hw);
    uwifi_genl_close(b->hwsim);
    uwifi_genl_close(b->nl80211);
    bridge_clear_bss(b);
    pthread_mutex_destroy(&b->lock);
    free(b->hop_freqs);
    free(b);
    return r;
}
