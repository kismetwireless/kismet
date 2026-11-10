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

/* 802.11ah to 802.11n/ac frame conversion, after morse_driver dot11ah/ (see mm_s1g.h) */

#include <errno.h>

#include "mm_s1g.h"
#include "mm_util.h"

#define FC_TYPE(fc)         (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)      (((fc) >> 4) & 0xF)
#define TYPE_MGMT           0
#define TYPE_EXT            3

#define ST_ASSOC_REQ        0
#define ST_ASSOC_RESP       1
#define ST_REASSOC_REQ      2
#define ST_REASSOC_RESP     3
#define ST_PROBE_REQ        4
#define ST_PROBE_RESP       5
#define ST_BEACON           8
#define ST_ACTION           13
#define ST_ACTION_NOACK     14
#define ST_EXT_S1G_BEACON   1

/* S1G beacon frame control: optional fields and security */
#define S1G_BCN_NEXT_TBTT   0x0100
#define S1G_BCN_CSSID       0x0200
#define S1G_BCN_ANO         0x0400
#define S1G_BCN_SECURITY    0x4000

#define EID_SSID            0
#define EID_SUPP_RATES      1
#define EID_DS_PARAMS       3
#define EID_TIM             5
#define EID_ERP             42
#define EID_HT_CAP          45
#define EID_RSN             48
#define EID_EXT_SUPP_RATES  50
#define EID_SUPP_OP_CLASSES 59
#define EID_HT_OP           61
#define EID_EXT_CAP         127
#define EID_VHT_CAP         191
#define EID_VHT_OP          192
#define EID_TX_POWER_ENV    195
#define EID_AID_REQUEST     210
#define EID_AID_RESPONSE    211
#define EID_S1G_BCN_COMPAT  213
#define EID_S1G_SHORT_BCN   214
#define EID_S1G_CAP         217
#define EID_VENDOR          221
#define EID_S1G_OP          232
#define EID_RSNX            244
#define EID_EXT             255
#define EID_EXT_HE_CAP      35
#define EID_EXT_HE_OP       36
#define EID_EXT_HE_6GHZ     59
#define EID_EXT_EHT_OP      106
#define EID_EXT_EHT_CAP     108

#define WLAN_CAP_ESS        0x0001
#define WLAN_CAP_PRIVACY    0x0010
#define WLAN_CAP_SHORT_SLOT 0x0400

#define ACTION_CAT_BACK     3

/* 6, 9, 12, 18, 24, 36, 48, 54 Mbps with 6, 12 and 24 basic */
static const uint8_t rates_ie[] = { EID_SUPP_RATES, 8, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c };

/* WMM parameters with the default EDCA values */
static const uint8_t wmm_param_ie[] = {
    EID_VENDOR, 24, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00,
    0x03, 0xa4, 0x00, 0x00,
    0x27, 0xa4, 0x00, 0x00,
    0x42, 0x43, 0x5e, 0x00,
    0x62, 0x32, 0x2f, 0x00,
};

/* SGI at 1, 2, 4 and 8MHz, up to 8MHz wide, a non-sensor station; one stream of MCS 0-9
 * each way */
static const uint8_t s1g_cap_ie[] = {
    EID_S1G_CAP, 15,
    0x9e, 0, 0, 0, 0x80, 0, 0, 0, 0, 0,
    0xfe, 0x00, 0xfc, 0x01, 0x00,
};

static const uint8_t aid_request_ie[] = { EID_AID_REQUEST, 1, 0x00 };

struct buf {
    uint8_t *p;
    size_t len;
    size_t max;
    bool overflow;
};

static void put(struct buf *b, const void *data, size_t len) {
    if (b->len + len > b->max) {
        b->overflow = true;
        return;
    }
    memcpy(b->p + b->len, data, len);
    b->len += len;
}

static void put_ie(struct buf *b, uint8_t id, const uint8_t *body, size_t len) {
    const uint8_t hdr[2] = { id, (uint8_t) len };

    put(b, hdr, 2);
    put(b, body, len);
}

static void put_u8(struct buf *b, uint8_t v) {
    put(b, &v, 1);
}

static void put_le16(struct buf *b, uint16_t v) {
    uint8_t p[2];

    mm_put_le16(p, v);
    put(b, p, 2);
}

static void put_le32(struct buf *b, uint32_t v) {
    uint8_t p[4];

    mm_put_le32(p, v);
    put(b, p, 4);
}

/* First element with an id, or NULL; elements running past the end end the search */
static const uint8_t *find_ie(const uint8_t *ies, size_t len, uint8_t id) {
    size_t off = 0;

    while (off + 2 <= len && off + 2 + ies[off + 1] <= len) {
        if (ies[off] == id)
            return ies + off;
        off += 2 + ies[off + 1];
    }

    return NULL;
}

static bool is_wmm_ie(const uint8_t *ie) {
    return ie[0] == EID_VENDOR && ie[1] >= 5 && ie[2] == 0x00 && ie[3] == 0x50 && ie[4] == 0xf2 &&
        ie[5] == 0x02;
}

static bool contains(const struct mm_s1g_channel *outer, const struct mm_s1g_channel *inner) {
    const int32_t d = (int32_t) inner->freq_khz - (int32_t) outer->freq_khz;
    const int32_t half_out = outer->bw_mhz * 500, half_in = inner->bw_mhz * 500;

    return d - half_in >= -half_out && d + half_in <= half_out;
}

const struct mm_s1g_channel *mm_s1g_containing(const struct mm_s1g_region *region,
        const struct mm_s1g_channel *ch, unsigned int bw_mhz, const struct mm_s1g_channel *within) {
    for (size_t i = 0; i < region->num_channels; i++) {
        const struct mm_s1g_channel *c = &region->channels[i];

        if (c->bw_mhz == bw_mhz && contains(c, ch) && (within == NULL || contains(within, c)))
            return c;
    }

    return NULL;
}

/* Operating width field: 0, 1, 3, 7, 15 for 1, 2, 4, 8, 16MHz */
bool mm_s1g_parse_op(const struct mm_s1g_region *region, const uint8_t *op_ie,
        struct mm_s1g_op *out) {
    const unsigned int bw = ((op_ie[0] >> 1) & 0xF) + 1;
    const bool pri_1mhz = (op_ie[0] & 0x01) != 0;
    const bool upper = (op_ie[0] & 0x20) != 0;
    const struct mm_s1g_channel *op, *pri;

    if (bw != 1 && bw != 2 && bw != 4 && bw != 8)
        return false;

    if ((op = mm_s1g_channel_lookup(region, op_ie[3])) == NULL || op->bw_mhz != bw)
        return false;

    out->op = op;
    out->pri2 = NULL;
    out->pri_bw = bw == 1 || pri_1mhz ? 1 : 2;

    if (bw == 1) {
        out->pri1 = op;
        return true;
    }

    if ((pri = mm_s1g_channel_lookup(region, op_ie[2])) == NULL)
        return false;

    /* The primary channel field names the 2MHz primary unless the primary is 1MHz */
    if (pri->bw_mhz == 2) {
        out->pri2 = pri;
        out->pri1 = mm_s1g_channel_lookup(region, upper ? pri->channel + 1 : pri->channel - 1);
    } else {
        out->pri1 = pri;
        out->pri2 = mm_s1g_containing(region, pri, 2, op);
    }

    return out->pri1 != NULL && out->pri1->bw_mhz == 1 && contains(op, out->pri1);
}

static struct mm_s1g_bss *bss_find(struct mm_s1g_conv *c, const uint8_t *bssid, bool create) {
    struct mm_s1g_bss *oldest = &c->bss[0];

    for (size_t i = 0; i < MM_S1G_MAX_BSS; i++) {
        struct mm_s1g_bss *b = &c->bss[i];

        if (b->used && memcmp(b->bssid, bssid, 6) == 0) {
            b->last_seen = c->now;
            return b;
        }
        if (!b->used || (oldest->used && b->last_seen < oldest->last_seen))
            oldest = b;
    }

    if (!create)
        return NULL;

    memset(oldest, 0, sizeof(*oldest));
    oldest->used = true;
    memcpy(oldest->bssid, bssid, 6);
    oldest->beacon_int = 100;
    oldest->last_seen = c->now;
    return oldest;
}

const struct mm_s1g_bss *mm_s1g_find_bss_on(const struct mm_s1g_conv *c,
        const struct mm_s1g_channel *op, const struct mm_s1g_channel *pri1) {
    const struct mm_s1g_bss *best = NULL;

    for (size_t i = 0; i < MM_S1G_MAX_BSS; i++) {
        const struct mm_s1g_bss *b = &c->bss[i];
        struct mm_s1g_op o;

        if (!b->used || !b->have_op || !mm_s1g_parse_op(c->region, b->s1g_op, &o))
            continue;
        if (o.op == op && o.pri1 == pri1 && (best == NULL || b->last_seen > best->last_seen))
            best = b;
    }

    return best;
}

static void bss_learn(struct mm_s1g_bss *b, const uint8_t *ies, size_t len) {
    const uint8_t *ie;

    if ((ie = find_ie(ies, len, EID_SSID)) != NULL && ie[1] <= 32 && ie[1] > 0) {
        memcpy(b->ssid, ie + 2, ie[1]);
        b->ssid_len = ie[1];
        b->have_ssid = true;
    }

    if ((ie = find_ie(ies, len, EID_RSN)) != NULL && (size_t) ie[1] + 2 <= sizeof(b->rsn)) {
        b->rsn_len = (uint8_t) (ie[1] + 2);
        memcpy(b->rsn, ie, b->rsn_len);
    }

    if ((ie = find_ie(ies, len, EID_RSNX)) != NULL && (size_t) ie[1] + 2 <= sizeof(b->rsnx)) {
        b->rsnx_len = (uint8_t) (ie[1] + 2);
        memcpy(b->rsnx, ie, b->rsnx_len);
    }

    if ((ie = find_ie(ies, len, EID_S1G_OP)) != NULL && ie[1] >= 6) {
        memcpy(b->s1g_op, ie + 2, 6);
        b->have_op = true;
    }

    if ((ie = find_ie(ies, len, EID_S1G_BCN_COMPAT)) != NULL && ie[1] >= 8) {
        b->capab = mm_get_le16(ie + 2);
        b->beacon_int = mm_get_le16(ie + 4);
        b->tsf_high = mm_get_le32(ie + 6);
    }
}

/* HT and VHT capabilities and operation for the BSS's channels as 5GHz channels */
static void put_ht_vht(struct buf *b, const struct mm_s1g_region *region, const struct mm_s1g_op *o) {
    const unsigned int bw = o->op->bw_mhz;
    uint8_t ht_cap[26] = { 0 }, ht_op[22] = { 0 }, vht_cap[12] = { 0 }, vht_op[5] = { 0 };
    uint32_t vcap;

    mm_put_le16(ht_cap, (uint16_t) (0x0020 | (bw >= 2 ? 0x0042 : 0)));
    ht_cap[2] = 0x03;
    ht_cap[3] = 0xff;
    ht_cap[15] = 0x01;
    put_ie(b, EID_HT_CAP, ht_cap, sizeof(ht_cap));

    ht_op[0] = o->pri1->chan_5g;
    if (bw >= 2 && o->pri2 != NULL)
        ht_op[1] = (uint8_t) ((o->pri2->chan_5g > o->pri1->chan_5g ? 0x01 : 0x03) | 0x04);
    put_ie(b, EID_HT_OP, ht_op, sizeof(ht_op));

    vcap = 0x00000020;
    if (bw >= 8)
        vcap |= 0x00000004 | 0x00000040;
    mm_put_le32(vht_cap, vcap);
    mm_put_le16(vht_cap + 4, 0xfffe);
    mm_put_le16(vht_cap + 8, 0xfffe);
    put_ie(b, EID_VHT_CAP, vht_cap, sizeof(vht_cap));

    /* 160MHz as an 80MHz segment holding the primary and the 160MHz center */
    if (bw == 4) {
        vht_op[0] = 1;
        vht_op[1] = o->op->chan_5g;
    } else if (bw == 8) {
        const struct mm_s1g_channel *seg = mm_s1g_containing(region, o->pri1, 4, o->op);

        vht_op[0] = 1;
        vht_op[1] = seg != NULL ? seg->chan_5g : o->op->chan_5g;
        vht_op[2] = seg != NULL ? o->op->chan_5g : 0;
    }
    mm_put_le16(vht_op + 3, 0xfffe);
    put_ie(b, EID_VHT_OP, vht_op, sizeof(vht_op));
}

static bool rx_strip_ie(uint8_t id) {
    switch (id) {
        case EID_SSID:
        case EID_SUPP_RATES:
        case EID_EXT_SUPP_RATES:
        case EID_DS_PARAMS:
        case EID_TIM:
        case EID_HT_CAP:
        case EID_HT_OP:
        case EID_VHT_CAP:
        case EID_VHT_OP:
        case EID_AID_RESPONSE:
        case EID_S1G_BCN_COMPAT:
        case EID_S1G_SHORT_BCN:
        case EID_S1G_CAP:
        case EID_S1G_OP:
        case EID_VENDOR:
            return true;
        default:
            return false;
    }
}

/* SSID, rates, TIM, the BSS's own elements, HT/VHT, then vendor elements with WMM */
static void rx_put_ies(struct buf *b, struct mm_s1g_conv *c, const struct mm_s1g_bss *bss,
        const struct mm_s1g_channel *rx_chan, const uint8_t *ies, size_t len, bool beacon) {
    const uint8_t *ie;
    struct mm_s1g_op o = { 0 };
    bool have_wmm = false;
    size_t off;

    if ((ie = find_ie(ies, len, EID_SSID)) != NULL)
        put(b, ie, (size_t) ie[1] + 2);
    else
        put_ie(b, EID_SSID, bss->ssid, bss->have_ssid ? bss->ssid_len : 0);

    put(b, rates_ie, sizeof(rates_ie));

    /* An S1G TIM's bitmap is encoded in blocks; a station without power save needs only
     * the DTIM count and period */
    if (beacon && (ie = find_ie(ies, len, EID_TIM)) != NULL && ie[1] >= 2) {
        const uint8_t tim[4] = { ie[2], ie[3], 0, 0 };
        put_ie(b, EID_TIM, tim, sizeof(tim));
    }

    if (beacon && find_ie(ies, len, EID_RSN) == NULL && bss->rsn_len)
        put(b, bss->rsn, bss->rsn_len);

    for (off = 0; off + 2 <= len && off + 2 + ies[off + 1] <= len; off += 2 + ies[off + 1])
        if (!rx_strip_ie(ies[off]))
            put(b, ies + off, (size_t) ies[off + 1] + 2);

    if (beacon && find_ie(ies, len, EID_RSNX) == NULL && bss->rsnx_len)
        put(b, bss->rsnx, bss->rsnx_len);

    if (bss->have_op && mm_s1g_parse_op(c->region, bss->s1g_op, &o)) {
        c->rx_pri_5g = o.pri1->chan_5g;
    } else {
        o.op = o.pri1 = rx_chan;
        o.pri2 = NULL;
        o.pri_bw = 1;
    }
    if (o.op != NULL)
        put_ht_vht(b, c->region, &o);

    for (off = 0; off + 2 <= len && off + 2 + ies[off + 1] <= len; off += 2 + ies[off + 1]) {
        if (ies[off] != EID_VENDOR)
            continue;
        have_wmm |= is_wmm_ie(ies + off);
        put(b, ies + off, (size_t) ies[off + 1] + 2);
    }

    if (!have_wmm)
        put(b, wmm_param_ie, sizeof(wmm_param_ie));
}

/* fc, duration, SA, timestamp (low 32 bits), change sequence, optional fields, elements */
static int rx_s1g_beacon(struct mm_s1g_conv *c, const struct mm_s1g_channel *rx_chan,
        const uint8_t *in, size_t len, struct buf *b) {
    const uint16_t fc = mm_get_le16(in);
    static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    size_t ies_off = 15;
    struct mm_s1g_bss *bss;
    uint16_t capab;

    if (fc & S1G_BCN_NEXT_TBTT)
        ies_off += 3;
    if (fc & S1G_BCN_CSSID)
        ies_off += 4;
    if (fc & S1G_BCN_ANO)
        ies_off += 1;

    if (len < ies_off)
        return 0;

    if ((bss = bss_find(c, in + 4, true)) == NULL)
        return 0;
    bss_learn(bss, in + ies_off, len - ies_off);

    capab = (uint16_t) ((bss->capab & ~WLAN_CAP_PRIVACY) | WLAN_CAP_ESS | WLAN_CAP_SHORT_SLOT);
    if ((fc & S1G_BCN_SECURITY) || bss->rsn_len)
        capab |= WLAN_CAP_PRIVACY;

    put_le16(b, 0x0080);
    put_le16(b, 0);
    put(b, bcast, 6);
    put(b, in + 4, 6);
    put(b, in + 4, 6);
    put_le16(b, 0);
    put(b, in + 10, 4);
    put_le32(b, bss->tsf_high);
    put_le16(b, bss->beacon_int);
    put_le16(b, capab);

    rx_put_ies(b, c, bss, rx_chan, in + ies_off, len - ies_off, true);
    return 1;
}

/* Probe responses keep their header and fixed fields */
static int rx_probe_resp(struct mm_s1g_conv *c, const struct mm_s1g_channel *rx_chan,
        const uint8_t *in, size_t len, struct buf *b) {
    struct mm_s1g_bss *bss;
    uint8_t fixed[12];

    if (len < 36 || (bss = bss_find(c, in + 16, true)) == NULL)
        return 0;

    bss_learn(bss, in + 36, len - 36);
    bss->beacon_int = mm_get_le16(in + 32);
    bss->capab = mm_get_le16(in + 34);

    memcpy(fixed, in + 24, sizeof(fixed));
    mm_put_le16(fixed + 10, (uint16_t) (mm_get_le16(fixed + 10) | WLAN_CAP_SHORT_SLOT));

    put(b, in, 24);
    put(b, fixed, sizeof(fixed));
    rx_put_ies(b, c, bss, rx_chan, in + 36, len - 36, false);
    return 1;
}

/* An S1G association response has no AID field; the AID response element carries it */
static int rx_assoc_resp(struct mm_s1g_conv *c, const struct mm_s1g_channel *rx_chan,
        const uint8_t *in, size_t len, struct buf *b) {
    struct mm_s1g_bss *bss;
    const uint8_t *ie;
    uint16_t aid = 0;

    if (len < 28 || (bss = bss_find(c, in + 16, true)) == NULL)
        return 0;

    if ((ie = find_ie(in + 28, len - 28, EID_AID_RESPONSE)) != NULL && ie[1] >= 2)
        aid = mm_get_le16(ie + 2) & 0x3fff;

    if ((ie = find_ie(in + 28, len - 28, EID_S1G_OP)) != NULL && ie[1] >= 6) {
        memcpy(bss->s1g_op, ie + 2, 6);
        bss->have_op = true;
    }

    put(b, in, 24);
    put_le16(b, (uint16_t) (mm_get_le16(in + 24) | WLAN_CAP_SHORT_SLOT));
    put(b, in + 26, 2);
    put_le16(b, aid ? (uint16_t) (aid | 0xc000) : 0);
    rx_put_ies(b, c, bss, rx_chan, in + 28, len - 28, false);
    return 1;
}

void mm_s1g_conv_init(struct mm_s1g_conv *c, const struct mm_s1g_region *region) {
    memset(c, 0, sizeof(*c));
    c->region = region;
}

int mm_s1g_rx(struct mm_s1g_conv *c, const struct mm_s1g_channel *rx_chan, const uint8_t *in,
        size_t len, uint8_t *out, size_t out_max) {
    struct buf b = { out, 0, out_max, false };
    uint16_t fc;
    int r = 1;

    if (len < 10)
        return 0;

    fc = mm_get_le16(in);
    c->now++;
    c->rx_pri_5g = 0;

    if (FC_TYPE(fc) == TYPE_EXT) {
        if (FC_SUBTYPE(fc) != ST_EXT_S1G_BEACON)
            return 0;
        r = rx_s1g_beacon(c, rx_chan, in, len, &b);
    } else if (FC_TYPE(fc) == TYPE_MGMT && len >= 24) {
        switch (FC_SUBTYPE(fc)) {
            case ST_PROBE_RESP:
                r = rx_probe_resp(c, rx_chan, in, len, &b);
                break;
            case ST_ASSOC_RESP:
            case ST_REASSOC_RESP:
                r = rx_assoc_resp(c, rx_chan, in, len, &b);
                break;
            case ST_BEACON:
                return 0;
            case ST_ACTION:
            case ST_ACTION_NOACK:
                if (len > 24 && in[24] == ACTION_CAT_BACK)
                    return 0;
                put(&b, in, len);
                break;
            default:
                put(&b, in, len);
                break;
        }
    } else {
        put(&b, in, len);
    }

    if (r <= 0)
        return r;

    return b.overflow ? -ENOSPC : (int) b.len;
}

static bool tx_strip_ie(const uint8_t *ie) {
    switch (ie[0]) {
        case EID_SUPP_RATES:
        case EID_EXT_SUPP_RATES:
        case EID_DS_PARAMS:
        case EID_ERP:
        case EID_HT_CAP:
        case EID_HT_OP:
        case EID_VHT_CAP:
        case EID_VHT_OP:
        case EID_TX_POWER_ENV:
        case EID_SUPP_OP_CLASSES:
        case 36:            /* supported channels */
            return true;
        case EID_EXT:
            return ie[1] >= 1 && (ie[2] == EID_EXT_HE_CAP || ie[2] == EID_EXT_HE_OP ||
                    ie[2] == EID_EXT_HE_6GHZ || ie[2] == EID_EXT_EHT_CAP ||
                    ie[2] == EID_EXT_EHT_OP);
        default:
            return false;
    }
}

/* The station's elements without the 2.4/5GHz ones, then the S1G ones before vendor elements */
static void tx_put_ies(struct buf *b, const uint8_t *ies, size_t len, bool assoc) {
    bool added = false;

    for (size_t off = 0; off + 2 <= len && off + 2 + ies[off + 1] <= len; off += 2 + ies[off + 1]) {
        const uint8_t *ie = ies + off;

        if (tx_strip_ie(ie))
            continue;

        if (!added && ie[0] == EID_VENDOR) {
            if (assoc)
                put(b, aid_request_ie, sizeof(aid_request_ie));
            put(b, s1g_cap_ie, sizeof(s1g_cap_ie));
            added = true;
        }

        /* Extended channel switching, which S1G stations support */
        if (assoc && ie[0] == EID_EXT_CAP && ie[1] >= 1) {
            put_u8(b, ie[0]);
            put_u8(b, ie[1]);
            put_u8(b, (uint8_t) (ie[2] | 0x04));
            put(b, ie + 3, (size_t) ie[1] - 1);
            continue;
        }

        put(b, ie, (size_t) ie[1] + 2);
    }

    if (!added) {
        if (assoc)
            put(b, aid_request_ie, sizeof(aid_request_ie));
        put(b, s1g_cap_ie, sizeof(s1g_cap_ie));
    }
}

/* S1G listen intervals have a scale in the top two bits; 1 = units of 10 */
static uint16_t s1g_listen_interval(uint16_t li) {
    if (li > 0x3fff || (li != 0 && li % 10 == 0))
        return (uint16_t) ((li / 10) | (1 << 14));
    return li;
}

int mm_s1g_tx(struct mm_s1g_conv *c, const uint8_t *in, size_t len, uint8_t *out, size_t out_max) {
    struct buf b = { out, 0, out_max, false };
    uint16_t fc;
    size_t fixed;

    (void) c;

    if (len < 10)
        return 0;

    fc = mm_get_le16(in);

    if (FC_TYPE(fc) != TYPE_MGMT || len < 24) {
        put(&b, in, len);
        return b.overflow ? -ENOSPC : (int) b.len;
    }

    switch (FC_SUBTYPE(fc)) {
        case ST_PROBE_REQ:
            put(&b, in, 24);
            tx_put_ies(&b, in + 24, len - 24, false);
            break;

        case ST_ASSOC_REQ:
        case ST_REASSOC_REQ:
            fixed = FC_SUBTYPE(fc) == ST_ASSOC_REQ ? 4 : 10;
            if (len < 24 + fixed)
                return 0;
            put(&b, in, 26);
            put_le16(&b, s1g_listen_interval(mm_get_le16(in + 26)));
            put(&b, in + 28, fixed - 4);
            tx_put_ies(&b, in + 24 + fixed, len - 24 - fixed, true);
            break;

        case ST_ACTION:
        case ST_ACTION_NOACK:
            if (len > 24 && in[24] == ACTION_CAT_BACK)
                return 0;
            put(&b, in, len);
            break;

        default:
            put(&b, in, len);
            break;
    }

    return b.overflow ? -ENOSPC : (int) b.len;
}
