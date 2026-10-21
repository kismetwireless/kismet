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
#ifndef TAP_HEADER
#define TAP_HEADER

/*
 * LINKTYPE_IEEE802_15_4_TAP (283): a header of version (1 octet, 0), reserved (1 octet, 0) and
 * length (2 octets, the header with all its TLVs, a multiple of 4), then TLVs of type (2),
 * length (2, the value only) and value zero-padded to 4 octets, all little-endian; then the PHY
 * payload, with an FCS if the FCS-type TLV says so.  Specification:
 * https://github.com/jkcko/ieee802.15.4-tap
 *
 * Kismet's own capture code writes the 28-byte header below (FCS type, RSS, channel), filled by
 * tap_802_15_4_fill(); anything reading a TAP header walks its TLVs with tap_802_15_4_parse(),
 * which also reads what Kismet's capture code wrote before it followed the specification.
 *
 * Plain C: the capture helpers include it too.
 */

#include <stdint.h>
#include <string.h>

typedef struct {
    uint16_t type; //type identifier
    uint16_t length; // number of octets for type in value field (not including padding
    uint32_t value; // data for type
} tap_tlv;

typedef struct {
    uint8_t version; // currently zero
    uint8_t reserved; // must be zero
    uint16_t length; // total length of header and tlvs in octets, min 4 and must be multiple of 4
    tap_tlv tlv[3];//tap tlvs 3 fcs, signal, channel
    uint8_t payload[0];
    ////payload + fcs per fcs type
} _802_15_4_tap;

/* TLV types */
#define TAP_802_15_4_FCS_TYPE           0   /* 1 octet: 0 none, 1 16-bit CRC, 2 32-bit CRC */
#define TAP_802_15_4_RSS                1   /* float, dBm */
#define TAP_802_15_4_BIT_RATE           2   /* uint32, bit/s */
#define TAP_802_15_4_CHANNEL            3   /* uint16 channel, uint8 page */
#define TAP_802_15_4_LQI                10  /* 1 octet */
#define TAP_802_15_4_CHANNEL_FREQUENCY  11  /* float, kHz */

/* What a TAP header says about the frame after it. */
struct tap_802_15_4_meta {
    unsigned int header_len;    /* octets before the PHY payload */
    int fcs_type;               /* -1: not given */
    int have_rss;
    float rss_dbm;
    int have_channel;
    uint16_t channel;
    uint8_t page;
    int have_frequency;
    float frequency_khz;
    int have_lqi;
    uint8_t lqi;
    int legacy_rssi;            /* the "RSSI" in an LQI TLV of earlier Kismet capture code, dBm */
    int have_legacy_rssi;
};

static inline uint32_t tap_802_15_4_le32(const uint8_t *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static inline float tap_802_15_4_float(const uint8_t *p) {
    uint32_t u = tap_802_15_4_le32(p);
    float f;

    memcpy(&f, &u, sizeof(f));
    return f;
}

/*
 * The header at d (len octets in all) into *m.  Returns 1, or 0 when it is not a usable header
 * (wrong version, a length that is not a multiple of 4 or runs past the data, a TLV past the header).
 *
 * Earlier Kismet capture code is read too: it put the RSSI in the LQI TLV as a signed 32-bit
 * value (padding not zero; also reported as have_legacy_rssi), and the CatSniffer wrote the
 * channel TLV as page, channel instead of channel, page.
 */
static inline int tap_802_15_4_parse(const uint8_t *d, size_t len, struct tap_802_15_4_meta *m) {
    unsigned int hlen, off;

    memset(m, 0, sizeof(*m));
    m->fcs_type = -1;

    if (len < 4 || d[0] != 0)
        return 0;

    hlen = (unsigned int) d[2] | ((unsigned int) d[3] << 8);
    if (hlen < 4 || (hlen % 4) != 0 || hlen > len)
        return 0;

    m->header_len = hlen;

    for (off = 4; off + 4 <= hlen; ) {
        const unsigned int type = (unsigned int) d[off] | ((unsigned int) d[off + 1] << 8);
        const unsigned int tlen = (unsigned int) d[off + 2] | ((unsigned int) d[off + 3] << 8);
        const uint8_t *v = d + off + 4;
        const unsigned int next = off + 4 + ((tlen + 3u) & ~3u);

        if (next > hlen)
            return 0;

        switch (type) {
            case TAP_802_15_4_FCS_TYPE:
                if (tlen >= 1)
                    m->fcs_type = v[0];
                break;
            case TAP_802_15_4_RSS:
                if (tlen >= 4) {
                    const float f = tap_802_15_4_float(v);

                    /* finite and plausible */
                    if (f == f && f > -200.0f && f < 50.0f) {
                        m->rss_dbm = f;
                        m->have_rss = 1;
                    }
                }
                break;
            case TAP_802_15_4_CHANNEL:
                if (tlen >= 3) {
                    if (v[0] == 0 && v[1] >= 11 && v[1] <= 26 && v[2] == 0) {
                        /* the CatSniffer's page, channel order */
                        m->channel = v[1];
                        m->page = 0;
                    } else {
                        m->channel = (uint16_t) (v[0] | (v[1] << 8));
                        m->page = v[2];
                    }
                    m->have_channel = 1;
                } else if (tlen >= 1) {
                    m->channel = v[0];
                    m->have_channel = 1;
                }
                break;
            case TAP_802_15_4_LQI:
                if (tlen == 1 && (v[1] | v[2] | v[3]) != 0) {
                    /* earlier Kismet capture code: a signed RSSI over the padding */
                    const int32_t r = (int32_t) tap_802_15_4_le32(v);

                    if (r < 0 && r > -200) {
                        m->legacy_rssi = r;
                        m->have_legacy_rssi = 1;
                    }
                } else if (tlen >= 1) {
                    m->lqi = v[0];
                    m->have_lqi = 1;
                }
                break;
            case TAP_802_15_4_CHANNEL_FREQUENCY:
                if (tlen >= 4) {
                    const float f = tap_802_15_4_float(v);

                    if (f == f && f > 0.0f) {
                        m->frequency_khz = f;
                        m->have_frequency = 1;
                    }
                }
                break;
            default:
                break;
        }

        off = next;
    }

    return 1;
}

/* The centre of a channel of page 0 (868, 915 and 2450 MHz bands), kHz; 0 when unknown. */
static inline double tap_802_15_4_channel_khz(uint16_t channel, uint8_t page) {
    if (page != 0)
        return 0;
    if (channel == 0)
        return 868300.0;
    if (channel >= 1 && channel <= 10)
        return (906.0 + 2.0 * (channel - 1)) * 1000.0;
    if (channel >= 11 && channel <= 26)
        return (2405.0 + 5.0 * (channel - 11)) * 1000.0;
    return 0;
}

static inline void tap_802_15_4_tlv(tap_tlv *t, uint16_t type, uint16_t length, uint32_t value) {
    const uint8_t b[4] = { (uint8_t) value, (uint8_t) (value >> 8), (uint8_t) (value >> 16), (uint8_t) (value >> 24) };

    /* little-endian on the wire whatever the host */
    memcpy(&t->value, b, 4);
    {
        const uint8_t tb[2] = { (uint8_t) type, (uint8_t) (type >> 8) };
        const uint8_t lb[2] = { (uint8_t) length, (uint8_t) (length >> 8) };

        memcpy(&t->type, tb, 2);
        memcpy(&t->length, lb, 2);
    }
}

/*
 * The 28-byte header of Kismet's capture code, as the specification has it: FCS type (0 none,
 * 1 a 16-bit FCS follows the payload), the signal (have_rss: RSS, a float in dBm; otherwise an
 * LQI TLV of `lqi`, for radios that only report a raw level), the channel (page 0).
 */
static inline void tap_802_15_4_fill(_802_15_4_tap *h, uint8_t fcs_type, int have_rss, float rss_dbm,
        uint8_t lqi, uint16_t channel) {
    const uint8_t len[2] = { (uint8_t) sizeof(_802_15_4_tap), 0 };
    uint32_t rss_bits;

    h->version = 0;
    h->reserved = 0;
    memcpy(&h->length, len, 2);
    tap_802_15_4_tlv(&h->tlv[0], TAP_802_15_4_FCS_TYPE, 1, fcs_type);
    if (have_rss) {
        memcpy(&rss_bits, &rss_dbm, 4);
        tap_802_15_4_tlv(&h->tlv[1], TAP_802_15_4_RSS, 4, rss_bits);
    } else {
        tap_802_15_4_tlv(&h->tlv[1], TAP_802_15_4_LQI, 1, lqi);
    }
    tap_802_15_4_tlv(&h->tlv[2], TAP_802_15_4_CHANNEL, 3, channel);
}

#endif
