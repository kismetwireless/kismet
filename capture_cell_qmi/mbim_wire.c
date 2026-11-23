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

#include <limits.h>
#include <string.h>

#include "mbim_wire.h"

/* a289cc33-bcbb-8b4f-b6b0-133ec2aae6df */
const uint8_t mbim_uuid_basic_connect[16] = {
    0xa2, 0x89, 0xcc, 0x33, 0xbc, 0xbb, 0x8b, 0x4f,
    0xb6, 0xb0, 0x13, 0x3e, 0xc2, 0xaa, 0xe6, 0xdf,
};

/* 3d01dcc5-fef5-4d05-0d3a-bef7058e9aaf */
const uint8_t mbim_uuid_ms_basic_connect_ext[16] = {
    0x3d, 0x01, 0xdc, 0xc5, 0xfe, 0xf5, 0x4d, 0x05,
    0x0d, 0x3a, 0xbe, 0xf7, 0x05, 0x8e, 0x9a, 0xaf,
};

/* 5967bdcc-7fd2-49a2-9f5c-b2e70e527db3 */
const uint8_t mbim_uuid_atds[16] = {
    0x59, 0x67, 0xbd, 0xcc, 0x7f, 0xd2, 0x49, 0xa2,
    0x9f, 0x5c, 0xb2, 0xe7, 0x0e, 0x52, 0x7d, 0xb3,
};

#define MBIM_HDR 12
/* type, length, tid; fragment total, fragment current */
#define MBIM_FRAG_HDR 20

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) |
        ((uint32_t) p[3] << 24);
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t) v;
    p[1] = (uint8_t) (v >> 8);
    p[2] = (uint8_t) (v >> 16);
    p[3] = (uint8_t) (v >> 24);
}

/* ------------------------------------------------------------- fragments */

static int fragmentable(uint32_t type) {
    return type == MBIM_COMMAND_DONE || type == MBIM_INDICATE_STATUS_MSG;
}

int mbim_is_fragment(const uint8_t *buf, size_t len) {
    int bad = 0;
    const size_t flen = mbim_frame_len(buf, len, &bad);

    if (bad || flen < MBIM_FRAG_HDR || !fragmentable(rd32(buf)))
        return 0;
    return rd32(buf + 12) > 1;
}

void mbim_reasm_reset(mbim_reasm_t *r) {
    r->len = 0;
    r->tid = 0;
    r->type = 0;
    r->total = 0;
    r->next = 0;
}

int mbim_reasm_add(mbim_reasm_t *r, const uint8_t *buf, size_t len) {
    int bad = 0;
    const size_t flen = mbim_frame_len(buf, len, &bad);

    if (bad || flen < MBIM_FRAG_HDR || !fragmentable(rd32(buf))) {
        mbim_reasm_reset(r);
        return -1;
    }

    const uint32_t type = rd32(buf), tid = rd32(buf + 8);
    const uint32_t total = rd32(buf + 12), cur = rd32(buf + 16);

    if (total < 1 || cur >= total) {
        mbim_reasm_reset(r);
        return -1;
    }

    if (cur == 0) {
        /* The first fragment holds the whole header; later ones only the
         * fragment header and more of the information buffer */
        if (flen > sizeof(r->buf)) {
            mbim_reasm_reset(r);
            return -1;
        }
        memcpy(r->buf, buf, flen);
        r->len = flen;
        r->tid = tid;
        r->type = type;
        r->total = total;
        r->next = 1;
    } else {
        const size_t more = flen - MBIM_FRAG_HDR;

        if (r->total == 0 || tid != r->tid || type != r->type || total != r->total ||
            cur != r->next || r->len + more > sizeof(r->buf)) {
            mbim_reasm_reset(r);
            return -1;
        }
        memcpy(r->buf + r->len, buf + MBIM_FRAG_HDR, more);
        r->len += more;
        r->next++;
    }

    if (r->next < r->total)
        return 0;

    /* Rewrite as one whole message */
    wr32(r->buf + 4, (uint32_t) r->len);
    wr32(r->buf + 12, 1);
    wr32(r->buf + 16, 0);
    r->total = 0;
    r->next = 0;
    return 1;
}

/* ------------------------------------------------------- device services */

int mbim_device_services_parse(const uint8_t *info, size_t len, mbim_caps_t *caps) {
    memset(caps, 0, sizeof(*caps));

    if (info == NULL || len < 8)
        return 0;

    const uint32_t count = rd32(info);
    if (count > 256 || 8 + (size_t) count * 8 > len)
        return 0;

    for (uint32_t i = 0; i < count; i++) {
        const uint32_t off = rd32(info + 8 + 8 * i);
        const uint32_t size = rd32(info + 12 + 8 * i);

        if (off > len || size > len - off || size < 28)
            return 0;

        const uint8_t *e = info + off;
        const uint32_t ncid = rd32(e + 24);
        if (ncid > (size - 28) / 4)
            return 0;

        caps->services++;

        const int is_ext = memcmp(e, mbim_uuid_ms_basic_connect_ext, 16) == 0;
        const int is_atds = memcmp(e, mbim_uuid_atds, 16) == 0;
        if (memcmp(e, mbim_uuid_qmi, 16) == 0)
            caps->have_qmi = 1;

        for (uint32_t c = 0; c < ncid; c++) {
            const uint32_t cid = rd32(e + 28 + 4 * c);
            if (is_ext && cid == MBIM_CID_BASE_STATIONS)
                caps->have_base_stations = 1;
            if (is_atds && cid == MBIM_CID_ATDS_LOCATION)
                caps->have_atds_location = 1;
            if (is_atds && cid == MBIM_CID_ATDS_SIGNAL)
                caps->have_atds_signal = 1;
        }
    }

    return 1;
}

/* ---------------------------------------------------------------- strings */

/* A UTF-16LE string at `off`/`size` inside `base` (`len` bytes), copied as
 * digits only.  "" when absent; 0 when it does not fit or is not digits. */
static int digits_at(const uint8_t *base, size_t len, uint32_t off, uint32_t size,
                     char *out, size_t cap) {
    out[0] = '\0';

    if (off == 0 && size == 0)
        return 1;
    if (off > len || size > len - off || (size & 1) || size / 2 >= cap)
        return 0;

    for (uint32_t i = 0; i < size / 2; i++) {
        const uint8_t lo = base[off + 2 * i], hi = base[off + 2 * i + 1];
        if (hi != 0 || lo < '0' || lo > '9') {
            out[0] = '\0';
            return 0;
        }
        out[i] = (char) lo;
    }
    out[size / 2] = '\0';
    return 1;
}

/* ---------------------------------------------------------- register state */

int mbim_register_parse(const uint8_t *info, size_t len, mbim_register_t *out) {
    memset(out, 0, sizeof(*out));

    /* nw error, state, mode, data classes, cellular class, then the
     * provider id, provider name and roaming text, then flags */
    if (info == NULL || len < 44)
        return 0;

    out->nw_error = rd32(info);
    out->state = rd32(info + 4);
    out->data_classes = rd32(info + 12);

    /* A provider id that is not digits is left empty, not refused */
    (void) digits_at(info, len, rd32(info + 20), rd32(info + 24), out->provider,
                     sizeof(out->provider));
    return 1;
}

int mbim_registered(uint32_t state) {
    return state == MBIM_REG_HOME || state == MBIM_REG_ROAMING ||
        state == MBIM_REG_PARTNER;
}

/* ------------------------------------------------------- base stations */

size_t mbim_base_stations_req(uint8_t *out, size_t cap, uint32_t max_per_rat) {
    /* MBIM 1.0 (MBIMEx 1.0/2.0): GSM, UMTS, TD-SCDMA, LTE, CDMA maxima.
     * MBIMEx 3.0 adds an NR count; this source never sends it. */
    if (out == NULL || cap < 20)
        return 0;
    for (int i = 0; i < 5; i++)
        wr32(out + 4 * i, max_per_rat);
    return 20;
}

/* An LTE cell: provider id offset/size, cell id, EARFCN, PCI, TAC, RSRP,
 * RSRQ (and the serving cell's timing advance after it, not read).  The
 * provider offset counts from the start of the structure holding it. */
#define LTE_CELL_FIXED 32

static int lte_cell_at(const uint8_t *s, size_t len, mbim_lte_cell_t *c) {
    if (len < LTE_CELL_FIXED)
        return 0;

    c->cell_id = rd32(s + 8);
    c->earfcn = rd32(s + 12);
    c->pci = rd32(s + 16);
    c->tac = rd32(s + 20);
    c->rsrp = (int32_t) rd32(s + 24);
    c->rsrq = (int32_t) rd32(s + 28);
    (void) digits_at(s, len, rd32(s), rd32(s + 4), c->provider, sizeof(c->provider));
    return 1;
}

int mbim_base_stations_parse(const uint8_t *info, size_t len, mbim_base_stations_t *out) {
    /* system type, then nine offset/size pairs: GSM, UMTS, TD-SCDMA, LTE
     * serving cells; GSM, UMTS, TD-SCDMA, LTE, CDMA neighbour lists */
    enum { HDR = 4 + 9 * 8, LTE_SERVING = 3, LTE_MRL = 7 };

    memset(out, 0, sizeof(*out));
    if (info == NULL || len < HDR)
        return 0;

    out->system_type = rd32(info);

    for (int i = 0; i < 9; i++) {
        const uint32_t off = rd32(info + 4 + 8 * i), size = rd32(info + 8 + 8 * i);

        if (size == 0)
            continue;
        if (off < HDR || off > len || size > len - off)
            return 0;

        const uint8_t *s = info + off;

        if (i == LTE_SERVING) {
            if (!lte_cell_at(s, size, &out->lte_serving))
                return 0;
            out->have_lte_serving = 1;
        } else if (i == LTE_MRL) {
            if (size < 4)
                return 0;
            const uint32_t n = rd32(s);
            if (n > (size - 4) / LTE_CELL_FIXED)
                return 0;
            for (uint32_t k = 0; k < n; k++) {
                if (out->nneighbours >= MBIM_LTE_NEIGHBOURS_MAX) {
                    out->neighbours_dropped++;
                    continue;
                }
                const uint8_t *e = s + 4 + (size_t) k * LTE_CELL_FIXED;
                if (!lte_cell_at(e, size - 4 - (size_t) k * LTE_CELL_FIXED,
                                 &out->neighbours[out->nneighbours]))
                    return 0;
                out->nneighbours++;
            }
        } else {
            out->other_rat_cells++;
        }
    }

    return 1;
}

int32_t mbim_lte_rsrp_x10(int32_t v) {
    if (v >= 0 && v <= 97)
        return (v - 141) * 10;          /* 36.133 index: n -> -141 + n dBm */
    if (v >= -156 && v <= -31)
        return v * 10;
    return INT32_MIN;
}

int32_t mbim_lte_rsrq_x10(int32_t v) {
    if (v >= 0 && v <= 34)
        return (v - 40) * 5;            /* 36.133 index: n -> -20 + n/2 dB */
    if (v >= -43 && v <= -2)
        return v * 10;
    return INT32_MIN;
}

/* ------------------------------------------------------------------ atds */

int mbim_atds_location_parse(const uint8_t *info, size_t len, mbim_atds_location_t *out) {
    memset(out, 0, sizeof(*out));
    if (info == NULL || len < 12)
        return 0;
    out->lac = rd32(info);
    out->tac = rd32(info + 4);
    out->cell_id = rd32(info + 8);
    return 1;
}

int mbim_atds_signal_parse(const uint8_t *info, size_t len, mbim_atds_signal_t *out) {
    /* RSSI (0..31 coded, 99 unknown), BER, RSCP, Ec/No, RSRQ, RSRP, RSSNR;
     * the LTE three are coded 0..34, 0..97 and 0..35 with 255 unknown */
    if (info == NULL || len < 28)
        return 0;

    const uint32_t rssi = rd32(info), rsrq = rd32(info + 16), rsrp = rd32(info + 20),
        snr = rd32(info + 24);

    out->rssi = rssi <= 31 ? -113 + 2 * (int32_t) rssi : INT32_MIN;
    out->rsrq_x10 = rsrq <= 34 ? (int32_t) rsrq * 5 - 195 : INT32_MIN;   /* -19.5 + n/2 */
    out->rsrp_x10 = rsrp <= 97 ? ((int32_t) rsrp - 140) * 10 : INT32_MIN;
    out->snr_x10 = snr <= 35 ? ((int32_t) snr - 5) * 10 : INT32_MIN;
    return 1;
}

/* ------------------------------------------------------------ provider id */

static int three_digit_mnc_region(const char *mcc) {
    static const char *const mccs[] = {
        "302", "310", "311", "312", "313", "314", "315", "316", "334",
    };
    for (size_t i = 0; i < sizeof(mccs) / sizeof(mccs[0]); i++) {
        if (strcmp(mcc, mccs[i]) == 0)
            return 1;
    }
    return 0;
}

int mbim_provider_split(const char *provider, char mcc[4], char mnc[4]) {
    const size_t n = provider != NULL ? strlen(provider) : 0;

    mcc[0] = mnc[0] = '\0';
    if (n != 5 && n != 6)
        return 0;
    for (size_t i = 0; i < n; i++) {
        if (provider[i] < '0' || provider[i] > '9')
            return 0;
    }

    memcpy(mcc, provider, 3);
    mcc[3] = '\0';

    if (n == 6) {
        memcpy(mnc, provider + 3, 3);
        mnc[3] = '\0';
    } else if (three_digit_mnc_region(mcc)) {
        mnc[0] = '0';
        memcpy(mnc + 1, provider + 3, 2);
        mnc[3] = '\0';
    } else {
        memcpy(mnc, provider + 3, 2);
        mnc[2] = '\0';
    }
    return 1;
}
