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

#include <string.h>

#include "qmi_wire.h"

const uint8_t mbim_uuid_qmi[16] = {
    0xd1, 0xa3, 0x0b, 0xc2, 0xf9, 0x7a, 0x6e, 0x43,
    0xbf, 0x65, 0xc7, 0xe2, 0x4f, 0xb0, 0xf0, 0xd3,
};

const uint8_t mbim_uuid_proxy_control[16] = {
    0x83, 0x8c, 0xf7, 0xfb, 0x8d, 0x0d, 0x4d, 0x7f,
    0x87, 0x1e, 0xd7, 0x1d, 0xbe, 0xfb, 0xb3, 0x9b,
};

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t) (p[0] | (p[1] << 8));
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) |
        ((uint32_t) p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) {
    return (uint64_t) rd32(p) | ((uint64_t) rd32(p + 4) << 32);
}

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t) v;
    p[1] = (uint8_t) (v >> 8);
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t) v;
    p[1] = (uint8_t) (v >> 8);
    p[2] = (uint8_t) (v >> 16);
    p[3] = (uint8_t) (v >> 24);
}

/* ------------------------------------------------------------------ QMUX */

/* SDU control flags: CTL marks a response with bit 0 and an indication
 * with bit 1, the other services with bits 1 and 2. */
#define CTL_FLAG_RESPONSE   0x01
#define CTL_FLAG_INDICATION 0x02
#define SVC_FLAG_RESPONSE   0x02
#define SVC_FLAG_INDICATION 0x04

size_t qmux_build(uint8_t *out, size_t cap, uint8_t service, uint8_t client,
                  uint16_t tid, uint16_t msg_id, const uint8_t *tlvs,
                  size_t tlvs_len) {
    const size_t sdu_hdr = service == QMI_SVC_CTL ? 6 : 7;
    const size_t total = 6 + sdu_hdr + tlvs_len;

    if (out == NULL || total > cap || total - 1 > 0xFFFF || tlvs_len > 0xFFFF)
        return 0;

    out[0] = 0x01;
    wr16(out + 1, (uint16_t) (total - 1));
    out[3] = 0x00;          /* from the host */
    out[4] = service;
    out[5] = client;

    uint8_t *s = out + 6;
    s[0] = 0x00;            /* request */
    if (service == QMI_SVC_CTL) {
        s[1] = (uint8_t) tid;
        wr16(s + 2, msg_id);
        wr16(s + 4, (uint16_t) tlvs_len);
    } else {
        wr16(s + 1, tid);
        wr16(s + 3, msg_id);
        wr16(s + 5, (uint16_t) tlvs_len);
    }

    if (tlvs_len > 0)
        memcpy(s + sdu_hdr, tlvs, tlvs_len);

    return total;
}

size_t qmux_frame_len(const uint8_t *buf, size_t len, int *bad) {
    if (bad != NULL)
        *bad = 0;
    if (len < 1)
        return 0;
    if (buf[0] != 0x01) {
        if (bad != NULL)
            *bad = 1;
        return 0;
    }
    if (len < 3)
        return 0;

    const size_t flen = (size_t) rd16(buf + 1) + 1;

    /* Header plus the shortest SDU; anything less cannot be a frame */
    if (flen < 12 || flen > QMI_MSG_MAX) {
        if (bad != NULL)
            *bad = 1;
        return 0;
    }

    return len >= flen ? flen : 0;
}

int qmux_parse(const uint8_t *buf, size_t len, qmux_msg_t *out) {
    int bad = 0;
    const size_t flen = qmux_frame_len(buf, len, &bad);

    if (bad || flen == 0 || out == NULL)
        return 0;

    memset(out, 0, sizeof(*out));
    out->service = buf[4];
    out->client = buf[5];

    const uint8_t *s = buf + 6;
    const size_t slen = flen - 6;
    size_t hdr, tlen;

    if (out->service == QMI_SVC_CTL) {
        hdr = 6;
        if (slen < hdr)
            return 0;
        out->sdu_flags = s[0];
        out->tid = s[1];
        out->msg_id = rd16(s + 2);
        tlen = rd16(s + 4);
        out->is_response = (s[0] & CTL_FLAG_RESPONSE) != 0;
        out->is_indication = (s[0] & CTL_FLAG_INDICATION) != 0;
    } else {
        hdr = 7;
        if (slen < hdr)
            return 0;
        out->sdu_flags = s[0];
        out->tid = rd16(s + 1);
        out->msg_id = rd16(s + 3);
        tlen = rd16(s + 5);
        out->is_response = (s[0] & SVC_FLAG_RESPONSE) != 0;
        out->is_indication = (s[0] & SVC_FLAG_INDICATION) != 0;
    }

    if (hdr + tlen > slen)
        return 0;

    out->tlvs = s + hdr;
    out->tlvs_len = tlen;

    return 1;
}

const uint8_t *qmi_tlv(const uint8_t *tlvs, size_t len, uint8_t type,
                       size_t *vlen) {
    size_t i = 0;

    while (tlvs != NULL && i + 3 <= len) {
        const uint8_t t = tlvs[i];
        const size_t l = rd16(tlvs + i + 1);

        if (i + 3 + l > len)
            return NULL;

        if (t == type) {
            if (vlen != NULL)
                *vlen = l;
            return tlvs + i + 3;
        }

        i += 3 + l;
    }

    return NULL;
}

int qmi_result(const qmux_msg_t *m, uint16_t *err) {
    size_t vl = 0;
    const uint8_t *v = qmi_tlv(m->tlvs, m->tlvs_len, 0x02, &vl);

    if (v == NULL || vl < 4)
        return -1;

    const uint16_t result = rd16(v);
    const uint16_t code = rd16(v + 2);

    if (err != NULL)
        *err = code;

    return (result == 0 && code == 0) ? 1 : 0;
}

int qmux_is_ctl_sync(const uint8_t *buf, size_t len) {
    return len >= 10 && buf[0] == 0x01 && buf[4] == QMI_SVC_CTL &&
        rd16(buf + 8) == QMI_CTL_SYNC;
}

size_t qmi_ctl_alloc_build(uint8_t *out, size_t cap, uint8_t tid,
                           uint8_t service) {
    const uint8_t tlv[4] = { 0x01, 0x01, 0x00, service };
    return qmux_build(out, cap, QMI_SVC_CTL, 0, tid, QMI_CTL_GET_CLIENT_ID,
                      tlv, sizeof(tlv));
}

size_t qmi_ctl_release_build(uint8_t *out, size_t cap, uint8_t tid,
                             uint8_t service, uint8_t client) {
    const uint8_t tlv[5] = { 0x01, 0x02, 0x00, service, client };
    return qmux_build(out, cap, QMI_SVC_CTL, 0, tid, QMI_CTL_RELEASE_CLIENT_ID,
                      tlv, sizeof(tlv));
}

size_t qmi_ctl_proxy_open_build(uint8_t *out, size_t cap, uint8_t tid,
                                const char *path) {
    uint8_t tlv[3 + 256];
    const size_t plen = path != NULL ? strlen(path) : 0;

    if (plen == 0 || plen > 256)
        return 0;

    tlv[0] = 0x01;
    wr16(tlv + 1, (uint16_t) plen);
    memcpy(tlv + 3, path, plen);     /* ASCII, no NUL */

    return qmux_build(out, cap, QMI_SVC_CTL, 0, tid, QMI_CTL_PROXY_OPEN,
                      tlv, 3 + plen);
}

int qmi_ctl_alloc_parse(const qmux_msg_t *m, uint8_t service, uint8_t *client) {
    size_t vl = 0;
    const uint8_t *v;

    if (m->service != QMI_SVC_CTL || m->msg_id != QMI_CTL_GET_CLIENT_ID ||
        !m->is_response || qmi_result(m, NULL) != 1)
        return 0;

    v = qmi_tlv(m->tlvs, m->tlvs_len, 0x01, &vl);
    if (v == NULL || vl < 2 || v[0] != service)
        return 0;

    if (client != NULL)
        *client = v[1];

    return 1;
}

/* ------------------------------------------------------------------ MBIM */

#define MBIM_HDR 12

static void mbim_hdr(uint8_t *out, uint32_t type, uint32_t len, uint32_t tid) {
    wr32(out, type);
    wr32(out + 4, len);
    wr32(out + 8, tid);
}

size_t mbim_open_build(uint8_t *out, size_t cap, uint32_t tid,
                       uint32_t max_control_transfer) {
    if (out == NULL || cap < 16)
        return 0;
    mbim_hdr(out, MBIM_OPEN_MSG, 16, tid);
    wr32(out + 12, max_control_transfer);
    return 16;
}

size_t mbim_close_build(uint8_t *out, size_t cap, uint32_t tid) {
    if (out == NULL || cap < MBIM_HDR)
        return 0;
    mbim_hdr(out, MBIM_CLOSE_MSG, MBIM_HDR, tid);
    return MBIM_HDR;
}

size_t mbim_command_build(uint8_t *out, size_t cap, uint32_t tid,
                          const uint8_t uuid[16], uint32_t cid,
                          uint32_t command_type, const uint8_t *info,
                          size_t info_len) {
    const size_t total = MBIM_HDR + 8 + 16 + 12 + info_len;

    if (out == NULL || total > cap || total > QMI_MSG_MAX)
        return 0;

    mbim_hdr(out, MBIM_COMMAND_MSG, (uint32_t) total, tid);
    wr32(out + 12, 1);      /* one fragment */
    wr32(out + 16, 0);      /* this is fragment 0 */
    memcpy(out + 20, uuid, 16);
    wr32(out + 36, cid);
    wr32(out + 40, command_type);
    wr32(out + 44, (uint32_t) info_len);
    if (info_len > 0)
        memcpy(out + 48, info, info_len);

    return total;
}

size_t mbim_proxy_config_build(uint8_t *out, size_t cap, uint32_t tid,
                               const char *path, uint32_t timeout_s) {
    uint8_t info[12 + 2 * 256 + 4];
    const size_t plen = path != NULL ? strlen(path) : 0;

    if (plen == 0 || plen > 256)
        return 0;

    /* offset, length (bytes of UTF-16LE), timeout, then the padded path */
    const size_t ulen = 2 * plen;
    const size_t padded = (ulen + 3) & ~(size_t) 3;

    memset(info, 0, sizeof(info));
    wr32(info, 12);
    wr32(info + 4, (uint32_t) ulen);
    wr32(info + 8, timeout_s);
    for (size_t i = 0; i < plen; i++)
        info[12 + 2 * i] = (uint8_t) path[i];

    return mbim_command_build(out, cap, tid, mbim_uuid_proxy_control,
                              MBIM_CID_PROXY_CONFIG, MBIM_COMMAND_TYPE_SET,
                              info, 12 + padded);
}

size_t mbim_frame_len(const uint8_t *buf, size_t len, int *bad) {
    if (bad != NULL)
        *bad = 0;
    if (len < MBIM_HDR)
        return 0;

    const size_t flen = rd32(buf + 4);

    if (flen < MBIM_HDR || flen > QMI_MSG_MAX) {
        if (bad != NULL)
            *bad = 1;
        return 0;
    }

    return len >= flen ? flen : 0;
}

int mbim_parse(const uint8_t *buf, size_t len, mbim_msg_t *out) {
    int bad = 0;
    const size_t flen = mbim_frame_len(buf, len, &bad);

    if (bad || flen == 0 || out == NULL)
        return 0;

    memset(out, 0, sizeof(*out));
    out->type = rd32(buf);
    out->length = (uint32_t) flen;
    out->tid = rd32(buf + 8);

    switch (out->type) {
        case MBIM_OPEN_DONE:
        case MBIM_CLOSE_DONE:
        case MBIM_FUNCTION_ERROR_MSG:
            if (flen < MBIM_HDR + 4)
                return 0;
            out->status = rd32(buf + 12);
            return 1;

        case MBIM_COMMAND_DONE:
        case MBIM_INDICATE_STATUS_MSG: {
            const int done = out->type == MBIM_COMMAND_DONE;
            const size_t fixed = MBIM_HDR + 8 + 16 + (done ? 12 : 8);

            if (flen < fixed)
                return 0;
            if (rd32(buf + 12) != 1 || rd32(buf + 16) != 0)
                return 0;

            out->uuid = buf + 20;
            out->cid = rd32(buf + 36);
            if (done) {
                out->status = rd32(buf + 40);
                out->info_len = rd32(buf + 44);
            } else {
                out->info_len = rd32(buf + 40);
            }

            if (out->info_len > flen - fixed)
                return 0;

            out->info = buf + fixed;
            return 1;
        }

        default:
            /* A message type this source never asks for; framed, so skippable */
            return 1;
    }
}

/* ------------------------------------------------------------------ NAS */

static int nibble_digit(unsigned int n, char *c) {
    if (n > 9)
        return 0;
    *c = (char) ('0' + n);
    return 1;
}

int qmi_bcd_plmn(const uint8_t b[3], char mcc[4], char mnc[4]) {
    char m1, m2, m3, n1, n2, n3 = 0;

    /* MCC1 MCC2 | MCC3 MNC3 | MNC1 MNC2, low nibble first in each byte */
    if (!nibble_digit(b[0] & 0x0F, &m1) || !nibble_digit(b[0] >> 4, &m2) ||
        !nibble_digit(b[1] & 0x0F, &m3) || !nibble_digit(b[2] & 0x0F, &n1) ||
        !nibble_digit(b[2] >> 4, &n2))
        return 0;

    if ((b[1] >> 4) != 0x0F && !nibble_digit(b[1] >> 4, &n3))
        return 0;

    mcc[0] = m1;
    mcc[1] = m2;
    mcc[2] = m3;
    mcc[3] = '\0';
    mnc[0] = n1;
    mnc[1] = n2;
    mnc[2] = n3;
    mnc[3] = '\0';

    return 1;
}

static int nas_response(const qmux_msg_t *m, uint16_t msg_id) {
    return m != NULL && m->service == QMI_SVC_NAS && m->msg_id == msg_id &&
        m->is_response;
}

/* 0 on success, else the error to store: the QMI error code, or -1 */
static int nas_error(const qmux_msg_t *m) {
    uint16_t err = 0;
    const int r = qmi_result(m, &err);

    if (r == 1)
        return 0;
    if (r == 0)
        return err != 0 ? err : -1;
    return -1;
}

int qmi_nas_signal_decode(const qmux_msg_t *m, qmi_signal_t *out) {
    size_t vl = 0;
    const uint8_t *v;

    if (out == NULL || !nas_response(m, QMI_NAS_GET_SIGNAL_INFO))
        return 0;

    memset(out, 0, sizeof(*out));
    if ((out->error = nas_error(m)) != 0)
        return 1;

    /* LTE: RSSI i8 dBm, RSRQ i8 dB, RSRP i16 dBm, SNR i16 in 0.1 dB */
    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x14, &vl)) != NULL && vl == 6) {
        out->have_lte = 1;
        out->lte_rssi = (int8_t) v[0];
        out->lte_rsrq = (int8_t) v[1];
        out->lte_rsrp = (int16_t) rd16(v + 2);
        out->lte_snr_x10 = (int16_t) rd16(v + 4);
    }

    /* 5G: RSRP i16 dBm, SNR i16 in 0.1 dB; 5G extended: RSRQ i16 dB */
    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x17, &vl)) != NULL && vl == 4) {
        const int16_t rsrp = (int16_t) rd16(v);
        const int16_t snr = (int16_t) rd16(v + 2);
        if (rsrp != INT16_MIN) {
            out->have_nr_rsrp = 1;
            out->nr_rsrp = rsrp;
        }
        if (snr != INT16_MIN) {
            out->have_nr_snr = 1;
            out->nr_snr_x10 = snr;
        }
    }

    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x18, &vl)) != NULL && vl == 2) {
        const int16_t rsrq = (int16_t) rd16(v);
        if (rsrq != INT16_MIN) {
            out->have_nr_rsrq = 1;
            out->nr_rsrq = rsrq;
        }
    }

    return 1;
}

/* LTE cell: PCI u16, RSRQ i16, RSRP i16, RSSI i16 (0.1 dB), srxlev i16 */
#define LTE_CELL_LEN 10

static void lte_cell(const uint8_t *p, qmi_lte_cell_t *c) {
    c->pci = rd16(p);
    c->rsrq_x10 = (int16_t) rd16(p + 2);
    c->rsrp_x10 = (int16_t) rd16(p + 4);
    c->rssi_x10 = (int16_t) rd16(p + 6);
}

/* 0x13: idle u8, PLMN 3 B BCD, TAC u16, cell id u32, EARFCN u16, serving PCI
 * u16, 4 x u8 reselection thresholds, n u8, n cells */
static void cellloc_intra(const uint8_t *v, size_t vl, qmi_cellloc_t *out) {
    if (vl < 19 || vl != 19 + (size_t) LTE_CELL_LEN * v[18])
        return;

    if (!qmi_bcd_plmn(v + 1, out->lte_mcc, out->lte_mnc)) {
        out->lte_mcc[0] = '\0';
        out->lte_mnc[0] = '\0';
    }

    out->lte_tac = rd16(v + 4);
    out->lte_cell_id = rd32(v + 6);
    out->lte_earfcn = rd16(v + 10);
    out->lte_pci = rd16(v + 12);

    const int n = v[18];
    for (int i = 0; i < n && out->nintra < QMI_LTE_CELLS_MAX; i++)
        lte_cell(v + 19 + LTE_CELL_LEN * i, &out->intra[out->nintra++]);

    out->have_lte = 1;
}

/* 0x14: idle u8, nfreq u8, then per frequency EARFCN u16, 3 x u8, n u8,
 * n cells.  Returns the frequency count on the wire, or -1 if malformed. */
static int cellloc_inter(const uint8_t *v, size_t vl, qmi_cellloc_t *out) {
    if (vl < 2)
        return -1;

    const int nfreq = v[1];
    size_t pos = 2;
    qmi_cellloc_t tmp;
    tmp.ninter = 0;

    for (int f = 0; f < nfreq; f++) {
        if (pos + 6 > vl)
            return -1;

        const uint16_t earfcn = rd16(v + pos);
        const int n = v[pos + 5];
        pos += 6;

        if (pos + (size_t) LTE_CELL_LEN * n > vl)
            return -1;

        if (tmp.ninter < QMI_LTE_FREQS_MAX) {
            qmi_lte_freq_t *fq = &tmp.inter[tmp.ninter++];
            fq->earfcn = earfcn;
            fq->earfcn_proven = 0;
            fq->ncells = 0;
            for (int i = 0; i < n && fq->ncells < QMI_LTE_CELLS_MAX; i++)
                lte_cell(v + pos + LTE_CELL_LEN * i, &fq->cells[fq->ncells++]);
        }

        pos += (size_t) LTE_CELL_LEN * n;
    }

    if (pos != vl)
        return -1;

    out->ninter = tmp.ninter;
    memcpy(out->inter, tmp.inter, sizeof(tmp.inter[0]) * (size_t) tmp.ninter);
    return nfreq;
}

/* 0x2F (22 B): PLMN 3 B BCD, TAC 3 B big-endian, cell id u64, PCI u16,
 * RSRQ, RSRP, SNR i16 in 0.1 dB */
static void cellloc_nr(const uint8_t *v, size_t vl, qmi_cellloc_t *out) {
    if (vl != 22)
        return;

    if (!qmi_bcd_plmn(v, out->nr_mcc, out->nr_mnc)) {
        out->nr_mcc[0] = '\0';
        out->nr_mnc[0] = '\0';
    }

    out->nr_tac = ((uint32_t) v[3] << 16) | ((uint32_t) v[4] << 8) | v[5];
    out->nr_cell_id = rd64(v + 6);
    out->nr_pci = rd16(v + 14);
    out->nr_rsrq_x10 = (int16_t) rd16(v + 16);
    out->nr_rsrp_x10 = (int16_t) rd16(v + 18);
    out->nr_snr_x10 = (int16_t) rd16(v + 20);
    out->have_nr = 1;
}

int qmi_nas_cellloc_decode(const qmux_msg_t *m, qmi_cellloc_t *out) {
    size_t vl = 0;
    const uint8_t *v;
    int inter_wire = -1;

    if (out == NULL || !nas_response(m, QMI_NAS_GET_CELL_LOCATION_INFO))
        return 0;

    memset(out, 0, sizeof(*out));
    out->rrc_connected = -1;
    if ((out->error = nas_error(m)) != 0)
        return 1;

    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x13, &vl)) != NULL)
        cellloc_intra(v, vl, out);

    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x14, &vl)) != NULL)
        inter_wire = cellloc_inter(v, vl, out);

    /* The 16-bit EARFCNs wrap above 65535.  TLV 0x27 carries the serving
     * EARFCN as a u32, and 0x28 the inter-frequency ones in 0x14's order; a
     * value is taken only when its low 16 bits are the 16-bit one. */
    if (out->have_lte &&
        (v = qmi_tlv(m->tlvs, m->tlvs_len, 0x27, &vl)) != NULL && vl == 4) {
        const uint32_t e = rd32(v);
        if ((e & 0xFFFF) == out->lte_earfcn) {
            out->lte_earfcn = e;
            out->lte_earfcn_proven = 1;
        }
    }

    if (inter_wire >= 0 && inter_wire <= QMI_LTE_FREQS_MAX &&
        (v = qmi_tlv(m->tlvs, m->tlvs_len, 0x28, &vl)) != NULL &&
        vl >= 1 && v[0] == inter_wire && vl == 1 + 4 * (size_t) v[0]) {
        int agree = 1;
        for (int i = 0; i < out->ninter; i++) {
            if ((rd32(v + 1 + 4 * i) & 0xFFFF) != out->inter[i].earfcn)
                agree = 0;
        }
        if (agree) {
            for (int i = 0; i < out->ninter; i++) {
                out->inter[i].earfcn = rd32(v + 1 + 4 * i);
                out->inter[i].earfcn_proven = 1;
            }
        }
    }

    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x2C, &vl)) != NULL && vl == 4) {
        const uint32_t c = rd32(v);
        if (c <= 1)
            out->rrc_connected = (int) c;
    }

    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x2E, &vl)) != NULL && vl == 4) {
        out->have_nr_arfcn = 1;
        out->nr_arfcn = rd32(v);
    }

    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x2F, &vl)) != NULL)
        cellloc_nr(v, vl, out);

    return 1;
}

/* An ASCII digit field padded with 0xFF.  1 if what is left is 2-3 digits. */
static int ascii_digits(const uint8_t *p, size_t n, char *out, size_t min) {
    size_t k = 0;

    for (size_t i = 0; i < n; i++) {
        if (p[i] == 0xFF)
            break;
        if (p[i] < '0' || p[i] > '9')
            return 0;
        out[k++] = (char) p[i];
    }

    out[k] = '\0';
    return k >= min;
}

/* 29 B, as (valid u8, value) pairs: domain u8, capability u8, roaming u8,
 * forbidden u8, LAC u16, cell id u32, reject (domain u8, cause u8), network
 * id (MCC 3 + MNC 3 ASCII), TAC u16 */
static void sysinfo_block(const uint8_t *v, size_t vl, qmi_sysinfo_rat_t *out) {
    if (vl != 29)
        return;

    out->have = 1;
    if (v[11]) {
        out->have_cell_id = 1;
        out->cell_id = rd32(v + 12);
    }
    if (v[19] && (!ascii_digits(v + 20, 3, out->mcc, 3) ||
                  !ascii_digits(v + 23, 3, out->mnc, 2))) {
        out->mcc[0] = '\0';
        out->mnc[0] = '\0';
    }
    if (v[26]) {
        out->have_tac = 1;
        out->tac = rd16(v + 27);
    }
}

int qmi_nas_sysinfo_decode(const qmux_msg_t *m, qmi_sysinfo_t *out) {
    size_t vl = 0;
    const uint8_t *v;

    if (out == NULL || !nas_response(m, QMI_NAS_GET_SYSTEM_INFO))
        return 0;

    memset(out, 0, sizeof(*out));
    out->lte_status = -1;
    out->nr_status = -1;
    if ((out->error = nas_error(m)) != 0)
        return 1;

    /* Service status: status u8, true status u8, preferred data path u8 */
    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x14, &vl)) != NULL && vl == 3)
        out->lte_status = v[0];
    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x4A, &vl)) != NULL && vl == 3)
        out->nr_status = v[0];

    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x19, &vl)) != NULL)
        sysinfo_block(v, vl, &out->lte);
    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x4B, &vl)) != NULL)
        sysinfo_block(v, vl, &out->nr);

    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x50, &vl)) != NULL && vl == 3) {
        out->have_nr_tac = 1;
        out->nr_tac = ((uint32_t) v[0] << 16) | ((uint32_t) v[1] << 8) | v[2];
    }

    if ((v = qmi_tlv(m->tlvs, m->tlvs_len, 0x5E, &vl)) != NULL && vl == 8) {
        out->have_nr_cell_id = 1;
        out->nr_cell_id = rd64(v);
    }

    return 1;
}
