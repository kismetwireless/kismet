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

    Selftest for the QMI cell source's framing, NAS decoders, observation
    builder and open order.  Every frame is built here from synthetic values:
    test PLMN 001/01, TAC 0x1234, cell 0xABCDE1, PCIs 1-9, EARFCN 100, and
    65636 (= 65536 + 100) for an EARFCN whose 16-bit form wraps.
*/

#define _GNU_SOURCE

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../capture_cell_diag/cell_discover.h"
#include "qmi_node.h"
#include "qmi_obs.h"
#include "qmi_wire.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                              \
    if (!(cond)) {                                                         \
        printf("FAIL %s:%d: ", __FILE__, __LINE__);                        \
        printf(__VA_ARGS__);                                               \
        printf("\n");                                                      \
        failures++;                                                        \
    }                                                                      \
} while (0)

/* ---------------------------------------------------------------- builders */

typedef struct {
    uint8_t b[2048];
    size_t n;
} tlvbuf_t;

static void put8(tlvbuf_t *t, uint8_t v) { t->b[t->n++] = v; }
static void put16(tlvbuf_t *t, uint16_t v) { put8(t, (uint8_t) v); put8(t, (uint8_t) (v >> 8)); }
static void put32(tlvbuf_t *t, uint32_t v) { put16(t, (uint16_t) v); put16(t, (uint16_t) (v >> 16)); }
static void put64(tlvbuf_t *t, uint64_t v) { put32(t, (uint32_t) v); put32(t, (uint32_t) (v >> 32)); }

/* Open a TLV; tlv_end() patches its length */
static size_t tlv_begin(tlvbuf_t *t, uint8_t type) {
    put8(t, type);
    put16(t, 0);
    return t->n;
}

static void tlv_end(tlvbuf_t *t, size_t start) {
    const size_t len = t->n - start;
    t->b[start - 2] = (uint8_t) len;
    t->b[start - 1] = (uint8_t) (len >> 8);
}

static void tlv_result(tlvbuf_t *t, uint16_t result, uint16_t err) {
    size_t s = tlv_begin(t, 0x02);
    put16(t, result);
    put16(t, err);
    tlv_end(t, s);
}

/* A NAS response frame from a TLV buffer */
static size_t nas_response(uint8_t *out, size_t cap, uint16_t msg, const tlvbuf_t *t) {
    const size_t len = qmux_build(out, cap, QMI_SVC_NAS, 7, 0x0042, msg, t->b, t->n);
    if (len > 0) {
        out[3] = 0x80;          /* from the service */
        out[6] = 0x02;          /* response */
    }
    return len;
}

/* BCD PLMN 001/01: MCC1 MCC2 | MCC3 MNC3(F) | MNC1 MNC2 */
static const uint8_t kPlmn00101[3] = { 0x00, 0xF1, 0x10 };

static void lte_cell(tlvbuf_t *t, uint16_t pci, int16_t rsrq, int16_t rsrp, int16_t rssi) {
    put16(t, pci);
    put16(t, (uint16_t) rsrq);
    put16(t, (uint16_t) rsrp);
    put16(t, (uint16_t) rssi);
    put16(t, 0);                /* srxlev */
}

/* 0x13 serving cell on 16-bit EARFCN `earfcn16`, PCI 1, plus PCI 2 */
static void tlv_intra(tlvbuf_t *t, uint16_t earfcn16) {
    size_t s = tlv_begin(t, 0x13);
    put8(t, 1);                                 /* idle */
    for (int i = 0; i < 3; i++) put8(t, kPlmn00101[i]);
    put16(t, 0x1234);                           /* TAC */
    put32(t, 0xABCDE1);                         /* cell id */
    put16(t, earfcn16);
    put16(t, 1);                                /* serving PCI */
    put8(t, 1); put8(t, 2); put8(t, 3); put8(t, 4);
    put8(t, 2);
    lte_cell(t, 1, -105, -950, -650);
    lte_cell(t, 2, -140, -1101, -801);
    tlv_end(t, s);
}

/* 0x14 two frequencies: `e0` with PCI 3, `e1` with PCIs 4 and 5 */
static void tlv_inter(tlvbuf_t *t, uint16_t e0, uint16_t e1) {
    size_t s = tlv_begin(t, 0x14);
    put8(t, 1);
    put8(t, 2);
    put16(t, e0); put8(t, 0); put8(t, 0); put8(t, 0); put8(t, 1);
    lte_cell(t, 3, -120, -1000, -700);
    put16(t, e1); put8(t, 0); put8(t, 0); put8(t, 0); put8(t, 2);
    lte_cell(t, 4, -130, -1050, -750);
    lte_cell(t, 5, -135, -1075, -775);
    tlv_end(t, s);
}

static void tlv_u32(tlvbuf_t *t, uint8_t type, uint32_t v) {
    size_t s = tlv_begin(t, type);
    put32(t, v);
    tlv_end(t, s);
}

static void tlv_u32_list(tlvbuf_t *t, uint8_t type, int n, const uint32_t *v) {
    size_t s = tlv_begin(t, type);
    put8(t, (uint8_t) n);
    for (int i = 0; i < n; i++)
        put32(t, v[i]);
    tlv_end(t, s);
}

static void tlv_nr_cell(tlvbuf_t *t) {
    size_t s = tlv_begin(t, 0x2F);
    for (int i = 0; i < 3; i++) put8(t, kPlmn00101[i]);
    put8(t, 0x00); put8(t, 0x12); put8(t, 0x34);   /* TAC, big-endian */
    put64(t, 0xABCDE1);
    put16(t, 5);
    put16(t, (uint16_t) -110);                     /* RSRQ -11.0 */
    put16(t, (uint16_t) -985);                     /* RSRP -98.5 */
    put16(t, 45);                                  /* SNR 4.5 */
    tlv_end(t, s);
}

static void tlv_status(tlvbuf_t *t, uint8_t type, uint8_t status) {
    size_t s = tlv_begin(t, type);
    put8(t, status); put8(t, 0); put8(t, 0);
    tlv_end(t, s);
}

/* The 29-byte per-RAT system info block, every value valid */
static void tlv_sysinfo_block(tlvbuf_t *t, uint8_t type) {
    size_t s = tlv_begin(t, type);
    put8(t, 1); put8(t, 2);        /* domain */
    put8(t, 1); put8(t, 3);        /* capability */
    put8(t, 1); put8(t, 0);        /* roaming */
    put8(t, 1); put8(t, 1);        /* forbidden */
    put8(t, 0); put16(t, 0);       /* LAC */
    put8(t, 1); put32(t, 0xABCDE1);
    put8(t, 0); put8(t, 0); put8(t, 0);
    put8(t, 1);
    put8(t, '0'); put8(t, '0'); put8(t, '1');
    put8(t, '0'); put8(t, '1'); put8(t, 0xFF);
    put8(t, 1); put16(t, 0x1234);
    tlv_end(t, s);
}

static int parse_nas(const uint8_t *frame, size_t len, qmux_msg_t *m) {
    return qmux_parse(frame, len, m);
}

/* ------------------------------------------------------------------ QMUX */

static void test_qmux_frames(void) {
    uint8_t f[64];
    qmux_msg_t m;

    /* CTL Get Client ID for NAS: one-byte transaction id */
    size_t n = qmi_ctl_alloc_build(f, sizeof(f), 1, QMI_SVC_NAS);
    static const uint8_t want_alloc[] = {
        0x01, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x22, 0x00, 0x04, 0x00,
        0x01, 0x01, 0x00, 0x03,
    };
    CHECK(n == sizeof(want_alloc) && memcmp(f, want_alloc, n) == 0,
          "CTL get client id frame");
    CHECK(qmux_parse(f, n, &m) && m.service == 0 && m.tid == 1 &&
          m.msg_id == QMI_CTL_GET_CLIENT_ID && !m.is_response, "CTL request parses");

    /* A service request: two-byte transaction id */
    n = qmux_build(f, sizeof(f), QMI_SVC_NAS, 8, 0x0102, QMI_NAS_GET_SIGNAL_INFO, NULL, 0);
    static const uint8_t want_nas[] = {
        0x01, 0x0c, 0x00, 0x00, 0x03, 0x08, 0x00, 0x02, 0x01, 0x4f, 0x00, 0x00, 0x00,
    };
    CHECK(n == sizeof(want_nas) && memcmp(f, want_nas, n) == 0, "NAS request frame");
    CHECK(qmux_parse(f, n, &m) && m.client == 8 && m.tid == 0x0102, "NAS request parses");

    /* Release and its prebuilt form */
    n = qmi_ctl_release_build(f, sizeof(f), 0xFF, QMI_SVC_NAS, 8);
    CHECK(n == 17 && f[7] == 0xFF && f[8] == 0x23 && f[15] == 0x03 && f[16] == 0x08,
          "CTL release frame");

    /* Framing on a stream */
    int bad = 0;
    CHECK(qmux_frame_len(want_nas, 2, &bad) == 0 && !bad, "short head waits");
    CHECK(qmux_frame_len(want_nas, 12, &bad) == 0 && !bad, "partial frame waits");
    CHECK(qmux_frame_len(want_nas, 13, &bad) == 13 && !bad, "whole frame");
    const uint8_t junk[4] = { 0x7e, 0x01, 0x02, 0x03 };
    CHECK(qmux_frame_len(junk, 4, &bad) == 0 && bad, "non-QMUX head is out of sync");
    const uint8_t tiny[3] = { 0x01, 0x03, 0x00 };
    CHECK(qmux_frame_len(tiny, 3, &bad) == 0 && bad, "impossible length is out of sync");

    /* CTL sync is recognised, so no transport sends it through a proxy */
    n = qmux_build(f, sizeof(f), QMI_SVC_CTL, 0, 3, QMI_CTL_SYNC, NULL, 0);
    CHECK(qmux_is_ctl_sync(f, n), "CTL sync recognised");
    n = qmi_ctl_alloc_build(f, sizeof(f), 3, QMI_SVC_NAS);
    CHECK(!qmux_is_ctl_sync(f, n), "CTL allocate is not sync");
}

static void test_qmux_replies(void) {
    uint8_t f[128];
    qmux_msg_t m;
    tlvbuf_t t = { .n = 0 };
    uint8_t cid = 0;
    uint16_t err = 0;

    /* Get Client ID reply: result success, TLV 0x01 = (NAS, 8) */
    tlv_result(&t, 0, 0);
    size_t s = tlv_begin(&t, 0x01);
    put8(&t, QMI_SVC_NAS);
    put8(&t, 8);
    tlv_end(&t, s);
    size_t n = qmux_build(f, sizeof(f), QMI_SVC_CTL, 0, 1, QMI_CTL_GET_CLIENT_ID, t.b, t.n);
    f[3] = 0x80;
    f[6] = 0x01;
    CHECK(qmux_parse(f, n, &m) && m.is_response && !m.is_indication, "CTL reply parses");
    CHECK(qmi_ctl_alloc_parse(&m, QMI_SVC_NAS, &cid) && cid == 8, "client id 8");
    CHECK(!qmi_ctl_alloc_parse(&m, 0x10, &cid), "a reply for another service is refused");

    /* A refused allocation */
    t.n = 0;
    tlv_result(&t, 1, 0x0005);
    n = qmux_build(f, sizeof(f), QMI_SVC_CTL, 0, 1, QMI_CTL_GET_CLIENT_ID, t.b, t.n);
    f[6] = 0x01;
    CHECK(qmux_parse(f, n, &m) && qmi_result(&m, &err) == 0 && err == 5, "error code read");
    CHECK(!qmi_ctl_alloc_parse(&m, QMI_SVC_NAS, &cid), "failed allocation has no id");

    /* No result TLV is never a success */
    t.n = 0;
    n = qmux_build(f, sizeof(f), QMI_SVC_CTL, 0, 1, QMI_CTL_GET_CLIENT_ID, t.b, t.n);
    CHECK(qmux_parse(f, n, &m) && qmi_result(&m, NULL) == -1, "missing result");

    /* A truncated TLV ends the walk instead of reading past the frame */
    const uint8_t tlvs[] = { 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0xff, 0x00, 0x01 };
    size_t vl;
    CHECK(qmi_tlv(tlvs, sizeof(tlvs), 0x02, &vl) != NULL && vl == 4, "TLV found");
    CHECK(qmi_tlv(tlvs, sizeof(tlvs), 0x13, &vl) == NULL, "overlong TLV refused");

    /* An indication is flagged, so a reply matcher skips it */
    t.n = 0;
    n = qmux_build(f, sizeof(f), QMI_SVC_NAS, 7, 9, 0x0024, t.b, t.n);
    f[3] = 0x80;
    f[6] = 0x04;
    CHECK(qmux_parse(f, n, &m) && m.is_indication && !m.is_response, "indication flagged");
}

static void test_proxy_open(void) {
    uint8_t f[300];

    /* qmi-proxy: CTL 0xFF00, TLV 0x01 = the path, ASCII, no NUL */
    size_t n = qmi_ctl_proxy_open_build(f, sizeof(f), 1, "/dev/cdc-wdm0");
    static const uint8_t want[] = {
        0x01, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0x10, 0x00,
        0x01, 0x0d, 0x00, '/', 'd', 'e', 'v', '/', 'c', 'd', 'c', '-', 'w', 'd', 'm', '0',
    };
    CHECK(n == sizeof(want) && memcmp(f, want, n) == 0, "qmi-proxy open frame");
    CHECK(qmi_ctl_proxy_open_build(f, sizeof(f), 1, "") == 0, "empty path refused");
}

/* ------------------------------------------------------------------ MBIM */

static void test_mbim(void) {
    uint8_t f[256], g[256];
    mbim_msg_t m;
    const uint8_t qmux[] = { 0x01, 0x0c, 0x00, 0x00, 0x03, 0x08, 0x00, 0x01, 0x00, 0x4f, 0x00, 0x00, 0x00 };

    size_t n = mbim_command_build(f, sizeof(f), 5, mbim_uuid_qmi, MBIM_CID_QMI_MSG,
                                  MBIM_COMMAND_TYPE_SET, qmux, sizeof(qmux));
    CHECK(n == 48 + sizeof(qmux), "command length");
    CHECK(f[0] == 3 && f[4] == n && f[8] == 5 && f[12] == 1 && f[16] == 0 &&
          memcmp(f + 20, mbim_uuid_qmi, 16) == 0 && f[36] == 1 && f[40] == 1 &&
          f[44] == sizeof(qmux) && memcmp(f + 48, qmux, sizeof(qmux)) == 0,
          "command layout");

    /* COMMAND_DONE carrying the QMUX reply */
    memcpy(g, f, n);
    g[0] = 0x03; g[1] = 0x00; g[2] = 0x00; g[3] = 0x80;
    /* status at 40, info length at 44 */
    memset(g + 40, 0, 4);
    g[44] = sizeof(qmux);
    CHECK(mbim_parse(g, n, &m) && m.type == MBIM_COMMAND_DONE && m.tid == 5 &&
          m.status == 0 && m.cid == 1 && memcmp(m.uuid, mbim_uuid_qmi, 16) == 0 &&
          m.info_len == sizeof(qmux) && memcmp(m.info, qmux, sizeof(qmux)) == 0,
          "command done parses");

    /* An info length past the end is refused */
    g[44] = 200;
    CHECK(!mbim_parse(g, n, &m), "overlong info refused");
    g[44] = sizeof(qmux);

    /* A fragment is refused: nothing read here needs them */
    g[12] = 2;
    CHECK(!mbim_parse(g, n, &m), "fragmented message refused");

    /* OPEN / OPEN_DONE / CLOSE */
    n = mbim_open_build(f, sizeof(f), 1, 4096);
    CHECK(n == 16 && f[0] == 1 && f[4] == 16 && f[8] == 1 && f[12] == 0x00 && f[13] == 0x10,
          "open message");
    n = mbim_close_build(f, sizeof(f), 2);
    CHECK(n == 12 && f[0] == 2, "close message");
    const uint8_t open_done[16] = { 0x01, 0, 0, 0x80, 16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 };
    CHECK(mbim_parse(open_done, 16, &m) && m.type == MBIM_OPEN_DONE && m.status == 0,
          "open done");
    const uint8_t ferr[16] = { 0x04, 0, 0, 0x80, 16, 0, 0, 0, 7, 0, 0, 0, 5, 0, 0, 0 };
    CHECK(mbim_parse(ferr, 16, &m) && m.type == MBIM_FUNCTION_ERROR_MSG && m.tid == 7 &&
          m.status == 5, "function error: not opened");

    /* mbim-proxy configuration: offset 12, UTF-16LE length, timeout, path
     * padded to 4 bytes */
    n = mbim_proxy_config_build(f, sizeof(f), 1, "/dev/cdc-wdm4", 30);
    CHECK(n == 88, "proxy config length (%zu)", n);
    CHECK(memcmp(f + 20, mbim_uuid_proxy_control, 16) == 0 && f[36] == 1 && f[40] == 1 &&
          f[44] == 40 && f[48] == 12 && f[52] == 26 && f[56] == 30 && f[60] == '/' &&
          f[61] == 0 && f[62] == 'd' && f[84] == '4' && f[86] == 0 && f[87] == 0,
          "proxy config layout");

    /* Stream framing */
    int bad = 0;
    CHECK(mbim_frame_len(f, 11, &bad) == 0 && !bad, "MBIM head waits");
    CHECK(mbim_frame_len(f, 50, &bad) == 0 && !bad, "MBIM partial waits");
    CHECK(mbim_frame_len(f, 88, &bad) == 88, "MBIM whole message");
    const uint8_t badlen[12] = { 3, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0 };
    CHECK(mbim_frame_len(badlen, 12, &bad) == 0 && bad, "impossible MBIM length");
}

/* ------------------------------------------------------------------ NAS */

static void test_bcd(void) {
    char mcc[4], mnc[4];
    const uint8_t two[3] = { 0x00, 0xF1, 0x10 };
    const uint8_t three[3] = { 0x00, 0x11, 0x00 };
    const uint8_t hex[3] = { 0x0A, 0xF1, 0x10 };

    CHECK(qmi_bcd_plmn(two, mcc, mnc) && strcmp(mcc, "001") == 0 && strcmp(mnc, "01") == 0,
          "001/01 (%s/%s)", mcc, mnc);
    CHECK(qmi_bcd_plmn(three, mcc, mnc) && strcmp(mcc, "001") == 0 && strcmp(mnc, "001") == 0,
          "001/001 keeps its third MNC digit (%s/%s)", mcc, mnc);
    CHECK(!qmi_bcd_plmn(hex, mcc, mnc), "a non-digit nibble is refused");
}

static void test_signal(void) {
    uint8_t f[256];
    qmux_msg_t m;
    qmi_signal_t s;
    tlvbuf_t t = { .n = 0 };

    tlv_result(&t, 0, 0);
    size_t st = tlv_begin(&t, 0x14);
    put8(&t, (uint8_t) -65); put8(&t, (uint8_t) -10); put16(&t, (uint16_t) -95); put16(&t, 125);
    tlv_end(&t, st);
    st = tlv_begin(&t, 0x17);
    put16(&t, 0x8000); put16(&t, 45);
    tlv_end(&t, st);
    st = tlv_begin(&t, 0x18);
    put16(&t, (uint16_t) -11);
    tlv_end(&t, st);

    size_t n = nas_response(f, sizeof(f), QMI_NAS_GET_SIGNAL_INFO, &t);
    CHECK(parse_nas(f, n, &m) && qmi_nas_signal_decode(&m, &s), "signal decodes");
    CHECK(s.error == 0 && s.have_lte && s.lte_rssi == -65 && s.lte_rsrq == -10 &&
          s.lte_rsrp == -95 && s.lte_snr_x10 == 125, "LTE signal");
    CHECK(!s.have_nr_rsrp && s.have_nr_snr && s.nr_snr_x10 == 45 && s.have_nr_rsrq &&
          s.nr_rsrq == -11, "NR 0x8000 is no measurement");

    /* Information unavailable (airplane mode) is an error, not empty data */
    t.n = 0;
    tlv_result(&t, 1, QMI_ERR_INFO_UNAVAILABLE);
    n = nas_response(f, sizeof(f), QMI_NAS_GET_SIGNAL_INFO, &t);
    CHECK(parse_nas(f, n, &m) && qmi_nas_signal_decode(&m, &s) &&
          s.error == QMI_ERR_INFO_UNAVAILABLE && !s.have_lte, "signal error kept");

    /* Another message's reply is not decoded as this one */
    CHECK(!qmi_nas_cellloc_decode(&m, &(qmi_cellloc_t){0}), "message id checked");
}

static size_t cellloc_frame(uint8_t *f, size_t cap, int serving_u32, int inter_u32) {
    tlvbuf_t t = { .n = 0 };
    tlv_result(&t, 0, 0);
    tlv_intra(&t, 100);
    tlv_inter(&t, 100, 200);
    if (serving_u32 == 1)
        tlv_u32(&t, 0x27, 65636);           /* 65536 + 100: the true serving EARFCN */
    else if (serving_u32 == 2)
        tlv_u32(&t, 0x27, 65637);           /* does not agree with the 16-bit 100 */
    if (inter_u32 == 1) {
        const uint32_t v[2] = { 65636, 200 };
        tlv_u32_list(&t, 0x28, 2, v);
    } else if (inter_u32 == 2) {
        const uint32_t v[1] = { 65636 };
        tlv_u32_list(&t, 0x28, 1, v);       /* fewer than 0x14's frequencies */
    } else if (inter_u32 == 3) {
        const uint32_t v[3] = { 65636, 200, 300 };
        tlv_u32_list(&t, 0x28, 3, v);       /* more: agrees as far as it goes */
    }
    tlv_u32(&t, 0x2C, 1);
    return nas_response(f, cap, QMI_NAS_GET_CELL_LOCATION_INFO, &t);
}

static void test_cellloc(void) {
    uint8_t f[512];
    qmux_msg_t m;
    qmi_cellloc_t c;

    size_t n = cellloc_frame(f, sizeof(f), 1, 1);
    CHECK(parse_nas(f, n, &m) && qmi_nas_cellloc_decode(&m, &c) && c.error == 0, "decodes");
    CHECK(c.have_lte && strcmp(c.lte_mcc, "001") == 0 && strcmp(c.lte_mnc, "01") == 0 &&
          c.lte_tac == 0x1234 && c.lte_cell_id == 0xABCDE1 && c.lte_pci == 1, "serving cell");
    CHECK(c.lte_earfcn == 65636 && c.lte_earfcn_proven, "serving EARFCN from 0x27");
    CHECK(c.nintra == 2 && c.intra[1].pci == 2 && c.intra[1].rsrp_x10 == -1101 &&
          c.intra[1].rssi_x10 == -801, "intra-frequency cells");
    CHECK(c.ninter == 2 && c.inter[0].earfcn == 65636 && c.inter[0].earfcn_proven &&
          c.inter[1].earfcn == 200 && c.inter[1].earfcn_proven &&
          c.inter[1].ncells == 2 && c.inter[1].cells[1].pci == 5, "inter-frequency cells");
    CHECK(c.rrc_connected == 1, "RRC connected");

    /* No 32-bit TLVs: the 16-bit values are kept but not proven */
    n = cellloc_frame(f, sizeof(f), 0, 0);
    CHECK(parse_nas(f, n, &m) && qmi_nas_cellloc_decode(&m, &c) && c.lte_earfcn == 100 &&
          !c.lte_earfcn_proven && !c.inter[0].earfcn_proven, "unproven without 0x27/0x28");

    /* A 32-bit value that disagrees proves nothing */
    n = cellloc_frame(f, sizeof(f), 2, 2);
    CHECK(parse_nas(f, n, &m) && qmi_nas_cellloc_decode(&m, &c) && c.lte_earfcn == 100 &&
          !c.lte_earfcn_proven && !c.inter[0].earfcn_proven && !c.inter[1].earfcn_proven,
          "mismatched 0x27 and a short 0x28 prove nothing");

    /* 0x28 lists the frequencies of 0x14, in order; a list of another
     * length is another list, even where its first values agree */
    n = cellloc_frame(f, sizeof(f), 1, 3);
    CHECK(parse_nas(f, n, &m) && qmi_nas_cellloc_decode(&m, &c) && c.lte_earfcn_proven &&
          !c.inter[0].earfcn_proven && !c.inter[1].earfcn_proven,
          "a long 0x28 proves nothing");

    /* NR serving cell */
    tlvbuf_t t = { .n = 0 };
    tlv_result(&t, 0, 0);
    tlv_u32(&t, 0x2E, 100);
    tlv_nr_cell(&t);
    n = nas_response(f, sizeof(f), QMI_NAS_GET_CELL_LOCATION_INFO, &t);
    CHECK(parse_nas(f, n, &m) && qmi_nas_cellloc_decode(&m, &c) && !c.have_lte &&
          c.have_nr && c.have_nr_arfcn && c.nr_arfcn == 100, "NR decodes");
    CHECK(strcmp(c.nr_mcc, "001") == 0 && strcmp(c.nr_mnc, "01") == 0 &&
          c.nr_tac == 0x1234 && c.nr_cell_id == 0xABCDE1 && c.nr_pci == 5 &&
          c.nr_rsrp_x10 == -985 && c.nr_rsrq_x10 == -110 && c.nr_snr_x10 == 45,
          "NR cell, TAC big-endian");

    /* A malformed 0x13 (count past the end) is ignored, not half read */
    t.n = 0;
    tlv_result(&t, 0, 0);
    size_t s = tlv_begin(&t, 0x13);
    for (int i = 0; i < 18; i++) put8(&t, 0);
    put8(&t, 3);                    /* claims 3 cells, carries none */
    tlv_end(&t, s);
    n = nas_response(f, sizeof(f), QMI_NAS_GET_CELL_LOCATION_INFO, &t);
    CHECK(parse_nas(f, n, &m) && qmi_nas_cellloc_decode(&m, &c) && !c.have_lte,
          "short 0x13 ignored");

    /* No network found */
    t.n = 0;
    tlv_result(&t, 1, QMI_ERR_NO_NETWORK_FOUND);
    n = nas_response(f, sizeof(f), QMI_NAS_GET_CELL_LOCATION_INFO, &t);
    CHECK(parse_nas(f, n, &m) && qmi_nas_cellloc_decode(&m, &c) &&
          c.error == QMI_ERR_NO_NETWORK_FOUND, "no network found");
}

static size_t sysinfo_frame(uint8_t *f, size_t cap, int lte_status, int nr_status,
                            int lte_block, int nr_ids) {
    tlvbuf_t t = { .n = 0 };
    tlv_result(&t, 0, 0);
    tlv_status(&t, 0x13, 0);
    if (lte_status >= 0)
        tlv_status(&t, 0x14, (uint8_t) lte_status);
    if (nr_status >= 0)
        tlv_status(&t, 0x4A, (uint8_t) nr_status);
    if (lte_block)
        tlv_sysinfo_block(&t, 0x19);
    if (nr_ids) {
        tlv_sysinfo_block(&t, 0x4B);
        size_t s = tlv_begin(&t, 0x50);
        put8(&t, 0x00); put8(&t, 0x12); put8(&t, 0x34);
        tlv_end(&t, s);
        s = tlv_begin(&t, 0x5E);
        put64(&t, 0xABCDE1);
        tlv_end(&t, s);
    }
    return nas_response(f, cap, QMI_NAS_GET_SYSTEM_INFO, &t);
}

static void test_sysinfo(void) {
    uint8_t f[512];
    qmux_msg_t m;
    qmi_sysinfo_t s;

    size_t n = sysinfo_frame(f, sizeof(f), QMI_SRV_LIMITED, QMI_SRV_AVAILABLE, 1, 1);
    CHECK(parse_nas(f, n, &m) && qmi_nas_sysinfo_decode(&m, &s) && s.error == 0, "decodes");
    CHECK(s.lte_status == QMI_SRV_LIMITED && s.nr_status == QMI_SRV_AVAILABLE, "statuses");
    CHECK(s.lte.have && s.lte.have_cell_id && s.lte.cell_id == 0xABCDE1 &&
          strcmp(s.lte.mcc, "001") == 0 && strcmp(s.lte.mnc, "01") == 0 &&
          s.lte.have_tac && s.lte.tac == 0x1234, "LTE block");
    CHECK(s.have_nr_tac && s.nr_tac == 0x1234 && s.have_nr_cell_id &&
          s.nr_cell_id == 0xABCDE1, "NR TAC big-endian, NR cell id");

    n = sysinfo_frame(f, sizeof(f), -1, -1, 0, 0);
    CHECK(parse_nas(f, n, &m) && qmi_nas_sysinfo_decode(&m, &s) && s.lte_status == -1 &&
          s.nr_status == -1 && !s.lte.have, "absent statuses are -1");
}

/* ---------------------------------------------------------- observations */

static char rows[QMI_OBS_MAX][QMI_OBS_JSON_MAX];

static int row_has(int n, const char *needle) {
    for (int i = 0; i < n; i++) {
        if (strstr(rows[i], needle) != NULL)
            return 1;
    }
    return 0;
}

static void decode_all(qmi_sysinfo_t *si, qmi_cellloc_t *cl, qmi_signal_t *sg,
                       int cl_serving_u32, int cl_inter_u32) {
    uint8_t f[512];
    qmux_msg_t m;
    tlvbuf_t t = { .n = 0 };

    size_t n = sysinfo_frame(f, sizeof(f), QMI_SRV_AVAILABLE, -1, 1, 0);
    parse_nas(f, n, &m);
    qmi_nas_sysinfo_decode(&m, si);

    n = cellloc_frame(f, sizeof(f), cl_serving_u32, cl_inter_u32);
    parse_nas(f, n, &m);
    qmi_nas_cellloc_decode(&m, cl);

    tlv_result(&t, 0, 0);
    size_t st = tlv_begin(&t, 0x14);
    put8(&t, (uint8_t) -65); put8(&t, (uint8_t) -10); put16(&t, (uint16_t) -95); put16(&t, -52);
    tlv_end(&t, st);
    n = nas_response(f, sizeof(f), QMI_NAS_GET_SIGNAL_INFO, &t);
    parse_nas(f, n, &m);
    qmi_nas_signal_decode(&m, sg);
}

static void test_obs_lte(void) {
    qmi_sysinfo_t si;
    qmi_cellloc_t cl;
    qmi_signal_t sg;
    qmi_obs_stats_t st;

    decode_all(&si, &cl, &sg, 1, 1);
    int n = qmi_obs_build(&si, &cl, &sg, 1000.5, rows, QMI_OBS_MAX, &st);
    CHECK(n == 5 && st.serving == 1 && st.neighbours == 4 && st.unproven_earfcn == 0,
          "serving + PCI 2 + PCIs 3, 4, 5 (n=%d)", n);
    CHECK(strcmp(rows[0], "{\"rat\":\"LTE\",\"mcc\":\"001\",\"mnc\":\"01\",\"tac\":4660,"
                 "\"cell_id\":11259361,\"pci\":1,\"earfcn\":65636,\"rsrp\":-95,"
                 "\"rsrq\":-10,\"rssi\":-65,\"snr\":-5.2,\"is_serving\":true,"
                 "\"observation_type\":\"serving\",\"prov\":{\"src\":\"qmi\","
                 "\"origin\":\"NAS:0x0043\",\"captured_at\":1000.500}}") == 0,
          "serving row: %s", rows[0]);
    CHECK(strcmp(rows[1], "{\"rat\":\"LTE\",\"pci\":2,\"earfcn\":65636,\"rsrp\":-110.1,"
                 "\"rsrq\":-14.0,\"rssi\":-80.1,\"is_serving\":false,"
                 "\"observation_type\":\"observation\",\"prov\":{\"src\":\"qmi\","
                 "\"origin\":\"NAS:0x0043\",\"captured_at\":1000.500}}") == 0,
          "intra neighbour row: %s", rows[1]);
    CHECK(row_has(n, "\"pci\":3,\"earfcn\":65636") && row_has(n, "\"pci\":5,\"earfcn\":200"),
          "inter neighbours carry their proven EARFCNs");

    /* Without the 32-bit TLVs: the serving cell keeps its global identity but
     * no EARFCN, and the neighbours (PCI + EARFCN only) are dropped */
    decode_all(&si, &cl, &sg, 0, 0);
    n = qmi_obs_build(&si, &cl, &sg, 1000.5, rows, QMI_OBS_MAX, &st);
    CHECK(n == 1 && st.serving == 1 && st.unproven_earfcn == 5, "unproven: n=%d unproven=%d",
          n, st.unproven_earfcn);
    CHECK(strstr(rows[0], "earfcn") == NULL && strstr(rows[0], "\"cell_id\":11259361") != NULL,
          "no EARFCN written unproven: %s", rows[0]);

    /* Signal falls back to the serving PCI's own measurement */
    decode_all(&si, &cl, &sg, 1, 1);
    n = qmi_obs_build(&si, &cl, NULL, 1.0, rows, QMI_OBS_MAX, &st);
    CHECK(n == 5 && strstr(rows[0], "\"rsrp\":-95.0,\"rsrq\":-10.5,\"rssi\":-65.0") != NULL,
          "serving signal from the cell list: %s", rows[0]);
}

static void test_obs_service(void) {
    uint8_t f[512];
    qmux_msg_t m;
    qmi_sysinfo_t si;
    qmi_cellloc_t cl;
    qmi_obs_stats_t st;
    tlvbuf_t t = { .n = 0 };

    /* Out of coverage: every RAT power-save */
    size_t n = sysinfo_frame(f, sizeof(f), QMI_SRV_POWER_SAVE, QMI_SRV_POWER_SAVE, 0, 0);
    parse_nas(f, n, &m);
    qmi_nas_sysinfo_decode(&m, &si);
    tlv_result(&t, 1, QMI_ERR_NO_NETWORK_FOUND);
    n = nas_response(f, sizeof(f), QMI_NAS_GET_CELL_LOCATION_INFO, &t);
    parse_nas(f, n, &m);
    qmi_nas_cellloc_decode(&m, &cl);
    CHECK(qmi_obs_build(&si, &cl, NULL, 1.0, rows, QMI_OBS_MAX, &st) == 0 && st.no_service,
          "power-save is no service");

    /* A refused camp: cell location finds no network, system info names the
     * cell.  It is a real cell, reported from system info. */
    n = sysinfo_frame(f, sizeof(f), QMI_SRV_LIMITED, QMI_SRV_NONE, 1, 0);
    parse_nas(f, n, &m);
    qmi_nas_sysinfo_decode(&m, &si);
    int r = qmi_obs_build(&si, &cl, NULL, 1.0, rows, QMI_OBS_MAX, &st);
    CHECK(r == 1 && !st.no_service && strstr(rows[0], "\"cell_id\":11259361") != NULL &&
          strstr(rows[0], "\"origin\":\"NAS:0x004D\"") != NULL,
          "limited camp from system info: %s", r > 0 ? rows[0] : "");

    /* With no system info, "no network found" alone decides */
    CHECK(qmi_obs_build(NULL, &cl, NULL, 1.0, rows, QMI_OBS_MAX, &st) == 0 && st.no_service,
          "cell location alone");

    /* Nothing read at all is not "no service": nothing is known */
    CHECK(qmi_obs_build(NULL, NULL, NULL, 1.0, rows, QMI_OBS_MAX, &st) == 0 && !st.no_service,
          "no replies, no verdict");
}

static void test_obs_nr(void) {
    uint8_t f[512];
    qmux_msg_t m;
    qmi_sysinfo_t si;
    qmi_cellloc_t cl;
    qmi_obs_stats_t st;
    tlvbuf_t t = { .n = 0 };

    size_t n = sysinfo_frame(f, sizeof(f), QMI_SRV_NONE, QMI_SRV_AVAILABLE, 0, 1);
    parse_nas(f, n, &m);
    qmi_nas_sysinfo_decode(&m, &si);

    tlv_result(&t, 0, 0);
    tlv_u32(&t, 0x2E, 100);
    tlv_nr_cell(&t);
    n = nas_response(f, sizeof(f), QMI_NAS_GET_CELL_LOCATION_INFO, &t);
    parse_nas(f, n, &m);
    qmi_nas_cellloc_decode(&m, &cl);

    int r = qmi_obs_build(&si, &cl, NULL, 2.0, rows, QMI_OBS_MAX, &st);
    CHECK(r == 1 && strcmp(rows[0], "{\"rat\":\"NR\",\"mcc\":\"001\",\"mnc\":\"01\","
                           "\"cell_id\":11259361,\"tac\":4660,\"pci\":5,\"earfcn\":100,"
                           "\"rsrp\":-98.5,\"rsrq\":-11.0,\"snr\":4.5,\"is_serving\":true,"
                           "\"observation_type\":\"serving\",\"prov\":{\"src\":\"qmi\","
                           "\"origin\":\"NAS:0x0043\",\"captured_at\":2.000}}") == 0,
          "NR serving row: %s", r > 0 ? rows[0] : "");

    /* Without cell location's NR cell, system info's identity is used */
    r = qmi_obs_build(&si, NULL, NULL, 2.0, rows, QMI_OBS_MAX, &st);
    CHECK(r == 1 && strstr(rows[0], "\"rat\":\"NR\"") != NULL &&
          strstr(rows[0], "\"cell_id\":11259361,\"tac\":4660") != NULL,
          "NR from system info: %s", r > 0 ? rows[0] : "");
}

/* ------------------------------------------------------------- open order */

static qmi_open_facts_t facts(int listening, const char *held, const char *other) {
    qmi_open_facts_t f;
    memset(&f, 0, sizeof(f));
    f.proxy_listening = listening;
    if (held != NULL) {
        f.held = 1;
        f.held_pid = 100;
        snprintf(f.held_comm, sizeof(f.held_comm), "%s", held);
    }
    if (other != NULL) {
        f.held_by_other = 1;
        f.other_pid = 200;
        snprintf(f.other_comm, sizeof(f.other_comm), "%s", other);
    }
    return f;
}

static void test_open_order(void) {
    qmi_open_plan_t p;
    qmi_open_facts_t f;
    const char *dev = "/dev/cdc-wdm9";

    f = facts(0, NULL, NULL);
    qmi_open_decide(dev, QMI_FRAMING_QMUX, QMI_OPEN_AUTO, &f, &p);
    CHECK(p.mode == QMI_PLAN_DIRECT, "nothing running: direct");

    f = facts(1, NULL, NULL);
    qmi_open_decide(dev, QMI_FRAMING_QMUX, QMI_OPEN_AUTO, &f, &p);
    CHECK(p.mode == QMI_PLAN_PROXY && strcmp(p.proxy, "qmi-proxy") == 0, "qmi-proxy");

    f = facts(1, "mbim-proxy", NULL);
    qmi_open_decide(dev, QMI_FRAMING_MBIM, QMI_OPEN_AUTO, &f, &p);
    CHECK(p.mode == QMI_PLAN_PROXY && strcmp(p.proxy, "mbim-proxy") == 0,
          "the proxy holding the node is the proxy doing its job");

    f = facts(1, "uqmi", "uqmi");
    qmi_open_decide(dev, QMI_FRAMING_QMUX, QMI_OPEN_AUTO, &f, &p);
    CHECK(p.mode == QMI_PLAN_REFUSE && strstr(p.reason, "uqmi (pid 200)") != NULL,
          "foreign holder refused beside a proxy: %s", p.reason);

    f = facts(0, "qmi-proxy", NULL);
    qmi_open_decide(dev, QMI_FRAMING_QMUX, QMI_OPEN_AUTO, &f, &p);
    CHECK(p.mode == QMI_PLAN_REFUSE, "a proxy holding the node but not listening");

    f = facts(0, NULL, NULL);
    qmi_open_decide(dev, QMI_FRAMING_QMUX, QMI_OPEN_PROXY_ONLY, &f, &p);
    CHECK(p.mode == QMI_PLAN_REFUSE && strstr(p.reason, "does not start it") != NULL,
          "open=proxy never starts one");

    f = facts(1, NULL, NULL);
    qmi_open_decide(dev, QMI_FRAMING_QMUX, QMI_OPEN_DIRECT_ONLY, &f, &p);
    CHECK(p.mode == QMI_PLAN_DIRECT, "open=direct ignores a listening proxy with no holder");

    f = facts(1, "qmi-proxy", NULL);
    qmi_open_decide(dev, QMI_FRAMING_QMUX, QMI_OPEN_DIRECT_ONLY, &f, &p);
    CHECK(p.mode == QMI_PLAN_REFUSE, "open=direct refuses a node the proxy holds");
}

/* A scratch filesystem root for the sysfs and /proc readers */
static char g_tmp[256];

static void mkdirs(const char *rel) {
    char path[512], *p;
    snprintf(path, sizeof(path), "%s%s", g_tmp, rel);
    for (p = path + strlen(g_tmp) + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(path, 0755);
            *p = '/';
        }
    }
    mkdir(path, 0755);
}

static void write_file(const char *rel, const char *text) {
    char path[512];
    snprintf(path, sizeof(path), "%s%s", g_tmp, rel);
    FILE *f = fopen(path, "w");
    if (f != NULL) {
        fputs(text, f);
        fclose(f);
    }
}

static void link_to(const char *rel, const char *target) {
    char path[512];
    snprintf(path, sizeof(path), "%s%s", g_tmp, rel);
    if (symlink(target, path) != 0)
        printf("note: symlink %s failed\n", path);
}

static void test_node_names(void) {
    CHECK(qmi_node_name_ok("cdc-wdm0") && qmi_node_name_ok("cdc-wdm12") &&
          qmi_node_name_ok("wwan0qmi0") && qmi_node_name_ok("wwan1mbim0") &&
          qmi_node_name_ok("mhi_QMI0") && qmi_node_name_ok("mhi_MBIM1"), "node names");
    CHECK(!qmi_node_name_ok("cdc-wdm") && !qmi_node_name_ok("ttyUSB2") &&
          !qmi_node_name_ok("wwan0at0") && !qmi_node_name_ok("mhi_DIAG") &&
          !qmi_node_name_ok("cdc-wdm0x") && !qmi_node_name_ok("cellqmi"),
          "other names refused");

    char drv[64];
    CHECK(qmi_node_framing("/dev/wwan0qmi0", drv, sizeof(drv)) == QMI_FRAMING_QMUX &&
          strcmp(drv, "wwan") == 0, "wwan QMI");
    CHECK(qmi_node_framing("/dev/wwan0mbim0", drv, sizeof(drv)) == QMI_FRAMING_MBIM,
          "wwan MBIM");
    CHECK(qmi_node_framing("/dev/mhi_QMI0", drv, sizeof(drv)) == QMI_FRAMING_QMUX &&
          strcmp(drv, "mhi") == 0, "MHI QMI");
}

static void test_node_sysfs(void) {
    char drv[64];

    mkdirs("/sys/class/usbmisc/cdc-wdm7/device");
    mkdirs("/sys/class/usbmisc/cdc-wdm8/device");
    mkdirs("/sys/class/usbmisc/cdc-wdm9/device");
    link_to("/sys/class/usbmisc/cdc-wdm7/device/driver", "../../../bus/usb/drivers/qmi_wwan");
    link_to("/sys/class/usbmisc/cdc-wdm8/device/driver", "../../../bus/usb/drivers/cdc_mbim");
    link_to("/sys/class/usbmisc/cdc-wdm9/device/driver", "../../../bus/usb/drivers/cdc_wdm");

    qmi_node_set_root(g_tmp);
    CHECK(qmi_node_framing("/dev/cdc-wdm7", drv, sizeof(drv)) == QMI_FRAMING_QMUX &&
          strcmp(drv, "qmi_wwan") == 0, "qmi_wwan speaks QMUX");
    CHECK(qmi_node_framing("/dev/cdc-wdm8", drv, sizeof(drv)) == QMI_FRAMING_MBIM &&
          strcmp(drv, "cdc_mbim") == 0, "cdc_mbim speaks MBIM");
    CHECK(qmi_node_framing("/dev/cdc-wdm9", drv, sizeof(drv)) == QMI_FRAMING_NONE &&
          strcmp(drv, "cdc_wdm") == 0, "an unknown driver is not guessed");
    CHECK(qmi_node_framing("/dev/cdc-wdm6", drv, sizeof(drv)) == QMI_FRAMING_NONE,
          "no driver link");

    /* /proc/net/unix: @qmi-proxy listening, @mbim-proxy only connected */
    mkdirs("/proc/net");
    write_file("/proc/net/unix",
               "Num       RefCount Protocol Flags    Type St Inode Path\n"
               "0000000000000000: 00000002 00000000 00010000 0001 01 1001 @qmi-proxy\n"
               "0000000000000000: 00000003 00000000 00000000 0001 03 1002 @mbim-proxy\n"
               "0000000000000000: 00000002 00000000 00010000 0001 01 1003 /run/other.sock\n");
    CHECK(qmi_abstract_listening("qmi-proxy"), "listening proxy found");
    CHECK(!qmi_abstract_listening("mbim-proxy"), "a connected socket is not listening");
    CHECK(!qmi_abstract_listening("other.sock"), "a path socket is not abstract");

    /* /proc/<pid>/fd holders: the proxy is not contention, anything else is */
    mkdirs("/proc/4001/fd");
    write_file("/proc/4001/comm", "qmi-proxy\n");
    link_to("/proc/4001/fd/5", "/dev/cdc-wdm7");
    mkdirs("/proc/4002/fd");
    write_file("/proc/4002/comm", "uqmi\n");
    link_to("/proc/4002/fd/3", "/dev/cdc-wdm8");
    mkdirs("/proc/4003/fd");
    write_file("/proc/4003/comm", "kismet_cap_cell\n");
    link_to("/proc/4003/fd/3", "/dev/cdc-wdm9");

    cell_busy_t b;
    CHECK(cell_node_held_path("/dev/cdc-wdm7", NULL, &b) && b.pid == 4001 &&
          strcmp(b.comm, "qmi-proxy") == 0, "the proxy holds wdm7");
    CHECK(!cell_node_held_path("/dev/cdc-wdm7", "qmi-proxy", &b),
          "nothing but the proxy holds wdm7");
    CHECK(cell_node_held_path("/dev/cdc-wdm8", "mbim-proxy", &b) && b.pid == 4002 &&
          strcmp(b.comm, "uqmi") == 0, "uqmi holds wdm8");
    CHECK(!cell_node_held_path("/dev/cdc-wdm9", NULL, &b),
          "a Kismet cell source is left to flock()");

    qmi_node_set_root("");
}

int main(void) {
    snprintf(g_tmp, sizeof(g_tmp), "/tmp/test_cellqmi.XXXXXX");
    if (mkdtemp(g_tmp) == NULL) {
        printf("FAIL: mkdtemp\n");
        return 1;
    }

    test_qmux_frames();
    test_qmux_replies();
    test_proxy_open();
    test_mbim();
    test_bcd();
    test_signal();
    test_cellloc();
    test_sysinfo();
    test_obs_lte();
    test_obs_service();
    test_obs_nr();
    test_open_order();
    test_node_names();
    test_node_sysfs();

    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_tmp);
    if (system(cmd) != 0)
        printf("note: could not remove %s\n", g_tmp);

    if (failures) {
        printf("test_cellqmi: %d FAILED\n", failures);
        return 1;
    }

    printf("test_cellqmi: all passed\n");
    return 0;
}
