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

#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "../capture_cell_diag/cell_discover.h"
#include "mbim_obs.h"
#include "mbim_wire.h"
#include "qmi_node.h"
#include "qmi_obs.h"
#include "qmi_transport.h"
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

/* ------------------------------------------------------ cold-open backlog */

/* A fake QMI node on a raw pty.  While the backlog lasts it sends a NAS
 * indication every PACE_MS for clients nobody released, as a cdc-wdm node
 * does on a cold open: one message per interrupt poll.  The reply to a CTL
 * Get Client ID queues behind the backlog, the way the real one does.  Each
 * client id request it sees is reported as one byte on `count_fd`, so a test
 * can tell an open that asked once from one that asked again (and so
 * allocated, and leaked, a second client).  `backlog_ms` < 0 never stops;
 * `answer` 0 never replies. */
#define FAKE_PACE_MS 30

static long fake_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void fake_node(int master, int count_fd, long backlog_ms, int answer) {
    const long t0 = fake_now_ms();
    long next_ind = t0;
    uint8_t in[4096], f[128];
    size_t inlen = 0;
    uint8_t pending[16];
    size_t npending = 0;
    uint8_t rel_tid[16], rel_cid[16];
    size_t nrel = 0;

    for (;;) {
        const long now = fake_now_ms();
        const int in_backlog = backlog_ms < 0 || now - t0 < backlog_ms;

        if (in_backlog && now >= next_ind) {
            tlvbuf_t t = { .n = 0 };
            size_t s = tlv_begin(&t, 0x01);
            put8(&t, 1);
            tlv_end(&t, s);
            size_t n = qmux_build(f, sizeof(f), QMI_SVC_NAS, (uint8_t) (3 + (now / FAKE_PACE_MS) % 5),
                                  0, 0x0024, t.b, t.n);
            f[3] = 0x80;
            f[6] = 0x04;
            if (write(master, f, n) < 0)
                _exit(0);
            next_ind += FAKE_PACE_MS;
        }

        if (!in_backlog && answer && npending > 0) {
            for (size_t i = 0; i < npending; i++) {
                tlvbuf_t t = { .n = 0 };
                tlv_result(&t, 0, 0);
                size_t s = tlv_begin(&t, 0x01);
                put8(&t, QMI_SVC_NAS);
                put8(&t, 8);
                tlv_end(&t, s);
                size_t n = qmux_build(f, sizeof(f), QMI_SVC_CTL, 0, pending[i],
                                      QMI_CTL_GET_CLIENT_ID, t.b, t.n);
                f[3] = 0x80;
                f[6] = 0x01;
                if (write(master, f, n) < 0)
                    _exit(0);
            }
            npending = 0;
        }

        for (size_t i = 0; i < nrel; i++) {
            tlvbuf_t t = { .n = 0 };
            tlv_result(&t, 0, 0);
            size_t s = tlv_begin(&t, 0x01);
            put8(&t, QMI_SVC_NAS);
            put8(&t, rel_cid[i]);
            tlv_end(&t, s);
            size_t n = qmux_build(f, sizeof(f), QMI_SVC_CTL, 0, rel_tid[i],
                                  QMI_CTL_RELEASE_CLIENT_ID, t.b, t.n);
            f[3] = 0x80;
            f[6] = 0x01;
            if (write(master, f, n) < 0)
                _exit(0);
        }
        nrel = 0;

        struct pollfd p = { .fd = master, .events = POLLIN };
        if (poll(&p, 1, 5) > 0) {
            ssize_t r = read(master, in + inlen, sizeof(in) - inlen);
            if (r <= 0)
                _exit(0);
            inlen += (size_t) r;
        }

        for (;;) {
            int bad = 0;
            size_t fl = qmux_frame_len(in, inlen, &bad);
            if (bad) {
                inlen = 0;
                break;
            }
            if (fl == 0 || fl > inlen)
                break;
            qmux_msg_t m;
            if (qmux_parse(in, fl, &m) && m.service == QMI_SVC_CTL &&
                m.msg_id == QMI_CTL_GET_CLIENT_ID) {
                if (write(count_fd, "a", 1) < 0)
                    _exit(0);
                if (npending < sizeof(pending))
                    pending[npending++] = (uint8_t) m.tid;
            }
            /* A release is reported as 'r' and the id it names */
            if (qmux_parse(in, fl, &m) && m.service == QMI_SVC_CTL &&
                m.msg_id == QMI_CTL_RELEASE_CLIENT_ID && fl >= 6 + 6 + 5) {
                const uint8_t rel[2] = { 'r', in[fl - 1] };
                if (write(count_fd, rel, 2) < 0)
                    _exit(0);
                if (nrel < sizeof(rel_tid)) {
                    rel_tid[nrel] = (uint8_t) m.tid;
                    rel_cid[nrel++] = in[fl - 1];
                }
            }
            memmove(in, in + fl, inlen - fl);
            inlen -= fl;
        }
    }
}

typedef struct {
    int opened;
    uint8_t cid;
    long elapsed_ms;
    int alloc_requests;
} cold_open_t;

static cold_open_t cold_open(long backlog_ms, int answer, int timeout_ms) {
    cold_open_t res = { 0, 0, 0, -1 };
    int counts[2];

    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0 || pipe(counts) < 0) {
        printf("FAIL: cannot make a pty for the fake node\n");
        failures++;
        return res;
    }
    const char *slave_name = ptsname(master);
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    struct termios tio;
    if (slave < 0 || tcgetattr(slave, &tio) < 0) {
        printf("FAIL: cannot open the pty slave\n");
        failures++;
        return res;
    }
    cfmakeraw(&tio);
    tcsetattr(slave, TCSANOW, &tio);

    pid_t pid = fork();
    if (pid == 0) {
        close(counts[0]);
        close(slave);
        fake_node(master, counts[1], backlog_ms, answer);
        _exit(0);
    }
    close(counts[1]);

    qmi_session_t s;
    char err[256] = "";
    const long t0 = fake_now_ms();
    res.opened = qmi_session_open(&s, slave_name, QMI_FRAMING_QMUX, 0, timeout_ms,
                                  err, sizeof(err));
    res.elapsed_ms = fake_now_ms() - t0;
    if (res.opened) {
        res.cid = s.nas_cid;
        qmi_session_close(&s);
    }

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

    char buf[64];
    ssize_t n = read(counts[0], buf, sizeof(buf));
    res.alloc_requests = 0;
    for (ssize_t i = 0; i < n; i++)
        res.alloc_requests += buf[i] == 'a';
    close(counts[0]);
    close(slave);
    close(master);
    return res;
}

static void test_cold_open_backlog(void) {
    /* The measured shape (#7363), scaled down: the reply sits behind a
     * backlog that never goes 150 ms quiet and outlasts the open's 2 s drain
     * plus two 400 ms deadlines.  The open must read through it and ask for a
     * client id exactly once: a second request allocates a second client,
     * whose late reply nobody reads, so it leaks and lengthens the backlog
     * on the next cold open. */
    cold_open_t r = cold_open(4000, 1, 400);
    CHECK(r.opened && r.cid == 8, "backlog: open reads through 4 s of indications "
          "(opened=%d cid=%u after %ld ms)", r.opened, r.cid, r.elapsed_ms);
    CHECK(r.alloc_requests == 1, "backlog: one client id request, not %d",
          r.alloc_requests);

    /* A node that never answers still fails on the caller's deadline: the
     * backlog allowance must not make a silent node cost the backlog cap */
    r = cold_open(0, 0, 400);
    CHECK(!r.opened, "silent: open fails");
    CHECK(r.elapsed_ms < 2000, "silent: fails in %ld ms, not the backlog cap",
          r.elapsed_ms);

    /* Indications that never stop and no reply: bounded by the cap */
    r = cold_open(-1, 0, 400);
    CHECK(!r.opened, "endless backlog: open fails");
    CHECK(r.elapsed_ms < 2 * QMI_OPEN_BACKLOG_MAX_MS + 3000,
          "endless backlog: gives up in %ld ms", r.elapsed_ms);
}

/* A fake node that stays up across several sessions, for the client id
 * record (#7452 b).  Its reports go to `counts`: 'a' per client id request,
 * 'r' and the id per release. */
typedef struct {
    int master, slave, counts;
    pid_t pid;
    char slave_name[128];
} fake_t;

static int fake_start(fake_t *fk) {
    int c[2];
    struct termios tio;

    memset(fk, 0, sizeof(*fk));
    fk->master = posix_openpt(O_RDWR | O_NOCTTY);
    if (fk->master < 0 || grantpt(fk->master) < 0 || unlockpt(fk->master) < 0 ||
        pipe(c) < 0)
        return 0;
    snprintf(fk->slave_name, sizeof(fk->slave_name), "%s", ptsname(fk->master));
    fk->slave = open(fk->slave_name, O_RDWR | O_NOCTTY);
    if (fk->slave < 0 || tcgetattr(fk->slave, &tio) < 0)
        return 0;
    cfmakeraw(&tio);
    tcsetattr(fk->slave, TCSANOW, &tio);
    fcntl(c[0], F_SETFL, O_NONBLOCK);

    fk->pid = fork();
    if (fk->pid == 0) {
        close(c[0]);
        close(fk->slave);
        fake_node(fk->master, c[1], 0, 1);
        _exit(0);
    }
    close(c[1]);
    fk->counts = c[0];
    return 1;
}

/* What the node saw since the last call: client id requests, releases, and
 * the last id released */
static void fake_seen(fake_t *fk, int *allocs, int *releases, int *last_rel) {
    char buf[256];
    *allocs = *releases = 0;
    *last_rel = -1;
    usleep(100 * 1000);     /* let the node report */
    const ssize_t n = read(fk->counts, buf, sizeof(buf));
    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] == 'a')
            (*allocs)++;
        else if (buf[i] == 'r' && i + 1 < n) {
            (*releases)++;
            *last_rel = (unsigned char) buf[++i];
        }
    }
}

static void fake_stop(fake_t *fk) {
    kill(fk->pid, SIGKILL);
    waitpid(fk->pid, NULL, 0);
    close(fk->counts);
    close(fk->slave);
    close(fk->master);
}

static long file_size(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 ? (long) st.st_size : -1;
}

/* A session in a child that opens, says so, then ends the way `how` says:
 * 'k' is SIGKILLed while it holds the id, 't' runs the signal handler's
 * release and exits, 'c' closes cleanly */
static void child_session(fake_t *fk, const char *state, char how) {
    int ready[2];
    if (pipe(ready) < 0)
        return;
    pid_t pid = fork();
    if (pid == 0) {
        qmi_session_t s;
        char err[256];
        close(ready[0]);
        const int ok = qmi_session_open_tracked(&s, fk->slave_name, QMI_FRAMING_QMUX,
                                                0, 400, state, err, sizeof(err));
        if (ok && how == 't')
            qmi_session_release_now(&s);
        if (ok && how == 'c')
            qmi_session_close(&s);
        if (write(ready[1], ok ? "o" : "x", 1) < 0)
            _exit(1);
        for (;;)
            pause();
    }
    close(ready[1]);
    char c = 0;
    if (read(ready[0], &c, 1) != 1 || c != 'o') {
        printf("FAIL: the child session did not open\n");
        failures++;
    }
    close(ready[0]);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

static void test_cid_record(void) {
    char state[300];
    fake_t fk;
    qmi_session_t s;
    char err[256] = "";
    int a, r, last;

    snprintf(state, sizeof(state), "%s/cellqmi-fake.cid", g_tmp);
    if (!fake_start(&fk)) {
        printf("FAIL: cannot make a pty for the fake node\n");
        failures++;
        return;
    }

    /* SIGKILL: no handler runs, the id stays allocated, the record stays */
    child_session(&fk, state, 'k');
    fake_seen(&fk, &a, &r, &last);
    CHECK(a == 1 && r == 0, "sigkill: the killed session allocated and released "
          "nothing (allocs=%d releases=%d)", a, r);
    CHECK(file_size(state) > 0, "sigkill: the record outlives the killed session");

    /* The next open releases the dead session's id 8, then takes its own */
    int ok = qmi_session_open_tracked(&s, fk.slave_name, QMI_FRAMING_QMUX, 0, 400,
                                      state, err, sizeof(err));
    CHECK(ok, "after sigkill: open (%s)", err);
    CHECK(ok && s.stale_released && s.stale_cid == 8 && s.stale_answered,
          "after sigkill: the open reports releasing id 8 (released=%d cid=%u)",
          ok ? s.stale_released : -1, ok ? s.stale_cid : 0);
    fake_seen(&fk, &a, &r, &last);
    CHECK(r == 1 && last == 8 && a == 1, "after sigkill: the node saw one release "
          "of id 8 and one request (releases=%d last=%d allocs=%d)", r, last, a);
    if (ok)
        qmi_session_close(&s);
    CHECK(file_size(state) == 0, "clean close: the record is emptied");
    fake_seen(&fk, &a, &r, &last);

    /* After a clean close there is nothing to release */
    ok = qmi_session_open_tracked(&s, fk.slave_name, QMI_FRAMING_QMUX, 0, 400, state,
                                  err, sizeof(err));
    CHECK(ok && !s.stale_released, "after a clean close: nothing released");
    if (ok)
        qmi_session_close(&s);
    fake_seen(&fk, &a, &r, &last);
    CHECK(r == 1, "after a clean close: only the session's own release (%d)", r);

    /* The signal handler's release empties the record too: an id it freed
     * must never be released again */
    child_session(&fk, state, 't');
    fake_seen(&fk, &a, &r, &last);
    CHECK(file_size(state) == 0, "sigterm path: the record is emptied");
    ok = qmi_session_open_tracked(&s, fk.slave_name, QMI_FRAMING_QMUX, 0, 400, state,
                                  err, sizeof(err));
    CHECK(ok && !s.stale_released, "after the sigterm path: nothing released");
    if (ok)
        qmi_session_close(&s);
    fake_seen(&fk, &a, &r, &last);

    /* A record for another node (a modem that re-enumerated) is not used.
     * Each identity field on its own must be enough to refuse it, so each
     * case differs from the real node in exactly one. */
    struct stat st;
    stat(fk.slave_name, &st);
    static const char *const kField[3] = { "device number", "inode", "change time" };
    for (int field = 0; field < 3; field++) {
        FILE *f = fopen(state, "w");
        if (f == NULL)
            break;
        fprintf(f, "cellqmi-cid 1 %llu %llu %lld %ld 3 9\n",
                (unsigned long long) st.st_rdev + (field == 0),
                (unsigned long long) st.st_ino + (field == 1),
                (long long) st.st_ctim.tv_sec + (field == 2), (long) st.st_ctim.tv_nsec);
        fclose(f);
        ok = qmi_session_open_tracked(&s, fk.slave_name, QMI_FRAMING_QMUX, 0, 400, state,
                                      err, sizeof(err));
        CHECK(ok && !s.stale_released, "another node's record (%s differs): nothing "
              "released", kField[field]);
        if (ok)
            qmi_session_close(&s);
        fake_seen(&fk, &a, &r, &last);
        CHECK(r == 1, "another node's record (%s differs): only the session's own "
              "release (%d)", kField[field], r);
    }

    /* Positive control for the cases above: the same record with every field
     * matching IS released */
    FILE *f = fopen(state, "w");
    if (f != NULL) {
        fprintf(f, "cellqmi-cid 1 %llu %llu %lld %ld 3 9\n",
                (unsigned long long) st.st_rdev, (unsigned long long) st.st_ino,
                (long long) st.st_ctim.tv_sec, (long) st.st_ctim.tv_nsec);
        fclose(f);
    }
    ok = qmi_session_open_tracked(&s, fk.slave_name, QMI_FRAMING_QMUX, 0, 400, state,
                                  err, sizeof(err));
    CHECK(ok && s.stale_released && s.stale_cid == 9, "matching record: id 9 released");
    if (ok)
        qmi_session_close(&s);
    fake_seen(&fk, &a, &r, &last);

    /* Untracked opens keep no record */
    unlink(state);
    ok = qmi_session_open(&s, fk.slave_name, QMI_FRAMING_QMUX, 0, 400, err, sizeof(err));
    CHECK(ok && file_size(state) == -1, "untracked open: no record file");
    if (ok)
        qmi_session_close(&s);

    fake_stop(&fk);
}

/* ------------------------------------------------------------ native MBIM */

static size_t utf16_put(tlvbuf_t *t, const char *s) {
    const size_t start = t->n;
    for (const char *p = s; *p; p++)
        put16(t, (uint16_t) (unsigned char) *p);
    while (t->n % 4)
        put8(t, 0);
    return start;
}

static void patch32(tlvbuf_t *t, size_t at, uint32_t v) {
    t->b[at] = (uint8_t) v;
    t->b[at + 1] = (uint8_t) (v >> 8);
    t->b[at + 2] = (uint8_t) (v >> 16);
    t->b[at + 3] = (uint8_t) (v >> 24);
}

/* A COMMAND_DONE carrying `info`, as one message */
static size_t mbim_done_build(uint8_t *out, size_t cap, uint32_t tid, const uint8_t uuid[16],
                              uint32_t cid, uint32_t status, const uint8_t *info,
                              size_t info_len) {
    tlvbuf_t t;
    t.n = 0;
    put32(&t, MBIM_COMMAND_DONE);
    put32(&t, 0);
    put32(&t, tid);
    put32(&t, 1);
    put32(&t, 0);
    memcpy(t.b + t.n, uuid, 16);
    t.n += 16;
    put32(&t, cid);
    put32(&t, status);
    put32(&t, (uint32_t) info_len);
    memcpy(t.b + t.n, info, info_len);
    t.n += info_len;
    patch32(&t, 4, (uint32_t) t.n);
    if (t.n > cap)
        return 0;
    memcpy(out, t.b, t.n);
    return t.n;
}

/* Split a whole message into fragments of at most `max` bytes, as a
 * function with that maximum control transfer sends it */
static int mbim_fragment(const uint8_t *msg, size_t len, size_t max,
                         uint8_t frags[][512], size_t *flen, int maxfrags) {
    const size_t first_data = max - 20, more_data = max - 20;
    const size_t body = len - 20;
    int n = body <= first_data ? 1 : 1 + (int) ((body - first_data + more_data - 1) / more_data);
    size_t off = 20;

    if (n > maxfrags)
        return 0;
    for (int i = 0; i < n; i++) {
        const size_t take = (len - off) < more_data ? (len - off) : more_data;
        memcpy(frags[i], msg, 12);
        frags[i][12] = (uint8_t) n;
        frags[i][13] = frags[i][14] = frags[i][15] = 0;
        frags[i][16] = (uint8_t) i;
        frags[i][17] = frags[i][18] = frags[i][19] = 0;
        memcpy(frags[i] + 20, msg + off, take);
        flen[i] = 20 + take;
        frags[i][4] = (uint8_t) flen[i];
        frags[i][5] = (uint8_t) (flen[i] >> 8);
        frags[i][6] = frags[i][7] = 0;
        off += take;
    }
    return n;
}

static void test_mbim_fragments(void) {
    uint8_t info[600], msg[700], frags[8][512];
    size_t flen[8];
    mbim_reasm_t r;
    mbim_msg_t m;

    for (size_t i = 0; i < sizeof(info); i++)
        info[i] = (uint8_t) (i * 7);
    const size_t len = mbim_done_build(msg, sizeof(msg), 9, mbim_uuid_atds, 1, 0, info,
                                       sizeof(info));
    CHECK(len == 48 + 600 && !mbim_is_fragment(msg, len), "frag: a whole message is "
          "not a fragment");

    const int n = mbim_fragment(msg, len, 256, frags, flen, 8);
    CHECK(n == 3, "frag: 648 bytes in 256-byte transfers are 3 fragments (%d)", n);
    CHECK(mbim_is_fragment(frags[0], flen[0]) && !mbim_parse(frags[0], flen[0], &m),
          "frag: a fragment is seen as one and not parsed alone");

    mbim_reasm_reset(&r);
    int a0 = mbim_reasm_add(&r, frags[0], flen[0]);
    int a1 = mbim_reasm_add(&r, frags[1], flen[1]);
    int a2 = mbim_reasm_add(&r, frags[2], flen[2]);
    CHECK(a0 == 0 && a1 == 0 && a2 == 1, "frag: 0, 0, then complete (%d %d %d)", a0, a1, a2);
    CHECK(r.len == len && mbim_parse(r.buf, r.len, &m) && m.info_len == sizeof(info) &&
          memcmp(m.info, info, sizeof(info)) == 0 && m.cid == 1 && m.tid == 9,
          "frag: the joined message reads as the original");

    mbim_reasm_reset(&r);
    (void) mbim_reasm_add(&r, frags[0], flen[0]);
    CHECK(mbim_reasm_add(&r, frags[2], flen[2]) == -1, "frag: a skipped fragment resets");
    CHECK(mbim_reasm_add(&r, frags[1], flen[1]) == -1, "frag: no continuation without a "
          "first fragment");

    mbim_reasm_reset(&r);
    (void) mbim_reasm_add(&r, frags[0], flen[0]);
    frags[1][8] = 10;   /* another transaction */
    CHECK(mbim_reasm_add(&r, frags[1], flen[1]) == -1, "frag: another transaction's "
          "fragment resets");
}

/* DEVICE_SERVICES information: each service a UUID and its CIDs */
static size_t devsvc_build(uint8_t *out, int with_qmi, int with_bsi, int with_atds) {
    const uint8_t *uuids[4];
    uint32_t cids[4][3];
    int ncids[4], n = 0;
    tlvbuf_t t;

    uuids[n] = mbim_uuid_basic_connect; cids[n][0] = 9; cids[n][1] = 16; ncids[n++] = 2;
    if (with_qmi) { uuids[n] = mbim_uuid_qmi; cids[n][0] = 1; ncids[n++] = 1; }
    uuids[n] = mbim_uuid_ms_basic_connect_ext; cids[n][0] = 3; ncids[n] = 1;
    if (with_bsi) cids[n][ncids[n]++] = 11;
    n++;
    if (with_atds) { uuids[n] = mbim_uuid_atds; cids[n][0] = 1; cids[n][1] = 2; ncids[n++] = 2; }

    t.n = 0;
    put32(&t, (uint32_t) n);
    put32(&t, 0);
    const size_t pairs = t.n;
    for (int i = 0; i < n; i++) { put32(&t, 0); put32(&t, 0); }
    for (int i = 0; i < n; i++) {
        const size_t at = t.n;
        memcpy(t.b + t.n, uuids[i], 16);
        t.n += 16;
        put32(&t, 0);
        put32(&t, 0);
        put32(&t, (uint32_t) ncids[i]);
        for (int c = 0; c < ncids[i]; c++)
            put32(&t, cids[i][c]);
        patch32(&t, pairs + 8 * (size_t) i, (uint32_t) at);
        patch32(&t, pairs + 8 * (size_t) i + 4, (uint32_t) (t.n - at));
    }
    memcpy(out, t.b, t.n);
    return t.n;
}

static void test_mbim_device_services(void) {
    uint8_t b[1024];
    mbim_caps_t c;

    size_t n = devsvc_build(b, 1, 1, 1);
    CHECK(mbim_device_services_parse(b, n, &c) && c.services == 4 && c.have_qmi &&
          c.have_base_stations && c.have_atds_location && c.have_atds_signal,
          "devsvc: QMI, BASE_STATIONS_INFO and atds all seen");

    /* The XMM7360 shape: the extensions service without CID 11, no QMI */
    n = devsvc_build(b, 0, 0, 1);
    CHECK(mbim_device_services_parse(b, n, &c) && !c.have_qmi && !c.have_base_stations &&
          c.have_atds_location, "devsvc: extensions without CID 11 is no "
          "BASE_STATIONS_INFO");

    n = devsvc_build(b, 0, 1, 0);
    CHECK(mbim_device_services_parse(b, n, &c) && c.have_base_stations &&
          !c.have_atds_location, "devsvc: no atds");

    CHECK(!mbim_device_services_parse(b, n - 4, &c), "devsvc: a truncated last service "
          "is refused");
    b[8] = 0xF0;   /* the first service's offset points past the buffer */
    b[9] = 0x0F;
    CHECK(!mbim_device_services_parse(b, n, &c), "devsvc: an offset past the end is "
          "refused");
}

/* One LTE cell structure; `ta` adds the serving cell's timing advance */
static void lte_cell_put(tlvbuf_t *t, const char *provider, uint32_t cell, uint32_t earfcn,
                         uint32_t pci, uint32_t tac, int32_t rsrp, int32_t rsrq, int ta) {
    const size_t start = t->n;
    put32(t, 0);
    put32(t, 0);
    put32(t, cell);
    put32(t, earfcn);
    put32(t, pci);
    put32(t, tac);
    put32(t, (uint32_t) rsrp);
    put32(t, (uint32_t) rsrq);
    if (ta)
        put32(t, 0xFFFFFFFFu);
    if (provider != NULL) {
        const size_t at = utf16_put(t, provider);
        patch32(t, start, (uint32_t) (at - start));
        patch32(t, start + 4, (uint32_t) (2 * strlen(provider)));
    }
}

typedef struct {
    uint32_t cell, earfcn, pci, tac;
    int32_t rsrp, rsrq;
} nb_t;

/* BASE_STATIONS_INFO, MBIM 1.0 layout, LTE serving + an LTE MRL */
static size_t bsi_build(uint8_t *out, const char *provider, uint32_t cell, uint32_t earfcn,
                        uint32_t pci, uint32_t tac, int32_t rsrp, int32_t rsrq,
                        const nb_t *nb, int nnb) {
    tlvbuf_t t;

    t.n = 0;
    put32(&t, MBIM_DATA_CLASS_LTE);
    for (int i = 0; i < 18; i++)
        put32(&t, 0);

    const size_t serving = t.n;
    lte_cell_put(&t, provider, cell, earfcn, pci, tac, rsrp, rsrq, 1);
    patch32(&t, 4 + 8 * 3, (uint32_t) serving);
    patch32(&t, 4 + 8 * 3 + 4, (uint32_t) (t.n - serving));

    if (nnb > 0) {
        const size_t mrl = t.n;
        put32(&t, (uint32_t) nnb);
        for (int i = 0; i < nnb; i++)
            lte_cell_put(&t, NULL, nb[i].cell, nb[i].earfcn, nb[i].pci, nb[i].tac,
                         nb[i].rsrp, nb[i].rsrq, 0);
        patch32(&t, 4 + 8 * 7, (uint32_t) mrl);
        patch32(&t, 4 + 8 * 7 + 4, (uint32_t) (t.n - mrl));
    }
    memcpy(out, t.b, t.n);
    return t.n;
}

static void test_mbim_base_stations(void) {
    const uint32_t U = MBIM_UNKNOWN_U32;
    /* The measured shape (EM9291, MBIM 1.0), synthetic values: the serving
     * PCI repeated as a neighbour with unknown identity, one inter-frequency
     * neighbour above the 16-bit range, one that may be wrapped */
    const nb_t nb[3] = {
        { U, U, 1, U, -87, -6 },
        { U, 65636, 2, U, -95, -10 },
        { U, 100, 3, U, -99, -12 },
    };
    uint8_t b[1024], req[32];
    mbim_base_stations_t bs;
    char rows[MBIM_OBS_MAX][QMI_OBS_JSON_MAX];
    qmi_obs_stats_t st;

    CHECK(mbim_base_stations_req(req, sizeof(req), 15) == 20 && req[0] == 15 &&
          req[16] == 15, "bsi: the MBIM 1.0 request is five counts, no NR count");

    size_t n = bsi_build(b, "00101", 0xABCDE1, 100, 1, 0x1234, -87, -6, nb, 3);
    CHECK(mbim_base_stations_parse(b, n, &bs) && bs.have_lte_serving &&
          bs.lte_serving.cell_id == 0xABCDE1 && bs.lte_serving.pci == 1 &&
          bs.lte_serving.tac == 0x1234 && bs.lte_serving.earfcn == 100 &&
          strcmp(bs.lte_serving.provider, "00101") == 0 && bs.nneighbours == 3 &&
          bs.neighbours[1].earfcn == 65636 && bs.neighbours[0].cell_id == U,
          "bsi: serving and neighbours decode");

    int nr = mbim_obs_build(NULL, &bs, NULL, NULL, 1.0, rows, MBIM_OBS_MAX, &st);
    CHECK(nr == 2 && st.serving == 1 && st.neighbours == 1, "bsi obs: serving + one "
          "neighbour (%d rows)", nr);
    CHECK(nr >= 1 && strstr(rows[0], "\"mcc\":\"001\",\"mnc\":\"01\",\"tac\":4660,"
                            "\"cell_id\":11259361,\"pci\":1") != NULL &&
          strstr(rows[0], "earfcn") == NULL && strstr(rows[0], "\"rsrp\":-87.0") != NULL &&
          strstr(rows[0], "\"rsrq\":-6.0") != NULL &&
          strstr(rows[0], "\"src\":\"mbim\",\"origin\":\"MBIM:BSI\"") != NULL &&
          strstr(rows[0], "\"is_serving\":true") != NULL,
          "bsi obs: serving row keeps its identity, no EARFCN at or below 65535: %s", rows[0]);
    CHECK(nr == 2 && strstr(rows[1], "\"pci\":2,\"earfcn\":65636") != NULL &&
          strstr(rows[1], "\"is_serving\":false") != NULL,
          "bsi obs: the proven neighbour is written: %s", nr == 2 ? rows[1] : "");
    CHECK(st.unproven_earfcn == 2, "bsi obs: the serving EARFCN and neighbour PCI 3 are "
          "unproven (%d)", st.unproven_earfcn);

    /* A proven serving EARFCN is written */
    n = bsi_build(b, "00101", 0xABCDE1, 65636, 1, 0x1234, -87, -6, NULL, 0);
    CHECK(mbim_base_stations_parse(b, n, &bs) &&
          mbim_obs_build(NULL, &bs, NULL, NULL, 1.0, rows, MBIM_OBS_MAX, &st) == 1 &&
          strstr(rows[0], "\"earfcn\":65636") != NULL, "bsi obs: EARFCN above 65535 kept");

    /* The T700 on MBIM 1.0: indices, and the MNC's leading zero dropped */
    n = bsi_build(b, "31001", 0xABCDE1, 100, 1, 0x1234, 47, 28, NULL, 0);
    CHECK(mbim_base_stations_parse(b, n, &bs) &&
          mbim_obs_build(NULL, &bs, NULL, NULL, 1.0, rows, MBIM_OBS_MAX, &st) == 1 &&
          strstr(rows[0], "\"mcc\":\"310\",\"mnc\":\"001\"") != NULL &&
          strstr(rows[0], "\"rsrp\":-94.0") != NULL && strstr(rows[0], "\"rsrq\":-6.0") != NULL,
          "bsi obs: 3GPP indices decode, 5-digit 310 id is MNC 001: %s", rows[0]);

    /* No provider in the cell: the registration's provider */
    mbim_register_t reg;
    memset(&reg, 0, sizeof(reg));
    reg.state = MBIM_REG_ROAMING;
    strcpy(reg.provider, "001010");
    n = bsi_build(b, NULL, 0xABCDE1, 100, 1, 0x1234, -87, -6, NULL, 0);
    CHECK(mbim_base_stations_parse(b, n, &bs) &&
          mbim_obs_build(&reg, &bs, NULL, NULL, 1.0, rows, MBIM_OBS_MAX, &st) == 1 &&
          strstr(rows[0], "\"mcc\":\"001\",\"mnc\":\"010\"") != NULL,
          "bsi obs: PLMN from REGISTER_STATE when the cell has none: %s", rows[0]);

    /* No PLMN at all and no proven EARFCN: nothing to key the cell on */
    CHECK(mbim_obs_build(NULL, &bs, NULL, NULL, 1.0, rows, MBIM_OBS_MAX, &st) == 0,
          "bsi obs: no PLMN and no proven EARFCN is no row");

    CHECK(mbim_lte_rsrp_x10(-1) == INT32_MIN && mbim_lte_rsrq_x10(-1) == INT32_MIN &&
          mbim_lte_rsrp_x10(0) == -1410 && mbim_lte_rsrp_x10(97) == -440 &&
          mbim_lte_rsrq_x10(0) == -200 && mbim_lte_rsrq_x10(34) == -30 &&
          mbim_lte_rsrp_x10(-140) == -1400 && mbim_lte_rsrq_x10(-20) == -200,
          "bsi: RSRP/RSRQ index and value ranges, 0xFFFFFFFF unknown");

    /* Offsets that leave the buffer are refused */
    n = bsi_build(b, "00101", 0xABCDE1, 100, 1, 0x1234, -87, -6, nb, 3);
    CHECK(!mbim_base_stations_parse(b, n - 8, &bs), "bsi: a truncated MRL is refused");
    b[4 + 8 * 7 + 4] = 0xFF;   /* MRL size past the end */
    CHECK(!mbim_base_stations_parse(b, n, &bs), "bsi: an MRL size past the end is refused");
    n = bsi_build(b, "00101", 0xABCDE1, 100, 1, 0x1234, -87, -6, nb, 3);
    b[4 + 8 * 7 + 0] = 8;      /* MRL offset inside the header */
    CHECK(!mbim_base_stations_parse(b, n, &bs), "bsi: an offset into the header is refused");
}

static void test_mbim_register_atds(void) {
    uint8_t b[256];
    tlvbuf_t t;
    mbim_register_t reg;
    mbim_atds_location_t loc;
    mbim_atds_signal_t sig;
    char rows[MBIM_OBS_MAX][QMI_OBS_JSON_MAX];
    qmi_obs_stats_t st;

    /* REGISTER_STATE: nw error, state, mode, data classes, cellular class,
     * provider id, provider name, roaming text, flags */
    t.n = 0;
    put32(&t, 0); put32(&t, MBIM_REG_ROAMING); put32(&t, 1); put32(&t, MBIM_DATA_CLASS_LTE);
    put32(&t, 1);
    put32(&t, 0); put32(&t, 0); put32(&t, 0); put32(&t, 0); put32(&t, 0); put32(&t, 0);
    put32(&t, 2);
    const size_t at = utf16_put(&t, "00101");
    patch32(&t, 20, (uint32_t) at);
    patch32(&t, 24, 10);
    memcpy(b, t.b, t.n);
    CHECK(mbim_register_parse(b, t.n, &reg) && reg.state == MBIM_REG_ROAMING &&
          strcmp(reg.provider, "00101") == 0 && mbim_registered(reg.state),
          "register: state and provider id");

    /* atds, the measured coding: RSSI 26, BER 99, RSCP/EcNo 255, RSRQ 25,
     * RSRP 52, RSSNR 29 */
    t.n = 0;
    put32(&t, 26); put32(&t, 99); put32(&t, 255); put32(&t, 255);
    put32(&t, 25); put32(&t, 52); put32(&t, 29);
    CHECK(mbim_atds_signal_parse(t.b, t.n, &sig) && sig.rssi == -61 && sig.rsrq_x10 == -70 &&
          sig.rsrp_x10 == -880 && sig.snr_x10 == 240, "atds signal: -61 dBm, RSRQ -7.0, "
          "RSRP -88, SNR 24 (%d %d %d %d)", sig.rssi, sig.rsrq_x10, sig.rsrp_x10, sig.snr_x10);

    t.n = 0;
    put32(&t, 0); put32(&t, 0x1234); put32(&t, 0xABCDE1);
    CHECK(mbim_atds_location_parse(t.b, t.n, &loc) && loc.tac == 0x1234, "atds location");

    int n = mbim_obs_build(&reg, NULL, &loc, &sig, 2.0, rows, MBIM_OBS_MAX, &st);
    CHECK(n == 1 && strstr(rows[0], "\"mcc\":\"001\",\"mnc\":\"01\",\"tac\":4660,"
                           "\"cell_id\":11259361") != NULL &&
          strstr(rows[0], "\"rsrp\":-88.0,\"rsrq\":-7.0,\"snr\":24.0,\"rssi\":-61") != NULL &&
          strstr(rows[0], "\"origin\":\"MBIM:ATDS\"") != NULL,
          "atds obs: serving row from the location and the registration: %s",
          n ? rows[0] : "");

    /* The XMM7360 refused registration: location all zero, deregistered */
    memset(&loc, 0, sizeof(loc));
    reg.state = MBIM_REG_DEREGISTERED;
    reg.provider[0] = '\0';
    n = mbim_obs_build(&reg, NULL, &loc, &sig, 2.0, rows, MBIM_OBS_MAX, &st);
    CHECK(n == 0 && st.no_service == 1, "atds obs: zero location, deregistered: no service");

    /* Registered, but no read names a cell (NR SA on MBIM 1.0): a gap, not
     * no service */
    reg.state = MBIM_REG_HOME;
    strcpy(reg.provider, "00101");
    n = mbim_obs_build(&reg, NULL, &loc, &sig, 2.0, rows, MBIM_OBS_MAX, &st);
    CHECK(n == 0 && st.no_service == 0, "atds obs: registered without a cell is not "
          "no service");

    char mcc[4], mnc[4];
    CHECK(mbim_provider_split("001010", mcc, mnc) && strcmp(mnc, "010") == 0 &&
          mbim_provider_split("31001", mcc, mnc) && strcmp(mnc, "001") == 0 &&
          mbim_provider_split("00101", mcc, mnc) && strcmp(mcc, "001") == 0 &&
          strcmp(mnc, "01") == 0 && !mbim_provider_split("3101", mcc, mnc) &&
          !mbim_provider_split("00a101", mcc, mnc), "provider split");
}

/* A fake native-MBIM node on a pty: answers DEVICE_SERVICES (after
 * MBIM_OPEN, unless `already_open`) and a BASE_STATIONS_INFO query, every
 * reply split into `max`-byte fragments.  Reports 'o' per MBIM_OPEN and 'c'
 * per MBIM_CLOSE on `count_fd`. */
static void fake_mbim_node(int fd, int count_fd, int already_open, size_t max) {
    uint8_t in[8192], out[4096], frags[16][512], info[2048];
    size_t inlen = 0, flen[16];
    int open = already_open;

    for (;;) {
        ssize_t r = read(fd, in + inlen, sizeof(in) - inlen);
        if (r <= 0)
            _exit(0);
        inlen += (size_t) r;

        for (;;) {
            int bad = 0;
            const size_t fl = mbim_frame_len(in, inlen, &bad);
            if (bad)
                _exit(1);
            if (fl == 0)
                break;

            const uint32_t type = in[0] | (in[1] << 8) | (in[2] << 16) | ((uint32_t) in[3] << 24);
            const uint8_t *tidp = in + 8;
            uint8_t reply[16];
            size_t olen = 0;

            if (type == MBIM_OPEN_MSG || type == MBIM_CLOSE_MSG) {
                if (write(count_fd, type == MBIM_OPEN_MSG ? "o" : "c", 1) < 0)
                    _exit(0);
                open = type == MBIM_OPEN_MSG;
                memset(reply, 0, sizeof(reply));
                reply[0] = type == MBIM_OPEN_MSG ? 1 : 2;
                reply[3] = 0x80;
                reply[4] = 16;
                memcpy(reply + 8, tidp, 4);
                if (write(fd, reply, 16) < 0)
                    _exit(0);
            } else if (type == MBIM_COMMAND_MSG && !open) {
                memset(reply, 0, sizeof(reply));
                reply[0] = 4;
                reply[3] = 0x80;
                reply[4] = 16;
                memcpy(reply + 8, tidp, 4);
                reply[12] = 5;      /* not opened */
                if (write(fd, reply, 16) < 0)
                    _exit(0);
            } else if (type == MBIM_COMMAND_MSG) {
                const uint32_t tid = tidp[0] | (tidp[1] << 8) | (tidp[2] << 16) |
                    ((uint32_t) tidp[3] << 24);
                const uint32_t cid = in[36] | (in[37] << 8);
                size_t il;
                if (memcmp(in + 20, mbim_uuid_basic_connect, 16) == 0 && cid == 16)
                    il = devsvc_build(info, 0, 1, 1);
                else {
                    nb_t nb[12];
                    for (int i = 0; i < 12; i++) {
                        nb[i].cell = nb[i].tac = MBIM_UNKNOWN_U32;
                        nb[i].earfcn = 65636;
                        nb[i].pci = (uint32_t) (i + 2) % 9 + 1;
                        nb[i].rsrp = -100;
                        nb[i].rsrq = -11;
                    }
                    il = bsi_build(info, "00101", 0xABCDE1, 100, 1, 0x1234, -87, -6, nb, 12);
                }
                olen = mbim_done_build(out, sizeof(out), tid, in + 20, cid, 0, info, il);
                const int n = mbim_fragment(out, olen, max, frags, flen, 16);
                for (int i = 0; i < n; i++) {
                    if (write(fd, frags[i], flen[i]) < 0)
                        _exit(0);
                }
            }
            memmove(in, in + fl, inlen - fl);
            inlen -= fl;
        }
    }
}

typedef struct {
    int opened, queried, opens, closes, have_bsi, have_atds, nneighbours;
} mbim_fake_t;

static mbim_fake_t mbim_fake_run(int already_open, size_t max) {
    mbim_fake_t res;
    int counts[2];

    memset(&res, 0, sizeof(res));
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0 || pipe(counts) < 0) {
        printf("FAIL: cannot make a pty for the fake MBIM node\n");
        failures++;
        return res;
    }
    const char *slave_name = ptsname(master);
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    struct termios tio;
    if (slave < 0 || tcgetattr(slave, &tio) < 0) {
        printf("FAIL: cannot open the pty slave\n");
        failures++;
        return res;
    }
    cfmakeraw(&tio);
    tcsetattr(slave, TCSANOW, &tio);
    tcsetattr(master, TCSANOW, &tio);

    pid_t pid = fork();
    if (pid == 0) {
        close(counts[0]);
        close(slave);
        fake_mbim_node(master, counts[1], already_open, max);
        _exit(0);
    }
    close(counts[1]);

    mbim_session_t s;
    char err[256] = "";
    res.opened = mbim_session_open(&s, slave_name, 0, 1500, err, sizeof(err));
    if (!res.opened)
        printf("     (fake MBIM open: %s)\n", err);
    if (res.opened) {
        uint8_t req[32], buf[QMI_MSG_MAX];
        mbim_msg_t done;
        mbim_base_stations_t bs;
        res.have_bsi = s.caps.have_base_stations;
        res.have_atds = s.caps.have_atds_location;
        const size_t rl = mbim_base_stations_req(req, sizeof(req), 15);
        if (mbim_session_query(&s, mbim_uuid_ms_basic_connect_ext, MBIM_CID_BASE_STATIONS,
                               req, rl, buf, sizeof(buf), &done, 1500, err,
                               sizeof(err)) == 1 &&
            done.status == 0 && mbim_base_stations_parse(done.info, done.info_len, &bs)) {
            res.queried = 1;
            res.nneighbours = bs.nneighbours;
        }
        mbim_session_close(&s);
    }

    usleep(100 * 1000);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

    char buf[64];
    ssize_t n = read(counts[0], buf, sizeof(buf));
    for (ssize_t i = 0; i < n; i++) {
        res.opens += buf[i] == 'o';
        res.closes += buf[i] == 'c';
    }
    close(counts[0]);
    close(slave);
    close(master);
    return res;
}

static void test_mbim_open_max_transfer(void) {
    /* The node's buffer bounds the open: the XMM7360's 512 must be asked for
     * as 512, never the 4096 that wedged its MBIM function */
    CHECK(mbim_open_max_transfer(1, 512) == 512, "open max: a 512-byte node is "
          "opened at 512, not %u", mbim_open_max_transfer(1, 512));
    CHECK(mbim_open_max_transfer(1, 4096) == 4096, "open max: 4096 stays 4096");
    CHECK(mbim_open_max_transfer(1, 16384) == 4096, "open max: a larger node is capped "
          "at 4096, the largest message read here");
    CHECK(mbim_open_max_transfer(1, 0) == 64, "open max: never under MBIM's 64");
    CHECK(mbim_open_max_transfer(0, 0) == 4096, "open max: without the ioctl, 4096");
}

static void test_mbim_native_open(void) {
    /* A closed function: asked first, then opened once, closed once; every
     * reply in 128-byte fragments (the BASE_STATIONS_INFO reply, 12
     * neighbours, spans five) */
    mbim_fake_t r = mbim_fake_run(0, 128);
    CHECK(r.opened && r.have_bsi && r.have_atds, "native open: DEVICE_SERVICES read "
          "after MBIM_OPEN (opened=%d bsi=%d atds=%d)", r.opened, r.have_bsi, r.have_atds);
    CHECK(r.opens == 1 && r.closes == 1, "native open: one MBIM_OPEN, one MBIM_CLOSE "
          "(%d, %d)", r.opens, r.closes);
    CHECK(r.queried && r.nneighbours == 12, "native open: a fragmented BASE_STATIONS_INFO "
          "reply joins (queried=%d, %d neighbours)", r.queried, r.nneighbours);

    /* An open function (another program's): never opened or closed here */
    r = mbim_fake_run(1, 512);
    CHECK(r.opened && r.queried, "native open: an open function answers at once");
    CHECK(r.opens == 0 && r.closes == 0, "native open: no MBIM_OPEN or MBIM_CLOSE on an "
          "open function (%d, %d)", r.opens, r.closes);
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
    test_cold_open_backlog();
    test_cid_record();
    test_mbim_fragments();
    test_mbim_device_services();
    test_mbim_base_stations();
    test_mbim_register_atds();
    test_mbim_open_max_transfer();
    test_mbim_native_open();

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
