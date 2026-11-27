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

    QMUX and MBIM framing, and the QMI NAS replies a cell survey reads, as
    pure functions over byte buffers.  No I/O, so the selftest drives every
    path with synthetic frames.

    QMUX: 0x01, length u16 (counting everything after the 0x01), control
    flags u8, service u8, client u8, then the SDU.  CTL (service 0) SDUs carry
    a 1-byte transaction id, every other service a 2-byte one.  All integers
    are little-endian.

    MBIM carries QMUX inside a COMMAND on the QMI service
    (d1a30bc2-f97a-6e43-bf65-c7e24fb0f0d3), CID 1, SET; the reply's
    information buffer is the QMUX response frame.

    The NAS layouts are those of Get Signal Info (0x004F), Get Cell Location
    Info (0x0043) and Get System Info (0x004D).  Only TLVs whose layout is
    known are read; anything else is ignored rather than guessed at.
*/

#ifndef __QMI_WIRE_H__
#define __QMI_WIRE_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QMI_SVC_CTL 0x00
#define QMI_SVC_NAS 0x03

#define QMI_CTL_GET_CLIENT_ID     0x0022
#define QMI_CTL_RELEASE_CLIENT_ID 0x0023
#define QMI_CTL_SYNC              0x0027
/* qmi-proxy's own CTL message: TLV 0x01 names the node the proxy opens */
#define QMI_CTL_PROXY_OPEN        0xFF00

#define QMI_NAS_GET_CELL_LOCATION_INFO 0x0043
#define QMI_NAS_GET_SYSTEM_INFO        0x004D
#define QMI_NAS_GET_SIGNAL_INFO        0x004F

/* QMI errors a NAS read returns when there is no cell to report: no network
 * found (cell location) and information unavailable (signal info). */
#define QMI_ERR_NO_NETWORK_FOUND       13
#define QMI_ERR_INFO_UNAVAILABLE       74

/* The largest message either framing carries here: MBIM's usual
 * MaxControlTransfer, far above any NAS reply. */
#define QMI_MSG_MAX 4096

/* ------------------------------------------------------------------ QMUX */

typedef struct {
    uint8_t service;
    uint8_t client;
    uint8_t sdu_flags;
    uint16_t tid;
    uint16_t msg_id;
    const uint8_t *tlvs;
    size_t tlvs_len;
    int is_response;
    int is_indication;
} qmux_msg_t;

/* Build one QMUX request into `out`.  Returns its length, 0 if it does not
 * fit.  A CTL frame uses the low byte of `tid`. */
size_t qmux_build(uint8_t *out, size_t cap, uint8_t service, uint8_t client,
                  uint16_t tid, uint16_t msg_id, const uint8_t *tlvs,
                  size_t tlvs_len);

/* The length of the QMUX frame at the head of a stream: 0 if more bytes are
 * needed.  `*bad` is set when the head is not a QMUX frame at all, so a
 * stream reader can tell "wait" from "lost sync". */
size_t qmux_frame_len(const uint8_t *buf, size_t len, int *bad);

/* Parse one whole frame.  1 on success, 0 if malformed. */
int qmux_parse(const uint8_t *buf, size_t len, qmux_msg_t *out);

/* The value of TLV `type`, or NULL.  `*vlen` gets its length. */
const uint8_t *qmi_tlv(const uint8_t *tlvs, size_t len, uint8_t type,
                       size_t *vlen);

/* The Result TLV (0x02): 1 success, 0 failure (`*err` = the QMI error
 * code), -1 missing or short.  A missing result is never a success. */
int qmi_result(const qmux_msg_t *m, uint16_t *err);

/* 1 if `buf` is a CTL Sync request.  Never send one through a proxy: the
 * proxy forwards it and every other client's client ids stop working. */
int qmux_is_ctl_sync(const uint8_t *buf, size_t len);

size_t qmi_ctl_alloc_build(uint8_t *out, size_t cap, uint8_t tid,
                           uint8_t service);
size_t qmi_ctl_release_build(uint8_t *out, size_t cap, uint8_t tid,
                             uint8_t service, uint8_t client);
size_t qmi_ctl_proxy_open_build(uint8_t *out, size_t cap, uint8_t tid,
                                const char *path);

/* The client id from a Get Client ID reply for `service`.  1 on success. */
int qmi_ctl_alloc_parse(const qmux_msg_t *m, uint8_t service, uint8_t *client);

/* ------------------------------------------------------------------ MBIM */

#define MBIM_OPEN_MSG            0x00000001u
#define MBIM_CLOSE_MSG           0x00000002u
#define MBIM_COMMAND_MSG         0x00000003u
#define MBIM_OPEN_DONE           0x80000001u
#define MBIM_CLOSE_DONE          0x80000002u
#define MBIM_COMMAND_DONE        0x80000003u
#define MBIM_FUNCTION_ERROR_MSG  0x80000004u
#define MBIM_INDICATE_STATUS_MSG 0x80000007u

#define MBIM_COMMAND_TYPE_QUERY 0
#define MBIM_COMMAND_TYPE_SET   1

#define MBIM_CID_QMI_MSG 1
/* mbim-proxy's configuration command: "open this node, with this timeout" */
#define MBIM_CID_PROXY_CONFIG 1

extern const uint8_t mbim_uuid_qmi[16];
extern const uint8_t mbim_uuid_proxy_control[16];

typedef struct {
    uint32_t type;
    uint32_t length;
    uint32_t tid;
    uint32_t status;         /* OPEN_DONE, CLOSE_DONE, COMMAND_DONE, FUNCTION_ERROR */
    const uint8_t *uuid;     /* COMMAND_DONE, INDICATE_STATUS */
    uint32_t cid;
    const uint8_t *info;
    size_t info_len;
} mbim_msg_t;

size_t mbim_open_build(uint8_t *out, size_t cap, uint32_t tid,
                       uint32_t max_control_transfer);
size_t mbim_close_build(uint8_t *out, size_t cap, uint32_t tid);
size_t mbim_command_build(uint8_t *out, size_t cap, uint32_t tid,
                          const uint8_t uuid[16], uint32_t cid,
                          uint32_t command_type, const uint8_t *info,
                          size_t info_len);
/* mbim-proxy's opening request: the node path (UTF-16LE) and a timeout */
size_t mbim_proxy_config_build(uint8_t *out, size_t cap, uint32_t tid,
                               const char *path, uint32_t timeout_s);

/* As qmux_frame_len, for MBIM (length at bytes 4..7). */
size_t mbim_frame_len(const uint8_t *buf, size_t len, int *bad);

/* Parse one whole message.  Fragmented messages are refused (0): nothing
 * read here is big enough to need them. */
int mbim_parse(const uint8_t *buf, size_t len, mbim_msg_t *out);

/* ------------------------------------------------------------------ NAS */

#define QMI_LTE_CELLS_MAX 16
#define QMI_LTE_FREQS_MAX 8

typedef struct {
    uint16_t pci;
    int16_t rsrq_x10;
    int16_t rsrp_x10;
    int16_t rssi_x10;
} qmi_lte_cell_t;

typedef struct {
    uint32_t earfcn;
    /* 1 when a 32-bit TLV confirms the value; a 16-bit EARFCN alone may be
     * a wrapped band 65+ channel (65636 reads as 100) */
    int earfcn_proven;
    int ncells;
    qmi_lte_cell_t cells[QMI_LTE_CELLS_MAX];
} qmi_lte_freq_t;

/* Get Signal Info.  -32768 in the NR TLVs means "no measurement". */
typedef struct {
    int error;          /* 0, a QMI error code, or -1 for no result */
    int have_lte;
    int8_t lte_rssi;
    int8_t lte_rsrq;
    int16_t lte_rsrp;
    int16_t lte_snr_x10;
    int have_nr_rsrp, have_nr_snr, have_nr_rsrq;
    int16_t nr_rsrp;
    int16_t nr_snr_x10;
    int16_t nr_rsrq;
} qmi_signal_t;

/* Get Cell Location Info. */
typedef struct {
    int error;

    /* TLV 0x13: the LTE serving cell and its intra-frequency neighbours */
    int have_lte;
    char lte_mcc[4];
    char lte_mnc[4];
    uint16_t lte_tac;
    uint32_t lte_cell_id;
    uint16_t lte_pci;
    uint32_t lte_earfcn;
    int lte_earfcn_proven;
    int nintra;
    qmi_lte_cell_t intra[QMI_LTE_CELLS_MAX];

    /* TLV 0x14: inter-frequency neighbours, EARFCNs proven by 0x28 */
    int ninter;
    qmi_lte_freq_t inter[QMI_LTE_FREQS_MAX];

    /* TLV 0x2C: 1 while the LTE RRC connection is up, -1 if absent */
    int rrc_connected;

    /* TLV 0x2E: NR-ARFCN; TLV 0x2F: the NR serving cell */
    int have_nr_arfcn;
    uint32_t nr_arfcn;
    int have_nr;
    char nr_mcc[4];
    char nr_mnc[4];
    uint32_t nr_tac;          /* 24 bits, big-endian on the wire */
    uint64_t nr_cell_id;
    uint16_t nr_pci;
    int16_t nr_rsrq_x10;
    int16_t nr_rsrp_x10;
    int16_t nr_snr_x10;
} qmi_cellloc_t;

/* Service status values of Get System Info */
#define QMI_SRV_NONE       0
#define QMI_SRV_LIMITED    1
#define QMI_SRV_AVAILABLE  2
#define QMI_SRV_POWER_SAVE 4   /* also what being out of coverage reads as */

typedef struct {
    int have;
    char mcc[4];
    char mnc[4];
    int have_cell_id;
    uint32_t cell_id;
    int have_tac;
    uint16_t tac;
} qmi_sysinfo_rat_t;

/* Get System Info. */
typedef struct {
    int error;
    int lte_status;     /* -1 if absent */
    int nr_status;
    qmi_sysinfo_rat_t lte;      /* TLV 0x19 */
    qmi_sysinfo_rat_t nr;       /* TLV 0x4B */
    int have_nr_tac;            /* TLV 0x50, 24 bits big-endian */
    uint32_t nr_tac;
    int have_nr_cell_id;        /* TLV 0x5E */
    uint64_t nr_cell_id;
} qmi_sysinfo_t;

/* Decode a parsed NAS response.  Each fills `out` completely and returns 1;
 * 0 if `m` is not that message's response. */
int qmi_nas_signal_decode(const qmux_msg_t *m, qmi_signal_t *out);
int qmi_nas_cellloc_decode(const qmux_msg_t *m, qmi_cellloc_t *out);
int qmi_nas_sysinfo_decode(const qmux_msg_t *m, qmi_sysinfo_t *out);

/* A 3-byte TS 24.008 BCD PLMN as MCC and MNC digit strings (2 or 3 MNC
 * digits; an 'F' third digit is filler).  1 on success, 0 for a non-digit. */
int qmi_bcd_plmn(const uint8_t b[3], char mcc[4], char mnc[4]);

#ifdef __cplusplus
}
#endif

#endif
