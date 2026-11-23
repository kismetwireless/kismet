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

    Native MBIM reads, for modems whose MBIM function carries no QMI service
    (Intel XMM, MediaTek T700, and Qualcomm parts without the QMI tunnel), as
    pure functions over byte buffers.  No I/O.

    The reads, all MBIM 1.0 queries:
      basic-connect DEVICE_SERVICES (CID 16): which services and CIDs the
          function offers, read once at open.
      basic-connect REGISTER_STATE (CID 9): registration state and the
          provider id (MCC + MNC).
      ms-basic-connect-extensions BASE_STATIONS_INFO (CID 11): serving and
          neighbour cells.  Only its MBIM 1.0 layout is read, and the source
          never negotiates MBIMEx 3.0 for it: on a MediaTek T700 (FM350-GL)
          that negotiation followed by this query crashes the firmware.
      atds LOCATION (CID 2) and SIGNAL (CID 1): the AT&T service, for
          modems without BASE_STATIONS_INFO.

    Every offset in a reply is checked against the bytes that hold it; a
    reply that does not fit is refused, not guessed at.  All integers are
    little-endian.

    Fragments: a function whose maximum control transfer is small (512 bytes
    on an XMM7360) splits a reply into fragments.  mbim_reasm_add() joins
    them back into one message that mbim_parse() reads.
*/

#ifndef __MBIM_WIRE_H__
#define __MBIM_WIRE_H__

#include <stddef.h>
#include <stdint.h>

#include "qmi_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const uint8_t mbim_uuid_basic_connect[16];
extern const uint8_t mbim_uuid_ms_basic_connect_ext[16];
extern const uint8_t mbim_uuid_atds[16];

#define MBIM_CID_REGISTER_STATE   9
#define MBIM_CID_DEVICE_SERVICES  16
#define MBIM_CID_BASE_STATIONS    11
#define MBIM_CID_ATDS_SIGNAL      1
#define MBIM_CID_ATDS_LOCATION    2

#define MBIM_DATA_CLASS_LTE 0x20u

/* ------------------------------------------------------------- fragments */

typedef struct {
    uint8_t buf[QMI_MSG_MAX];
    size_t len;          /* bytes joined so far, header included */
    uint32_t tid;
    uint32_t type;
    uint32_t total;      /* fragments expected */
    uint32_t next;       /* the fragment expected next */
} mbim_reasm_t;

/* 1 if this framed message is one fragment of several (total > 1) */
int mbim_is_fragment(const uint8_t *buf, size_t len);

/* Add one fragment.  1: the message is complete in r->buf (r->len bytes,
 * rewritten as a single fragment); 0: more to come; -1: out of order, a
 * different transaction, or too big (the assembly is reset). */
int mbim_reasm_add(mbim_reasm_t *r, const uint8_t *buf, size_t len);

void mbim_reasm_reset(mbim_reasm_t *r);

/* ------------------------------------------------------- device services */

typedef struct {
    int have_qmi;           /* the QMI tunnel service is offered */
    int have_base_stations; /* ms-basic-connect-extensions CID 11 */
    int have_atds_location;
    int have_atds_signal;
    int services;           /* services listed */
} mbim_caps_t;

int mbim_device_services_parse(const uint8_t *info, size_t len, mbim_caps_t *caps);

/* ---------------------------------------------------------- register state */

#define MBIM_REG_UNKNOWN      0
#define MBIM_REG_DEREGISTERED 1
#define MBIM_REG_SEARCHING    2
#define MBIM_REG_HOME         3
#define MBIM_REG_ROAMING      4
#define MBIM_REG_PARTNER      5
#define MBIM_REG_DENIED       6

typedef struct {
    uint32_t nw_error;
    uint32_t state;
    uint32_t data_classes;
    char provider[8];       /* digits only, or "" */
} mbim_register_t;

int mbim_register_parse(const uint8_t *info, size_t len, mbim_register_t *out);

/* 1 for home, roaming and partner */
int mbim_registered(uint32_t state);

/* ------------------------------------------------------- base stations */

/* The MBIM 1.0 query: the most cells of each RAT the reply may carry */
size_t mbim_base_stations_req(uint8_t *out, size_t cap, uint32_t max_per_rat);

#define MBIM_LTE_NEIGHBOURS_MAX 16
#define MBIM_UNKNOWN_U32 0xFFFFFFFFu

typedef struct {
    char provider[8];
    uint32_t cell_id;       /* MBIM_UNKNOWN_U32 when absent */
    uint32_t earfcn;
    uint32_t pci;
    uint32_t tac;
    int32_t rsrp;           /* as sent: dBm, or a 3GPP index (mbim_lte_rsrp_x10) */
    int32_t rsrq;
} mbim_lte_cell_t;

typedef struct {
    uint32_t system_type;
    int have_lte_serving;
    mbim_lte_cell_t lte_serving;
    int nneighbours;
    mbim_lte_cell_t neighbours[MBIM_LTE_NEIGHBOURS_MAX];
    int neighbours_dropped;  /* more than MBIM_LTE_NEIGHBOURS_MAX */
    int other_rat_cells;     /* GSM/UMTS/TD-SCDMA/CDMA sections, not read */
} mbim_base_stations_t;

int mbim_base_stations_parse(const uint8_t *info, size_t len, mbim_base_stations_t *out);

/* RSRP / RSRQ in tenths of dBm / dB, or INT32_MIN when absent.  Firmware
 * sends either the value itself (always negative: RSRP -156..-31 dBm, RSRQ
 * -43..-2 dB) or the 3GPP TS 36.133 report index (RSRP 0..97, RSRQ 0..34;
 * a MediaTek T700 on MBIM 1.0 sends indices).  The ranges do not overlap.
 * An index decodes to the lower edge of its 36.133 range. */
int32_t mbim_lte_rsrp_x10(int32_t v);
int32_t mbim_lte_rsrq_x10(int32_t v);

/* ------------------------------------------------------------------ atds */

typedef struct {
    uint32_t lac;
    uint32_t tac;
    uint32_t cell_id;
} mbim_atds_location_t;

typedef struct {
    int32_t rsrp_x10;       /* INT32_MIN when absent */
    int32_t rsrq_x10;
    int32_t snr_x10;
    int32_t rssi;           /* dBm, INT32_MIN when absent */
} mbim_atds_signal_t;

int mbim_atds_location_parse(const uint8_t *info, size_t len, mbim_atds_location_t *out);
int mbim_atds_signal_parse(const uint8_t *info, size_t len, mbim_atds_signal_t *out);

/* ------------------------------------------------------------ provider id */

/* Split a provider id into MCC and MNC.  Six digits are MCC + a 3-digit
 * MNC, five are MCC + 2 digits.  Some firmware drops a 3-digit MNC's
 * leading zero (a T700 on MBIM 1.0 sends "310" + "001" as "31001"); in the
 * North American MCCs, whose MNCs are all three digits, a 5-digit id is
 * padded back.  0 if the id is not 5 or 6 digits. */
int mbim_provider_split(const char *provider, char mcc[4], char mnc[4]);

#ifdef __cplusplus
}
#endif

#endif
