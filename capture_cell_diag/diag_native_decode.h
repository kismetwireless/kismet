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

    C-callable surface over the diagspec cell_observation decode legs -- the
    piece that lets THIS process decode DIAG natively.

    WHY THIS EXISTS. Decoding happens in THIS helper, the process that holds
    the raw DIAG bytes; it sends decoded results upstream via cf_send_json(),
    and no decodable DIAG record reaches the server. (Raw stream slices do, as
    DLT 147 packets, but only for the kismetdb/pcapng loggers -- a slice is a
    cut of the byte stream, not a record.) So the diagspec C++ legs
    (diagspec/enrichment/cpp/diag_0xbNNN_observation.*) belong here.

    This shim is how the helper reaches them. It is `extern "C"` over the
    C++ legs, returning flat C structs, so capture_cell_diag.c (C) can call them
    with no C++ in its translation unit. The helper is linked with $(CCLD) = gcc,
    so the link line gains $(CXXLIBS) = -lstdc++.

    NOT a reimplementation: every function here forwards to the diagspec leg.
    There is exactly one decode implementation per log code.

    Ownership/lifetime: each decode_* fills a caller-provided fixed array and
    returns the count written, so there is no allocation to free and no
    C++-allocated memory crossing the boundary. A record with more cells than the
    caller's capacity is TRUNCATED and the return value tells the caller how many
    were written -- see diag_native_*_max().
*/

#ifndef __DIAG_NATIVE_DECODE_H__
#define __DIAG_NATIVE_DECODE_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One decoded cell observation, flattened for C. Mirrors the union of the
 * per-code CellObservation structs; a field a given log code does not carry is
 * reported absent via its has_* flag rather than as a sentinel value, so a
 * consumer can never mistake "no measurement" for a real reading. */
typedef struct {
    /* "LTE" or "NR" -- the rat the emitted observation carries. */
    const char *rat;
    /* Origin log code, e.g. 0xB97F -- becomes the prov block's "origin". */
    uint16_t log_code;

    int32_t pci;
    int32_t earfcn;        /* NR-ARFCN when rat == "NR" */
    bool is_serving;

    bool has_rsrp;
    double rsrp;           /* dBm; only meaningful when has_rsrp */
    bool has_rsrq;
    double rsrq;           /* dB;  only meaningful when has_rsrq */
    /* Per-cell RSSI -- 0xB17F only, the DIAG leg's one rssi source. */
    bool has_rssi;
    double rssi;           /* dBm; only meaningful when has_rssi */

    /* Full-identity fields -- 0xB0C0 SIB1 only; absent on the measurement codes.
     * MCC/MNC are STRINGS, not integers: a 2-digit MNC can lead with a zero
     * ("310"/"01" is not "310"/1), so narrowing them to an int loses the
     * distinction the PLMN actually encodes. NUL-terminated. */
    bool has_identity;
    char mcc[8];
    char mnc[8];
    uint32_t tac;
    /* 64-bit, not 32. LTE's CellIdentity is 28 bits, but NR's NCI is
     * 36 -- so a uint32_t here would silently truncate the top 4 bits of every
     * 5G cell identity that arrives via cross-record enrichment, producing a
     * plausible-looking wrong cell rather than a visible failure. */
    uint64_t cell_id;

    /* 0xB0C0 MeasurementReport neighbour row, not the record's own
     * SIB1 identity cell. Selects that row's key order in
     * diag_native_obs_to_json. Set only by diag_native_lte_meas_neighbours. */
    bool meas_neighbour;
    /* True when the row has NO earfcn key at all: a CGI neighbour whose measId
     * did not map to a carrier. Inverted (absent, not has_) so that init_obs's
     * memset leaves every other code's earfcn present, as it always was. */
    bool earfcn_absent;

    /* LTE serving-cell config from a cached 0xB197, attached by
     * diag_native_lte_cell_config(). Rendered
     * after band/duplex as bandwidth_rb, bandwidth (MHz, none for 6 RB) and
     * tx_antennas, each only when set. */
    bool has_bandwidth_rb;
    int32_t bandwidth_rb;
    bool has_tx_antennas;
    int32_t tx_antennas;

    /* 0xB97F only: the first SSB beam of the cell (rendered as a one-entry
     * `beams` list), and the serving row's SSB index and burst period. */
    bool has_beam;
    int64_t beam_ssb_index;
    bool has_beam_rsrp_a;
    double beam_rsrp_a;
    bool has_beam_rsrp_b;
    double beam_rsrp_b;
    bool has_beam_rsrq_a;
    double beam_rsrq_a;
    bool has_beam_rsrq_b;
    double beam_rsrq_b;
    bool has_serving_ssb_index;
    int32_t serving_ssb_index;
    bool has_ssb_periodicity_ms;
    int32_t ssb_periodicity_ms;

    /* NR rows (0xB97F, 0xB821): the cell's SSB subcarrier spacing in kHz, from
     * the sib1 map's MIB cache. Attached by
     * diag_native_sib1_enrich, rendered last, after any identity. */
    bool has_scs;
    int32_t scs;
    /* NR rows (0xB97F, 0xB821): the cell's SIB1 servingCellConfigCommon
     * headline, from the sib1 map's NR config cache. Attached by
     * diag_native_sib1_enrich next
     * to scs, rendered right after it as band, carrier_scs, bandwidth_rb and
     * bandwidth, each only when set. Separate from the LTE band (derived from
     * the EARFCN at render time) and from has_bandwidth_rb (the 0xB197 cache,
     * whose MHz comes from the LTE RB table): `bandwidth` here is the SIB1
     * decode's own TS 38.101 value, absent for a non-table N_RB. */
    bool has_nr_band;
    int32_t nr_band;
    bool has_nr_carrier_scs;
    int32_t nr_carrier_scs;          /* kHz */
    bool has_nr_bandwidth_rb;
    int32_t nr_bandwidth_rb;         /* carrier PRBs */
    bool has_nr_bandwidth;
    int32_t nr_bandwidth;            /* MHz */
    /* 0xB821 only: the MeasurementReport's serving SINR (dB). */
    bool has_sinr;
    double sinr;

    /* 0xB0C0 identity cell only: the SIB1 cellAccessRelatedInfo flags the
     * rendered on every identity cell, and its MOCN PLMN list (rendered as
     * `plmns` only when it holds more than one entry). */
    bool has_access_flags;
    bool cell_barred;
    bool csg;
    int n_plmns;
    char plmn_mcc[6][8];
    char plmn_mnc[6][8];
} diag_native_obs_t;

/* Decode one log-code-stripped DIAG LOG_F payload natively.
 *
 * Returns the number of observations written into out_obs (0 is a NORMAL
 * outcome, not an error: a record with no measurement subpacket, a 0xB0C0 that
 * carries no SIB1, or a payload the leg rejects all yield 0).
 *
 * Returns -1 if log_code has no native leg. That distinction matters: "no leg"
 * and "leg ran, found nothing" must not collapse, or the census could not tell
 * an uncovered code from a covered one that carried nothing.
 */
int diag_native_decode(uint16_t log_code, const uint8_t *payload, size_t payload_len,
        diag_native_obs_t *out_obs, size_t max_obs);

/* diag_native_decode, plus whether the leg REFUSED the record.
 *
 * *refused is true exactly when the leg refuses this record (version gate,
 * layout/truncation decline), and false for a completed parse, whatever its
 * row count. The two would otherwise collapse into the same 0 return, and the
 * census would count a refused record as decoded rather than dropped.
 * refused may be NULL. It is false whenever the return is -1. */
int diag_native_decode_ex(uint16_t log_code, const uint8_t *payload, size_t payload_len,
        diag_native_obs_t *out_obs, size_t max_obs, bool *refused);

/* The value diag_native_cell_config_learn returns for a 0xB197 the leg
 * refuses, distinct from 0 ("parsed, learned nothing") and -1
 * ("not 0xB197"). */
#define DIAG_NATIVE_REFUSED (-2)

/* True iff log_code has a native leg (i.e. diag_native_decode would not return
 * -1). Lets the caller route without a throwaway decode. */
bool diag_native_has_leg(uint16_t log_code);

/* ---- GNSS position ---------------------------------------------------------
 *
 * A SECOND entry point, not a fifth branch of diag_native_decode(). 0x1476 does
 * not produce a cell_observation: the helper CACHES a decoded fix to geo-tag
 * later observations rather than relaying it upstream, and diag_native_obs_t
 * has no shape for lat/lon/alt. Folding it into the cell surface would mean either a struct
 * whose meaning depends on log_code, or a caller that has to know which fields
 * are live per code -- both of which are how "no measurement" starts reading as
 * a real value.
 *
 * WHY THIS MATTERS AT ALL. Kismet geo-tags every DIAG cell observation from
 * these fixes (local->last_gps, cf_send_json's `gps` param).
 *
 * THERE IS NO 0x14D8 LEG, DELIBERATELY, although 0x14D8 is often described as
 * the backup GNSS position code. Its lat/lon/alt bytes [+20..+43] are unbound
 * carryover that no firmware populates, so they read 0.0, which fails the
 * position validity gate: a 0x14D8 record can never yield a fix. On an
 * RM520N-GL capture that is 53 of its 69 GNSS records producing nothing. A
 * 0x14D8 leg would be a decode path that is provably always empty.
 */

/* Why a GNSS record produced no usable fix, so a caller counting declines can distinguish the four findings instead of
 * folding them -- two of which are OPPOSITE: NO_POSITION (0,0) is a benign
 * engine-with-no-sky-view, while NO_TIME_SOLUTION is a chipset seed position
 * measured 215 km from truth on SDX62. DECLINE_NONE == a fix was
 * produced. There is deliberately no "not a GNSS code" member: this type is only
 * ever written for a code diag_native_has_gps_leg() already accepted. */
typedef enum {
    DIAG_NATIVE_GPS_DECLINE_NONE = 0,    /* a usable fix was produced */
    DIAG_NATIVE_GPS_DECLINE_UNPARSEABLE, /* payload too short/malformed */
    DIAG_NATIVE_GPS_DECLINE_NO_POSITION, /* coord out of band, incl. (0,0) */
    DIAG_NATIVE_GPS_DECLINE_PLACEHOLDER, /* vendor "no fix" sentinel */
    DIAG_NATIVE_GPS_DECLINE_NO_TIME,     /* gps_week == 0xFFFF, seed position */
    /* Older than the newest GNSS clock its STREAM carried by more than the
     * bound: a real fix at real degrees, being RE-SERVED -- an RM500Q-AE can
     * serve one 13.68 h old. Only a tracker can produce this one; see
     * diag_native_gnss_tracker_t below. Appended, never inserted: the counters
     * are keyed on these values. */
    DIAG_NATIVE_GPS_DECLINE_STALE,
    /* Altitude outside [-500, +9,000] m, or NaN: a re-acquiring
     * LM960A18's WLS seeds can sit at -806 ... -3,866 m. Per-record. */
    DIAG_NATIVE_GPS_DECLINE_ALTITUDE,
    /* Implied speed from the last ACCEPTED fix above the bound:
     * the same WLS cold-start trajectory, 146 km -> 1.6 km off a stationary
     * bench. Tracker-only, like STALE. DISARMED by default (the leg's
     * kDefaultMaxSpeedMps is infinity) until its anchor is redesigned: one
     * anchor fed by a source re-serving a parked position refuses the real
     * moving track. Never produced today; the value is reserved. */
    DIAG_NATIVE_GPS_DECLINE_JUMP,
} diag_native_gps_decline_t;

/* One decoded GNSS position fix. `valid` false means the record carried no
 * usable fix -- a short/unparseable payload, an out-of-band coordinate, or a
 * known vendor "no fix" placeholder (Qualcomm's Nevada default, Telit's
 * no-antenna sentinel, (0,0)). A caller must NOT geo-tag from an invalid fix, or
 * every cell in the run anchors at a fabricated coordinate. `decline_reason`
 * names WHICH gate refused (DIAG_NATIVE_GPS_DECLINE_NONE when valid). */
typedef struct {
    bool valid;
    double lat_deg;
    double lon_deg;
    double alt_m;
    diag_native_gps_decline_t decline_reason;
} diag_native_gps_fix_t;

/* ---- GNSS freshness: the staleness gate's reference ----------------------
 *
 * Every gate above is a function of ONE record. Staleness is not: a fix is
 * stale when its own GNSS clock is more than a bound behind the newest clock
 * the SAME STREAM has carried. Measured on an RM500Q-AE: 106 of 406 accepted
 * records re-served one frozen fix 13.68 h old, at real degrees, with a time
 * solution -- every per-record gate passes them, and every cell after one is
 * geo-tagged from where the receiver was yesterday.
 *
 * So the reference is cross-record state with exactly the SIB1 map's
 * lifecycle -- one per capture source, created when the source opens, freed
 * (or reset) on restart -- and it mirrors the map's opaque-handle ABI for the
 * same reasons. The judge sequence itself (read this record's clock, judge it
 * against the reference as it stood BEFORE this record, then fold the clock in,
 * on EVERY record that carries one, including ones the coordinate gates refuse)
 * is the diagspec leg's diag_0x1476_gpsfix::FreshnessTracker. This shim owns
 * the handle; nothing here decides.
 *
 * Host-clock-free by construction: the reference is the stream's own GNSS
 * time, so a capture host with no NTP cannot invert the gate. */
typedef struct diag_native_gnss_tracker diag_native_gnss_tracker_t;

/* The leg's default bound in ms (60 s). A
 * caller takes it from here rather than restating the number. */
int64_t diag_native_gnss_default_max_fix_age_ms(void);

/* NULL on allocation failure (nothrow). A caller treats NULL as "staleness gate
 * unavailable" and keeps capturing, as a NULL sib1 map is "enrichment
 * unavailable" -- and says so, because the gate is then OFF. */
diag_native_gnss_tracker_t *diag_native_gnss_tracker_new(int64_t max_fix_age_ms);
void diag_native_gnss_tracker_free(diag_native_gnss_tracker_t *tracker);
/* Forget the reference and the warm-up count (a source restart). */
void diag_native_gnss_tracker_reset(diag_native_gnss_tracker_t *tracker);
/* Records accepted before any reference existed: the warm-up hole, one record
 * wide on a stream whose first clocked record seeds it. Counted, not hidden --
 * an operator comparing fixes= against stale= is entitled to know the gate was
 * blind for part of the run. 0 for a NULL tracker. */
uint64_t diag_native_gnss_tracker_unjudged(const diag_native_gnss_tracker_t *tracker);

/* The decline reason's name: "no_position", "placeholder_position",
 * "no_time_solution", "stale_fix", "implausible_altitude", "implausible_jump"
 * -- and "unparseable" for a record the parser refused before any gate ran.
 * NULL for DIAG_NATIVE_GPS_DECLINE_NONE. The strings are the diagspec leg's. */
const char *diag_native_gps_decline_name(diag_native_gps_decline_t reason);

/* Decode one log-code-stripped DIAG LOG_F payload into a position fix.
 *
 * `tracker` is the capture source's freshness reference: the record is judged
 * against it, then folded into it. NULL makes the staleness gate INERT -- the
 * per-record verdict only -- which is right for a one-off decode (a test, a probe) and wrong for a capture
 * source, which must pass the tracker it holds.
 *
 * Returns 1 when a fix was produced, 0 when the leg ran and declined (no usable
 * position -- a NORMAL outcome), and -1 when log_code has no GNSS leg. Same
 * three-way contract as diag_native_decode(): "no leg" and "found nothing"
 * must not collapse.
 *
 * out_fix is always fully written when the return value is >= 0. */
int diag_native_decode_gps_fix(diag_native_gnss_tracker_t *tracker,
        uint16_t log_code, const uint8_t *payload,
        size_t payload_len, diag_native_gps_fix_t *out_fix);

/* True iff log_code has a native GNSS leg. */
bool diag_native_has_gps_leg(uint16_t log_code);

/* The log codes with native CELL legs, for logging/inventory. Returns the count
 * and fills out_codes up to max_codes. */
size_t diag_native_codes(uint16_t *out_codes, size_t max_codes);

/* The log codes with native GNSS legs. Separate from diag_native_codes() rather
 * than merged into it, for the same reason the decode entry points are separate:
 * these route to a different surface with a different output type, and an
 * inventory that flattened them would say "5 native legs" while
 * diag_native_has_leg() answers false for one of them. */
size_t diag_native_gps_codes(uint16_t *out_codes, size_t max_codes);

/* ---- Cross-record SIB1 enrichment -----------------------------------------
 *
 * A THIRD surface. Everything above is a pure function of ONE record; this is
 * not. A bare measurement observation inherits MCC / MNC / TAC / CellID from a
 * SIB1 seen EARLIER in the stream, keyed by (pci, earfcn) -- learned before
 * the record's own observations are decoded. No per-record leg can do that,
 * however byte-correct it is.
 *
 * On a real LTE wardrive, about half the observations (10,259 / 20,984) carry
 * identity that came only from this mechanism. Native decode without it loses
 * those fields with the observation COUNT UNCHANGED -- a silent field loss
 * that every counter-based check reports as green.
 *
 * Two identity sources:
 *   0xB0C0  LTE RRC OTA  -- key (pci, earfcn), via the 0xB0C0 observation leg
 *   0xB821  NR5G RRC OTA -- key (pci, arfcn),  via the 0xB821 identity leg
 *
 * ONE MAP, SHARED BY BOTH RATs, KEYED WITHOUT THE RAT. An LTE EARFCN and an
 * NR-ARFCN that happen to be the same integer, on the same PCI, collide -- and
 * first-write-wins means the earlier one persists. Adding `rat` to the key
 * would be an improvement; it changes which identity such a pair renders, so
 * the replay goldens would have to move with it.
 */

/* Opaque cross-record identity cache. Heap-allocated so an unarmed source pays
 * nothing, and so the C helper never needs a C++ type in its translation unit. */
typedef struct diag_native_sib1_map diag_native_sib1_map_t;

diag_native_sib1_map_t *diag_native_sib1_map_new(void);
void diag_native_sib1_map_free(diag_native_sib1_map_t *map);

/* Distinct keys learned so far -- the operator-facing "how much identity does
 * this stream actually know" number. */
size_t diag_native_sib1_map_size(const diag_native_sib1_map_t *map);

/* True iff log_code can contribute a map entry (0xB0C0 / 0xB821).
 *
 * This set is NOT a subset of diag_native_has_leg(): 0xB0C0 is both (it emits
 * an identity observation AND seeds the map) but 0xB821 is ONLY an identity
 * source -- it has no cell-observation leg of its own. A caller that routed on
 * has_leg() alone would never learn a single NR identity. */
bool diag_native_is_identity_source(uint16_t log_code);

/* 0xB197 serving-cell config. It is cached in the sib1 map under
 * ("lte_cfg", pci, earfcn & 0xFFFF) and attaches it to every LTE observation of
 * that cell. It is a separate entry point, not an identity source: it seeds no
 * (pci, earfcn) identity, so it must not move the identity_* counters.
 *
 * diag_native_cell_config_learn returns 1 when the record was cached, 0 when a
 * 0xB197 carried nothing cacheable (or map is NULL), and -1 for any other code.
 * Call it on every record before decoding, like diag_native_sib1_learn.
 *
 * diag_native_lte_cell_config fills obs's has_bandwidth_rb/has_tx_antennas
 * fields and returns true when it attached anything. It MUTATES the map (the
 * alias guard records every full EARFCN seen under a truncated key), so it must
 * run on EVERY LTE observation, in emit order, after diag_native_sib1_enrich --
 * whether or not the observation is rendered. NR rows and rows with no earfcn
 * are left alone. */
int diag_native_cell_config_learn(diag_native_sib1_map_t *map, uint16_t log_code,
        const uint8_t *payload, size_t payload_len);
bool diag_native_lte_cell_config(diag_native_sib1_map_t *map, diag_native_obs_t *obs);

/* Learn identity from one SIB1-bearing record.
 *
 * An 0xB821 SIB1 also caches the cell's servingCellConfigCommon headline (band,
 * carrier SCS, carrier PRBs, channel MHz) under its own (pci, arfcn) key: one
 * snapshot per SIB1, first write wins, and
 * none when the SIB1 reached none of the four fields. That is independent of
 * the identity key and does not move the return value.
 *
 * Returns 1 when a NEW key was inserted, 0 when the leg ran and inserted
 * nothing (no SIB1 in this record, or the key was already known -- first-write
 * -wins), and -1 when log_code is not an identity source. Call this BEFORE
 * decoding the same record's observations: a serving cell seen after its own SIB1 in the same record
 * stream must be emitted WITH identity. */
int diag_native_sib1_learn(diag_native_sib1_map_t *map, uint16_t log_code,
        const uint8_t *payload, size_t payload_len);

/* Merge cached identity onto one observation, keyed (obs->pci, obs->earfcn).
 *
 * Also attaches an NR row's cached SSB `scs` (keyed the same way) and its
 * cached SIB1 cell config.
 * Both happen whether or not identity is found, and neither counts
 * toward the return value, which stays "identity attached".
 * Returns true iff obs was enriched (i.e. the key was known and obs did not
 * already carry identity).
 *
 * An observation that ALREADY carries identity is left alone. That is not a
 * safety belt, it is the rule: only MEASUREMENT rows are enriched, never a
 * 0xB0C0 row, whose identity is the record's own freshly-decoded SIB1. Since 0xB0C0 is the
 * only leg that sets has_identity, `!has_identity` is exactly that condition. */
bool diag_native_sib1_enrich(const diag_native_sib1_map_t *map,
        diag_native_obs_t *obs);

/* ---- LTE MeasurementReport neighbours -----------------------------------
 *
 * A second piece of cross-record state, and the reason it lives in this map.
 * A MeasurementReport names its neighbours by PCI only; the carrier comes from
 * measId -> measObjectId -> EARFCN, configured by an EARLIER
 * RRCConnectionReconfiguration and invalidated by release / setup / handover /
 * re-establishment. That state lives in the same sib1 map the SIB1 identities
 * live in, updated from EVERY 0xB0C0 record by diag_native_sib1_learn, before
 * the SIB1 gate; this reads it, with the same lifetime and the same
 * learn-before-decode ordering.
 *
 * The join itself (the state machine and the emit rules) is the diagspec leg
 * diagspec/enrichment/cpp/lte_meas_join.*. Nothing here decides.
 *
 * Writes the neighbour rows of a 0xB0C0 UL-DCCH MeasurementReport into
 * out_obs, as meas_neighbour observations: LTE, not serving, rsrp/rsrq as
 * reported, identity set only for a cgi-Info neighbour (so SIB1 enrichment
 * reaches exactly the PCI-only rows), and
 * earfcn_absent for a CGI row whose measId did not map. Returns the count
 * written (0 is normal: most 0xB0C0 records are not reports, and an unmapped
 * PCI-only neighbour is omitted), or -1 when log_code is not 0xB0C0. A NULL
 * map knows no carriers, so only CGI neighbours can be returned. */
int diag_native_lte_meas_neighbours(const diag_native_sib1_map_t *map,
        uint16_t log_code, const uint8_t *payload, size_t payload_len,
        diag_native_obs_t *out_obs, size_t max_obs);

/* ---- Serialize an observation to its JSON line ---------------------------
 *
 * The render step: everything above DECODES a record into a diag_native_obs_t,
 * and this turns that struct into the cell_observation line Kismet consumes.
 *
 * THE KEY ORDER IS PER CODE, NOT STRUCT-WIDE. 0xB193 places prov before
 * rsrp/rsrq, 0xB192/0xB195/0xB97F place it after is_serving, 0xB0C0 carries
 * its identity inline and puts prov last; the separators are "," and ":" with
 * no spaces. That is why this switches on obs->log_code rather than emitting a
 * uniform field list. The offline test pins every branch byte for byte.
 *
 * `imei`, `captured_at` (Unix-epoch seconds) and `log_tick` (the raw DIAG ts64)
 * are taken as PARAMETERS, not read from a clock, so the rendered line is a
 * pure function of its inputs and can be pinned byte-for-byte offline. Live,
 * the caller passes gettimeofday() and rec->ts64.
 *
 * Returns the number of bytes the full line occupies excluding the NUL,
 * snprintf-style: a value >= out_len means the line was truncated and the caller
 * MUST NOT emit it. Never writes the trailing newline -- the caller frames it.
 * Returns -1 if log_code has no cell-observation serialization (e.g. a GNSS code,
 * or 0xB821, which seeds identity but emits no observation of its own). */
int diag_native_obs_to_json(const diag_native_obs_t *obs, const char *imei,
        double captured_at, uint64_t log_tick, char *out, size_t out_len);

/* ---- Live GSMTAP framing (gsmtap=) ----------------------------------------
 *
 * The record as one GSMTAP datagram for the live tap: a 16-byte GSMTAP header
 * plus the raw over-the-air PDU. Wireshark's lte-rrc / nas-eps
 * dissectors do the field decode, so no ASN.1 is on this path.
 *
 * Returns the frame length written to `out` (> 0), 0 when the framer ran and
 * declined (no PDU, or a channel with no GSMTAP sub-type, as the encoder
 * returns None), and -1 when this binary has no native framer for `log_code`.
 * -1 is NOT a decline of the record: for an eligible code it means "not
 * framed natively". Every eligible code has a framer today (LTE RRC 0xB0C0
 * and the five LTE NAS codes); -1 stays the answer for a code a
 * future eligible set adds before its framer exists.
 * A frame longer than `out_cap` is declined (0), never truncated. */
int diag_native_gsmtap_frame(uint16_t log_code, const uint8_t *payload,
        size_t payload_len, uint8_t *out, size_t out_cap);

/* True iff diag_native_gsmtap_frame would not return -1 for `log_code`. */
bool diag_native_has_gsmtap_framer(uint16_t log_code);

#ifdef __cplusplus
}
#endif

#endif /* __DIAG_NATIVE_DECODE_H__ */
