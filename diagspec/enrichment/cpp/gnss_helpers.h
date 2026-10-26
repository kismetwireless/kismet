// SPDX-License-Identifier: GPL-2.0-or-later
// diagspec C++ GNSS enrichment helpers — the GNSS parser-side utilities for
// 0x1476 (position report), 0x1477 / 0x1480 (GPS / GLONASS measurement az/el),
// and 0x1384 (NMEA-over-DIAG envelope), ported from the reference decoder.
// Independent of the RRC/ASN.1 decoders.
//
// This is OUR enrichment code, NOT kaitai-struct-compiler output and
// not the vendored MIT runtime. `.ksy` is layout-only: the raw scaled integers / IEEE-754 fields come out of the
// generated layer, and the SV-ID/constellation maps, radian→degree +
// velocity→speed scaling, and NMEA sentence extraction that make them
// WiGLE-usable live HERE, out of the raw-field equivalence diff. Zero
// dependencies beyond the STL.
//
// Equivalence to the reference decoder's GNSS helpers is diffed at the
// FIELD-VALUE level (harness/gnss_verify.py), so identifiers are chosen for a
// C++ reader rather than mirrored from the reference: e.g. the public
// `is_measurement_track` / `constellation_for_secondary_sv` predicates, and the
// inline output-rendering arithmetic lifted into named scaling functions.
//
// Layout note: the MDM9600/SWI9200X 797-byte gpsOne record needs its own
// layout to land lat/lon on the right bytes. That is handled in the
// parser/`.ksy` layer, not here. These scaling helpers are layout-agnostic:
// they take correctly-parsed raw radians and produce the derived output.
#ifndef DIAGSPEC_GNSS_HELPERS_H
#define DIAGSPEC_GNSS_HELPERS_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace diagspec {
namespace gnss {

// π as an IEEE-754 double — the double nearest pi (3.141592653589793), so
// `rad_to_deg` rounds identically to the reference decoder's scaling.
constexpr double kPi = 3.141592653589793;

// ---- coordinate / velocity scaling --------------------------------------
//
// The 0x1476 output exposes lat/lon/heading in DEGREES and a ground speed in
// m/s derived from the raw radians / east+north velocities; 0x1477 / 0x1480
// expose per-SV azimuth/elevation in degrees the same way.

// Radians → degrees. Operation order is `rad * 180.0 / pi` left to right,
// EXACTLY (`(rad * 180.0) / kPi`, not `rad * (180.0 / kPi)`) so the IEEE-754
// rounding is bit-identical. Used for lat_deg / lon_deg / heading_deg /
// heading_unc_deg (0x1476) and az_deg / el_deg (0x1477 / 0x1480).
inline double rad_to_deg(double rad) { return (rad * 180.0) / kPi; }

// Horizontal ground speed from east/north velocity components, `sqrt(ve² +
// vn²)` — the 0x1476 `speed_mps` output. The vertical component (vel_u) is
// deliberately excluded: this is horizontal ground speed.
double ground_speed_mps(double vel_e, double vel_n);

// DOP validity gate. The 0x1476 output carries pdop/hdop/vdop only when
// `< 100.0`, else null (100.0+ is the firmware's "no DOP" fill). Callers that
// need the null-or-value shape branch on this; the value itself is unscaled.
inline bool dop_is_known(double dop) { return dop < 100.0; }

// ---- SV-ID / constellation maps (single-sourced shared data) -------------
//
// Shareable data, not C++ logic. The const_id → constellation map is GENERATED into diagspec::gnss::constellation_names()
// from shared_data/enrichment_tables.yaml (the same shared source that feeds
// the asn1_helpers ENUMERATED tables and the diag_0xb0c0_enrich channel_name
// map); constellation_name() below is a thin lookup over it. Drift vs. the
// reference decoder's copy of the table is caught by the shared-table drift
// check, and the equivalence diff (harness/gnss_verify.py) still pins the values.

// v10 secondary-SV-block const_id → constellation name. Returns "" for an
// unmapped const_id (no name); the caller can fall back to
// `constellation_for_secondary_sv`,
// which adds sv_id-range inference.
const char* constellation_name(int const_id);

// True when a secondary-SV-block slot carries measurement-engine Kalman
// residuals. The low bit of const_id is the (constellation_index,
// engine_track_bit) track flag: odd = measurement track (floats populated),
// even = acquisition-only (floats always zero).
inline bool is_measurement_track(int const_id) {
  return (const_id & 0x01) != 0;
}

// Best-effort constellation name for a secondary-block slot: the const_id map
// first, then sv_id-range inference (Galileo 301..336, BeiDou 201..237).
// Returns "" when the slot is ambiguous (no name); the caller keeps the raw
// const_id.
const char* constellation_for_secondary_sv(int const_id, int sv_id);

// ---- SV-ID → PRN conversions --------------------------------------------
//
// The v10 secondary block encodes non-GPS PRNs with a per-constellation
// offset. These reproduce the offset arithmetic; the caller is responsible for
// the const_id / sv_id range guards that gate them (documented on each
// function).

// BeiDou PRN from a const_id==0x04 slot: `sv_id - 200` (valid for sv_id in
// 201..237, i.e. PRN 1..37).
inline int beidou_prn(int sv_id) { return sv_id - 200; }

// Galileo PRN from a Galileo slot. const_id 0x06 uses `sv_id - 50` (sv_id>50);
// const_id 0x07 uses `sv_id - 46` (sv_id>46) — different signal-band slots
// observed on EM7511. Returns sv_id unchanged for a non-Galileo const_id (the
// caller should not have called it in that case).
int galileo_prn(int const_id, int sv_id);

// GLONASS frequency-channel number (FCN) from byte 3 of a GLONASS slot,
// decoded as a SIGNED int8 in [-7, +6] (`byte3 - 256` when `byte3 >= 128`,
// else `byte3`).
inline int glonass_fcn(int byte3) {
  return byte3 >= 128 ? byte3 - 256 : byte3;
}

// ---- NMEA-over-DIAG envelope --------------------------------------------
//
// 0x1384 wraps a raw NMEA sentence in a versioned DIAG envelope. The
// reusable "envelope" step — locate the `$`, trim the line terminator, ASCII-
// decode, split off the talker — is ported here; the structured GGA/RMC/GSV/…
// field parse is out of scope here.

struct NmeaEnvelope {
  bool found = false;    // false when the body is truncated or holds no `$` (no envelope)
  std::string talker;    // first comma-field, e.g. "$GPGGA" (whole sentence if no comma)
  std::string sentence;  // the ASCII-decoded sentence, `$` up to the first CR/LF/NUL
};

// Both 0x1384 layouts carry a FIXED 200-byte NMEA body after the header:
// v1/0x32 is 8 + 200 = 208 B and v2/0x02 is 10 + 200 = 210 B on every committed
// real record. The rest of the 200 B past the
// sentence is a reused, non-zeroed buffer.
constexpr std::size_t kNmeaBodyLen = 200;

// Extract the NMEA sentence + talker from a 0x1384 payload, starting the `$`
// scan at `search_start` (8 for v1/0x32, 10 for v2/0x02 — the version dispatch
// stays in the caller / generated layer). The extraction: a record that cannot
// hold the whole fixed body (size < search_start + kNmeaBodyLen) is truncated
// and not found; otherwise find the first `$` at/after search_start, cut at the
// shortest of the CR-LF / CR / LF / NUL terminators, ASCII-decode with
// replacement, and take the first comma-field as the talker. Replacement maps
// each non-ASCII byte to U+FFFD, emitted here as its UTF-8 encoding to keep the
// strings byte-equal.
NmeaEnvelope extract_nmea(const std::vector<uint8_t>& data, std::size_t search_start);

}  // namespace gnss
}  // namespace diagspec

#endif  // DIAGSPEC_GNSS_HELPERS_H
