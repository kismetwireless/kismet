// SPDX-License-Identifier: GPL-2.0-or-later
// Linkable surface of the 0x1476 gps_fix enrichment leg.
//
// Unlike the cell legs, this one does not emit a cell_observation. Kismet
// geo-tags every DIAG cell observation from these fixes (`local->last_gps`,
// cf_send_json's `gps` param), so without this leg the capture helper would
// have no position to tag any cell observation with.
//
// 0x14D8 is not a second source. The reference decoder's 0x14D8 parser sets
// lat/lon/alt to a hardcoded 0.0: bytes [+20..+43] are unbound carryover from an
// earlier RE pass and no observed firmware populates them. 0.0 fails the
// `1 < |lat| < 90` coordinate gate, so a 0x14D8 position leg could never emit a
// fix. There is deliberately no 0x14D8 leg here: it would be a decode path that
// is provably always empty.
//
// The layout regime is the hard part. 0x1476 lands the fix fields at four
// different bases depending on (version, payload_size), and the reference
// modem uses one the .ksy's `seq` does NOT model:
//
//   `_POS_FMT` v1/v2/v7/v8/v10      week@23 lat@40 lon@48 alt@56   (the seq)
//   mdm9600 gpsOne                  week@19 lat@36 lon@44 alt@52   (version==2 && size==797)
//   compact v4/v6 | v11 | v12       week@19 | 23 | 24, lat/lon/alt at +17/+25/+33
//   v13 (SDX55) / v24 (SDX62+)      week@32 lat@49 lon@57 alt@65   (version>=13 && size>=407)
//
// RM520N-GL records are version=24. Read through the seq offsets they yield
// lat=0.0 and a ~1e185 lon, which the validity gate rejects, so a leg built on
// the seq accessors emits zero fixes on a modem that is reporting good ones, and
// "no fixes" is indistinguishable from "no sky view". This leg therefore reads
// the regime-resolving `fix_lat_rad()` / `fix_lon_rad()` / `fix_alt_m()` /
// `fix_gps_week()` / `fix_gps_tow_ms()` instances in the .ksy, never the seq's
// `lat_rad()` / `lon_rad()` / `alt_m()` / `gps_week()` / `gps_tow_ms()`.
//
// EQUIVALENCE CONTRACT: the fixes this leg emits must equal the reference
// decoder's 0x1476 fixes — same accept/reject decision AND the same rounded
// lat/lon/alt — over every committed diag_0x1476 fixture, in every layout
// regime. That includes the STATEFUL path: FreshnessTracker below must
// agree with the reference freshness tracker record by record over an ordered
// stream, decline reason, reference and warm-up count included.
#ifndef DIAGSPEC_DIAG_0X1476_GPSFIX_H
#define DIAGSPEC_DIAG_0X1476_GPSFIX_H

#include <cmath>
#include <cstdint>
#include <string>

namespace diag_0x1476_gpsfix {

// One GNSS position fix, in the shape the helper caches as `last_gps`. `valid`
// false means the record carried no usable fix (short/unparseable payload, an
// out-of-band coordinate, a known vendor "no fix" placeholder, no time
// solution, or a stale fix) — the caller must NOT geo-tag from an invalid fix,
// or every cell in the run anchors at a fabricated coordinate.
struct GpsFix {
    bool valid;
    double lat_deg;
    double lon_deg;
    double alt_m;
};

// True if (lat, lon) is a known vendor "no fix" sentinel that looks like valid
// degrees but is not a real observation. The sentinel set:
//   * Qualcomm Nevada default (38.0, -117.0)
//   * Telit FN980m "no antenna" placeholder (~5.5, ~6.6)
//   * (0, 0) generic "value unavailable" sentinel
// Exposed (not file-static) so the negative-control tests can hit it directly:
// a leg that got the scaling right and this gate wrong would pass on every
// clean-fix fixture and fail only on the sentinel-bearing ones.
bool is_placeholder_position(double lat_deg, double lon_deg);

// Decode a raw 0x1476 LOG_F payload (log-code-stripped) into at most one
// position fix. Returns `valid == false` rather
// than throwing for any payload the reference parser would reject, so a
// malformed record on a live stream degrades to "no fix", never to a crash in
// the capture helper. Per-record: no staleness gate (see FreshnessTracker).
GpsFix fix(const std::string& payload);

// Named decline reasons, the same taxonomy the reference decoder's GNSS gate
// uses. This exists so a
// caller counting declines can say WHICH gate refused, rather than collapsing
// five different findings -- two of them OPPOSITE (a benign no-sky-view (0,0) vs
// a chipset seed position that can sit hundreds of km from truth) -- into one
// undifferentiated "nofix" that an operator reads as "indoors" and gets wrong.
//
// kNoTimeSolution (gps_week == 0xFFFF) is the seed-position case: the coordinate
// is perfectly plausible degrees, so only the absence of a time solution reveals
// it. kStale is a real fix at real degrees whose own GNSS clock is more
// than the bound behind the newest clock the STREAM has carried: a position
// being re-served, measured 13.68 h old on an RM500Q-AE. kUnparseable is the
// C-seam-only bucket for a short/truncated payload the generated reader throws
// on; the reference gate has no name for it because it never sees such a
// record. There is deliberately no kNotAGnssCode: this seam is only
// ever reached for a code diag_native_has_gps_leg() already accepted.
//
// Members are only ever APPENDED: the C ABI's diag_native_gps_decline_t mirrors
// this order, and the operator-facing counters are keyed on it.
enum class Decline {
    kNone = 0,            // a usable fix was produced (GpsFix.valid == true)
    kUnparseable,         // payload too short/malformed to read a fix
    kNoPosition,          // coordinate out of the plausible band, incl. (0,0)
    kPlaceholder,         // known vendor "no fix" sentinel (Nevada / Telit)
    kNoTimeSolution,      // gps_week == 0xFFFF -- a seed position, no time
    kStale,               // older than the stream's newest clock by > the bound
    kAltitude,            // alt_m outside [kMinPlausibleAltM, kMaxPlausibleAltM] or NaN
    kJump,                // implied speed from the last ACCEPTED fix > the bound
};

// The decline reason as a stable string ("no_position", "placeholder_position",
// "no_time_solution", "stale_fix", "implausible_altitude", "implausible_jump"),
// byte-equal to the reference gate's names, which the
// stateful equivalence harness asserts. kUnparseable has no reference name (the
// gate is never reached for a record the parser refused) and answers
// "unparseable"; kNone answers nullptr, since nothing was declined.
const char* decline_name(Decline why);

// fix(), but also reports WHY a record declined via *reason. The GpsFix returned
// is byte-identical to fix()'s -- same accept/reject decision and coords -- so
// the equivalence harness that pins fix() is unaffected; this only adds the
// justification. `reason` is set to kNone iff the returned fix is valid. `fix()`
// is a thin wrapper over this.
GpsFix fix_verdict(const std::string& payload, Decline* reason);

// ---- Staleness -----------------------------------------------------
//
// Milliseconds in a GPS week -- the (week, tow) pair's radix.
const int64_t kMsPerGpsWeek = 604800000;
// The default staleness bound, chosen by measurement: over a 118-capture corpus
// sample, 60 s refuses only re-served pos_source=4 copies 60 s to 13.7 h old,
// while 10 s also refuses live fixes behind a clock that ran up to 51 s ahead
// (RM520N-GL after a reboot), and 300 s lets 368 re-served copies through. The
// equivalence harness holds this constant equal to the reference decoder's.
const int64_t kDefaultMaxFixAgeMs = 60000;

// The record's own GNSS clock as one monotone scalar, week * kMsPerGpsWeek +
// tow_ms. False (and
// *out_ms untouched) when the record has no clock: a payload the reference
// parser refuses, or gps_week == 0xFFFF. Host-clock-free by construction.
bool gps_time_ms(const std::string& payload, int64_t* out_ms);

// ---- Plausibility --------------------------------------------------
//
// A ground receiver's altitude band. Per-record and always on, so it is the only guard
// on a stream's first fix. Measured: a re-acquiring LM960A18 emitted 28 fixes at
// -806 ... -3,866 m inside a WLS cold-start trajectory 146 km from truth.
const double kMinPlausibleAltM = -500.0;
const double kMaxPlausibleAltM = 9000.0;
// The jump gate's bound on the speed implied by the last accepted fix and this
// one. The equivalence harness holds it equal to the reference decoder's.
// DISARMED (infinity) until the anchor is redesigned: one anchor fed by
// every source lets an engine re-serving a PARKED position with fresh clocks
// re-anchor the gate, which then refuses the real moving track (measured: 410
// moving fixes refused on a CFW-3212 survey at 150 m/s). Pass a finite bound to
// arm it; 150.0 is the working number. HUGE_VAL is +infinity on IEEE 754;
// a macro, not a call, so check_binary_symbols.sh's header
// scan does not read it as a declared function.
const double kDefaultMaxSpeedMps = HUGE_VAL;
// The jump gate's |dt| floor, so two engines emitting
// ~0.3 s apart (or backwards in GNSS time) cannot turn jitter into a jump.
const double kJumpMinDtS = 1.0;

// Great-circle metres between two (deg, deg) points, in a fixed operation order
// (deg * (pi/180), squares as s * s, h clamped to 1, 2 * R * asin(sqrt(h))) so
// the result is reproducible to the last bit. Exposed so the equivalence
// harness can pin it byte for byte.
double haversine_m(double lat1, double lon1, double lat2, double lon2);

// fix_verdict() with the staleness arm armed. `reference_gnss_ms` nullptr makes
// the arm INERT -- byte-identical to the 2-argument form. Otherwise a record that passes the
// coordinate / placeholder / time gates is declined kStale when
// `*reference_gnss_ms - its own clock > max_fix_age_ms`. Staleness runs LAST:
// a record with no time solution has no meaningful age and keeps reporting
// kNoTimeSolution.
GpsFix fix_verdict(const std::string& payload, Decline* reason,
                   const int64_t* reference_gnss_ms, int64_t max_fix_age_ms);

// The jump anchor: the last ACCEPTED fix's position and own GNSS clock. Only a
// tracker holds one.
struct Anchor {
    double lat_deg;
    double lon_deg;
    int64_t gnss_ms;
};

// The stream-relative freshness reference, one instance per capture source.
//
// judge() is the whole stateful step: read the record's own clock, judge it
// against the newest clock seen BEFORE it, then fold its clock into the
// reference. The reference advances on EVERY record that carries a clock,
// including ones the coordinate gates refuse (a no-position record can still
// carry a perfectly good time solution); it never advances on a record the
// parser refuses or one with gps_week == 0xFFFF.
//
// It also holds the jump anchor, which advances ONLY when a record with
// a clock is accepted, so a declined outlier can never seed it. A bad anchor
// self-heals: dt grows while it stands still.
//
// The warm-up hole is exactly one record wide: the first record with a clock
// defines the reference and cannot be judged. unjudged() COUNTS it rather than
// hiding it.
//
// The fold lives here, in the leg, and not in a caller's C ABI shim: a
// re-assembly of the judge sequence outside the leg is a second copy of the
// decision, free to drift from the one the harness pins.
class FreshnessTracker {
 public:
    explicit FreshnessTracker(int64_t max_fix_age_ms = kDefaultMaxFixAgeMs,
                              double max_speed_mps = kDefaultMaxSpeedMps);

    // Judge one log-code-stripped 0x1476 payload, then fold it in. Same
    // contract as fix_verdict(): *reason (may be nullptr) is kNone iff valid.
    GpsFix judge(const std::string& payload, Decline* reason);

    // Forget the reference and the warm-up count (a source restart).
    void reset();

    bool has_reference() const { return has_newest_; }
    int64_t newest_gnss_ms() const { return newest_; }   // 0 until has_reference()
    uint64_t unjudged() const { return unjudged_; }
    int64_t max_fix_age_ms() const { return max_fix_age_ms_; }
    bool has_anchor() const { return has_anchor_; }
    const Anchor& anchor() const { return anchor_; }   // zeros until has_anchor()
    double max_speed_mps() const { return max_speed_mps_; }

 private:
    int64_t max_fix_age_ms_;
    double max_speed_mps_;
    bool has_newest_;
    int64_t newest_;
    uint64_t unjudged_;
    bool has_anchor_;
    Anchor anchor_;
};

}  // namespace diag_0x1476_gpsfix

#endif  // DIAGSPEC_DIAG_0X1476_GPSFIX_H
