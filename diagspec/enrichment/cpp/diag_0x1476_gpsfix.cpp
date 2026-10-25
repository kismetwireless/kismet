// SPDX-License-Identifier: GPL-2.0-or-later
// 0x1476 gps_fix enrichment leg — see diag_0x1476_gpsfix.h.
//
// Turns the generated Kaitai raw view (diag_0x1476_t) into the single position
// fix the celldiag helper caches as `last_gps` and stamps onto every DIAG cell
// observation — pure C++, the datasource's only source of position.
//
// Output contract, pinned by the equivalence harness over the committed
// diag_0x1476 fixtures in every layout regime:
//   * lat_deg == (lat_rad * 180.0) / pi, EXACTLY that operation order —
//     `lat_rad * 180.0 / pi` evaluated left to right; `rad * (180.0/pi)`
//     would round differently in the last ulp.
//     gnss::rad_to_deg already encodes the order; do not inline a rewrite of it.
//   * the source offsets come from fix_lat_rad()/fix_lon_rad()/fix_alt_m()/
//     fix_gps_week()/fix_gps_tow_ms(), the regime-resolving instances, NOT the
//     seq fields of the same name minus the `fix_` prefix. See the header: the
//     seq models the 291 B `_POS_FMT` regime and the reference modem (SDX62,
//     version=24) is not in it.
//   * accept iff 1 < |lat| < 90 AND 1 < |lon| < 180 AND not a placeholder AND a
//     time solution AND a plausible altitude AND (with a reference) not stale
//     AND (with an anchor) no implausible jump. The |·| > 1 half of that
//     also swallows the (0,0) sentinel, so the explicit (0,0) arm of
//     is_placeholder_position is redundant HERE — it is retained because the
//     predicate is shared with callers that do not pre-gate.
//   * any payload the reference parser rejects yields valid=false, not an
//     exception: a malformed record is a silent no-fix, never a crash.
//
// ROUNDING IS NOT IN THIS CONTRACT. Rounding lat/lon to 6 decimals and alt to 1
// (round-half-to-EVEN over the decimal repr) is presentation, the emitter's job
// at JSON-emit time, not decode; reproducing half-to-even decimal rounding here
// would add a failure mode worth more than the ≤5e-7° (≈5 cm) it controls. This
// leg returns the unrounded full-precision double, and the equivalence harness
// compares pre-rounding values on both sides.

#include "diag_0x1476_gpsfix.h"

#include <cmath>
#include <cstdint>
#include <string>

#include "kaitai/kaitaistream.h"
#include "diag_0x1476.h"
#include "gnss_helpers.h"

namespace diag_0x1476_gpsfix {

bool is_placeholder_position(double lat_deg, double lon_deg) {
    // Qualcomm Nevada default (38.0, -117.0).
    if (std::fabs(lat_deg - 38.0) < 0.5 && std::fabs(lon_deg + 117.0) < 0.5)
        return true;
    // Telit FN980m "no antenna" placeholder (~5.5, ~6.6).
    if (std::fabs(lat_deg - 5.5) < 0.5 && std::fabs(lon_deg - 6.6) < 0.5)
        return true;
    // Generic "value unavailable" sentinel.
    if (lat_deg == 0.0 && lon_deg == 0.0)
        return true;
    return false;
}

namespace {

// The record-level declines: the version allowlist, the per-version
// size rules, and the final `size < kPosSz` gate of the 291 B path. Each one
// refuses the record, so no parse ran and no fix exists, whatever bytes happen to sit where
// the generated reader would look. The census counts such a record DROPPED.
bool layout_refused(const std::string& p) {
    static const uint8_t kVersions[] = {0x02, 0x04, 0x06, 0x07, 0x08, 0x0A,
                                        0x0B, 0x0C, 0x0D, 0x15, 0x18, 0x1A};
    const size_t kPosSz = 291, kPosMdm9600Sz = 797;
    const size_t kPosV13FixedSz = 2477, kPosV13MinSz = 407, kSv30Stride = 30;
    if (p.empty())
        return true;
    const uint8_t v = static_cast<uint8_t>(p[0]);
    bool known = false;
    for (uint8_t k : kVersions)
        known = known || k == v;
    if (!known)
        return true;
    const size_t n = p.size();
    bool compact = false;
    switch (v) {          // per-version size rules
    case 0x04: if (n != 1151) return true; compact = true; break;   // _COMPACT_FIXED_SZ
    case 0x06: if (n != 1175) return true; compact = true; break;
    case 0x0B: if (n != 2244) return true; compact = true; break;
    case 0x0C: if (n != 1895) return true; compact = true; break;
    case 0x02: if (n > kPosSz && n < kPosMdm9600Sz) return true; break;
    case 0x0D: if (n < kPosV13FixedSz) return true; break;
    case 0x07: if (!(n == 2115 || n > 2115 || n == kPosSz)) return true; break;  // _ATTESTED_SZ
    case 0x08: if (!(n == 2229 || n > 2229 || n == kPosSz)) return true; break;
    case 0x0A: if (!(n == 2237 || n == 2325 || n == 2332 || n > 2332)) return true; break;
    case 0x15: if (n < 647 || (n - 647) % kSv30Stride) return true; break;  // _SV30_BASE
    case 0x18:
    case 0x1A: if (n < 1215 || (n - 1215) % kSv30Stride) return true; break;
    default: break;
    }
    if (compact || (v == 0x02 && n == kPosMdm9600Sz) || (v >= 13 && n >= kPosV13MinSz))
        return false;     // the compact / MDM9600 / v13 sub-parsers
    return n < kPosSz;    // the 291 B _POS_FMT path
}

}  // namespace

// GPS week-number "unknown" sentinel: the record has no time solution.
const uint16_t kGpsWeekUnknown = 0xFFFF;

// Every fix field is read through a generated `fix_*()` instance, which
// resolves the layout regime from (version, payload_size). Do not
// hand-roll those offsets here: they would duplicate the .ksy gates.

namespace {

// The double nearest pi (3.141592653589793).
const double kPi = 3.141592653589793;

// One record's fix fields, read ONCE. `parsed` false means the reference parser
// refuses this payload: such a record never reaches the gate, and never folds
// its clock into a freshness reference either.
struct Reading {
    bool parsed;
    double lat_deg;
    double lon_deg;
    double alt_m;
    uint16_t gps_week;
    uint32_t gps_tow_ms;
};

Reading read_record(const std::string& payload) {
    Reading r;
    r.parsed = false;
    r.lat_deg = 0.0;
    r.lon_deg = 0.0;
    r.alt_m = 0.0;
    r.gps_week = 0;
    r.gps_tow_ms = 0;

    if (layout_refused(payload))
        return r;                                   // layout refused -> no parse

    try {
        kaitai::kstream ks(payload);
        diag_0x1476_t rec(&ks);
        // Regime-resolving instances -- see the header's table.
        const double lat_rad = rec.fix_lat_rad();
        const double lon_rad = rec.fix_lon_rad();
        r.alt_m = rec.fix_alt_m();
        // Read here, not at the gates below: the generated instance THROWS on a
        // payload too short to hold it rather than returning a sentinel. Either
        // way the result is "no fix". week and tow precede lat in every regime
        // (B < B+2 < B+17), so this cannot actually throw once lat parsed, but
        // keeping it inside the try means the equivalence does not rest on that
        // ordering holding forever.
        r.gps_week = rec.fix_gps_week();
        r.gps_tow_ms = rec.fix_gps_tow_ms();
        // The mdm9600 regime's structural guard: a 797 B v2 record with an
        // implausible clock or out-of-range radians is refused outright ("no
        // record"). Without it this leg would accept -- and fold the clock of --
        // a record that is not a fix at all. The comparisons are written so a
        // NaN fails them, as a chained `lo <= x <= hi` does.
        if (rec.is_mdm9600()) {
            const bool time_ok = 0 < r.gps_week && r.gps_tow_ms < 604800000u;
            const bool pos_ok = -kPi / 2 <= lat_rad && lat_rad <= kPi / 2 &&
                                -kPi <= lon_rad && lon_rad <= kPi;
            if (!(time_ok && pos_ok))
                return r;
        }
        r.lat_deg = diagspec::gnss::rad_to_deg(lat_rad);
        r.lon_deg = diagspec::gnss::rad_to_deg(lon_rad);
    } catch (...) {
        // Short/truncated/unparseable payload -> no fix, never an exception
        // out of the leg.
        return r;
    }
    r.parsed = true;
    return r;
}

// The record's own GNSS clock over one Reading: no clock for a refused
// record or the 0xFFFF "no time solution" week.
bool time_of(const Reading& r, int64_t* out_ms) {
    if (!r.parsed || r.gps_week == kGpsWeekUnknown)
        return false;
    *out_ms = static_cast<int64_t>(r.gps_week) * kMsPerGpsWeek +
              static_cast<int64_t>(r.gps_tow_ms);
    return true;
}

// The gate sequence, written ONCE for both fix_verdict() and
// FreshnessTracker::judge(). `reference_gnss_ms` nullptr keeps the staleness
// arm inert; `anchor` nullptr keeps the jump arm inert.
GpsFix verdict_of(const Reading& rd, Decline* reason,
                  const int64_t* reference_gnss_ms, int64_t max_fix_age_ms,
                  const Anchor* anchor, double max_speed_mps) {
    // A local so the gate arms below can `return` without every one having to
    // remember to write through the pointer; the single exit stamps it once.
    Decline why = Decline::kNone;
    GpsFix out;
    out.valid = false;
    out.lat_deg = 0.0;
    out.lon_deg = 0.0;
    out.alt_m = 0.0;

    if (!rd.parsed) {
        if (reason) *reason = Decline::kUnparseable;
        return out;
    }
    out.alt_m = rd.alt_m;
    const double lat = rd.lat_deg;
    const double lon = rd.lon_deg;
    const uint16_t gps_week = rd.gps_week;
    int64_t own_ms = 0;
    const bool has_clock = time_of(rd, &own_ms);

    // Gate order is load-bearing and mirrors gps_gate_verdict exactly:
    // coordinate plausibility, then placeholder, then time solution, then
    // altitude, then staleness, then jump. A seed position passes the coordinate gates (that is why the
    // time gate exists), so reordering would relabel every kNoTimeSolution as
    // something else.

    // Coordinate validity gate: plausible degrees, and > 1 in magnitude so the
    // (0,0) "unavailable" sentinel cannot pass as a real equatorial fix.
    if (!(1.0 < std::fabs(lat) && std::fabs(lat) < 90.0) ||
        !(1.0 < std::fabs(lon) && std::fabs(lon) < 180.0))
        why = Decline::kNoPosition;
    else if (is_placeholder_position(lat, lon))
        why = Decline::kPlaceholder;
    // Time-solution gate. A seed position presents as perfectly
    // plausible degrees, so none of the coordinate gates above can see it —
    // only the absence of a time solution can.
    else if (gps_week == kGpsWeekUnknown)
        why = Decline::kNoTimeSolution;
    // Altitude band. Written so a NaN fails, as a chained `<=`
    // does: `!(a >= lo && a <= hi)`, never `a < lo || a > hi`.
    else if (!(rd.alt_m >= kMinPlausibleAltM && rd.alt_m <= kMaxPlausibleAltM))
        why = Decline::kAltitude;
    // Staleness gate, LAST: a record with no time solution has no
    // meaningful age and must keep reporting kNoTimeSolution. Signed: a record
    // NEWER than the reference (the normal case in a live stream) has a
    // negative age and is never stale.
    else if (reference_gnss_ms != nullptr && has_clock &&
             *reference_gnss_ms - own_ms > max_fix_age_ms)
        why = Decline::kStale;
    // Jump gate, after staleness: a re-served old fix is the stale
    // finding. dt is |own - anchor| in seconds, floored --
    // `max(abs(own - a_ms) / 1000.0, 1.0)`, int64 difference converted once.
    else if (anchor != nullptr && has_clock) {
        const int64_t d_ms = own_ms - anchor->gnss_ms;
        double dt_s = static_cast<double>(d_ms < 0 ? -d_ms : d_ms) / 1000.0;
        if (dt_s < kJumpMinDtS)
            dt_s = kJumpMinDtS;
        if (haversine_m(anchor->lat_deg, anchor->lon_deg, lat, lon) / dt_s >
            max_speed_mps)
            why = Decline::kJump;
    }

    if (why == Decline::kNone) {
        out.valid = true;
        out.lat_deg = lat;
        out.lon_deg = lon;
    }
    if (reason) *reason = why;
    return out;
}

}  // namespace

double haversine_m(double lat1, double lon1, double lat2, double lon2) {
    const double kEarthRadiusM = 6371000.0;
    const double kDegToRad = kPi / 180.0;
    const double p1 = lat1 * kDegToRad;
    const double p2 = lat2 * kDegToRad;
    const double s_lat = std::sin((lat2 - lat1) * kDegToRad / 2.0);
    const double s_lon = std::sin((lon2 - lon1) * kDegToRad / 2.0);
    double h = s_lat * s_lat + std::cos(p1) * std::cos(p2) * s_lon * s_lon;
    if (h > 1.0)
        h = 1.0;
    return 2.0 * kEarthRadiusM * std::asin(std::sqrt(h));
}

const char* decline_name(Decline why) {
    switch (why) {
    case Decline::kNone:           return nullptr;
    case Decline::kUnparseable:    return "unparseable";
    case Decline::kNoPosition:     return "no_position";
    case Decline::kPlaceholder:    return "placeholder_position";
    case Decline::kNoTimeSolution: return "no_time_solution";
    case Decline::kStale:          return "stale_fix";
    case Decline::kAltitude:       return "implausible_altitude";
    case Decline::kJump:           return "implausible_jump";
    }
    return nullptr;
}

GpsFix fix_verdict(const std::string& payload, Decline* reason,
                   const int64_t* reference_gnss_ms, int64_t max_fix_age_ms) {
    return verdict_of(read_record(payload), reason, reference_gnss_ms,
                      max_fix_age_ms, nullptr, kDefaultMaxSpeedMps);
}

GpsFix fix_verdict(const std::string& payload, Decline* reason) {
    // No reference: the staleness arm is inert, so this is byte-identical to the
    // three-gate leg that preceded the staleness gate.
    return fix_verdict(payload, reason, nullptr, kDefaultMaxFixAgeMs);
}

GpsFix fix(const std::string& payload) {
    // The value-only entry point the equivalence harness pins: identical
    // return to fix_verdict(), the reason discarded.
    Decline ignored;
    return fix_verdict(payload, &ignored);
}

bool gps_time_ms(const std::string& payload, int64_t* out_ms) {
    int64_t t = 0;
    if (!time_of(read_record(payload), &t))
        return false;
    if (out_ms) *out_ms = t;
    return true;
}

FreshnessTracker::FreshnessTracker(int64_t max_fix_age_ms,
                                   double max_speed_mps)
    : max_fix_age_ms_(max_fix_age_ms), max_speed_mps_(max_speed_mps),
      has_newest_(false), newest_(0), unjudged_(0), has_anchor_(false) {
    anchor_.lat_deg = 0.0;
    anchor_.lon_deg = 0.0;
    anchor_.gnss_ms = 0;
}

void FreshnessTracker::reset() {
    has_newest_ = false;
    newest_ = 0;
    unjudged_ = 0;
    has_anchor_ = false;
    anchor_.lat_deg = 0.0;
    anchor_.lon_deg = 0.0;
    anchor_.gnss_ms = 0;
}

GpsFix FreshnessTracker::judge(const std::string& payload, Decline* reason) {
    // GnssFreshnessTracker.judge, step for step, on ONE parse of the record:
    // count the warm-up hole, judge against the reference as it stood BEFORE
    // this record, then fold this record's clock in -- whatever the gates said,
    // so a no-position record with a good clock still moves the reference.
    const Reading rd = read_record(payload);
    int64_t own_ms = 0;
    const bool has_clock = time_of(rd, &own_ms);
    if (!has_newest_ && has_clock)
        ++unjudged_;
    GpsFix f = verdict_of(rd, reason, has_newest_ ? &newest_ : nullptr,
                          max_fix_age_ms_, has_anchor_ ? &anchor_ : nullptr,
                          max_speed_mps_);
    if (has_clock && (!has_newest_ || own_ms > newest_)) {
        newest_ = own_ms;
        has_newest_ = true;
    }
    // The anchor moves only on an accepted fix with a clock.
    if (has_clock && f.valid) {
        anchor_.lat_deg = f.lat_deg;
        anchor_.lon_deg = f.lon_deg;
        anchor_.gnss_ms = own_ms;
        has_anchor_ = true;
    }
    return f;
}

}  // namespace diag_0x1476_gpsfix
