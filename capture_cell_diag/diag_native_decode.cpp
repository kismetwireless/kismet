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

    C-callable shim over the diagspec cell_observation legs -- see
    diag_native_decode.h for why it lives in the helper rather than the server.

    This file contains NO decode logic. Every branch forwards to the diagspec
    leg, so there is exactly one implementation per log code and no second copy
    to drift.
*/

#include "diag_native_decode.h"

#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <new>
#include <string>
#include <utility>
#include <vector>

#include "diag_0x512f_observation.h"
#include "diag_0xb192_observation.h"
#include "diag_0xb195_observation.h"
#include "diag_0xb0c0_observation.h"
#include "diag_0xb97f_observation.h"
#include "diag_0xb193_observation.h"
#include "diag_0xb17f_observation.h"
#include "diag_0xb821_identity.h"
#include "diag_0xb821_observation.h"
#include "diag_0x1476_gpsfix.h"
#include "lte_meas_join.h"
#include "lte_band.h"
#include "lte_cell_config.h"
#include "diag_0xb0c0_gsmtap.h"
#include "diag_0xb0e1_gsmtap.h"
#include "diag_0xb0e2_gsmtap.h"
#include "diag_0xb0e3_gsmtap.h"
#include "diag_0xb0ec_gsmtap.h"
#include "diag_0xb0ed_gsmtap.h"

namespace {

const uint16_t kNativeCodes[] = {0x512F, 0xB192, 0xB195, 0xB0C0, 0xB97F, 0xB193, 0xB17F, 0xB821};

// Identity sources. 0xB821 is in both sets: it seeds the sib1_map (SIB1
// identity, MIB scs) AND, for a UL-DCCH MeasurementReport, emits one NR
// serving row.
const uint16_t kIdentityCodes[] = {0xB0C0, 0xB821};

// GNSS codes are a SEPARATE set, not an extension of kNativeCodes: they feed a
// different entry point with a different output type. 0x14D8 is deliberately
// absent -- see diag_native_decode.h.
const uint16_t kNativeGpsCodes[] = {0x1476};

// Zero a slot and set the fields every code shares, so a leg only has to fill in
// what it actually carries and an unset optional can never read as populated.
void init_obs(diag_native_obs_t *o, const char *rat, uint16_t log_code) {
    std::memset(o, 0, sizeof(*o));
    o->rat = rat;
    o->log_code = log_code;
}

void copy_plmn_field(char *dst, size_t dst_sz, const std::string& src) {
    // Truncate rather than overflow; MCC is 3 digits and MNC 2-3, so the 8-byte
    // buffers are ample and this is a belt-and-braces bound, not an expected path.
    const size_t n = src.size() < dst_sz - 1 ? src.size() : dst_sz - 1;
    std::memcpy(dst, src.data(), n);
    dst[n] = '\0';
}

// One cached SIB1 identity.
struct Sib1Identity {
    std::string mcc;
    std::string mnc;
    uint32_t tac = 0;
    uint64_t cell_id = 0;
};

}  // namespace

// The opaque type the C header forward-declares. A std::map keyed by the
// (pci, earfcn) pair -- see the header on why the RAT is NOT part of the key.
struct diag_native_sib1_map {
    std::map<std::pair<int32_t, int32_t>, Sib1Identity> by_pci_earfcn;
    // The measId -> EARFCN measConfig state, with the map's per-source lifetime.
    lte_meas_join::State lte_meas;
    // The 0xB197 cell-config cache, with the same lifetime.
    lte_cell_config::State lte_cfg;
    // The NR MIB SSB subcarrier spacing, keyed (pci, arfcn), read back onto NR
    // rows of that cell.
    std::map<std::pair<int32_t, int32_t>, int32_t> nr_scs;
    // The NR SIB1 cell config, keyed (pci, arfcn), read back onto NR rows of
    // that cell.
    std::map<std::pair<int32_t, int32_t>, diag_0xb821_identity::CellConfig> nr_cfg;
};

extern "C" bool diag_native_has_leg(uint16_t log_code) {
    for (uint16_t c : kNativeCodes)
        if (c == log_code)
            return true;
    return false;
}

extern "C" size_t diag_native_codes(uint16_t *out_codes, size_t max_codes) {
    const size_t n = sizeof(kNativeCodes) / sizeof(kNativeCodes[0]);
    const size_t w = n < max_codes ? n : max_codes;
    for (size_t i = 0; i < w; i++)
        out_codes[i] = kNativeCodes[i];
    return n;
}

extern "C" size_t diag_native_gps_codes(uint16_t *out_codes, size_t max_codes) {
    const size_t n = sizeof(kNativeGpsCodes) / sizeof(kNativeGpsCodes[0]);
    const size_t w = n < max_codes ? n : max_codes;
    for (size_t i = 0; i < w; i++)
        out_codes[i] = kNativeGpsCodes[i];
    return n;
}

extern "C" int diag_native_decode(uint16_t log_code, const uint8_t *payload,
        size_t payload_len, diag_native_obs_t *out_obs, size_t max_obs) {
    return diag_native_decode_ex(log_code, payload, payload_len, out_obs, max_obs,
                                 nullptr);
}

extern "C" int diag_native_decode_ex(uint16_t log_code, const uint8_t *payload,
        size_t payload_len, diag_native_obs_t *out_obs, size_t max_obs,
        bool *refused) {
    if (refused != nullptr)
        *refused = false;
    if (out_obs == nullptr || max_obs == 0)
        return -1;
    if (!diag_native_has_leg(log_code))
        return -1;                       // no leg for this code
    if (payload == nullptr)
        return 0;

    const std::string blob(reinterpret_cast<const char *>(payload), payload_len);
    size_t n = 0;

    // A leg is not expected to throw -- each one already guards its own record
    // -- but this shim is the C/C++ boundary, and an exception escaping into a C
    // caller is undefined behaviour, not a caught error. Contain it here.
    try {
        switch (log_code) {
            case 0x512F: {
                // GSM System Information Type 3 -> one identity, never serving.
                // has_identity is set, as on 0xB0C0's own SIB1 cell, so the
                // cross-record SIB1 enrich skips the row (it is rendered
                // unenriched); lte_cell_config is LTE-only.
                diag_0x512f_observation::Decline why;
                auto cells = diag_0x512f_observation::observations(blob, &why);
                if (refused != nullptr)
                    *refused = diag_0x512f_observation::is_refusal(why);
                for (const auto& c : cells) {
                    if (n >= max_obs) break;
                    init_obs(&out_obs[n], "GSM", 0x512F);
                    out_obs[n].has_identity = true;
                    std::snprintf(out_obs[n].mcc, sizeof(out_obs[n].mcc), "%s", c.mcc.c_str());
                    std::snprintf(out_obs[n].mnc, sizeof(out_obs[n].mnc), "%s", c.mnc.c_str());
                    out_obs[n].tac = static_cast<uint32_t>(c.lac);
                    out_obs[n].cell_id = static_cast<uint64_t>(c.cell_id);
                    out_obs[n].is_serving = false;
                    n++;
                }
                break;
            }
            case 0xB192: {
                diag_0xb192_observation::Decline why;
                auto cells = diag_0xb192_observation::observations(blob, &why);
                if (refused != nullptr)
                    *refused = diag_0xb192_observation::is_refusal(why);
                for (const auto& c : cells) {
                    if (n >= max_obs) break;
                    init_obs(&out_obs[n], "LTE", 0xB192);
                    out_obs[n].pci = c.pci;
                    out_obs[n].earfcn = c.earfcn;
                    n++;
                }
                break;
            }
            case 0xB195: {
                diag_0xb195_observation::Decline why;
                auto cells = diag_0xb195_observation::observations(blob, &why);
                if (refused != nullptr)
                    *refused = diag_0xb195_observation::is_refusal(why);
                for (const auto& c : cells) {
                    if (n >= max_obs) break;
                    init_obs(&out_obs[n], "LTE", 0xB195);
                    out_obs[n].pci = c.pci;
                    out_obs[n].earfcn = c.earfcn;
                    n++;
                }
                break;
            }
            case 0xB0C0: {
                diag_0xb0c0_observation::Decline why;
                auto cells = diag_0xb0c0_observation::observations(blob, &why);
                if (refused != nullptr)
                    *refused = diag_0xb0c0_observation::is_refusal(why);
                for (const auto& c : cells) {
                    if (n >= max_obs) break;
                    init_obs(&out_obs[n], "LTE", 0xB0C0);
                    out_obs[n].pci = c.pci;
                    out_obs[n].earfcn = c.earfcn;
                    out_obs[n].has_identity = true;
                    copy_plmn_field(out_obs[n].mcc, sizeof(out_obs[n].mcc), c.mcc);
                    copy_plmn_field(out_obs[n].mnc, sizeof(out_obs[n].mnc), c.mnc);
                    out_obs[n].tac = c.tac;
                    out_obs[n].cell_id = c.cell_id;
                    out_obs[n].has_access_flags = true;
                    out_obs[n].cell_barred = c.cell_barred;
                    out_obs[n].csg = c.csg_indication;
                    out_obs[n].n_plmns = 0;
                    for (const auto& pl : c.plmns) {
                        if (out_obs[n].n_plmns >= 6) break;   // SIZE (1..6)
                        const int k = out_obs[n].n_plmns++;
                        copy_plmn_field(out_obs[n].plmn_mcc[k], sizeof(out_obs[n].plmn_mcc[k]), pl.first);
                        copy_plmn_field(out_obs[n].plmn_mnc[k], sizeof(out_obs[n].plmn_mnc[k]), pl.second);
                    }
                    n++;
                }
                break;
            }
            case 0xB821: {
                // One NR serving row per UL-DCCH
                // MeasurementReport, signal from the report itself.
                diag_0xb821_observation::Decline why;
                const auto cells = diag_0xb821_observation::observations(blob, &why);
                if (refused != nullptr)
                    *refused = diag_0xb821_observation::is_refusal(why);
                for (const auto& c : cells) {
                    if (n >= max_obs) break;
                    init_obs(&out_obs[n], "NR", 0xB821);
                    out_obs[n].pci = c.pci;
                    out_obs[n].earfcn = c.arfcn;
                    out_obs[n].is_serving = true;
                    out_obs[n].has_rsrp = c.has_rsrp;
                    out_obs[n].rsrp = c.rsrp;
                    out_obs[n].has_rsrq = c.has_rsrq;
                    out_obs[n].rsrq = c.rsrq;
                    out_obs[n].has_sinr = c.has_sinr;
                    out_obs[n].sinr = c.sinr;
                    n++;
                }
                break;
            }
            case 0xB97F: {
                diag_0xb97f_observation::Decline why;
                auto cells = diag_0xb97f_observation::observations(blob, &why);
                if (refused != nullptr)
                    *refused = diag_0xb97f_observation::is_refusal(why);
                for (const auto& c : cells) {
                    if (n >= max_obs) break;
                    init_obs(&out_obs[n], "NR", 0xB97F);
                    out_obs[n].pci = c.pci;
                    out_obs[n].earfcn = c.earfcn;
                    out_obs[n].is_serving = c.is_serving;
                    out_obs[n].has_rsrp = c.has_rsrp;
                    out_obs[n].rsrp = c.rsrp;
                    out_obs[n].has_rsrq = c.has_rsrq;
                    out_obs[n].rsrq = c.rsrq;
                    // The beam + serving SSB keys.
                    out_obs[n].has_beam = c.has_beam;
                    out_obs[n].beam_ssb_index = c.beam.ssb_index;
                    out_obs[n].has_beam_rsrp_a = c.beam.has_rsrp_a;
                    out_obs[n].beam_rsrp_a = c.beam.rsrp_a;
                    out_obs[n].has_beam_rsrp_b = c.beam.has_rsrp_b;
                    out_obs[n].beam_rsrp_b = c.beam.rsrp_b;
                    out_obs[n].has_beam_rsrq_a = c.beam.has_rsrq_a;
                    out_obs[n].beam_rsrq_a = c.beam.rsrq_a;
                    out_obs[n].has_beam_rsrq_b = c.beam.has_rsrq_b;
                    out_obs[n].beam_rsrq_b = c.beam.rsrq_b;
                    out_obs[n].has_serving_ssb_index = c.has_serving_ssb_index;
                    out_obs[n].serving_ssb_index = c.serving_ssb_index;
                    out_obs[n].has_ssb_periodicity_ms = c.has_ssb_periodicity_ms;
                    out_obs[n].ssb_periodicity_ms = c.ssb_periodicity_ms;
                    n++;
                }
                break;
            }
            case 0xB193: {
                // 0xB193's rsrp/rsrq are ABSENT far more often than present --
                // the v22/v35/v36 scales are unknown, v3/v18 are undecoded, v48
                // is decoded single-cell only, v59 serving-cell only -- so the
                // has_* flags here are load-bearing rather than a formality: a
                // consumer treating rsrp==0.0 as a reading would put roughly half
                // of all LTE serving-cell observations at a fabricated 0 dBm.
                diag_0xb193_observation::Decline why;
                auto cells = diag_0xb193_observation::observations(blob, &why);
                if (refused != nullptr)
                    *refused = diag_0xb193_observation::is_refusal(why);
                for (const auto& c : cells) {
                    if (n >= max_obs) break;
                    init_obs(&out_obs[n], "LTE", 0xB193);
                    out_obs[n].pci = c.pci;
                    out_obs[n].earfcn = c.earfcn;
                    out_obs[n].is_serving = c.is_serving;
                    out_obs[n].has_rsrp = c.has_rsrp;
                    out_obs[n].rsrp = c.rsrp;
                    out_obs[n].has_rsrq = c.has_rsrq;
                    out_obs[n].rsrq = c.rsrq;
                    n++;
                }
                break;
            }
            case 0xB17F: {
                // One record IS one cell: identity plus rsrp/rsrq/rssi
                // for serving AND neighbour cells, with no serving flag -- so
                // is_serving stays false.
                diag_0xb17f_observation::Decline why;
                auto cells = diag_0xb17f_observation::observations(blob, &why);
                if (refused != nullptr)
                    *refused = diag_0xb17f_observation::is_refusal(why);
                for (const auto& c : cells) {
                    if (n >= max_obs) break;
                    init_obs(&out_obs[n], "LTE", 0xB17F);
                    out_obs[n].pci = c.pci;
                    out_obs[n].earfcn = c.earfcn;
                    out_obs[n].has_rsrp = c.has_rsrp;
                    out_obs[n].rsrp = c.rsrp;
                    out_obs[n].has_rsrq = c.has_rsrq;
                    out_obs[n].rsrq = c.rsrq;
                    out_obs[n].has_rssi = c.has_rssi;
                    out_obs[n].rssi = c.rssi;
                    n++;
                }
                break;
            }
            default:
                return -1;
        }
    } catch (...) {
        return 0;                        // malformed record -> no observations
    }

    return static_cast<int>(n);
}

extern "C" bool diag_native_has_gps_leg(uint16_t log_code) {
    for (uint16_t c : kNativeGpsCodes)
        if (c == log_code)
            return true;
    return false;
}

// Translate the leg's C++ Decline enum to the C ABI enum the tap counts on.
// One-to-one by construction -- kept as an explicit switch (not a cast) so a
// future member added to one enum but not the other fails to compile here rather
// than silently mis-counting.
static diag_native_gps_decline_t map_decline(diag_0x1476_gpsfix::Decline why) {
    switch (why) {
        case diag_0x1476_gpsfix::Decline::kNone:
            return DIAG_NATIVE_GPS_DECLINE_NONE;
        case diag_0x1476_gpsfix::Decline::kUnparseable:
            return DIAG_NATIVE_GPS_DECLINE_UNPARSEABLE;
        case diag_0x1476_gpsfix::Decline::kNoPosition:
            return DIAG_NATIVE_GPS_DECLINE_NO_POSITION;
        case diag_0x1476_gpsfix::Decline::kPlaceholder:
            return DIAG_NATIVE_GPS_DECLINE_PLACEHOLDER;
        case diag_0x1476_gpsfix::Decline::kNoTimeSolution:
            return DIAG_NATIVE_GPS_DECLINE_NO_TIME;
        case diag_0x1476_gpsfix::Decline::kStale:
            return DIAG_NATIVE_GPS_DECLINE_STALE;
        case diag_0x1476_gpsfix::Decline::kAltitude:
            return DIAG_NATIVE_GPS_DECLINE_ALTITUDE;
        case diag_0x1476_gpsfix::Decline::kJump:
            return DIAG_NATIVE_GPS_DECLINE_JUMP;
    }
    return DIAG_NATIVE_GPS_DECLINE_NONE;  // unreachable; keeps -Werror happy
}

// The inverse, for diag_native_gps_decline_name: the NAME is the leg's
// (diag_0x1476_gpsfix::decline_name), never restated here.
static diag_0x1476_gpsfix::Decline to_leg_decline(diag_native_gps_decline_t why) {
    switch (why) {
        case DIAG_NATIVE_GPS_DECLINE_NONE:
            return diag_0x1476_gpsfix::Decline::kNone;
        case DIAG_NATIVE_GPS_DECLINE_UNPARSEABLE:
            return diag_0x1476_gpsfix::Decline::kUnparseable;
        case DIAG_NATIVE_GPS_DECLINE_NO_POSITION:
            return diag_0x1476_gpsfix::Decline::kNoPosition;
        case DIAG_NATIVE_GPS_DECLINE_PLACEHOLDER:
            return diag_0x1476_gpsfix::Decline::kPlaceholder;
        case DIAG_NATIVE_GPS_DECLINE_NO_TIME:
            return diag_0x1476_gpsfix::Decline::kNoTimeSolution;
        case DIAG_NATIVE_GPS_DECLINE_STALE:
            return diag_0x1476_gpsfix::Decline::kStale;
        case DIAG_NATIVE_GPS_DECLINE_ALTITUDE:
            return diag_0x1476_gpsfix::Decline::kAltitude;
        case DIAG_NATIVE_GPS_DECLINE_JUMP:
            return diag_0x1476_gpsfix::Decline::kJump;
    }
    return diag_0x1476_gpsfix::Decline::kNone;
}

extern "C" const char *diag_native_gps_decline_name(diag_native_gps_decline_t reason) {
    return diag_0x1476_gpsfix::decline_name(to_leg_decline(reason));
}

/* ---- GNSS freshness ------------------------------------------------------ */

// The opaque type the C header forward-declares: the leg's tracker, whole. The
// fold lives in the leg; a copy of
// it here would be a re-assembled decision that drifts from the leg's.
struct diag_native_gnss_tracker {
    diag_0x1476_gpsfix::FreshnessTracker leg;
    explicit diag_native_gnss_tracker(int64_t max_fix_age_ms) : leg(max_fix_age_ms) {}
};

extern "C" int64_t diag_native_gnss_default_max_fix_age_ms(void) {
    return diag_0x1476_gpsfix::kDefaultMaxFixAgeMs;
}

extern "C" diag_native_gnss_tracker_t *diag_native_gnss_tracker_new(int64_t max_fix_age_ms) {
    // nothrow, as diag_native_sib1_map_new: the helper treats NULL as "gate
    // unavailable" and keeps capturing rather than dying mid-wardrive.
    return new (std::nothrow) diag_native_gnss_tracker(max_fix_age_ms);
}

extern "C" void diag_native_gnss_tracker_free(diag_native_gnss_tracker_t *tracker) {
    delete tracker;
}

extern "C" void diag_native_gnss_tracker_reset(diag_native_gnss_tracker_t *tracker) {
    if (tracker != nullptr)
        tracker->leg.reset();
}

extern "C" uint64_t diag_native_gnss_tracker_unjudged(const diag_native_gnss_tracker_t *tracker) {
    return tracker == nullptr ? 0 : tracker->leg.unjudged();
}

extern "C" int diag_native_decode_gps_fix(diag_native_gnss_tracker_t *tracker,
        uint16_t log_code, const uint8_t *payload,
        size_t payload_len, diag_native_gps_fix_t *out_fix) {
    if (out_fix == nullptr)
        return -1;
    // Written before any early return, so a caller that ignores the return value
    // still reads a well-defined "no fix" rather than whatever was on its stack.
    out_fix->valid = false;
    out_fix->lat_deg = 0.0;
    out_fix->lon_deg = 0.0;
    out_fix->alt_m = 0.0;
    out_fix->decline_reason = DIAG_NATIVE_GPS_DECLINE_NONE;

    if (!diag_native_has_gps_leg(log_code))
        return -1;                       // no leg for this code
    if (payload == nullptr) {
        out_fix->decline_reason = DIAG_NATIVE_GPS_DECLINE_UNPARSEABLE;
        return 0;
    }

    const std::string blob(reinterpret_cast<const char *>(payload), payload_len);

    // Same C/C++ boundary containment as diag_native_decode: the leg already
    // guards its own record, but an exception escaping into a C caller is
    // undefined behaviour, not a caught error. The leg also tells us WHICH gate
    // refused, so the tap can split its decline counter per reason instead of
    // collapsing five findings -- two of them opposite -- into one. With a
    // tracker the record is judged against the stream's freshness reference and
    // folded into it; without one the staleness gate is inert.
    try {
        diag_0x1476_gpsfix::Decline why = diag_0x1476_gpsfix::Decline::kNone;
        diag_0x1476_gpsfix::GpsFix f = tracker != nullptr
            ? tracker->leg.judge(blob, &why)
            : diag_0x1476_gpsfix::fix_verdict(blob, &why);
        if (!f.valid) {
            out_fix->decline_reason = map_decline(why);
            return 0;
        }
        out_fix->valid = true;
        out_fix->lat_deg = f.lat_deg;
        out_fix->lon_deg = f.lon_deg;
        out_fix->alt_m = f.alt_m;
    } catch (...) {
        out_fix->valid = false;
        out_fix->decline_reason = DIAG_NATIVE_GPS_DECLINE_UNPARSEABLE;
        return 0;                        // malformed record -> no fix
    }

    return 1;
}

/* ---- Cross-record SIB1 enrichment ---------------------------------------- */

extern "C" bool diag_native_is_identity_source(uint16_t log_code) {
    for (uint16_t c : kIdentityCodes)
        if (c == log_code)
            return true;
    return false;
}

extern "C" diag_native_sib1_map_t *diag_native_sib1_map_new(void) {
    // nothrow: the helper treats a NULL map as "enrichment unavailable" and
    // keeps capturing, rather than dying on an allocation failure mid-wardrive.
    return new (std::nothrow) diag_native_sib1_map();
}

extern "C" void diag_native_sib1_map_free(diag_native_sib1_map_t *map) {
    delete map;
}

extern "C" size_t diag_native_sib1_map_size(const diag_native_sib1_map_t *map) {
    return map == nullptr ? 0 : map->by_pci_earfcn.size();
}

extern "C" int diag_native_sib1_learn(diag_native_sib1_map_t *map,
        uint16_t log_code, const uint8_t *payload, size_t payload_len) {
    if (!diag_native_is_identity_source(log_code))
        return -1;                       // not an identity source
    if (map == nullptr || payload == nullptr)
        return 0;

    const std::string blob(reinterpret_cast<const char *>(payload), payload_len);

    // Same C/C++ boundary containment as the decode entry points: an exception
    // escaping into a C caller is undefined behaviour, not a caught error.
    try {
        std::pair<int32_t, int32_t> key;
        Sib1Identity ident;

        if (log_code == 0xB0C0) {
            // measConfig state first, for EVERY 0xB0C0 record: the
            // release / setup / handover messages that invalidate it carry no
            // SIB1, so it must not sit behind the SIB1 gate below.
            lte_meas_join::update(map->lte_meas, blob);

            // Reuse the EXISTING 0xB0C0 observation leg rather than adding a
            // second decode of the same record. Its emit gate is already
            // the identity condition: the leg emits an observation exactly when
            // the SIB1 cell-access decode succeeds with a non-empty PLMN list,
            // which is when there is an identity to learn. A
            // separate LTE identity leg would be a second implementation to
            // drift -- the thing this shim's header exists to forbid.
            auto cells = diag_0xb0c0_observation::observations(blob);
            if (cells.empty())
                return 0;
            const auto& c = cells.front();
            key = std::make_pair(c.pci, c.earfcn);
            ident.mcc = c.mcc;
            ident.mnc = c.mnc;
            ident.tac = c.tac;
            ident.cell_id = c.cell_id;
        } else {
            // The MIB scs cache first, for EVERY 0xB821 record: the MIB rides on
            // records that carry no SIB1, so the scs key is written before the
            // SIB1 gate. emplace: first write wins.
            const diag_0xb821_identity::CellScs s = diag_0xb821_identity::mib_scs(blob);
            if (s.valid)
                map->nr_scs.emplace(std::make_pair(s.pci, s.arfcn), s.scs_khz);

            diag_0xb821_identity::CellIdentity c =
                diag_0xb821_identity::identity(blob);
            if (!c.valid)
                return 0;
            key = std::make_pair(c.pci, c.arfcn);
            // The SIB1 cell config, behind the same SIB1 gate as the identity
            // but before its first-write-wins return: it is written whether or
            // not the identity key is taken. One snapshot per SIB1, first write
            // wins (emplace),
            // and nothing for a SIB1 that reached none of the fields.
            if (c.config.valid)
                map->nr_cfg.emplace(key, c.config);
            ident.mcc = c.mcc;
            ident.mnc = c.mnc;
            ident.tac = c.tac;
            ident.cell_id = c.cell_id;
        }

        // First write wins -- SIB1 identity for a cell does not change within a
        // camp, so the first decode is kept and later ones are skipped. NB
        // emplace() is the
        // first-write-wins primitive; operator[] would be last-write-wins.
        return map->by_pci_earfcn.emplace(key, ident).second ? 1 : 0;
    } catch (...) {
        return 0;                        // malformed record -> nothing learned
    }
}

extern "C" bool diag_native_sib1_enrich(const diag_native_sib1_map_t *map,
        diag_native_obs_t *obs) {
    if (map == nullptr || obs == nullptr)
        return false;
    // The NR scs: independent of the identity outcome, NR rows only, and keyed
    // (pci, earfcn) in its own namespace so it cannot leak onto an LTE row whose
    // (pci, earfcn) collides with an NR cell's (pci, arfcn).
    if (obs->rat != nullptr && std::strcmp(obs->rat, "NR") == 0 && !obs->earfcn_absent) {
        auto s = map->nr_scs.find(std::make_pair(obs->pci, obs->earfcn));
        if (s != map->nr_scs.end()) {
            obs->has_scs = true;
            obs->scs = s->second;
        }
        // add_nr_cell_config: the same footing, its own namespace. A field the
        // SIB1 walk did not reach is kAbsent in the cache and stays unset.
        auto c = map->nr_cfg.find(std::make_pair(obs->pci, obs->earfcn));
        if (c != map->nr_cfg.end()) {
            const diag_0xb821_identity::CellConfig& cfg = c->second;
            const int absent = diag_0xb821_identity::kAbsent;
            obs->has_nr_band = cfg.band != absent;
            obs->nr_band = cfg.band;
            obs->has_nr_carrier_scs = cfg.carrier_scs_khz != absent;
            obs->nr_carrier_scs = cfg.carrier_scs_khz;
            obs->has_nr_bandwidth_rb = cfg.bandwidth_rb != absent;
            obs->nr_bandwidth_rb = cfg.bandwidth_rb;
            obs->has_nr_bandwidth = cfg.bandwidth_mhz != absent;
            obs->nr_bandwidth = cfg.bandwidth_mhz;
        }
    }
    // See the header: only MEASUREMENT rows are enriched, never 0xB0C0's
    // self-emitted identity cell. has_identity is set by that leg alone, so
    // this test is exactly that rule.
    if (obs->has_identity)
        return false;

    if (obs->earfcn_absent)
        return false;                    // nothing to key on (a CGI row anyway)

    auto it = map->by_pci_earfcn.find(std::make_pair(obs->pci, obs->earfcn));
    if (it == map->by_pci_earfcn.end())
        return false;

    obs->has_identity = true;
    copy_plmn_field(obs->mcc, sizeof(obs->mcc), it->second.mcc);
    copy_plmn_field(obs->mnc, sizeof(obs->mnc), it->second.mnc);
    obs->tac = it->second.tac;
    obs->cell_id = it->second.cell_id;
    return true;
}

extern "C" int diag_native_cell_config_learn(diag_native_sib1_map_t *map,
        uint16_t log_code, const uint8_t *payload, size_t payload_len) {
    if (log_code != 0xB197)
        return -1;
    if (map == nullptr || payload == nullptr)
        return 0;
    try {
        const std::string blob(reinterpret_cast<const char *>(payload), payload_len);
        lte_cell_config::Decline why;
        const bool learned = lte_cell_config::learn(map->lte_cfg, blob, &why);
        if (lte_cell_config::is_refusal(why))
            return DIAG_NATIVE_REFUSED;      // parse_0xb197 -> None
        return learned ? 1 : 0;
    } catch (...) {
        return 0;                        // same C/C++ boundary containment
    }
}

extern "C" bool diag_native_lte_cell_config(diag_native_sib1_map_t *map,
        diag_native_obs_t *obs) {
    // add_lte_cell_config returns early with no earfcn or pci key; the NR
    // branch never calls it at all.
    if (map == nullptr || obs == nullptr || obs->earfcn_absent ||
            std::strcmp(obs->rat, "LTE") != 0)
        return false;
    try {
        const lte_cell_config::Config c =
            lte_cell_config::attach(map->lte_cfg, obs->pci, obs->earfcn);
        obs->has_bandwidth_rb = c.has_bandwidth_rb;
        obs->bandwidth_rb = c.bandwidth_rb;
        obs->has_tx_antennas = c.has_tx_antennas;
        obs->tx_antennas = c.tx_antennas;
        return c.has_bandwidth_rb || c.has_tx_antennas;
    } catch (...) {
        return false;
    }
}

extern "C" int diag_native_lte_meas_neighbours(const diag_native_sib1_map_t *map,
        uint16_t log_code, const uint8_t *payload, size_t payload_len,
        diag_native_obs_t *out_obs, size_t max_obs) {
    if (log_code != 0xB0C0)
        return -1;
    if (out_obs == nullptr || max_obs == 0 || payload == nullptr)
        return 0;

    const std::string blob(reinterpret_cast<const char *>(payload), payload_len);
    // A NULL map is "enrichment unavailable" everywhere else in this surface;
    // here it is an empty measConfig, which still lets a CGI neighbour through.
    static const lte_meas_join::State kEmpty;
    size_t n = 0;
    try {
        for (const auto& r : lte_meas_join::neighbours(
                 map != nullptr ? map->lte_meas : kEmpty, blob)) {
            if (n >= max_obs) break;
            diag_native_obs_t *o = &out_obs[n];
            init_obs(o, "LTE", 0xB0C0);
            o->meas_neighbour = true;
            o->pci = r.pci;
            o->earfcn = r.earfcn;
            o->earfcn_absent = !r.has_earfcn;
            o->has_rsrp = r.has_rsrp;
            o->rsrp = r.rsrp;
            o->has_rsrq = r.has_rsrq;
            o->rsrq = r.rsrq;
            if (r.has_cgi) {
                o->has_identity = true;
                copy_plmn_field(o->mcc, sizeof(o->mcc), r.mcc);
                copy_plmn_field(o->mnc, sizeof(o->mnc), r.mnc);
                o->tac = r.tac;
                o->cell_id = r.cell_id;
            }
            n++;
        }
    } catch (...) {
        return 0;                        // same C/C++ boundary containment
    }
    return static_cast<int>(n);
}

// ---- Serialize an observation to its JSON line -----------------------------

namespace {

// Bounded, snprintf-style incremental appender. `total` accumulates the full
// length the line WOULD occupy so the caller can detect truncation exactly the
// way snprintf reports it; once `left` hits zero we keep counting but stop
// writing, so a short buffer is a reported overrun, never a silent half-line.
struct jbuf {
    char  *p;
    size_t left;
    int    total;
};

void japp(struct jbuf *j, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(j->p, j->left, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    j->total += n;
    if ((size_t)n >= j->left) {
        j->left = 0;                     // truncated -- stop writing, keep counting
    } else {
        j->p    += n;
        j->left -= n;
    }
}

// Render a double the way Python's json.dumps (i.e. repr(float)) does: the
// SHORTEST decimal that round-trips, in fixed notation with at least one digit
// after the point ("-104.0", never "-104"), or in repr's exponent form outside
// [1e-4, 1e16).
//
// A fixed "%.6f" with trailing zeros stripped is NOT enough: 0xB97F values are
// x128 fixed-point and need up to 7 decimals (-108.5078125 would render as
// -108.507812), which corrupts about half of the /128 dBm grid. The loop below
// is exact for every double: validated against repr() over dBm grids,
// timestamps and 1e-9..1e20 with no mismatches. The typical value stops at
// d <= 7.
void fmt_json_double(char *buf, size_t n, double v) {
    const double mag = std::fabs(v);
    if (mag != 0.0 && (mag < 1e-4 || mag >= 1e16)) {
        for (int p = 0; p <= 16; p++) {
            std::snprintf(buf, n, "%.*e", p, v);
            if (std::strtod(buf, nullptr) == v)
                return;
        }
        return;
    }
    for (int d = 1; d <= 40; d++) {
        std::snprintf(buf, n, "%.*f", d, v);
        if (std::strtod(buf, nullptr) == v)
            break;
    }
    char *dot = std::strchr(buf, '.');
    if (dot == nullptr)
        return;
    char *end = buf + std::strlen(buf) - 1;
    while (end > dot + 1 && *end == '0')
        *end-- = '\0';
}

// The prov block -- identical bytes for every code, only its position and origin
// vary: {"src":"diag","origin":..,"imei":..,"captured_at":..,"log_tick":..}. log_tick is the exact ts64 as a JSON integer
// (as a float it would lose the low bits of any tick past 2^53).
void japp_prov(struct jbuf *j, uint16_t log_code, const char *imei,
        double captured_at, uint64_t log_tick) {
    char ca[64];
    fmt_json_double(ca, sizeof(ca), captured_at);
    japp(j, ",\"prov\":{\"src\":\"diag\",\"origin\":\"0x%04X\",\"imei\":\"%s\","
            "\"captured_at\":%s,\"log_tick\":%llu}",
         log_code, imei, ca, (unsigned long long)log_tick);
}

// The four enrich-merged identity keys, in their fixed render order.
void japp_identity(struct jbuf *j, const diag_native_obs_t *o) {
    japp(j, ",\"mcc\":\"%s\",\"mnc\":\"%s\",\"tac\":%u,\"cell_id\":%llu",
         o->mcc, o->mnc, (unsigned)o->tac, (unsigned long long)o->cell_id);
}

// band + duplex: pure functions of the
// EARFCN, stamped on EVERY LTE row after everything else the branch emitted, and
// omitted -- never zeroed -- for band 0 or an unclassified band. No earfcn key
// (a CGI-only neighbour) means no band either.
// NR rows never get them.
void japp_band_duplex(struct jbuf *j, const diag_native_obs_t *o) {
    if (std::strcmp(o->rat, "LTE") != 0 || o->earfcn_absent || o->earfcn < 0)
        return;
    const int band = lte_band::earfcn_to_band(static_cast<uint32_t>(o->earfcn));
    if (band == 0)
        return;
    japp(j, ",\"band\":%d", band);
    const char *duplex = lte_band::band_to_duplex(band);
    if (duplex != nullptr)
        japp(j, ",\"duplex\":\"%s\"", duplex);
}

// The 0xB197 cell config: stamped
// right after band/duplex on every LTE row it was attached to. bandwidth is the
// integer MHz, absent for 6 RB (1.4 MHz), which only bandwidth_rb can carry.
void japp_cell_config(struct jbuf *j, const diag_native_obs_t *o) {
    if (o->has_bandwidth_rb) {
        japp(j, ",\"bandwidth_rb\":%d", (int)o->bandwidth_rb);
        const int mhz = lte_cell_config::rb_to_mhz((int)o->bandwidth_rb);
        if (mhz != 0)
            japp(j, ",\"bandwidth\":%d", mhz);
    }
    if (o->has_tx_antennas)
        japp(j, ",\"tx_antennas\":%d", (int)o->tx_antennas);
}

// 0xB97F's beams / serving_ssb_index / ssb_periodicity_ms, in that order, each
// only when bound.
void japp_nr_beam_keys(struct jbuf *j, const diag_native_obs_t *o) {
    char v[64];
    if (o->has_beam) {
        japp(j, ",\"beams\":[{\"ssb_index\":%lld", (long long)o->beam_ssb_index);
        if (o->has_beam_rsrp_a) { fmt_json_double(v, sizeof(v), o->beam_rsrp_a);
            japp(j, ",\"rsrp_a\":%s", v); }
        if (o->has_beam_rsrp_b) { fmt_json_double(v, sizeof(v), o->beam_rsrp_b);
            japp(j, ",\"rsrp_b\":%s", v); }
        if (o->has_beam_rsrq_a) { fmt_json_double(v, sizeof(v), o->beam_rsrq_a);
            japp(j, ",\"rsrq_a\":%s", v); }
        if (o->has_beam_rsrq_b) { fmt_json_double(v, sizeof(v), o->beam_rsrq_b);
            japp(j, ",\"rsrq_b\":%s", v); }
        japp(j, "}]");
    }
    if (o->has_serving_ssb_index)
        japp(j, ",\"serving_ssb_index\":%d", (int)o->serving_ssb_index);
    if (o->has_ssb_periodicity_ms)
        japp(j, ",\"ssb_periodicity_ms\":%d", (int)o->ssb_periodicity_ms);
}

// The NR SIB1 cell config: band,
// carrier_scs, bandwidth_rb, bandwidth, each only when the SIB1 bound it. Only
// diag_native_sib1_enrich sets these, and only on NR rows.
void japp_nr_cell_config(struct jbuf *j, const diag_native_obs_t *o) {
    if (o->has_nr_band)
        japp(j, ",\"band\":%d", (int)o->nr_band);
    if (o->has_nr_carrier_scs)
        japp(j, ",\"carrier_scs\":%d", (int)o->nr_carrier_scs);
    if (o->has_nr_bandwidth_rb)
        japp(j, ",\"bandwidth_rb\":%d", (int)o->nr_bandwidth_rb);
    if (o->has_nr_bandwidth)
        japp(j, ",\"bandwidth\":%d", (int)o->nr_bandwidth);
}

}  // namespace

extern "C" int diag_native_obs_to_json(const diag_native_obs_t *obs,
        const char *imei, double captured_at, uint64_t log_tick,
        char *out, size_t out_len) {
    if (obs == nullptr || out == nullptr || out_len == 0)
        return -1;

    struct jbuf j = { out, out_len, 0 };

    // observation_type follows is_serving uniformly across every code (a row is
    // "serving" exactly when is_serving is true); deriving it here keeps the two
    // from drifting.
    const char *obs_type = obs->is_serving ? "serving" : "observation";
    char rsrp_s[64], rsrq_s[64];

    // 0x512F: a GSM identity has no pci/earfcn, so it skips the shared prefix.
    // A GSM SI3 row: rat, mcc, mnc, lac, tac (== lac, the generic area-code
    // slot), cell_id, observation_type, is_serving, prov -- and no band/duplex
    // or cell config: the row is rendered unenriched.
    if (obs->log_code == 0x512F) {
        if (!obs->has_identity)
            return -1;
        japp(&j, "{\"rat\":\"%s\",\"mcc\":\"%s\",\"mnc\":\"%s\",\"lac\":%u,"
             "\"tac\":%u,\"cell_id\":%llu", obs->rat, obs->mcc, obs->mnc,
             obs->tac, obs->tac, (unsigned long long)obs->cell_id);
        japp(&j, ",\"observation_type\":\"%s\",\"is_serving\":%s",
             obs_type, obs->is_serving ? "true" : "false");
        japp_prov(&j, obs->log_code, imei, captured_at, log_tick);
        japp(&j, "}");
        return j.total;
    }

    // A MeasurementReport neighbour row has its own key order, starting
    // before earfcn: rat, pci, observation_type, is_serving, prov, then
    // [earfcn], [rsrp], [rsrq], then identity (its own cgi-Info, or the SIB1
    // cache's via enrichment).
    if (obs->log_code == 0xB0C0 && obs->meas_neighbour) {
        japp(&j, "{\"rat\":\"%s\",\"pci\":%d", obs->rat, obs->pci);
        japp(&j, ",\"observation_type\":\"%s\",\"is_serving\":%s",
             obs_type, obs->is_serving ? "true" : "false");
        japp_prov(&j, obs->log_code, imei, captured_at, log_tick);
        if (!obs->earfcn_absent)
            japp(&j, ",\"earfcn\":%d", obs->earfcn);
        if (obs->has_rsrp) { fmt_json_double(rsrp_s, sizeof(rsrp_s), obs->rsrp);
            japp(&j, ",\"rsrp\":%s", rsrp_s); }
        if (obs->has_rsrq) { fmt_json_double(rsrq_s, sizeof(rsrq_s), obs->rsrq);
            japp(&j, ",\"rsrq\":%s", rsrq_s); }
        if (obs->has_identity) japp_identity(&j, obs);
        japp_band_duplex(&j, obs);
        japp_cell_config(&j, obs);
        japp(&j, "}");
        return j.total;
    }

    // Opening + the (rat, pci, earfcn) prefix every branch shares.
    japp(&j, "{\"rat\":\"%s\",\"pci\":%d,\"earfcn\":%d",
         obs->rat, obs->pci, obs->earfcn);

    switch (obs->log_code) {
    case 0xB193:
        // rat,pci,earfcn, prov, [rsrp],[rsrq], observation_type, is_serving, [id]
        japp_prov(&j, obs->log_code, imei, captured_at, log_tick);
        if (obs->has_rsrp) { fmt_json_double(rsrp_s, sizeof(rsrp_s), obs->rsrp);
            japp(&j, ",\"rsrp\":%s", rsrp_s); }
        if (obs->has_rsrq) { fmt_json_double(rsrq_s, sizeof(rsrq_s), obs->rsrq);
            japp(&j, ",\"rsrq\":%s", rsrq_s); }
        japp(&j, ",\"observation_type\":\"%s\",\"is_serving\":%s",
             obs_type, obs->is_serving ? "true" : "false");
        if (obs->has_identity) japp_identity(&j, obs);
        break;

    case 0xB192:
        // rat,pci,earfcn, observation_type, is_serving, prov, [id]
        japp(&j, ",\"observation_type\":\"%s\",\"is_serving\":%s",
             obs_type, obs->is_serving ? "true" : "false");
        japp_prov(&j, obs->log_code, imei, captured_at, log_tick);
        if (obs->has_identity) japp_identity(&j, obs);
        break;

    case 0xB195:
        // rat,pci,earfcn, observation_type, is_serving, prov, [rsrp], [id]
        japp(&j, ",\"observation_type\":\"%s\",\"is_serving\":%s",
             obs_type, obs->is_serving ? "true" : "false");
        japp_prov(&j, obs->log_code, imei, captured_at, log_tick);
        if (obs->has_rsrp) { fmt_json_double(rsrp_s, sizeof(rsrp_s), obs->rsrp);
            japp(&j, ",\"rsrp\":%s", rsrp_s); }
        if (obs->has_identity) japp_identity(&j, obs);
        break;

    case 0xB97F:
        // rat,pci,earfcn, observation_type, is_serving, prov, [rsrp],[rsrq],
        // [beams],[serving_ssb_index],[ssb_periodicity_ms], [id]
        japp(&j, ",\"observation_type\":\"%s\",\"is_serving\":%s",
             obs_type, obs->is_serving ? "true" : "false");
        japp_prov(&j, obs->log_code, imei, captured_at, log_tick);
        if (obs->has_rsrp) { fmt_json_double(rsrp_s, sizeof(rsrp_s), obs->rsrp);
            japp(&j, ",\"rsrp\":%s", rsrp_s); }
        if (obs->has_rsrq) { fmt_json_double(rsrq_s, sizeof(rsrq_s), obs->rsrq);
            japp(&j, ",\"rsrq\":%s", rsrq_s); }
        japp_nr_beam_keys(&j, obs);
        if (obs->has_identity) japp_identity(&j, obs);
        break;

    case 0xB0C0:
        // rat,pci,earfcn, mcc,mnc,tac,cell_id (INLINE, not via enrichment),
        // observation_type, is_serving, prov (LAST). This cell comes from the
        // record's own freshly-decoded SIB1, so identity is always present and
        // placed mid-object, and prov trails everything.
        if (!obs->has_identity)
            return -1;                   // a 0xB0C0 obs without SIB1 is never emitted
        japp_identity(&j, obs);
        japp(&j, ",\"observation_type\":\"%s\",\"is_serving\":%s",
             obs_type, obs->is_serving ? "true" : "false");
        japp_prov(&j, obs->log_code, imei, captured_at, log_tick);
        // SIB1 flags, then the MOCN list only for a multi-PLMN cell, in the
        // order cell_barred, csg, plmns.
        if (obs->has_access_flags) {
            japp(&j, ",\"cell_barred\":%s,\"csg\":%s",
                 obs->cell_barred ? "true" : "false", obs->csg ? "true" : "false");
            if (obs->n_plmns > 1) {
                japp(&j, ",\"plmns\":[");
                for (int k = 0; k < obs->n_plmns; k++)
                    japp(&j, "%s{\"mcc\":\"%s\",\"mnc\":\"%s\"}", k ? "," : "",
                         obs->plmn_mcc[k], obs->plmn_mnc[k]);
                japp(&j, "]");
            }
        }
        break;

    case 0xB821:
        // rat,pci,earfcn, observation_type, is_serving, prov, [rsrp],[rsrq],[sinr], [id]
        japp(&j, ",\"observation_type\":\"%s\",\"is_serving\":%s",
             obs_type, obs->is_serving ? "true" : "false");
        japp_prov(&j, obs->log_code, imei, captured_at, log_tick);
        if (obs->has_rsrp) { fmt_json_double(rsrp_s, sizeof(rsrp_s), obs->rsrp);
            japp(&j, ",\"rsrp\":%s", rsrp_s); }
        if (obs->has_rsrq) { fmt_json_double(rsrq_s, sizeof(rsrq_s), obs->rsrq);
            japp(&j, ",\"rsrq\":%s", rsrq_s); }
        if (obs->has_sinr) { char sinr_s[64];
            fmt_json_double(sinr_s, sizeof(sinr_s), obs->sinr);
            japp(&j, ",\"sinr\":%s", sinr_s); }
        if (obs->has_identity) japp_identity(&j, obs);
        break;

    case 0xB17F:
        // rat,pci,earfcn, observation_type, is_serving, prov, [rsrp],[rsrq],[rssi], [id]
        japp(&j, ",\"observation_type\":\"%s\",\"is_serving\":%s",
             obs_type, obs->is_serving ? "true" : "false");
        japp_prov(&j, obs->log_code, imei, captured_at, log_tick);
        if (obs->has_rsrp) { fmt_json_double(rsrp_s, sizeof(rsrp_s), obs->rsrp);
            japp(&j, ",\"rsrp\":%s", rsrp_s); }
        if (obs->has_rsrq) { fmt_json_double(rsrq_s, sizeof(rsrq_s), obs->rsrq);
            japp(&j, ",\"rsrq\":%s", rsrq_s); }
        if (obs->has_rssi) { char rssi_s[64];
            fmt_json_double(rssi_s, sizeof(rssi_s), obs->rssi);
            japp(&j, ",\"rssi\":%s", rssi_s); }
        if (obs->has_identity) japp_identity(&j, obs);
        break;

    default:
        return -1;                       // no cell-observation serialization
    }

    japp_band_duplex(&j, obs);
    japp_cell_config(&j, obs);
    // scs and then the SIB1 cell config are the last keys of an NR row, after
    // any identity. LTE rows never carry them.
    if (obs->has_scs)
        japp(&j, ",\"scs\":%d", (int)obs->scs);
    japp_nr_cell_config(&j, obs);
    japp(&j, "}");
    return j.total;
}

// ---- Live GSMTAP framing -----------------------------------------------------

// Every GSMTAP-eligible code: LTE RRC 0xB0C0 and the five LTE NAS codes. The
// NAS framers decline a PDU that fails the TS 24.301 structure check
// (0xB0E2/E3/EC/ED) or the security-protected gates (0xB0E1), so every frame
// sent is a well-formed NAS PDU.
using gsmtap_bridge_fn = bool (*)(const uint8_t *, std::size_t,
                                  std::vector<uint8_t> &);

static gsmtap_bridge_fn gsmtap_bridge_for(uint16_t log_code) {
    switch (log_code) {
        case 0xB0C0: return diagspec::celldiag::diag_0xb0c0_to_gsmtap;
        case 0xB0E1: return diagspec::celldiag::diag_0xb0e1_to_gsmtap;
        case 0xB0E2: return diagspec::celldiag::diag_0xb0e2_to_gsmtap;
        case 0xB0E3: return diagspec::celldiag::diag_0xb0e3_to_gsmtap;
        case 0xB0EC: return diagspec::celldiag::diag_0xb0ec_to_gsmtap;
        case 0xB0ED: return diagspec::celldiag::diag_0xb0ed_to_gsmtap;
        default:     return nullptr;
    }
}

extern "C" bool diag_native_has_gsmtap_framer(uint16_t log_code) {
    return gsmtap_bridge_for(log_code) != nullptr;
}

extern "C" int diag_native_gsmtap_frame(uint16_t log_code, const uint8_t *payload,
        size_t payload_len, uint8_t *out, size_t out_cap) {
    if (!diag_native_has_gsmtap_framer(log_code))
        return -1;
    if (payload == nullptr || out == nullptr)
        return 0;
    // Same C/C++ boundary containment as every entry point above.
    try {
        std::vector<uint8_t> frame;
        if (!gsmtap_bridge_for(log_code)(payload, payload_len, frame))
            return 0;
        if (frame.empty() || frame.size() > out_cap ||
                frame.size() > static_cast<size_t>(INT32_MAX))
            return 0;
        std::memcpy(out, frame.data(), frame.size());
        return static_cast<int>(frame.size());
    } catch (...) {
        return 0;
    }
}
