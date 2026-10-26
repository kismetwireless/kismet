// SPDX-License-Identifier: GPL-2.0-or-later
// LTE MeasurementReport neighbour join: the
// measId -> measObjectId -> EARFCN state machine.
//
// A MeasurementReport's MeasResultEUTRA carries physCellId only. The carrier
// comes from measId -> measObjectId -> measObjectEUTRA.carrierFreq, configured
// by an EARLIER RRCConnectionReconfiguration. So unlike every other
// cell_observation leg this one is STATEFUL: the caller owns one State per
// capture session and feeds it every 0xB0C0 record, in capture order.
//
// It composes already-verified units and reimplements no decode:
//   * generated Kaitai raw parse (generated/cpp/diag_0xb0c0.*) for version,
//     channel_type and msg_data;
//   * diag_0xb0c0_enrich::channel_name() for the channel NAME;
//   * decode_rrc_reconfig_meas_config() (lte_rrc_reconfig.*, tshark-pinned by
//     test_lte_rrc_reconfig_tshark_4894.py) for the join keys;
//   * decode_measurement_report() (lte_rrc_meas_report.*) for the neighbours.
//
// EQUIVALENCE CONTRACT (harness/lte_meas_join_verify.py): over any sequence of
// 0xB0C0 payloads, update() then neighbours() per record yields the same rows,
// field for field, as the reference decoder's measConfig state update then
// neighbour emit with an empty SIB1 cache. SIB1 enrichment of a PCI-only row,
// and band/duplex, are the caller's (applied after the join, not part of it).
#ifndef DIAGSPEC_LTE_MEAS_JOIN_H
#define DIAGSPEC_LTE_MEAS_JOIN_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace lte_meas_join {

// The UE's measConfig as far as this session has seen it:
// objects {measObjectId: earfcn or none}, links {measId: measObjectId}.
struct State {
    struct Object {
        bool eutra = false;   // false: a non-EUTRA object (UTRA/GERAN/CDMA2000/NR)
        int32_t earfcn = 0;   // effective EARFCN, only when eutra
    };
    std::map<int, Object> objects;   // measObjectId -> carrier
    std::map<int, int> links;        // measId -> measObjectId
};

// One reported neighbour row. has_earfcn is false only for a CGI neighbour
// whose measId did not map (the row then has no "earfcn" key).
struct Neighbour {
    int32_t pci = 0;
    bool has_earfcn = false;
    int32_t earfcn = 0;
    bool has_rsrp = false;
    double rsrp = 0.0;
    bool has_rsrq = false;
    double rsrq = 0.0;
    bool has_cgi = false;     // cgi-Info: authoritative identity, never SIB1-enriched
    std::string mcc;
    std::string mnc;
    uint32_t tac = 0;
    uint32_t cell_id = 0;
};

// Apply one 0xB0C0 LOG_F payload (log-code-stripped) to `state`. Records that
// neither configure nor invalidate the measConfig leave it untouched, and a
// malformed payload is ignored (a capture source must not abort on one record).
//
// Rules, each chosen so an unknown carrier is OMITTED rather than guessed:
//   * DL-DCCH rrcConnectionRelease / mobilityFromEUTRACommand, DL-CCCH
//     rrcConnectionSetup: clear everything.
//   * DL-CCCH rrcConnectionReestablishment, and a reconfiguration carrying
//     mobilityControlInfo (handover): drop every measId link, keep objects.
//   * measConfig in TS 36.331 5.5.1 order: object remove (also removes its
//     measIds, 5.5.2.4), non-EUTRA (re)definitions, EUTRA add/modify, measId
//     remove, measId add/modify.
void update(State& state, const std::string& payload);

// The neighbour rows of a UL-DCCH MeasurementReport in `payload`, joined
// against `state`. Empty for any other record. A PCI outside 0..503 is
// dropped; a PCI-only neighbour whose measId has no EUTRA carrier is omitted;
// a CGI neighbour is emitted regardless, with the EARFCN only when mapped.
std::vector<Neighbour> neighbours(const State& state, const std::string& payload);

}  // namespace lte_meas_join

#endif  // DIAGSPEC_LTE_MEAS_JOIN_H
