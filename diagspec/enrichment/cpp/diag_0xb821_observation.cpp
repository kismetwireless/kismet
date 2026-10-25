// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the 0xB821 NR serving observation leg. See the header.
#include "diag_0xb821_observation.h"

#include <exception>

#include "kaitai/kaitaistream.h"
#include "diag_0xb821.h"
#include "diag_0xb821_enrich.h"
#include "nr5g_rrc_meas_report.h"

namespace diag_0xb821_observation {

namespace {

void note(Decline* why, Decline d) {
    if (why != nullptr)
        *why = d;
}
const char* const kUlDcch = "UL-DCCH";
const int32_t kMaxNrPci = 1007;   // TS 38.211 7.4.2.1
}  // namespace

std::vector<CellObservation> observations(const std::string& payload, Decline* why) {
    std::vector<CellObservation> out;
    note(why, Decline::kNone);
    if (diag_0xb821_enrich::record_refused(payload)) {
        note(why, Decline::kRefused);    // the 0xB821 parse refuses it
        return out;
    }
    try {
        kaitai::kstream ks(payload);
        diag_0xb821_t rec(&ks);
        if (diag_0xb821_enrich::channel_name(rec.version(), rec.pdu_id()) != kUlDcch)
            return out;
        const std::string& pdu = rec.msg_data();
        if (pdu.empty())
            return out;
        const std::vector<uint8_t> msg(pdu.begin(), pdu.end());
        diagspec::nr5g_rrc::NrMeasurementReport mr;
        if (!diagspec::nr5g_rrc::decode_measurement_report(0, msg, mr))
            return out;                  // not a MeasurementReport: no row

        // A camped-cell PCI outside the spec range is a decode that walked off
        // its stride: drop the row rather than emit a fabricated tower.
        const int32_t pci = static_cast<int32_t>(rec.pci());
        if (pci < 0 || pci > kMaxNrPci)
            return out;

        CellObservation o;
        o.pci = pci;
        o.arfcn = static_cast<int32_t>(rec.arfcn());
        o.has_rsrp = mr.has_serving_rsrp;
        o.rsrp = mr.serving_rsrp;
        o.has_rsrq = mr.has_serving_rsrq;
        o.rsrq = mr.serving_rsrq;
        o.has_sinr = mr.has_serving_sinr;
        o.sinr = mr.serving_sinr;
        out.push_back(o);
    } catch (const std::exception&) {
        return std::vector<CellObservation>();
    }
    return out;
}

bool is_refusal(Decline d) {
    return d == Decline::kRefused;
}

}  // namespace diag_0xb821_observation
