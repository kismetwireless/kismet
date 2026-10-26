// SPDX-License-Identifier: GPL-2.0-or-later
// Implementation of the 0xB821 NR SIB1 identity leg. See the header for
// why this returns a map entry rather than a CellObservation.
#include "diag_0xb821_identity.h"

#include <exception>
#include <vector>

#include "kaitai/kaitaistream.h"
#include "diag_0xb821.h"
#include "diag_0xb821_enrich.h"
#include "nr5g_rrc.h"
#include "nr_rrc_sib.h"

namespace diag_0xb821_identity {

namespace {

void note(Decline* why, Decline d) {
    if (why != nullptr)
        *why = d;
}
const char* const kSib1Channel = "BCCH-DL-SCH";
const char* const kMibChannel = "BCCH-BCH";
// TS 38.104: an NR-ARFCN at or above this is FR2.
const int32_t kFr2ArfcnFloor = 2016667;
// CellConfig's absent value is copied straight from the decoder's, so the two
// must be one value.
static_assert(kAbsent == diagspec::nr_rrc::kNrAbsent,
              "CellConfig::kAbsent must equal nr_rrc::kNrAbsent");
}  // namespace

CellIdentity identity(const std::string& payload, Decline* why) {
    CellIdentity out;
    note(why, Decline::kNone);
    if (diag_0xb821_enrich::record_refused(payload)) {
        note(why, Decline::kRefused);    // the 0xB821 parse refuses it
        return out;
    }

    // Kaitai (and the UPER reader beneath it) throw std::exception subclasses on
    // a truncated / malformed buffer; a capture source must decline the record,
    // not abort the stream — so a parse failure yields an invalid entry.
    try {
        kaitai::kstream ks(payload);
        diag_0xb821_t rec(&ks);

        // Gate part 1: the resolved channel NAME must be BCCH-DL-SCH. The
        // SIB1 dispatch keys on the NAME because a byte[5]==0x90 test fires on
        // PCCH records that happen to share that rrc_rel_min value. An unmapped (version, pdu_id) yields "" and declines.
        const std::string chan =
            diag_0xb821_enrich::channel_name(rec.version(), rec.pdu_id());
        if (chan != kSib1Channel)
            return out;

        // msg_data() is the raw ASN.1 PER RRC PDU (KS_STR_ENCODING_NONE). An
        // empty PDU has no SIB1 to decode.
        const std::string& pdu = rec.msg_data();
        if (pdu.empty())
            return out;

        // Gate part 2: the PDU must decode as an NR SIB1 — the map entry's own
        // condition. A BCCH-DL-SCH carrying a SystemInformation (SIB2+)
        // container returns false here, so it contributes no map entry.
        const std::vector<uint8_t> msg(pdu.begin(), pdu.end());
        diagspec::nr_rrc::NrSib1CellId sib1;
        if (!diagspec::nr_rrc::decode_nr_sib1(msg, sib1))
            return out;

        out.valid = true;
        out.pci = static_cast<int32_t>(rec.pci());
        out.arfcn = static_cast<int32_t>(rec.arfcn());
        out.mcc = sib1.mcc;
        out.mnc = sib1.mnc;
        out.tac = sib1.tac;
        out.cell_id = sib1.cell_id;

        // The ("nr_cfg", pci, arfcn) entry: Diag0xB821's sib1_band /
        // sib1_scs_khz / sib1_carrier_bandwidth_prb / sib1_channel_bandwidth_mhz,
        // straight from the walk. A field past scc.walk_stopped_at is still
        // kNrAbsent here, so it stays absent rather than reading as 0.
        const diagspec::nr_rrc::NrServingCellConfigCommon& scc = sib1.scc;
        out.config.band = scc.band;
        out.config.carrier_scs_khz = scc.scs_khz;
        out.config.bandwidth_rb = scc.carrier_bandwidth_prb;
        out.config.bandwidth_mhz = scc.channel_bandwidth_mhz;
        out.config.valid = scc.band != kAbsent || scc.scs_khz != kAbsent ||
                           scc.carrier_bandwidth_prb != kAbsent ||
                           scc.channel_bandwidth_mhz != kAbsent;
    } catch (const std::exception&) {
        return CellIdentity();
    }
    return out;
}

CellScs mib_scs(const std::string& payload, Decline* why) {
    CellScs out;
    note(why, Decline::kNone);
    if (diag_0xb821_enrich::record_refused(payload)) {
        note(why, Decline::kRefused);    // the 0xB821 parse refuses it
        return out;
    }
    try {
        kaitai::kstream ks(payload);
        diag_0xb821_t rec(&ks);
        if (diag_0xb821_enrich::channel_name(rec.version(), rec.pdu_id()) != kMibChannel)
            return out;
        const std::string& pdu = rec.msg_data();
        if (pdu.empty())
            return out;
        const std::vector<uint8_t> msg(pdu.begin(), pdu.end());
        diagspec::nr5g_rrc::NrMib mib;
        if (!diagspec::nr5g_rrc::decode_mib(msg, mib))
            return out;
        const int32_t arfcn = static_cast<int32_t>(rec.arfcn());
        const bool fr2 = arfcn >= kFr2ArfcnFloor;
        if (mib.sub_carrier_spacing_common_name == "scs15or60")
            out.scs_khz = fr2 ? 60 : 15;
        else if (mib.sub_carrier_spacing_common_name == "scs30or120")
            out.scs_khz = fr2 ? 120 : 30;
        else
            return out;                  // unrecognised enum: omitted, never guessed
        out.valid = true;
        out.pci = static_cast<int32_t>(rec.pci());
        out.arfcn = arfcn;
    } catch (const std::exception&) {
        return CellScs();
    }
    return out;
}

bool is_refusal(Decline d) {
    return d == Decline::kRefused;
}

}  // namespace diag_0xb821_identity
