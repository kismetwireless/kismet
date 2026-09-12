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

*/

#include "config.h"

#include <string>
#include <sstream>

#include "phy_cell.h"
#include "devicetracker.h"
#include "macaddr.h"
#include "kis_httpd_registry.h"
#include "messagebus.h"

kis_cellular_phy::kis_cellular_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("Cellular");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    cell_device_entry_id =
        entrytracker->register_field("cellular.device",
                tracker_element_factory<kis_cellular_tracked_cell>(),
                "Cellular cell device");

    prov_source_entry_id =
        entrytracker->register_field("cellular.prov_source",
                tracker_element_factory<kis_cellular_tracked_prov_source>(),
                "Cellular per-source provenance record");

    pack_comp_common = packetchain->register_packet_component("COMMON");
    pack_comp_json = packetchain->register_packet_component("JSON");
    pack_comp_meta = packetchain->register_packet_component("METABLOB");
    pack_comp_gps = packetchain->register_packet_component("GPS");
    pack_comp_device = packetchain->register_packet_component("DEVICE");
    pack_comp_radiodata = packetchain->register_packet_component("RADIODATA");

    // Cache device type strings — "Cell" has full identity (MCC+MNC+CID),
    // "Cell (Partial)" has only PCI+EARFCN (observed via signal, no global cell identity).
    devtype_cell = devicetracker->get_cached_devicetype("Cell");
    devtype_cell_partial = devicetracker->get_cached_devicetype("Cell (Partial)");

    packetchain->register_handler(&packet_handler, this, CHAINPOS_CLASSIFIER, -100);

    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_cell", "js/kismet.ui.cell.js");
}

kis_cellular_phy::~kis_cellular_phy() {
    packetchain->remove_handler(&packet_handler, CHAINPOS_CLASSIFIER);
}

mac_addr kis_cellular_phy::cellkey_to_mac(const std::string& cell_key) {
    uint8_t bytes[6];

    memset(bytes, 0, 6);

    uint32_t csum1 = adler32_checksum(cell_key);
    uint32_t csum2 = adler32_checksum(cell_key + "_cell");

    bytes[0] = (csum1 >> 24) & 0xFF;
    bytes[1] = (csum1 >> 16) & 0xFF;
    bytes[2] = (csum1 >> 8) & 0xFF;
    bytes[3] = csum1 & 0xFF;
    bytes[4] = (csum2 >> 8) & 0xFF;
    bytes[5] = csum2 & 0xFF;

    // Set locally administered bit
    bytes[0] |= 0x02;
    // Clear multicast bit
    bytes[0] &= 0xFE;

    return mac_addr(bytes, 6);
}

bool kis_cellular_phy::device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) {
    auto cell = dev->get_sub_as<kis_cellular_tracked_cell>(cell_device_entry_id);
    return (cell != nullptr);
}

std::shared_ptr<kis_cellular_tracked_cell> kis_cellular_phy::fetch_cell_record(
    const std::shared_ptr<kis_tracked_device_base>& dev) {
    return dev->get_sub_as<kis_cellular_tracked_cell>(cell_device_entry_id);
}

void kis_cellular_phy::load_phy_storage(
    shared_tracker_element in_storage, shared_tracker_element in_device) {
    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    auto celli = storage->find(cell_device_entry_id);

    if (celli != storage->end()) {
        auto celldev = std::make_shared<kis_cellular_tracked_cell>(
            cell_device_entry_id,
            std::static_pointer_cast<tracker_element_map>(
                celli->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(
            celldev);
    }
}

int kis_cellular_phy::packet_handler(CHAINCALL_PARMS) {
    kis_cellular_phy *cell_phy = (kis_cellular_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto json = in_pack->fetch<kis_json_packinfo>(cell_phy->pack_comp_json);
    if (json == NULL)
        return 0;

    if (json->type != "CellModem" && json->type != "Cellular")
        return 0;

    std::stringstream ss(json->json_string);
    nlohmann::json device_json;

    try {
        ss >> device_json;

        if (cell_phy->json_to_cell(device_json, in_pack)) {
            auto adata = in_pack->fetch_or_add<packet_metablob>(cell_phy->pack_comp_meta);
            adata->set_data("Cellular", json->json_string);
        }
    } catch (std::exception& e) {
        _MSG_DEBUG("Cellular JSON error: {}", e.what());
        return 0;
    }

    return 1;
}

/* Convert an ARFCN/EARFCN/NR-ARFCN to a center frequency in kHz.
 *
 * LTE EARFCN:  3GPP TS 36.101 Table 5.7.3-1
 * NR-ARFCN:    3GPP TS 38.104 Table 5.4.2.1-1
 *
 * Returns 0 if the ARFCN cannot be converted.
 */
static uint64_t arfcn_to_khz(const std::string& rat, uint32_t arfcn) {
    if (rat == "LTE") {
        /* LTE EARFCN → DL frequency
         * F_DL = F_DL_low + 0.1 * (EARFCN - N_Offs_DL)
         * Result in MHz, we return kHz.
         *
         * Covers the most common bands. */
        struct earfcn_band {
            uint32_t noffs_dl;
            uint32_t noffs_dl_max;
            double fdl_low_mhz;
        };
        static const struct earfcn_band lte_bands[] = {
            {    0,   599, 2110.0},   /* Band 1 */
            {  600,  1199, 1930.0},   /* Band 2 */
            { 1200,  1949, 1805.0},   /* Band 3 */
            { 1950,  2399, 2110.0},   /* Band 4 */
            { 2400,  2649,  869.0},   /* Band 5 */
            { 2650,  2749,  875.0},   /* Band 6 */
            { 2750,  3449, 2620.0},   /* Band 7 */
            { 3450,  3799,  925.0},   /* Band 8 */
            { 3800,  4149, 1844.9},   /* Band 9 */
            { 4150,  4749, 2110.0},   /* Band 10 */
            { 4750,  4949, 1475.9},   /* Band 11 */
            { 5010,  5179,  729.0},   /* Band 12 */
            { 5180,  5279,  746.0},   /* Band 13 */
            { 5280,  5379,  758.0},   /* Band 14 */
            { 5730,  5849,  860.0},   /* Band 17 */
            { 5850,  5999,  875.0},   /* Band 18 */
            { 6000,  6149,  890.0},   /* Band 19 */
            { 6150,  6449,  791.0},   /* Band 20 */
            { 6450,  6599, 1495.9},   /* Band 21 */
            { 6600,  7399, 3510.0},   /* Band 22 */
            { 7500,  7699, 1525.0},   /* Band 24 */
            { 7700,  8039, 1930.0},   /* Band 25 */
            { 8040,  8689,  859.0},   /* Band 26 */
            { 8690,  9039,  852.0},   /* Band 27 */
            { 9040,  9209,  758.0},   /* Band 28 */
            { 9210,  9659,  717.0},   /* Band 29 (SDL) */
            { 9660,  9769, 2350.0},   /* Band 30 */
            { 9770,  9869,  462.5},   /* Band 31 */
            { 9870, 10359, 1452.0},   /* Band 32 (SDL) */
            {36000, 36199, 1900.0},   /* Band 33 */
            {36200, 36349, 2010.0},   /* Band 34 */
            {36350, 36949, 1850.0},   /* Band 35 */
            {36950, 37549, 1930.0},   /* Band 36 */
            {37550, 37749, 1910.0},   /* Band 37 */
            {37750, 38249, 2570.0},   /* Band 38 */
            {38250, 38649, 1880.0},   /* Band 39 */
            {38650, 39649, 2300.0},   /* Band 40 */
            {39650, 41589, 2496.0},   /* Band 41 */
            {41590, 43589, 3400.0},   /* Band 42 */
            {43590, 45589, 3600.0},   /* Band 43 */
            {45590, 46589,  703.0},   /* Band 44 */
            {46590, 46789, 1447.0},   /* Band 45 */
            {46790, 54539, 5150.0},   /* Band 46 */
            {54540, 55239, 5855.0},   /* Band 47 */
            {55240, 56739, 3550.0},   /* Band 48 */
            {56740, 58239, 3550.0},   /* Band 49 */
            {58240, 59089, 1432.0},   /* Band 50 */
            {59090, 59139, 1427.0},   /* Band 51 */
            {59140, 60139, 3300.0},   /* Band 52 */
            {60140, 60254, 2483.5},   /* Band 53 */
            {65536, 66435,  2110.0},  /* Band 65 */
            {66436, 67335,  2110.0},  /* Band 66 */
            {67336, 67535,   738.0},  /* Band 67 (SDL) */
            {67536, 67835,   753.0},  /* Band 68 */
            {67836, 68335,  2570.0},  /* Band 69 (SDL) */
            {68336, 68585,  1995.0},  /* Band 70 */
            {68586, 68935,   617.0},  /* Band 71 */
            {68936, 68985,   461.0},  /* Band 72 */
            {68986, 69035,   460.0},  /* Band 73 */
            {69036, 69465,  1475.0},  /* Band 74 */
            {69466, 70315,  1432.0},  /* Band 75 (SDL) */
            {70316, 70365,  1427.0},  /* Band 76 (SDL) */
            {70366, 70545,   728.0},  /* Band 85 */
        };

        for (size_t i = 0; i < sizeof(lte_bands) / sizeof(lte_bands[0]); i++) {
            if (arfcn >= lte_bands[i].noffs_dl && arfcn <= lte_bands[i].noffs_dl_max) {
                double freq_mhz = lte_bands[i].fdl_low_mhz +
                    0.1 * (arfcn - lte_bands[i].noffs_dl);
                return (uint64_t)(freq_mhz * 1000.0);
            }
        }
        return 0;

    } else if (rat == "NR") {
        /* NR-ARFCN → frequency
         * 3GPP TS 38.104 Table 5.4.2.1-1:
         *   Range 0–599999:    ΔF_Global=5kHz,  F_OFFS=0,       N_OFFS=0
         *   Range 600000–2016666: ΔF_Global=15kHz, F_OFFS=3000MHz, N_OFFS=600000
         *   Range 2016667–3279165: ΔF_Global=60kHz, F_OFFS=24250.08MHz, N_OFFS=2016667
         */
        if (arfcn <= 599999) {
            return (uint64_t)arfcn * 5;                    /* 5 kHz steps */
        } else if (arfcn <= 2016666) {
            return 3000000 + (uint64_t)(arfcn - 600000) * 15;  /* 15 kHz steps */
        } else if (arfcn <= 3279165) {
            return 24250080 + (uint64_t)(arfcn - 2016667) * 60; /* 60 kHz steps */
        }
        return 0;

    } else if (rat == "WCDMA") {
        /* UARFCN → frequency (simplified: common bands only)
         * F_DL = UARFCN * 0.2 MHz for most bands */
        return (uint64_t)arfcn * 200;
    }

    return 0;
}

/* Derive LTE band number from EARFCN.
 * EARFCN ranges per 3GPP TS 36.101 Table 5.7.3-1.
 * Returns 0 if unknown. */
static int earfcn_to_band(uint32_t earfcn) {
    struct { uint32_t lo; uint32_t hi; int band; } lte[] = {
        {    0,   599,  1}, {  600,  1199,  2}, { 1200,  1949,  3},
        { 1950,  2399,  4}, { 2400,  2649,  5}, { 2650,  2749,  6},
        { 2750,  3449,  7}, { 3450,  3799,  8}, { 3800,  4149,  9},
        { 4150,  4749, 10}, { 4750,  4949, 11}, { 5010,  5179, 12},
        { 5180,  5279, 13}, { 5280,  5379, 14}, { 5730,  5849, 17},
        { 5850,  5999, 18}, { 6000,  6149, 19}, { 6150,  6449, 20},
        { 6450,  6599, 21}, { 6600,  7399, 22}, { 7500,  7699, 24},
        { 7700,  8039, 25}, { 8040,  8689, 26}, { 8690,  9039, 27},
        { 9040,  9209, 28}, { 9210,  9659, 29}, { 9660,  9769, 30},
        { 9770,  9869, 31}, { 9870, 10359, 32}, {36000, 36199, 33},
        {36200, 36349, 34}, {36350, 36949, 35}, {36950, 37549, 36},
        {37550, 37749, 37}, {37750, 38249, 38}, {38250, 38649, 39},
        {38650, 39649, 40}, {39650, 41589, 41}, {41590, 43589, 42},
        {43590, 45589, 43}, {45590, 46589, 44}, {46590, 46789, 45},
        {46790, 54539, 46}, {54540, 55239, 47}, {55240, 56739, 48},
        {56740, 58239, 49}, {58240, 59089, 50}, {59090, 59139, 51},
        {59140, 60139, 52}, {60140, 60254, 53}, {65536, 66435, 65},
        {66436, 67335, 66}, {67336, 67535, 67}, {67536, 67835, 68},
        {67836, 68335, 69}, {68336, 68585, 70}, {68586, 68935, 71},
        {68936, 68985, 72}, {68986, 69035, 73}, {69036, 69465, 74},
        {69466, 70315, 75}, {70316, 70365, 76}, {70366, 70545, 85},
    };
    for (size_t i = 0; i < sizeof(lte) / sizeof(lte[0]); i++) {
        if (earfcn >= lte[i].lo && earfcn <= lte[i].hi)
            return lte[i].band;
    }
    return 0;
}

/* Collect the observation fields this JSON object actually carried, so a
 * provenance source can advertise what it contributes (e.g. AT supplies
 * mcc/mnc/tac/cell_id, DIAG supplies rsrp/rsrq). Only keys present and
 * non-null are reported. */
static std::vector<std::string> prov_contributed_fields(nlohmann::json& json) {
    static const char *keys[] = {
        "rat", "mcc", "mnc", "tac", "cell_id", "pci", "earfcn",
        "band", "bandwidth", "rsrp", "rsrq", "sinr", "rssi",
        "operator_name", "duplex",
    };

    std::vector<std::string> out;
    for (auto k : keys) {
        auto v = json[k];
        if (!v.is_null())
            out.push_back(k);
    }

    return out;
}

void kis_cellular_phy::update_seen_via(
    const std::shared_ptr<kis_cellular_tracked_cell>& celldev,
    const std::string& src, const std::string& origin,
    double captured_at, const std::vector<std::string>& fields) {

    auto seen_via = celldev->get_cell_seen_via();

    std::shared_ptr<kis_cellular_tracked_prov_source> rec;

    auto existing = seen_via->find(src);
    if (existing == seen_via->end()) {
        rec = entrytracker->get_shared_instance_as<kis_cellular_tracked_prov_source>(
                prov_source_entry_id);
        rec->set_prov_src(src);
        seen_via->insert(src, rec);
    } else {
        rec = std::static_pointer_cast<kis_cellular_tracked_prov_source>(existing->second);
    }

    if (!origin.empty())
        rec->set_prov_origin(origin);

    // Server time is always meaningful; prov.captured_at is retained verbatim
    // but its epoch-vs-tick normalization is a separate follow-up (#2672).
    rec->set_prov_last_seen((uint64_t) time(0));
    rec->set_prov_captured_at(captured_at);
    rec->set_prov_observation_count(rec->get_prov_observation_count() + 1);

    // Union the contributed field names into the record's field list.
    auto fv = rec->get_prov_fields();
    for (const auto& f : fields) {
        bool present = false;
        for (const auto& e : *fv) {
            if (e == f) {
                present = true;
                break;
            }
        }
        if (!present)
            fv->push_back(f);
    }
}

bool kis_cellular_phy::json_to_cell(nlohmann::json& json,
    const std::shared_ptr<kis_packet>& packet) {

    // RAT is required
    auto rat_j = json["rat"];
    if (rat_j.is_null() || !rat_j.is_string())
        return false;

    std::string rat = rat_j.get<std::string>();

    // Extract identity fields
    int64_t mcc = -1, mnc = -1, tac = -1, cid = -1, pci = -1;
    uint32_t earfcn = 0;
    bool have_earfcn = false;

    auto mcc_j = json["mcc"];
    if (mcc_j.is_number())
        mcc = mcc_j.get<int64_t>();

    auto mnc_j = json["mnc"];
    if (mnc_j.is_number())
        mnc = mnc_j.get<int64_t>();

    auto tac_j = json["tac"];
    if (tac_j.is_number())
        tac = tac_j.get<int64_t>();

    auto cid_j = json["cell_id"];
    if (cid_j.is_number())
        cid = cid_j.get<int64_t>();

    auto pci_j = json["pci"];
    if (pci_j.is_number())
        pci = pci_j.get<int64_t>();

    auto earfcn_j = json["earfcn"];
    if (earfcn_j.is_number()) {
        earfcn = earfcn_j.get<uint32_t>();
        have_earfcn = true;
    }

    // Build cell key and determine identity level
    //
    // Two identity levels:
    //   "full"    — MCC + MNC + CellID known (globally unique cell identity)
    //               Minimum fields: mcc, mnc, cell_id (tac used if available)
    //               Sources: AT#RFSTS, AT#SERVINFO, AT+QENG="servingcell",
    //                        AT#CSURVC (11-field lines), AT+QSCAN
    //
    //   "partial" — Only PCI + EARFCN + RAT known (locally unique, not globally)
    //               Minimum fields: pci, earfcn
    //               Sources: AT#MONI, AT+QENG="neighbourcell", AT$QCRSRP?,
    //                        AT#CSURVC (6-field lines), AT!LTEINFO?
    //
    std::string cell_key;
    bool is_full_identity = false;

    if (mcc > 0 && mnc >= 0 && cid > 0) {
        cell_key = fmt::format("{:03d}{:03d}_{}_{}", mcc, mnc,
            (tac >= 0 ? tac : 0), cid);
        is_full_identity = true;
    } else if (pci >= 0 && have_earfcn) {
        cell_key = fmt::format("{}_pci{}_{}", rat, pci, earfcn);
    } else {
        return false;
    }

    // Convert to pseudo-MAC
    mac_addr cell_mac = cellkey_to_mac(cell_key);

    if (cell_mac.error())
        return false;

    // Populate common info
    auto common = packet->fetch_or_add<kis_common_info>(pack_comp_common);

    // Cell observations are broadcast management info received from the tower.
    // Use packet_basic_mgmt → LLC/management packet counter (not data).
    // The tower MAC goes in dest so the device tracker counts RX packets.
    // Source must be a non-zero, non-matching MAC (mac_addr(0) compares equal
    // to everything due to maskbits=0 in Kismet's mac_addr operator==).
    common->type = packet_basic_mgmt;
    common->phyid = fetch_phy_id();
    common->datasize = 0;

    // Source and transmitter must be non-zero MACs that don't match cell_mac.
    // mac_addr(0) has maskbits=0, making operator== match anything.
    // "02:CE:11:00:00:00" — locally-administered placeholder, won't collide.
    mac_addr modem_placeholder("02:CE:11:00:00:00");
    common->source = modem_placeholder;
    common->transmitter = modem_placeholder;
    common->dest = cell_mac;

    if (have_earfcn)
        common->freq_khz = arfcn_to_khz(rat, earfcn);

    // Build channel string from explicit band or EARFCN-derived band
    auto band_j = json["band"];
    int band_num = 0;
    if (band_j.is_number()) {
        band_num = band_j.get<int>();
    } else if (have_earfcn && rat == "LTE") {
        band_num = earfcn_to_band(earfcn);
    }
    if (band_num > 0) {
        common->channel = fmt::format("{} B{}", rat, band_num);
    }

    // Extract RSRP early — used for both L1 signal info and cell-specific tracking.
    // Reject observations with no signal — they produce ghost devices with no
    // useful data (zero RSRP, no band, no channel).
    auto rsrp_j = json["rsrp"];
    if (!rsrp_j.is_number() || rsrp_j.get<int>() == 0)
        return false;

    // Populate L1 radio info so the base signal tracker picks up RSRP
    {
        auto l1info = packet->fetch_or_add<kis_layer1_packinfo>(pack_comp_radiodata);

        l1info->signal_type = kis_l1_signal_type_dbm;
        l1info->signal_dbm = rsrp_j.get<int>();

        if (common->freq_khz != 0)
            l1info->freq_khz = common->freq_khz;

        if (!common->channel.empty())
            l1info->channel = common->channel;
    }

    // Update common device
    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->update_common_device(common, cell_mac, this, packet,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS |
                 UCD_UPDATE_LOCATION | UCD_UPDATE_SEENBY), "Cellular");

    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(), "cell_json_to_cell");

    // Fallback: if device has no channel yet, set generic
    if (basedev->get_channel().empty())
        basedev->set_channel("Cellular");

    // Set device type based on identity level.
    // Use KIS_DEVICE_BASICTYPE_AP to mark full-identity towers (like 802.11 APs)
    // so the conditional setter won't demote a cell back to partial.
    if (is_full_identity) {
        basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_AP);
        basedev->set_tracker_type_string(devtype_cell);
    } else {
        // Only set "Cell (Partial)" if not already a "Cell"
        auto cellular_phy = this;
        basedev->set_type_string_ifnotany([cellular_phy]() {
            return cellular_phy->devtype_cell_partial;
        }, KIS_DEVICE_BASICTYPE_AP);
    }

    if (is_full_identity) {
        basedev->set_devicename(fmt::format("{} {}", rat, cell_key));
    } else {
        /* Partial identity — build a readable name from components
         * instead of using the key (which redundantly includes RAT) */
        if (band_num > 0)
            basedev->set_devicename(fmt::format("{} PCI {} B{}", rat, pci, band_num));
        else
            basedev->set_devicename(fmt::format("{} PCI {} EARFCN {}", rat, pci, earfcn));
    }

    // Get or create cell tower sub-device
    auto celldev =
        basedev->get_sub_as<kis_cellular_tracked_cell>(cell_device_entry_id);

    if (celldev == NULL) {
        celldev = Globalreg::globalreg->entrytracker->get_shared_instance_as<kis_cellular_tracked_cell>(cell_device_entry_id);
        basedev->insert(celldev);

        if (is_full_identity) {
            _MSG_INFO("Detected new cell {} {}", rat, cell_key);
        } else {
            if (band_num > 0)
                _MSG_INFO("Detected new cell (partial) {} PCI {} B{} EARFCN {}",
                          rat, pci, band_num, earfcn);
            else
                _MSG_INFO("Detected new cell (partial) {} PCI {} EARFCN {}",
                          rat, pci, earfcn);
        }
    }

    // Update identity fields
    if (mcc >= 0)
        celldev->set_cell_mcc(mcc);
    if (mnc >= 0)
        celldev->set_cell_mnc(mnc);
    if (tac >= 0)
        celldev->set_cell_tac(tac);
    if (cid >= 0)
        celldev->set_cell_cellid(cid);
    if (pci >= 0)
        celldev->set_cell_pci(pci);

    celldev->set_cell_key(cell_key);
    celldev->set_cell_identity_level(is_full_identity ? "full" : "partial");

    // Related-device linking between full-identity and PCI-only devices.
    //
    // Two directions:
    // 1. Full-identity observation with PCI+EARFCN → register in lookup table,
    //    and link to any existing PCI-only device.
    // 2. PCI-only observation → check lookup table for a known full-identity
    //    tower with that PCI+EARFCN, and link if found.
    //
    if (pci >= 0 && have_earfcn) {
        std::string pci_earfcn_key = fmt::format("{}_{}", pci, earfcn);

        if (is_full_identity) {
            // Register this tower's PCI+EARFCN in the lookup table
            pci_to_full_identity[pci_earfcn_key] = basedev->get_key();

            // Link to existing PCI-only device if it exists
            std::string pci_cell_key = fmt::format("{}_pci{}_{}", rat, pci, earfcn);
            mac_addr pci_mac = cellkey_to_mac(pci_cell_key);

            if (!pci_mac.error()) {
                device_key pci_devkey(fetch_phyname_hash(), pci_mac);
                auto pci_dev = devicetracker->fetch_device_nr(pci_devkey);

                if (pci_dev != nullptr) {
                    basedev->add_related_device("cell_identity", pci_devkey);
                    pci_dev->add_related_device("cell_identity", basedev->get_key());
                }
            }
        } else {
            // PCI-only observation — check if we know the full identity
            auto it = pci_to_full_identity.find(pci_earfcn_key);
            if (it != pci_to_full_identity.end()) {
                auto full_dev = devicetracker->fetch_device_nr(it->second);

                if (full_dev != nullptr) {
                    basedev->add_related_device("cell_identity", it->second);
                    full_dev->add_related_device("cell_identity", basedev->get_key());
                }
            }
        }
    }

    auto oper_j = json["operator_name"];
    if (oper_j.is_string())
        celldev->set_cell_operator(oper_j.get<std::string>());

    // Update network fields
    celldev->set_cell_rat(rat);

    auto duplex_j = json["duplex"];
    if (duplex_j.is_string())
        celldev->set_cell_duplex(duplex_j.get<std::string>());

    if (have_earfcn)
        celldev->set_cell_arfcn(earfcn);

    if (band_num > 0)
        celldev->set_cell_band(band_num);

    auto bw_j = json["bandwidth"];
    if (bw_j.is_number())
        celldev->set_cell_bandwidth(bw_j.get<int>());

    // Update signal fields
    if (rsrp_j.is_number()) {
        int16_t rsrp = rsrp_j.get<int16_t>();
        celldev->set_cell_rsrp(rsrp);

        // Track min/max RSRP
        if (celldev->get_cell_min_rsrp() == 0 || rsrp < celldev->get_cell_min_rsrp())
            celldev->set_cell_min_rsrp(rsrp);
        if (celldev->get_cell_max_rsrp() == 0 || rsrp > celldev->get_cell_max_rsrp())
            celldev->set_cell_max_rsrp(rsrp);
    }

    auto rsrq_j = json["rsrq"];
    if (rsrq_j.is_number())
        celldev->set_cell_rsrq(rsrq_j.get<int16_t>());

    auto sinr_j = json["sinr"];
    if (sinr_j.is_number())
        celldev->set_cell_sinr(sinr_j.get<int16_t>());

    auto rssi_j = json["rssi"];
    if (rssi_j.is_number())
        celldev->set_cell_rssi(rssi_j.get<int16_t>());

    // Update observation count
    celldev->set_cell_observation_count(celldev->get_cell_observation_count() + 1);

    // Update serving/neighbor flags
    auto serving_j = json["is_serving"];
    if (serving_j.is_boolean() && serving_j.get<bool>())
        celldev->set_cell_seen_serving(true);

    auto obs_type_j = json["observation_type"];
    if (obs_type_j.is_string() && obs_type_j.get<std::string>() == "observation")
        celldev->set_cell_seen_observed(true);

    // Provenance (M3.3): record which capture pipe supplied this observation and
    // which fields it contributed, keyed by source name in celldev->seen_via.
    // Both capture_cell_at and capture_cell_diag stamp a prov block; a tower fed
    // by both ends up with two seen_via entries (identity from at, signal from diag).
    auto prov_j = json["prov"];
    if (prov_j.is_object()) {
        auto psrc_j = prov_j["src"];
        if (psrc_j.is_string()) {
            std::string psrc = psrc_j.get<std::string>();

            std::string porigin;
            auto porigin_j = prov_j["origin"];
            if (porigin_j.is_string())
                porigin = porigin_j.get<std::string>();

            double pcaptured = 0.0;
            auto pcap_j = prov_j["captured_at"];
            if (pcap_j.is_number())
                pcaptured = pcap_j.get<double>();

            update_seen_via(celldev, psrc, porigin, pcaptured,
                            prov_contributed_fields(json));
        }
    }

    return true;
}
