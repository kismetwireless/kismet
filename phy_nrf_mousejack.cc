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

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <memory>

#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "phy_nrf_mousejack.h"
#include "kis_httpd_registry.h"
#include "devicetracker.h"
#include "dlttracker.h"
#include "manuf.h"
#include "messagebus.h"

Kis_Mousejack_Phy::Kis_Mousejack_Phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("NrfMousejack");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();
    alertracker =
        Globalreg::fetch_mandatory_global_as<alert_tracker>();

    mousejack_device_entry_id =
        entrytracker->register_field("nrfmousejack.device",
                tracker_element_factory<mousejack_tracked_device>(),
                "NRF Mousejack device");

	pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_nrf = packetchain->register_packet_component("NRFESB");

    // Extract the dynamic DLT
    auto dltt =
        Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");
    dlt = dltt->register_linktype("NRFMOUSEJACK");

    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_nrf_mousejack", "js/kismet.ui.nrf_mousejack.js");

    // Make the manuf string
    mj_manuf_amazon = Globalreg::globalreg->manufdb->make_manuf("Amazon");
    mj_manuf_logitech = Globalreg::globalreg->manufdb->make_manuf("Logitech");
    mj_manuf_microsoft = Globalreg::globalreg->manufdb->make_manuf("Microsoft");
    mj_manuf_nrf = Globalreg::globalreg->manufdb->make_manuf("nRF/Mousejack HID");

    alert_plaintext_ref =
        alertracker->activate_configured_alert("NRFPLAINTEXTKEYS",
                "EXPLOIT", kis_alert_severity::high,
                "An nRF24 keyboard sends its keystrokes unencrypted (a Logitech 0xC1 report): "
                "anyone in radio range can read what is typed.", phyid);

    packetchain->register_handler(&DissectorMousejack, this, CHAINPOS_LLCDISSECT, -100);
    packetchain->register_handler(&CommonClassifierMousejack, this, CHAINPOS_CLASSIFIER, -100);
}

Kis_Mousejack_Phy::~Kis_Mousejack_Phy() {
    packetchain->remove_handler(&DissectorMousejack, CHAINPOS_LLCDISSECT);
    packetchain->remove_handler(&CommonClassifierMousejack, CHAINPOS_CLASSIFIER);
}

/*
 * Two sources, one packet: the address, the payload, and from an SDR's pcap the channel, rate and
 * signal. A dongle packet (NRFMOUSEJACK) is the research firmware's promiscuous-mode buffer: the
 * 5-byte address, then the payload. A pcap packet (user link type 147) carries the "ESB" header
 * (phy_nrf_mousejack.h); one whose CRC failed is counted as an error and not attributed.
 */
int Kis_Mousejack_Phy::DissectorMousejack(CHAINCALL_PARMS) {
    auto mphy = static_cast<Kis_Mousejack_Phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == NULL)
        return 0;

    if (in_pack->common_info.common_info_ok)
        return 0;

    // Every phy's packets pass through here; check the link type before making anything
    if (packdata->dlt != mphy->dlt && packdata->dlt != nrf_esb_dlt)
        return 0;

    const auto *d = reinterpret_cast<const uint8_t *>(packdata->data());
    const size_t len = packdata->length();
    auto pi = mphy->packetchain->new_packet_component<kis_nrf_packinfo>();
    const uint8_t *addr = nullptr;

    if (packdata->dlt == mphy->dlt) {
        // The firmware answers "nothing received" with one octet, which the capture helper skips
        if (len < 5)
            return 0;

        addr = d;
        pi->addr_len = 5;
        pi->payload.assign(reinterpret_cast<const char *>(d + 5), len - 5);
    } else if (packdata->dlt == nrf_esb_dlt) {
        if (len < nrf_esb_hdr_len || d[0] != 'E' || d[1] != 'S' || d[2] != 'B' || d[3] != 1)
            return 0;

        const unsigned int alen = d[8], plen = d[9];

        if (alen < 3 || alen > 5 || plen > 32 || len != nrf_esb_hdr_len + alen + plen + 2 || d[4] > 125)
            return 0;

        if (!(d[5] & 0x02)) {
            // a packet of a known address whose CRC failed: seen, but whose it is is not sure
            in_pack->error = 1;
            return 0;
        }

        addr = d + nrf_esb_hdr_len;
        pi->addr_len = (int) alen;
        pi->payload.assign(reinterpret_cast<const char *>(addr + alen), plen);
        pi->rf_channel = d[4];
        pi->rate_kbps = (d[5] & 0x01) ? 2000 : 1000;
        pi->crc_known = true;

        // The signal, channel and frequency, unless the datasource set them
        if (!in_pack->signal_info.data_ok) {
            auto& si = in_pack->signal_info;

            si.signal_type = kis_l1_signal_type_dbm;
            si.signal_dbm = (int8_t) d[7];
            si.channel = fmt::format("{}", d[4]);
            si.freq_khz = (2400 + d[4]) * 1000.0;
            si.data_ok = true;
        }
    } else {
        return 0;
    }

    in_pack->common_info.common_info_ok = true;
    in_pack->common_info.phyid = mphy->fetch_phy_id();
    in_pack->common_info.basic_crypt_set = KIS_DEVICE_BASICCRYPT_NONE;
    in_pack->common_info.type = packet_basic_data;
    in_pack->common_info.source = mac_addr(addr, (unsigned int) pi->addr_len);

    // A Logitech encrypted keystroke report: the device encrypts
    if (pi->payload.length() == 22 && (uint8_t) pi->payload[1] == 0xD3)
        in_pack->common_info.basic_crypt_set = KIS_DEVICE_BASICCRYPT_ENCRYPTED;

    in_pack->insert(mphy->pack_comp_nrf, pi);

    return 1;
}

// A Logitech Unifying / Lightspeed payload: device index, frame type, ..., a checksum that makes the
// octets sum to 0 mod 256
static bool logitech_payload(const std::string& p) {
    if (p.length() < 3)
        return false;

    unsigned int sum = 0;
    for (auto c : p)
        sum += (uint8_t) c;

    return (sum & 0xff) == 0;
}

int Kis_Mousejack_Phy::CommonClassifierMousejack(CHAINCALL_PARMS) {
    auto mphy = static_cast<Kis_Mousejack_Phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == nullptr)
        return 0;

    // Is it a packet we care about?
    if (packdata->dlt != mphy->dlt && packdata->dlt != nrf_esb_dlt)
        return 0;

    if (!in_pack->common_info.common_info_ok)
        return 0;

    auto pi = in_pack->fetch<kis_nrf_packinfo>(mphy->pack_comp_nrf);

    if (pi == nullptr)
        return 0;

    const auto source = in_pack->common_info.source;
    bool raise_plaintext = false;

    {
        auto device =
            mphy->devicetracker->update_common_device(source,
                    mphy, in_pack,
                    (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                     UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                     UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                    "KB/Mouse");

        kis_lock_guard<kis_mutex> lk(mphy->devicetracker->get_devicelist_mutex(), "common_classifier_mousejack");

        auto nrf =
            device->get_sub_as<mousejack_tracked_device>(mphy->mousejack_device_entry_id);

        if (nrf == NULL) {
            _MSG_INFO("Detected new nRF cordless input device (mouse, keyboard, etc) {}",
                    source.mac_to_string());
            nrf = Globalreg::globalreg->entrytracker->get_shared_instance_as<mousejack_tracked_device>(mphy->mousejack_device_entry_id);
            device->insert(nrf);
            device->set_manuf(mphy->mj_manuf_nrf);
        }

        nrf->set_addr_len((uint8_t) pi->addr_len);
        if (pi->rate_kbps)
            nrf->set_rate_kbps(pi->rate_kbps);
        if (pi->rf_channel >= 0)
            nrf->set_rf_channel((int16_t) pi->rf_channel);

        // Fingerprints on the payload (the MouseJack research's), Logitech's checked by its checksum
        const auto& p = pi->payload;
        const size_t n = p.length();
        const uint8_t t = n >= 2 ? (uint8_t) p[1] : 0;
        bool logitech = false;

        if (n == 0) {
            // an acknowledgement, which the device's receiver sends with the device's address
            nrf->inc_acks(1);
        } else if (logitech_payload(p) && p[0] == 0x00 &&
                ((n == 10 && (t == 0xC2 || t == 0xC1 || t == 0x4F)) || (n == 22 && t == 0xD3) || (n == 5 && t == 0x40))) {
            logitech = true;

            if (t == 0xC2)
                nrf->inc_mouse_reports(1);
            else if (t == 0xD3)
                nrf->inc_encrypted_keys(1);
            else if (t == 0xC1)
                nrf->inc_plaintext_keys(1);
            else
                nrf->inc_keepalives(1);
        } else if (n == 19 && ((p[0] == 0x08 || p[0] == 0x0c) && p[6] == 0x40)) {
            device->set_manuf(mphy->mj_manuf_microsoft);
            nrf->set_kind("Microsoft device");
            nrf->inc_other_packets(1);
        } else if (n == 19 && p[0] == 0x0a) {
            device->set_manuf(mphy->mj_manuf_microsoft);
            nrf->set_kind("Microsoft device");
            nrf->inc_other_packets(1);
        } else if (n == 6) {
            device->set_manuf(mphy->mj_manuf_amazon);
            nrf->inc_other_packets(1);
        } else {
            nrf->inc_other_packets(1);
        }

        if (logitech) {
            device->set_manuf(mphy->mj_manuf_logitech);

            // A Unifying receiver's devices share its first four address octets
            if (pi->addr_len == 5)
                nrf->set_receiver(fmt::format("{:02X}:{:02X}:{:02X}:{:02X}",
                            source[0], source[1], source[2], source[3]));
        }

        // What it is and how it protects what it sends, from everything it has sent
        const bool keys = nrf->get_encrypted_keys() || nrf->get_plaintext_keys(), mouse = nrf->get_mouse_reports() != 0;

        if (logitech || keys || mouse) {
            const std::string kind = keys && mouse ? "Logitech keyboard and mouse" :
                keys ? "Logitech keyboard" : mouse ? "Logitech mouse" : nrf->get_kind().empty() ? "Logitech device" : nrf->get_kind();

            nrf->set_kind(kind);
            device->set_tracker_type_string(mphy->devicetracker->get_cached_devicetype(kind));
        }

        if (nrf->get_plaintext_keys())
            device->set_crypt_string("None: unencrypted keystrokes");
        else if (nrf->get_encrypted_keys())
            device->set_crypt_string("AES (Logitech)");
        else if (mouse)
            device->set_crypt_string("None (mouse reports)");

        if (logitech && t == 0xC1) {
            kis_lock_guard<kis_mutex> alk(mphy->alert_mutex, "mousejack_plaintext_alert");
            raise_plaintext = mphy->plaintext_alerted.insert(source).second;
        }
    }

    if (raise_plaintext &&
            mphy->alertracker->raise_alert(mphy->alert_plaintext_ref, in_pack, mac_addr{}, source,
                mac_addr{}, mac_addr{}, in_pack->signal_info.channel,
                fmt::format("nRF24 keyboard {} sends unencrypted keystrokes (Logitech 0xC1 reports): "
                    "anyone in radio range can read what is typed", source.mac_to_string())) != 1) {
        // held back by the rate limit: a later report raises it
        kis_lock_guard<kis_mutex> alk(mphy->alert_mutex, "mousejack_plaintext_alert");
        mphy->plaintext_alerted.erase(source);
    }

    return 1;
}

void Kis_Mousejack_Phy::load_phy_storage(shared_tracker_element in_storage,
        shared_tracker_element in_device) {
    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    auto nrfdevi = storage->find(mousejack_device_entry_id);

    if (nrfdevi != storage->end()) {
        auto nrfdev =
            std::make_shared<mousejack_tracked_device>(mousejack_device_entry_id,
                    std::static_pointer_cast<tracker_element_map>(nrfdevi->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(nrfdev);
    }
}

