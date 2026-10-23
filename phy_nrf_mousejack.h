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

#ifndef __PHY_NRF_MOUSEJACK_H__
#define __PHY_NRF_MOUSEJACK_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "alertracker.h"
#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "packet.h"
#include "gpstracker.h"
#include "uuid.h"

#include "devicetracker.h"
#include "devicetracker_component.h"

/*
 * Nordic Enhanced ShockBurst (nRF24L01+ and the radios like it: Logitech Unifying, Microsoft and
 * other wireless mice, keyboards and presenters), from two kinds of source:
 *
 *  - the nRF24LU1+ dongles (CrazyRadio PA and the like) running Bastille's research firmware, through
 *    kismet_cap_nrf_mousejack: the internal link type NRFMOUSEJACK, each packet as the firmware's
 *    promiscuous mode returns it: the 5-byte address, then the payload (its CRC checked by the
 *    firmware and left out, the packet control field left out);
 *
 *  - SDR receivers that write Enhanced ShockBurst packets as pcap, such as w1700k's wifi-rx
 *    --esb-pcap, read with the pcapfile source: user link type 147 with the header below.
 */

// LINKTYPE_USER0, as an ESB packet with a 12-byte header: 'E' 'S' 'B', version 1, the RF channel
// (MHz - 2400), flags (bit 0 2 Mbps, bit 1 CRC ok, bit 2 NO_ACK, bit 3 bits repaired to make the
// CRC check), the PID, the signal in dBm (int8), the address length (3-5), the payload length
// (0-32), two reserved octets; then the address, the payload and the 2-byte CRC as sent.
constexpr int nrf_esb_dlt = 147;
constexpr size_t nrf_esb_hdr_len = 12;

// Per-packet ESB info the classifier needs beyond the common info
class kis_nrf_packinfo : public packet_component {
public:
    kis_nrf_packinfo() { }

    void reset() {
        addr_len = 0;
        payload.clear();
        rf_channel = -1;
        rate_kbps = 0;
        crc_known = false;
    }

    int addr_len = 0;
    std::string payload;        // the payload, without the PCF or CRC
    int rf_channel = -1;        // 0-125 when the source gives it
    unsigned int rate_kbps = 0; // 1000 or 2000 when the source gives it
    bool crc_known = false;     // the source checked a CRC we saw (pcap); the dongle checks its own
};

class mousejack_tracked_device : public tracker_component {
public:
    mousejack_tracked_device() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    mousejack_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    mousejack_tracked_device(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    mousejack_tracked_device(const mousejack_tracked_device *p) :
        tracker_component{p} {

        __ImportField(kind, p);
        __ImportField(receiver, p);
        __ImportField(addr_len, p);
        __ImportField(rate_kbps, p);
        __ImportField(rf_channel, p);
        __ImportField(mouse_reports, p);
        __ImportField(encrypted_keys, p);
        __ImportField(plaintext_keys, p);
        __ImportField(keepalives, p);
        __ImportField(acks, p);
        __ImportField(other_packets, p);

        reserve_fields(nullptr);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("mousejack_tracked_device");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(kind, std::string, std::string, std::string, kind);
    __Proxy(receiver, std::string, std::string, std::string, receiver);
    __Proxy(addr_len, uint8_t, uint8_t, uint8_t, addr_len);
    __Proxy(rate_kbps, uint32_t, uint32_t, uint32_t, rate_kbps);
    __Proxy(rf_channel, int16_t, int16_t, int16_t, rf_channel);
    __Proxy(mouse_reports, uint64_t, uint64_t, uint64_t, mouse_reports);
    __ProxyIncDec(mouse_reports, uint64_t, uint64_t, mouse_reports);
    __Proxy(encrypted_keys, uint64_t, uint64_t, uint64_t, encrypted_keys);
    __ProxyIncDec(encrypted_keys, uint64_t, uint64_t, encrypted_keys);
    __Proxy(plaintext_keys, uint64_t, uint64_t, uint64_t, plaintext_keys);
    __ProxyIncDec(plaintext_keys, uint64_t, uint64_t, plaintext_keys);
    __Proxy(keepalives, uint64_t, uint64_t, uint64_t, keepalives);
    __ProxyIncDec(keepalives, uint64_t, uint64_t, keepalives);
    __Proxy(acks, uint64_t, uint64_t, uint64_t, acks);
    __ProxyIncDec(acks, uint64_t, uint64_t, acks);
    __Proxy(other_packets, uint64_t, uint64_t, uint64_t, other_packets);
    __ProxyIncDec(other_packets, uint64_t, uint64_t, other_packets);

protected:

    virtual void register_fields() override {
        register_field("nrfmousejack.device.kind", "Device kind: Logitech keyboard, Logitech mouse, ...", &kind);
        register_field("nrfmousejack.device.receiver",
                "The receiver (dongle) the device is paired with: a Logitech address's first four octets", &receiver);
        register_field("nrfmousejack.device.addr_len", "Address length (octets)", &addr_len);
        register_field("nrfmousejack.device.rate_kbps", "Data rate (kbit/s, 0 if not known)", &rate_kbps);
        register_field("nrfmousejack.device.rf_channel", "Last RF channel (MHz - 2400, -1 if not known)", &rf_channel);
        register_field("nrfmousejack.device.mouse_reports", "Mouse reports", &mouse_reports);
        register_field("nrfmousejack.device.encrypted_keys", "Encrypted keystroke reports", &encrypted_keys);
        register_field("nrfmousejack.device.plaintext_keys", "Unencrypted keystroke reports", &plaintext_keys);
        register_field("nrfmousejack.device.keepalives", "Keep-alives", &keepalives);
        register_field("nrfmousejack.device.acks", "Acknowledgements (empty payloads, from its receiver)", &acks);
        register_field("nrfmousejack.device.other_packets", "Other packets", &other_packets);
    }

    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);

        if (e == nullptr)
            set_rf_channel(-1);
    }

    std::shared_ptr<tracker_element_string> kind;
    std::shared_ptr<tracker_element_string> receiver;
    std::shared_ptr<tracker_element_uint8> addr_len;
    std::shared_ptr<tracker_element_uint32> rate_kbps;
    std::shared_ptr<tracker_element_int16> rf_channel;
    std::shared_ptr<tracker_element_uint64> mouse_reports;
    std::shared_ptr<tracker_element_uint64> encrypted_keys;
    std::shared_ptr<tracker_element_uint64> plaintext_keys;
    std::shared_ptr<tracker_element_uint64> keepalives;
    std::shared_ptr<tracker_element_uint64> acks;
    std::shared_ptr<tracker_element_uint64> other_packets;
};

class Kis_Mousejack_Phy : public kis_phy_handler {
public:
    Kis_Mousejack_Phy() :
        kis_phy_handler() { }

    Kis_Mousejack_Phy(int in_phyid);

    virtual ~Kis_Mousejack_Phy();

    virtual kis_phy_handler *create_phy_handler(int in_phyid) {
        return new Kis_Mousejack_Phy(in_phyid);
    }

    static int DissectorMousejack(CHAINCALL_PARMS);
    static int CommonClassifierMousejack(CHAINCALL_PARMS);

    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device);


protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<alert_tracker> alertracker;

    int mousejack_device_entry_id;
    int dev_comp_common;
    int pack_comp_linkframe;
    int pack_comp_nrf;

    int dlt;

    std::shared_ptr<tracker_element_string> mj_manuf_amazon;
    std::shared_ptr<tracker_element_string> mj_manuf_logitech;
    std::shared_ptr<tracker_element_string> mj_manuf_microsoft;
    std::shared_ptr<tracker_element_string> mj_manuf_nrf;

    // NRFPLAINTEXTKEYS, once per device
    int alert_plaintext_ref;
    kis_mutex alert_mutex;
    std::set<mac_addr> plaintext_alerted;
};

#endif

