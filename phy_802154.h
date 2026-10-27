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

#ifndef __PHY_802154_H__
#define __PHY_802154_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "packet.h"
#include "gpstracker.h"
#include "uuid.h"

#include "alertracker.h"
#include "devicetracker.h"
#include "devicetracker_component.h"

#include "tap_802_15_4.h"
#include "zigbee_crypto.h"

#include <atomic>
#include <deque>
#include <set>
#include <unordered_map>

#ifndef KDLT_IEEE802_15_4_TAP
#define KDLT_IEEE802_15_4_TAP             283
#endif

#ifndef KDLT_IEEE802_15_4_NOFCS
#define KDLT_IEEE802_15_4_NOFCS           230
#endif

// Per-packet 802.15.4 info the classifier needs beyond the common info
class kis_802154_packinfo : public packet_component {
public:
    kis_802154_packinfo() { }

    void reset() {
        src_pan = 0;
        has_src_pan = false;
        network = network_kind::unknown;
        pan_coordinator = false;
        beacon = false;
        stack_profile = 0;
        ext_pan_id.clear();
        network_name.clear();
        nwk_src = 0xFFFF;
        has_nwk_ieee = false;
        nwk_secured = false;
        has_gpd_srcid = false;
        gpd_srcid = 0;
        weak_keys = 0;
        aps_key_name.clear();
        nwk_key_name.clear();
        nwk_key.clear();
        exposed_key.clear();
        exposed_key_type.clear();
        key_checked = false;
        key_matched = false;
        user_key_name.clear();
    }

    // PAN ID of the sender; only present if the frame carries one (directly, or as the
    // destination PAN when the PAN ID is compressed)
    uint16_t src_pan = 0;
    bool has_src_pan = false;

    // What the payload says about the network, in rising order of certainty
    enum class network_kind : uint8_t { unknown = 0, lowpan, zigbee_gp, zigbee, thread };
    network_kind network = network_kind::unknown;

    bool beacon = false;                // a beacon frame
    bool pan_coordinator = false;       // its superframe specification's PAN coordinator bit
    uint8_t stack_profile = 0;          // Zigbee beacon: 1 Zigbee, 2 Zigbee PRO
    std::string ext_pan_id;             // the extended PAN ID of a Zigbee or Thread beacon
    std::string network_name;           // a Thread 1.1 beacon's network name

    // The Zigbee NWK header: its source short address and, when it carries it, the source's IEEE
    // address (most significant octet first), and whether the NWK payload is secured
    uint16_t nwk_src = 0xFFFF;
    bool has_nwk_ieee = false;
    uint8_t nwk_ieee[8] = {0};
    bool nwk_secured = false;

    // A Zigbee Green Power frame's GPD source ID, which names its sender when the frame has no
    // MAC source address
    bool has_gpd_srcid = false;
    uint32_t gpd_srcid = 0;
    // Keys anyone can know that the frame shows in use: a Transport Key command sent without APS
    // security, APS security under a known link key (or the keys hashed from it), NWK security
    // under a known network key; the known key's name (and the network key)
    static constexpr uint8_t weak_key_clear_transport = 0x01;
    static constexpr uint8_t weak_key_aps = 0x02;
    static constexpr uint8_t weak_key_nwk = 0x04;
    uint8_t weak_keys = 0;
    std::string aps_key_name;
    std::string nwk_key_name;
    std::string nwk_key;

    // The key a Transport Key command carried, readable because of one of these, and its type
    std::string exposed_key;
    std::string exposed_key_type;

    // A secured NWK or APS frame was checked against the publicly known keys, and one of them
    // matched (its MIC verified)
    bool key_checked = false;
    bool key_matched = false;

    // The name of the user's key (zigbee_key=) that matched, when one did
    std::string user_key_name;
};

// A key the user gave (zigbee_key=name,key): tried after the publicly known keys, as the network
// key and as a link key (by key identifier: the key itself, its key-transport and key-load keys)
struct zigbee_user_key {
    std::string name;
    zigbee_crypto::key_ciphers ciphers;
};

// The key check's outcome for a device
enum class zigbee_key_state : uint8_t {
    none = 0,           // no secured frame checked, no key seen
    not_known = 1,      // secured frames checked, no known key matched
    known = 2,          // a publicly known or exposed key seen in use
    user = 3,           // one of the user's keys (zigbee_key=) in use
};

/* Largely a placeholder for future possible data; right now we can't decode
 * much of anything */
class kis_802154_tracked_device : public tracker_component {
public:
    kis_802154_tracked_device() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    kis_802154_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    kis_802154_tracked_device(int in_id,
        std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("802154_tracked_device");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(pan_id, uint16_t, uint16_t, uint16_t, pan_id);
    __Proxy(network_type, std::string, std::string, std::string, network_type);
    __Proxy(role, std::string, std::string, std::string, role);
    __Proxy(short_addr, uint16_t, uint16_t, uint16_t, short_addr);
    __Proxy(ieee_addr, mac_addr, mac_addr, mac_addr, ieee_addr);
    __Proxy(ext_pan_id, std::string, std::string, std::string, ext_pan_id);
    __Proxy(network_name, std::string, std::string, std::string, network_name);
    __Proxy(stack_profile, uint8_t, uint8_t, uint8_t, stack_profile);
    __Proxy(network_rank, uint8_t, uint8_t, uint8_t, network_rank);
    __Proxy(gpd_srcid, uint32_t, uint32_t, uint32_t, gpd_srcid);
    // Only created once the key check has something to say
    __ProxyDynamic(weak_keys, uint8_t, uint8_t, uint8_t, weak_keys, weak_keys_id);
    __ProxyDynamic(weak_key, std::string, std::string, std::string, weak_key, weak_key_id);
    __ProxyDynamic(exposed_key, std::string, std::string, std::string, exposed_key, exposed_key_id);
    __ProxyDynamic(known_link_key, std::string, std::string, std::string, known_link_key,
            known_link_key_id);
    __ProxyDynamic(known_network_key, std::string, std::string, std::string, known_network_key,
            known_network_key_id);
    __ProxyDynamic(key_state, uint8_t, zigbee_key_state, zigbee_key_state, key_state, key_state_id);
    __ProxyDynamic(key_status, std::string, std::string, std::string, key_status, key_status_id);
    __ProxyDynamic(key_first_time, uint64_t, uint64_t, uint64_t, key_first_time, key_first_time_id);
    __ProxyDynamic(key_frames, uint64_t, uint64_t, uint64_t, key_frames, key_frames_id);
    __ProxyDynamic(key_frames_matched, uint64_t, uint64_t, uint64_t, key_frames_matched,
            key_frames_matched_id);
    __ProxyDynamic(user_key, std::string, std::string, std::string, user_key, user_key_id);

protected:

    virtual void register_fields() override {
        register_field("802154.device.pan_id", "PAN ID (0xFFFF if not seen)", &pan_id);
        register_field("802154.device.network_type", "Network: Zigbee, Zigbee Green Power, Thread, 6LoWPAN", &network_type);
        register_field("802154.device.role", "Role: PAN coordinator, router", &role);
        register_field("802154.device.short_addr", "Short address (0xFFFF if not seen)", &short_addr);
        register_field("802154.device.ieee_addr", "IEEE (EUI-64) address learned for a short address", &ieee_addr);
        register_field("802154.device.ext_pan_id", "Extended PAN ID", &ext_pan_id);
        register_field("802154.device.network_name", "Network name (Thread)", &network_name);
        register_field("802154.device.stack_profile", "Zigbee stack profile (1 Zigbee, 2 Zigbee PRO)", &stack_profile);
        register_field("802154.device.network_rank", "Certainty of network_type (internal)", &network_rank);
        register_field("802154.device.gpd_srcid", "Zigbee Green Power source ID (0 if not seen)", &gpd_srcid);
        weak_keys_id =
            register_dynamic_field("802154.device.weak_keys", "Publicly known keys seen in use (bitmask, internal)", &weak_keys);
        weak_key_id =
            register_dynamic_field("802154.device.weak_key", "Publicly known keys seen in use", &weak_key);
        exposed_key_id =
            register_dynamic_field("802154.device.exposed_key", "A key its Transport Key command exposed", &exposed_key);
        known_link_key_id =
            register_dynamic_field("802154.device.known_link_key", "The publicly known link key its APS security uses", &known_link_key);
        known_network_key_id =
            register_dynamic_field("802154.device.known_network_key", "The publicly known network key its NWK security uses", &known_network_key);
        key_state_id =
            register_dynamic_field("802154.device.key_state", "Key check: 0 nothing checked, 1 no known key, 2 a known or exposed key in use, 3 a key of the user's (zigbee_key) in use", &key_state);
        user_key_id =
            register_dynamic_field("802154.device.user_key", "The name of the user's key (zigbee_key) its frames matched", &user_key);
        key_status_id =
            register_dynamic_field("802154.device.key_status", "Key check, in words", &key_status);
        key_first_time_id =
            register_dynamic_field("802154.device.key_first_time", "When a known or exposed key was first seen in use", &key_first_time);
        key_frames_id =
            register_dynamic_field("802154.device.key_frames", "Secured NWK and APS frames checked against the publicly known keys", &key_frames);
        key_frames_matched_id =
            register_dynamic_field("802154.device.key_frames_matched", "Secured frames a publicly known key matched", &key_frames_matched);
    }

    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);

        // 0xFFFF is the broadcast PAN, which a sender's own PAN never is
        if (e == nullptr) {
            set_pan_id(0xFFFF);
            set_short_addr(0xFFFF);
        }
    }

    std::shared_ptr<tracker_element_uint16> pan_id;
    std::shared_ptr<tracker_element_string> network_type;
    std::shared_ptr<tracker_element_string> role;
    std::shared_ptr<tracker_element_uint16> short_addr;
    std::shared_ptr<tracker_element_mac_addr> ieee_addr;
    std::shared_ptr<tracker_element_string> ext_pan_id;
    std::shared_ptr<tracker_element_string> network_name;
    std::shared_ptr<tracker_element_uint8> stack_profile;
    std::shared_ptr<tracker_element_uint8> network_rank;
    std::shared_ptr<tracker_element_uint32> gpd_srcid;
    std::shared_ptr<tracker_element_uint8> weak_keys;
    uint16_t weak_keys_id;
    std::shared_ptr<tracker_element_string> weak_key;
    uint16_t weak_key_id;
    std::shared_ptr<tracker_element_string> exposed_key;
    uint16_t exposed_key_id;
    std::shared_ptr<tracker_element_string> known_link_key;
    uint16_t known_link_key_id;
    std::shared_ptr<tracker_element_string> known_network_key;
    uint16_t known_network_key_id;
    std::shared_ptr<tracker_element_uint8> key_state;
    uint16_t key_state_id;
    std::shared_ptr<tracker_element_string> key_status;
    uint16_t key_status_id;
    std::shared_ptr<tracker_element_uint64> key_first_time;
    uint16_t key_first_time_id;
    std::shared_ptr<tracker_element_uint64> key_frames;
    uint16_t key_frames_id;
    std::shared_ptr<tracker_element_uint64> key_frames_matched;
    uint16_t key_frames_matched_id;
    std::shared_ptr<tracker_element_string> user_key;
    uint16_t user_key_id;
};

class kis_802154_phy : public kis_phy_handler {
public:
    kis_802154_phy() :
        kis_phy_handler() { }

    kis_802154_phy(int in_phyid);

    virtual ~kis_802154_phy();

    virtual kis_phy_handler *create_phy_handler(int in_phyid) {
        return new kis_802154_phy(in_phyid);
    }

    static int dissector802154(CHAINCALL_PARMS);
    static int commonclassifier802154(CHAINCALL_PARMS);

    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device);


protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<alert_tracker> alertracker;

    int kis_802154_device_entry_id;
    int dev_comp_common;
    int pack_comp_linkframe;
    int pack_comp_802154;

    int dlt;

    // PAN + short address -> the IEEE address a Zigbee NWK header gave for it, so a device seen
    // only by its short address gets its EUI-64 (and manufacturer).  Bounded, oldest entry first
    // out, so spoofed NWK headers can't grow it without limit.
    static constexpr size_t ieee_map_max = 4096;
    kis_mutex ieee_map_mutex;
    std::unordered_map<uint32_t, mac_addr> ieee_by_short;
    std::deque<uint32_t> ieee_by_short_order;

    void learn_ieee(uint32_t pan_short, const mac_addr& ieee);

    // The ZIGBEEWEAKKEY alert, raised once per PAN and kind of weak key (PAN << 8 | weak_key_* bit).
    // Alerts the rate limit holds back wait in a queue that later frames raise, as a Transport Key
    // command may be the only frame that shows its key.
    struct weak_key_alert {
        mac_addr source, dest;
        std::string channel, text;
    };

    int alert_weakkey_ref;
    kis_mutex weak_key_mutex;
    std::set<uint32_t> weak_key_alerted;
    std::deque<weak_key_alert> weak_key_backlog;
    std::atomic<bool> weak_key_backlogged{false};
    int weak_key_timer;

    // Raise held-back alerts, oldest first, as far as the rate limit allows; weak_key_mutex held
    void drain_weak_key_backlog();

    // Most alerts held back at once; when full the oldest is dropped
    unsigned int weak_key_backlog_max;

    // Whether key values appear in device records, alerts and messages (zigbee_show_keys);
    // otherwise only the key's name or type
    bool show_keys;

    // The user's keys, from zigbee_key= in kismet_zigbee.conf; read once at startup
    std::vector<zigbee_user_key> user_keys;
};

#endif

