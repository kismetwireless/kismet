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

#ifndef __ENTITY_TRACKER_H__
#define __ENTITY_TRACKER_H__

#include "config.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "devicetracker_view.h"
#include "entity_graph.h"
#include "eventbus.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "kis_net_beast_httpd.h"
#include "trackedelement.h"

class device_tracker;
class kis_tracked_device_base;

// Links Wi-Fi and Ethernet records with the same MAC (a Wi-Fi client, a host bridged onto
// Wi-Fi, an AP) so what the wire sees of a device can be read from its Wi-Fi record.  The
// records stay separate: a linked pair shares kismet.device.base.entity_id and lists the other
// under the wired_same_mac or wired_bridged relationship, and /entities/ serves the evidence.
//
// Nothing here runs per packet.  New-device events and device removals queue the MAC (only
// MACs with an Ethernet record are kept), and a 1 s timer reads the records, updates the
// graph and writes each changed record's desired state.  A sweep re-reads every link in turn,
// so evidence that changes later (a bridged host turns out to be a client, a new IP) is seen.
// Nothing refused at a cap is lost: links refused at an edge cap are read again after the
// graph removes an edge, and Ethernet MACs refused by a full index are found again by a
// rescan of the Ethernet records once it has room, a batch of view slots per pass.  A pass
// that fails puts back the MACs and dirty records it took.
//
// Lock order:
//   device list mutex -> index_mutex (the removal hook runs under the device list mutex)
//   index_mutex and graph_mutex are leaves: nothing is taken while holding them, and they
//   are never held together.  Device locks are taken one at a time, and view locks, only with
//   neither held.
// The timer is the only writer of the graph and of entity data on devices.
class entity_tracker : public lifetime_global, public deferred_startup {
public:
    static std::string global_name() { return "ENTITYTRACKER"; }

    static std::shared_ptr<entity_tracker> create_entity_tracker() {
        std::shared_ptr<entity_tracker> mon(new entity_tracker());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->register_deferred_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

    // Client records read per Wi-Fi device, and its records behind a WDS radio checked
    static constexpr size_t max_client_records = 16;
    // When wired_max_devices and tracker_max_devices are both 0
    static constexpr size_t index_unlimited_cap = 65536;
    static constexpr size_t index_max_cap = 1048576;
    // Most often a walk of the Ethernet records for MACs a full index refused starts, and the
    // view slots it reads each timer pass
    static constexpr auto rescan_interval = std::chrono::seconds(10);
    static constexpr size_t rescan_batch_slots = 4096;
    // Errors from a timer pass are reported at most this often
    static constexpr auto error_report_interval = std::chrono::seconds(60);
    static constexpr size_t n_status_fields = 26;

private:
    entity_tracker();

public:
    virtual ~entity_tracker();

    virtual void trigger_deferred_startup() override;
    virtual void trigger_deferred_shutdown() override;

protected:
    // What one MAC's records show, read under each record's own lock; the record is kept for
    // the writes of the same pass
    struct wifi_facts {
        bool present = false;
        std::shared_ptr<kis_tracked_device_base> dev;
        entity::node n;
        uint64_t iid = 0;
        uint16_t evidence = 0;
        std::array<uint64_t, entity::max_via> via{};
        uint8_t n_via = 0;
        std::vector<uint32_t> ips;
    };

    struct wired_facts {
        bool present = false;
        std::shared_ptr<kis_tracked_device_base> dev;
        entity::node n;
        uint64_t iid = 0;
        bool ips_usable = false;
        std::vector<std::array<uint8_t, 4>> ips;
    };

    struct reconcile_item {
        uint64_t mac = 0;
        bool refused = false;
        wifi_facts wifi;
        wired_facts wired;
    };

    // What a pass took from the index and the graph, so a pass that fails puts it back
    struct pass_state {
        std::vector<uint64_t> macs;
        std::vector<std::pair<entity::node, uint64_t>> dirty;
    };

    void handle_new_device(const std::shared_ptr<eventbus_event>& evt);
    void device_removed(const kis_tracked_device_base& d);

    void timer_pass();
    void tick(pass_state& ps);
    void restore_pass(const pass_state& ps);
    void rescan_step();
    void read_records(reconcile_item& item);
    void read_wifi(const std::shared_ptr<kis_tracked_device_base>& dev, wifi_facts& w);
    void read_wired(const std::shared_ptr<kis_tracked_device_base>& dev, wired_facts& w);
    bool apply_mirror(kis_tracked_device_base& dev, const entity::graph::mirror& m);
    std::shared_ptr<kis_tracked_device_base> record_for(const std::vector<reconcile_item>& items,
            const entity::node& n);

    entity::node node_for(uint32_t phy_hash, uint64_t mac) const;

    std::shared_ptr<tracker_element> status_endpoint();
    std::shared_ptr<tracker_element> linked_endpoint(const std::shared_ptr<kis_net_beast_httpd_connection>& con);
    std::shared_ptr<tracker_element> edges_endpoint(const std::shared_ptr<kis_net_beast_httpd_connection>& con);
    std::shared_ptr<tracker_element_map> edge_record(const entity::edge& e);

    std::shared_ptr<device_tracker> devicetracker;

    bool enabled = true;
    entity::params gparams;
    size_t evidence_per_tick = 2048;
    size_t sweep_per_tick = 1024;
    size_t index_cap = 0;

    int wifi_phyid = -1, wired_phyid = -1;
    uint32_t wifi_hash = 0, wired_hash = 0;
    int dot11_device_id = -1, ethernet_device_id = -1;

    kis_mutex index_mutex;
    std::unique_ptr<entity::mac_index> index;
    // index->size(), stored under index_mutex; read without it to skip Wi-Fi events while no
    // Ethernet MAC is indexed
    std::atomic<size_t> n_indexed{0};

    kis_mutex graph_mutex;
    std::unique_ptr<entity::graph> graph;

    unsigned long new_device_listener = 0;
    unsigned long removed_hook_id = 0;
    int timer_id = -1;

    // Timer thread only, apart from the atomics the status endpoint reads
    std::atomic<uint64_t> n_ticks{0}, n_reconciled{0}, n_writes{0};
    std::atomic<uint64_t> last_tick_us{0}, max_tick_us{0};
    std::atomic<uint64_t> n_rescans{0}, max_rescan_us{0};
    bool reported_index_full = false, reported_edge_cap = false;
    uint64_t retry_removals = 0;
    std::chrono::steady_clock::time_point last_rescan{}, last_error_report{};
    bool reported_error = false;

    // The walk for MACs a full index refused, a batch per pass: the Ethernet phy view, or the
    // view of every device filtered to Ethernet records when there are no phy views
    std::shared_ptr<device_tracker_view> rescan_view;
    bool rescan_all_phys = false;
    bool rescanning = false;
    device_tracker_view::walk_cursor rescan_cursor;

    // Debug only, to time the event and removal costs alone: entity_debug_timer=false keeps
    // the listener and hook but makes no links, entity_debug_removed_hook=false drops the hook
    bool debug_timer = true, debug_removed_hook = true;

    std::array<int, n_status_fields> f_status_fields{};
    int f_dev_entity_id = -1, f_entity_id = -1, f_device_key = -1, f_edges = -1, f_total = -1, f_start = -1;
    int f_e_a = -1, f_e_b = -1, f_e_peer_key = -1, f_e_mac = -1, f_e_rel = -1, f_e_kind = -1, f_e_conf = -1,
        f_e_linked = -1, f_e_conflicted = -1, f_e_evidence = -1, f_e_evidence_names = -1, f_e_evidence_name = -1,
        f_e_via = -1, f_e_via_mac = -1, f_e_first = -1, f_e_last = -1, f_e_peer = -1;
};

#endif
