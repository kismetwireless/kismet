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

#include "entity_tracker.h"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <random>

#include "configfile.h"
#include "devicetracker.h"
#include "devicetracker_view.h"
#include "entrytracker.h"
#include "messagebus.h"
#include "phy_80211.h"
#include "phy_ethernet.h"
#include "timetracker.h"
#include "util.h"

namespace {
    // Device and MAC path parameters are short; anything longer is refused before parsing
    constexpr size_t max_key_param = 64;
    constexpr size_t max_page_start = 1048576;
    constexpr size_t max_page_length = 1000;

    constexpr std::array<entity::relationship, 2> mirrored_rels{
        entity::relationship::wired_same_mac, entity::relationship::wired_bridged,
    };

    std::shared_ptr<tracker_element_device_key> key_element(int id, const device_key& k) {
        auto e = std::make_shared<tracker_element_device_key>(id);
        e->set(k);
        return e;
    }

    uint64_t random_seed() {
        std::random_device rd;
        return (static_cast<uint64_t>(rd()) << 32) ^ rd();
    }

    size_t opt_in_range(const char *name, size_t dfl, size_t lo, size_t hi) {
        const size_t v = Globalreg::globalreg->kismet_config->fetch_opt_uint(name, static_cast<unsigned int>(dfl));
        if (v >= lo && v <= hi)
            return v;

        const size_t c = std::clamp(v, lo, hi);
        _MSG_ERROR("{}={} is outside {} to {}; using {}", name, v, lo, hi, c);
        return c;
    }
}

entity_tracker::entity_tracker() :
    lifetime_global(),
    deferred_startup() {

    index_mutex.set_name("entity_tracker index");
    graph_mutex.set_name("entity_tracker graph");

    devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();

    enabled = Globalreg::globalreg->kismet_config->fetch_opt_bool("entity_linking", true);
    // A threshold above the best score would turn linking off unseen
    gparams.min_confidence = static_cast<uint8_t>(opt_in_range("entity_link_min_confidence",
                entity::default_min_confidence, 1, entity::max_reachable_confidence));
    gparams.max_edges = opt_in_range("entity_max_edges", 65536, 0, 1048576);
    gparams.max_edges_per_node = opt_in_range("entity_max_edges_per_device", 16, 1, 64);
    gparams.max_component = opt_in_range("entity_max_component", 32, 2, 256);
    evidence_per_tick = opt_in_range("entity_max_evidence_per_tick", 2048, 64, 65536);
    sweep_per_tick = opt_in_range("entity_sweep_per_tick", 1024, 0, 65536);

    auto wifi = devicetracker->fetch_phy_handler_by_name("IEEE802.11");
    auto wired = dynamic_cast<kis_ethernet_phy *>(devicetracker->fetch_phy_handler_by_name("IEEE802.3"));

    if (wifi == nullptr || wired == nullptr) {
        enabled = false;
    } else {
        wifi_phyid = wifi->fetch_phy_id();
        wifi_hash = wifi->fetch_phyname_hash();
        wired_phyid = wired->fetch_phy_id();
        wired_hash = wired->fetch_phyname_hash();

        // One entry per Ethernet record, which wired_max_devices and tracker_max_devices cap;
        // room for records forgotten and not yet reconciled, or trimmed late
        const size_t wmax = wired->get_max_devices();
        const size_t tmax = devicetracker->get_max_num_devices();
        const size_t records = (wmax == 0 || tmax == 0) ? std::max(wmax, tmax) : std::min(wmax, tmax);
        index_cap = records == 0 ? index_unlimited_cap : std::min(records * 2, index_max_cap);
    }

    debug_timer = Globalreg::globalreg->kismet_config->fetch_opt_bool("entity_debug_timer", true);
    debug_removed_hook = Globalreg::globalreg->kismet_config->fetch_opt_bool("entity_debug_removed_hook", true);

    if (gparams.max_edges == 0)
        enabled = false;

    index = std::make_unique<entity::mac_index>(enabled ? index_cap : 0, random_seed());
    graph = std::make_unique<entity::graph>(gparams, random_seed());

    auto et = Globalreg::globalreg->entrytracker;
    dot11_device_id = et->get_field_id("dot11.device");
    ethernet_device_id = et->get_field_id("ethernet.device");

    auto reg_u64 = [&et](const std::string& n, const std::string& d) {
        return et->register_field(n, tracker_element_factory<tracker_element_uint64>(), d);
    };

    static constexpr std::array<std::pair<const char *, const char *>, n_status_fields> status_names{{
        {"enabled", "linking is on (entity_linking, and both phys present)"},
        {"min_confidence", "entity_link_min_confidence"},
        {"max_edges", "entity_max_edges"},
        {"max_edges_per_device", "entity_max_edges_per_device"},
        {"max_component", "entity_max_component"},
        {"index_capacity", "Ethernet MACs the index can hold (twice wired_max_devices or tracker_max_devices)"},
        {"edges", "links kept, linked or possible"},
        {"linked", "links at or above the threshold"},
        {"entities", "groups of linked records"},
        {"records", "records with a link"},
        {"index_size", "Ethernet MACs in the index"},
        {"index_queued", "MACs waiting to be read"},
        {"index_refused", "Ethernet MACs not indexed because the index was full; found again once it has room"},
        {"index_deferred", "MACs whose link waits for room under entity_max_edges or entity_max_edges_per_device"},
        {"refused_cap", "links not kept because entity_max_edges was reached"},
        {"refused_per_device", "links not kept because a record had entity_max_edges_per_device"},
        {"component_capped", "links kept unlinked because the group would pass entity_max_component"},
        {"ticks", "timer passes"},
        {"reconciled", "MACs read and reconciled"},
        {"writes", "records whose entity id or related devices were written"},
        {"last_tick_us", "length of the last timer pass, microseconds"},
        {"max_tick_us", "longest timer pass, microseconds"},
        {"evidence_per_tick", "entity_max_evidence_per_tick"},
        {"sweep_per_tick", "entity_sweep_per_tick"},
        {"rescans", "walks of the Ethernet records for MACs the full index refused, finished"},
        {"max_rescan_us", "longest rescan batch of a timer pass, microseconds"},
    }};
    // Every entry is filled: a short list fails to compile
    static_assert(status_names.back().first != nullptr);

    for (size_t i = 0; i < status_names.size(); i++)
        f_status_fields[i] = reg_u64(fmt::format("kismet.entity.status.{}", status_names[i].first),
                status_names[i].second);

    // Registered with linking off too, so device rules naming it still load; records carry it
    // only once linked, and the device class has no member for it
    f_dev_entity_id = reg_u64("kismet.device.base.entity_id",
            "entity shared with linked records on other phys, such as the Ethernet record of a "
            "Wi-Fi client; ids last one server run");
    f_entity_id = reg_u64("kismet.entity.entity_id", "entity id of the record, 0 when not linked");
    f_device_key = et->register_field("kismet.entity.device_key",
            tracker_element_factory<tracker_element_device_key>(), "record asked about");
    f_edges = et->register_field("kismet.entity.edges",
            tracker_element_factory<tracker_element_vector>(), "links");
    f_total = reg_u64("kismet.entity.total", "links matching the filter");
    f_start = reg_u64("kismet.entity.start", "first link returned");

    f_e_a = et->register_field("kismet.entity.edge.a_key",
            tracker_element_factory<tracker_element_device_key>(), "one record of the link");
    f_e_b = et->register_field("kismet.entity.edge.b_key",
            tracker_element_factory<tracker_element_device_key>(), "the other record of the link");
    f_e_peer_key = et->register_field("kismet.entity.edge.peer_key",
            tracker_element_factory<tracker_element_device_key>(), "the linked record");
    f_e_mac = et->register_field("kismet.entity.edge.macaddr",
            tracker_element_factory<tracker_element_mac_addr>(), "MAC the records share");
    f_e_rel = et->register_field("kismet.entity.edge.relationship",
            tracker_element_factory<tracker_element_string>(),
            "wired_same_mac (Wi-Fi client or AP) or wired_bridged (bridged onto Wi-Fi)");
    f_e_kind = et->register_field("kismet.entity.edge.wifi_kind",
            tracker_element_factory<tracker_element_string>(),
            "what the Wi-Fi record is: client, client_mgmt, bridged, ap or inferred");
    f_e_conf = reg_u64("kismet.entity.edge.confidence", "confidence 0-100, from the evidence");
    f_e_linked = et->register_field("kismet.entity.edge.linked",
            tracker_element_factory<tracker_element_uint8>(),
            "at or above entity_link_min_confidence and grouped; 0 is a possible link");
    f_e_conflicted = et->register_field("kismet.entity.edge.conflicted",
            tracker_element_factory<tracker_element_uint8>(), "the wire contradicts the link");
    f_e_evidence = reg_u64("kismet.entity.edge.evidence", "evidence bitfield");
    f_e_evidence_names = et->register_field("kismet.entity.edge.evidence_names",
            tracker_element_factory<tracker_element_vector>(), "evidence, by name");
    f_e_evidence_name = et->register_field("kismet.entity.edge.evidence_name",
            tracker_element_factory<tracker_element_string>(), "evidence name");
    f_e_via = et->register_field("kismet.entity.edge.via",
            tracker_element_factory<tracker_element_vector>(),
            "BSSIDs or WDS radios the Wi-Fi record was heard behind, newest first");
    f_e_via_mac = et->register_field("kismet.entity.edge.via_mac",
            tracker_element_factory<tracker_element_mac_addr>(), "BSSID or WDS radio");
    f_e_first = reg_u64("kismet.entity.edge.first_time", "when the link was made (server time)");
    f_e_last = reg_u64("kismet.entity.edge.last_time", "when the link was last confirmed (server time)");
    f_e_peer = et->register_field("kismet.entity.edge.peer",
            tracker_element_factory<tracker_element_vector>(), "the linked record, if it still exists");

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/entities/status", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](const std::shared_ptr<kis_net_beast_httpd_connection>&) {
                    return status_endpoint();
                }));

    httpd->register_route("/entities/edges", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](const std::shared_ptr<kis_net_beast_httpd_connection>& con) {
                    return edges_endpoint(con);
                }));

    httpd->register_route("/entities/by-device/:key/linked", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](const std::shared_ptr<kis_net_beast_httpd_connection>& con) {
                    return linked_endpoint(con);
                }));
}

entity_tracker::~entity_tracker() {
    entity_tracker::trigger_deferred_shutdown();
}

void entity_tracker::trigger_deferred_startup() {
    if (!enabled)
        return;

    auto eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();
    new_device_listener =
        eventbus->register_listener(device_tracker::event_new_device(),
                [this](const std::shared_ptr<eventbus_event>& evt) {
                    handle_new_device(evt);
                });

    if (debug_removed_hook)
        removed_hook_id = devicetracker->add_removed_hook([this](const kis_tracked_device_base& d) {
                device_removed(d);
            });

    // Without phy views (track_device_phy_views=false) the walk reads every record and keeps
    // the Ethernet ones
    rescan_view = devicetracker->get_phy_view(wired_phyid);
    rescan_all_phys = rescan_view == nullptr;
    if (rescan_all_phys)
        rescan_view = devicetracker->get_all_view();

    if (!debug_timer) {
        _MSG_ERROR("entity_debug_timer=false: wired/Wi-Fi devices are indexed but never linked.  "
                "This is for debugging only.");
        return;
    }

    timer_id =
        Globalreg::fetch_mandatory_global_as<time_tracker>()->register_timer(
                std::chrono::seconds(1), true, [this](int) -> int {
                    timer_pass();
                    return 1;
                });
}

void entity_tracker::trigger_deferred_shutdown() {
    if (timer_id >= 0) {
        auto timetracker = Globalreg::fetch_global_as<time_tracker>(time_tracker::global_name());
        if (timetracker != nullptr)
            timetracker->remove_timer(timer_id);
        timer_id = -1;
    }

    if (new_device_listener != 0) {
        auto eventbus = Globalreg::fetch_global_as<event_bus>();
        if (eventbus != nullptr)
            eventbus->remove_listener(new_device_listener);
        new_device_listener = 0;
    }

    // Our own reference keeps the device tracker alive until the hook is gone
    if (removed_hook_id != 0) {
        devicetracker->remove_removed_hook(removed_hook_id);
        removed_hook_id = 0;
    }
}

entity::node entity_tracker::node_for(uint32_t phy_hash, uint64_t mac) const {
    const device_key k(phy_hash, mac);
    return entity::node{k.get_spkey(), k.get_dkey()};
}

// Runs on the event bus thread for every new device of every phy, so anything else returns
// before any lock.  A Wi-Fi record only matters once an Ethernet MAC is indexed; a stale 0
// read here loses nothing, since an Ethernet record indexed meanwhile queues its MAC itself
// and the Wi-Fi record was published before its event.
void entity_tracker::handle_new_device(const std::shared_ptr<eventbus_event>& evt) {
    const auto& content = evt->get_event_content();
    const auto ci = content->find(device_tracker::event_new_device());
    if (ci == content->end())
        return;

    // The key, MAC and phy are set before the device is published and never change
    const auto dev = static_cast<kis_tracked_device_base *>(ci->second.get());
    const int phy = dev->get_phyid();

    if (phy == wifi_phyid) {
        if (n_indexed.load(std::memory_order_relaxed) == 0)
            return;

        kis_lock_guard<kis_mutex> lk(index_mutex, "entity_tracker new wifi device");
        index->touch(dev->get_macaddr().longmac);
        return;
    }

    if (phy != wired_phyid)
        return;

    bool newly_full = false;
    {
        kis_lock_guard<kis_mutex> lk(index_mutex, "entity_tracker new wired device");
        if (index->add(dev->get_macaddr().longmac) == entity::mac_index::add_result::full && !reported_index_full) {
            reported_index_full = true;
            newly_full = true;
        }
        n_indexed.store(index->size(), std::memory_order_relaxed);
    }

    if (newly_full)
        _MSG_INFO("The wired/Wi-Fi link index is full ({} Ethernet MACs); Ethernet devices it "
                "refuses are linked once it has room again.  It holds twice wired_max_devices or "
                "tracker_max_devices, and 65536 MACs when both are 0.", index_cap);
}

void entity_tracker::device_removed(const kis_tracked_device_base& d) {
    const int phy = d.get_phyid();

    if (phy != wired_phyid && phy != wifi_phyid)
        return;

    // A Wi-Fi record seen as unindexed by a stale 0 still has its link found by the sweep
    if (phy == wifi_phyid && n_indexed.load(std::memory_order_relaxed) == 0)
        return;

    // Under the device list mutex: queue it only; the timer unlinks the other record
    kis_lock_guard<kis_mutex> lk(index_mutex, "entity_tracker device removed");
    index->touch(d.get_macaddr().longmac);
}

void entity_tracker::read_wifi(const std::shared_ptr<kis_tracked_device_base>& dev, wifi_facts& w) {
    struct client_rec {
        uint64_t bssid;
        device_key key;
        time_t last;
    };

    std::vector<client_rec> recs;
    bool peer_only = false;

    {
        kis_device_lock lk(dev, true);

        if (dev->get_removed())
            return;

        w.present = true;
        w.dev = dev;
        w.n = entity::node{dev->get_key().get_spkey(), dev->get_key().get_dkey()};
        w.iid = dev->get_kis_internal_id();

        const uint64_t basic = dev->get_basic_type_set();
        uint16_t e = 0;

        if (basic & KIS_DEVICE_BASICTYPE_CLIENT)
            e |= entity::ev::radio_client;
        if (basic & KIS_DEVICE_BASICTYPE_AP) {
            e |= entity::ev::radio_ap;
            if (basic & KIS_DEVICE_BASICTYPE_PEER)
                e |= entity::ev::wds_radio;
        }
        // Only set while the record was never a radio client or AP: a from-DS source
        if (basic & KIS_DEVICE_BASICTYPE_WIRED)
            e |= entity::ev::bridged_from_ds;
        if (entity::mac_is_local(dev->get_macaddr().longmac))
            e |= entity::ev::local_mac;

        // A 4-address source is a peer and nothing else; whether it was behind a WDS radio
        // is on that radio's record
        peer_only = (basic & KIS_DEVICE_BASICTYPE_PEER) &&
            !(basic & (KIS_DEVICE_BASICTYPE_CLIENT | KIS_DEVICE_BASICTYPE_AP));

        auto d11 = dev->get_sub_as<dot11_tracked_device>(dot11_device_id);
        if (d11 != nullptr && d11->has_client_map()) {
            for (const auto& [m, v] : *d11->get_client_map()) {
                if (recs.size() >= max_client_records)
                    break;
                if (v == nullptr)
                    continue;

                auto c = std::static_pointer_cast<dot11_client>(v);
                recs.push_back(client_rec{c->get_bssid().longmac, c->get_bssid_key(),
                        static_cast<time_t>(c->get_last_time())});

                if (c->has_ipdata()) {
                    const uint64_t ip = c->get_ipdata()->get_ip_addr();
                    if (ip != 0 && ip <= 0xffffffffULL)
                        w.ips.push_back(static_cast<uint32_t>(ip));
                }
            }
        }

        if ((e & entity::ev::radio_client) && dev->get_data_packets() > 0 && !recs.empty())
            e |= entity::ev::associated;

        w.evidence = e;
    }

    std::stable_sort(recs.begin(), recs.end(), [](const client_rec& a, const client_rec& b) {
            return a.last > b.last;
        });

    for (const auto& r : recs) {
        if (w.n_via >= entity::max_via)
            break;
        w.via[w.n_via++] = r.bssid;
    }

    if (!peer_only)
        return;

    // One device lock at a time: the Wi-Fi record's is released
    for (size_t i = 0; i < recs.size() && i < entity::max_via; i++) {
        auto radio = devicetracker->fetch_device(recs[i].key);
        if (radio == nullptr)
            continue;

        kis_device_lock lk(radio, true);
        const uint64_t rb = radio->get_basic_type_set();
        if (!radio->get_removed() && (rb & KIS_DEVICE_BASICTYPE_AP) && (rb & KIS_DEVICE_BASICTYPE_PEER)) {
            w.evidence |= entity::ev::bridged_4addr;
            break;
        }
    }
}

void entity_tracker::read_wired(const std::shared_ptr<kis_tracked_device_base>& dev, wired_facts& w) {
    kis_device_lock lk(dev, true);

    if (dev->get_removed())
        return;

    w.present = true;
    w.dev = dev;
    w.n = entity::node{dev->get_key().get_spkey(), dev->get_key().get_dkey()};
    w.iid = dev->get_kis_internal_id();

    auto ed = dev->get_sub_as<ethernet_tracked_device>(ethernet_device_id);
    if (ed == nullptr)
        return;

    // A gateway forwards for others, and a host that filled its IPv4 list (sending from many
    // addresses, or replacing some) would match too easily.  The VLAN and name lists don't
    // matter here.
    if ((ed->get_roles() & ethernet_tracked_device::role_gateway) || !ed->has_ipv4() ||
            ed->get_ipv4()->size() >= kis_ethernet_phy::max_addrs)
        return;

    w.ips_usable = true;

    for (const auto& i : *ed->get_ipv4()) {
        if (w.ips.size() >= kis_ethernet_phy::max_addrs)
            break;
        if (i == nullptr)
            continue;

        const auto& raw = std::static_pointer_cast<ethernet_tracked_ip>(i)->raw;
        if (raw.family == 4)
            w.ips.push_back({raw.a[0], raw.a[1], raw.a[2], raw.a[3]});
    }
}

void entity_tracker::read_records(reconcile_item& item) {
    for (const auto& dev : devicetracker->fetch_devices(mac_from_u64(item.mac))) {
        if (dev == nullptr)
            continue;

        const int phy = dev->get_phyid();
        if (phy == wifi_phyid && !item.wifi.present)
            read_wifi(dev, item.wifi);
        else if (phy == wired_phyid && !item.wired.present)
            read_wired(dev, item.wired);
    }
}

bool entity_tracker::apply_mirror(kis_tracked_device_base& dev, const entity::graph::mirror& m) {
    bool changed = false;

    for (const auto rel : mirrored_rels) {
        const std::string name{entity::relationship_name(rel)};

        std::vector<device_key> want;
        for (const auto& [r, n] : m.linked)
            if (r == rel)
                want.emplace_back(static_cast<uint32_t>(n.spkey), n.dkey);

        std::vector<device_key> have;
        auto rmap = dev.get_related_devices_map();
        auto gi = rmap->find(name);
        if (gi != rmap->end() && gi->second != nullptr)
            for (const auto& [k, v] : *std::static_pointer_cast<tracker_element_device_key_map>(gi->second))
                have.push_back(k);

        for (const auto& k : have)
            if (std::find(want.begin(), want.end(), k) == want.end())
                changed |= dev.remove_related_device(name, k);

        for (const auto& k : want) {
            if (std::find(have.begin(), have.end(), k) == have.end()) {
                dev.add_related_device(name, k);
                changed = true;
            }
        }
    }

    // Only linked records carry the field, which nothing else writes
    const auto ei = dev.find(f_dev_entity_id);
    if (m.entity_id == 0) {
        if (ei != dev.end()) {
            dev.erase(ei);
            changed = true;
        }
    } else if (ei == dev.end()) {
        dev.insert(std::make_shared<tracker_element_uint64>(f_dev_entity_id, m.entity_id));
        changed = true;
    } else {
        auto e = std::static_pointer_cast<tracker_element_uint64>(ei->second);
        if (e->get() != m.entity_id) {
            e->set(m.entity_id);
            changed = true;
        }
    }

    return changed;
}

// One failed pass (an allocation, a malformed record) mustn't stop linking for the rest of
// the run; the locks are released by the time it's caught
void entity_tracker::timer_pass() {
    pass_state ps;

    try {
        tick(ps);
    } catch (const std::exception& e) {
        std::string why = e.what();

        try {
            restore_pass(ps);
        } catch (const std::exception& re) {
            why += fmt::format("; putting back what it took failed too: {}", re.what());
        }

        const auto t = std::chrono::steady_clock::now();
        if (!reported_error || t - last_error_report >= error_report_interval) {
            reported_error = true;
            last_error_report = t;
            _MSG_ERROR("Entity linking pass failed, continuing with the next one: {}", why);
        }
    }
}

// The next pass reads the MACs again and writes the records this one didn't; writing a record
// twice changes nothing
void entity_tracker::restore_pass(const pass_state& ps) {
    {
        kis_lock_guard<kis_mutex> lk(index_mutex, "entity_tracker restore pass");
        index->requeue(ps.macs);
    }

    kis_lock_guard<kis_mutex> lk(graph_mutex, "entity_tracker restore pass");
    graph->restore_dirty(ps.dirty);
}

// One batch of the walk over the Ethernet records for MACs the index refused while full.  The
// batch is copied under the view lock alone, and a record's phy and MAC are set before it's
// published and never change, so no device lock is taken.
void entity_tracker::rescan_step() {
    const auto started = std::chrono::steady_clock::now();

    std::vector<std::shared_ptr<kis_tracked_device_base>> devs;
    const bool read_view = rescan_view != nullptr;
    const bool more = read_view && rescan_view->copy_devices_batch(rescan_cursor, rescan_batch_slots, devs);

    bool full = false;
    {
        kis_lock_guard<kis_mutex> lk(index_mutex, "entity_tracker rescan");
        for (const auto& d : devs) {
            if (d->get_removed() || (rescan_all_phys && d->get_phyid() != wired_phyid))
                continue;
            // Stop once the room is used, rather than count the rest as refused again
            if (index->size() >= index->capacity()) {
                full = true;
                break;
            }
            index->add_missing(d->get_macaddr().longmac);
        }

        const auto state = entity::rescan_after(read_view, more, full);
        if (state == entity::rescan_state::unfinished)
            index->rescan_unfinished();
        if (state != entity::rescan_state::more)
            rescanning = false;
        if (state == entity::rescan_state::finished)
            n_rescans.fetch_add(1, std::memory_order_relaxed);

        n_indexed.store(index->size(), std::memory_order_relaxed);
    }

    const auto us = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started).count());
    if (us > max_rescan_us.load(std::memory_order_relaxed))
        max_rescan_us.store(us, std::memory_order_relaxed);
}

// The record a dirty node names: the one read this pass when there is one, so most writes
// need no lookup.  Items are sorted by MAC, and a node's dkey is its MAC.
std::shared_ptr<kis_tracked_device_base> entity_tracker::record_for(const std::vector<reconcile_item>& items,
        const entity::node& n) {
    const auto ii = std::lower_bound(items.begin(), items.end(), n.dkey,
            [](const reconcile_item& it, uint64_t m) { return it.mac < m; });

    if (ii != items.end() && ii->mac == n.dkey) {
        if (ii->wifi.present && ii->wifi.n == n)
            return ii->wifi.dev;
        if (ii->wired.present && ii->wired.n == n)
            return ii->wired.dev;
    }

    return devicetracker->fetch_device(device_key(static_cast<uint32_t>(n.spkey), n.dkey));
}

void entity_tracker::tick(pass_state& ps) {
    const auto started = std::chrono::steady_clock::now();
    const time_t now = Globalreg::globalreg->last_tv_sec;

    // Room for all the MACs this pass takes, made first: from the sweep or the queue they go
    // into the pass state without an allocation that could throw and drop them
    auto& macs = ps.macs;
    macs.reserve(sweep_per_tick + evidence_per_tick);
    std::vector<entity::edge> swept;
    swept.reserve(sweep_per_tick);
    std::vector<uint64_t> taken;
    taken.reserve(evidence_per_tick);

    uint64_t removals = 0;
    {
        kis_lock_guard<kis_mutex> lk(graph_mutex, "entity_tracker tick sweep");
        graph->sweep(sweep_per_tick, swept);
        removals = graph->removals();
    }

    for (const auto& e : swept)
        macs.push_back(e.mac);

    {
        kis_lock_guard<kis_mutex> lk(index_mutex, "entity_tracker tick take");

        // Links refused at a cap can only fit after an edge went
        if (removals != retry_removals) {
            retry_removals = removals;
            index->requeue_deferred(evidence_per_tick);
        }

        if (!rescanning && index->rescan_due() && started - last_rescan >= rescan_interval) {
            index->rescan_started();
            last_rescan = started;
            rescanning = true;
            rescan_cursor = {};
        } else if (rescanning && index->size() >= index->capacity()) {
            rescanning = false;
            index->rescan_unfinished();
        }

        index->take(evidence_per_tick, taken);
        macs.insert(macs.end(), taken.begin(), taken.end());
    }

    if (rescanning)
        rescan_step();

    std::sort(macs.begin(), macs.end());
    macs.erase(std::unique(macs.begin(), macs.end()), macs.end());

    std::vector<reconcile_item> items(macs.size());
    for (size_t i = 0; i < macs.size(); i++) {
        items[i].mac = macs[i];
        read_records(items[i]);
    }

    auto& dirty = ps.dirty;
    std::vector<entity::graph::mirror> mirrors;
    size_t n_refused = 0;

    {
        kis_lock_guard<kis_mutex> lk(graph_mutex, "entity_tracker tick apply");

        for (auto& it : items) {
            if (it.wifi.present && it.wired.present && !entity::mac_excluded(it.mac)) {
                uint16_t e = it.wifi.evidence;
                if (it.wired.ips_usable && entity::ipv4_match(it.wifi.ips, it.wired.ips))
                    e |= entity::ev::ip_match;

                const auto r = graph->upsert(it.wifi.n, it.wifi.iid, it.wired.n, it.wired.iid, it.mac,
                        entity::evaluate(e, it.wifi.via, it.wifi.n_via), now);
                if (r == entity::graph::upsert_result::refused_cap ||
                        r == entity::graph::upsert_result::refused_node_cap) {
                    it.refused = true;
                    n_refused++;
                }
                continue;
            }

            if (!it.wifi.present)
                graph->remove_node(node_for(wifi_hash, it.mac));
            if (!it.wired.present)
                graph->remove_node(node_for(wired_hash, it.mac));
        }

        graph->take_dirty(dirty);
        mirrors.reserve(dirty.size());
        for (const auto& [n, iid] : dirty)
            mirrors.push_back(graph->desired(n));
    }

    {
        kis_lock_guard<kis_mutex> lk(index_mutex, "entity_tracker tick forget");
        for (const auto& it : items) {
            if (!it.wired.present) {
                index->erase_if_idle(it.mac);
            } else if (it.refused) {
                // Held until an edge is removed; a removal earlier in this pass shows next pass
                index->defer(it.mac);
            } else if (index->deferred() != 0) {
                // Linked, or with nothing left to link, after a read for another reason
                index->release(it.mac);
            }
        }
        n_indexed.store(index->size(), std::memory_order_relaxed);
    }

    uint64_t writes = 0;

    for (size_t i = 0; i < dirty.size(); i++) {
        const auto& [n, iid] = dirty[i];
        auto dev = record_for(items, n);
        if (dev == nullptr)
            continue;

        kis_device_lock lk(dev, false);

        // Only the record the link was made with; one made again under its key starts clean
        if (dev->get_removed() || dev->get_kis_internal_id() != iid)
            continue;

        if (apply_mirror(*dev, mirrors[i])) {
            dev->update_modtime();
            writes++;
        }
    }

    const auto us = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started).count());

    n_ticks.fetch_add(1, std::memory_order_relaxed);
    n_reconciled.fetch_add(items.size(), std::memory_order_relaxed);
    n_writes.fetch_add(writes, std::memory_order_relaxed);
    last_tick_us.store(us, std::memory_order_relaxed);
    if (us > max_tick_us.load(std::memory_order_relaxed))
        max_tick_us.store(us, std::memory_order_relaxed);

    if (n_refused != 0 && !reported_edge_cap) {
        reported_edge_cap = true;
        _MSG_INFO("Reached entity_max_edges ({}) or entity_max_edges_per_device ({}); further wired/Wi-Fi "
                "links wait until older links go.", gparams.max_edges, gparams.max_edges_per_node);
    }
}

std::shared_ptr<tracker_element> entity_tracker::status_endpoint() {
    auto m = std::make_shared<tracker_element_map>();

    entity::stats gs;
    {
        kis_lock_guard<kis_mutex> lk(graph_mutex, "entity_tracker status");
        gs = graph->get_stats();
    }

    size_t isize, iqueued, ideferred;
    uint64_t irefused;
    {
        kis_lock_guard<kis_mutex> lk(index_mutex, "entity_tracker status");
        isize = index->size();
        iqueued = index->queued();
        ideferred = index->deferred();
        irefused = index->refused();
    }

    const uint64_t v[] = {
        enabled ? 1u : 0u, gparams.min_confidence, gparams.max_edges, gparams.max_edges_per_node,
        gparams.max_component, enabled ? index_cap : 0, gs.edges, gs.linked, gs.entities, gs.nodes,
        isize, iqueued, irefused, ideferred, gs.refused_cap, gs.refused_node_cap, gs.component_capped,
        n_ticks.load(std::memory_order_relaxed), n_reconciled.load(std::memory_order_relaxed),
        n_writes.load(std::memory_order_relaxed), last_tick_us.load(std::memory_order_relaxed),
        max_tick_us.load(std::memory_order_relaxed), evidence_per_tick, sweep_per_tick,
        n_rescans.load(std::memory_order_relaxed), max_rescan_us.load(std::memory_order_relaxed),
    };
    static_assert(std::size(v) == n_status_fields);

    for (size_t i = 0; i < std::size(v); i++)
        m->insert(std::make_shared<tracker_element_uint64>(f_status_fields[i], v[i]));

    return m;
}

std::shared_ptr<tracker_element_map> entity_tracker::edge_record(const entity::edge& e) {
    auto m = std::make_shared<tracker_element_map>();

    m->insert(key_element(f_e_a, device_key(static_cast<uint32_t>(e.a.spkey), e.a.dkey)));
    m->insert(key_element(f_e_b, device_key(static_cast<uint32_t>(e.b.spkey), e.b.dkey)));
    m->insert(std::make_shared<tracker_element_mac_addr>(f_e_mac, mac_from_u64(e.mac)));
    m->insert(std::make_shared<tracker_element_string>(f_e_rel,
                std::string(entity::relationship_name(e.info.rel))));
    m->insert(std::make_shared<tracker_element_string>(f_e_kind,
                std::string(entity::wifi_kind_name(e.info.kind))));
    m->insert(std::make_shared<tracker_element_uint64>(f_e_conf, e.info.confidence));
    m->insert(std::make_shared<tracker_element_uint8>(f_e_linked, e.linked ? 1 : 0));
    m->insert(std::make_shared<tracker_element_uint8>(f_e_conflicted, e.info.conflicted ? 1 : 0));
    m->insert(std::make_shared<tracker_element_uint64>(f_e_evidence, e.info.evidence));

    auto names = std::make_shared<tracker_element_vector>(f_e_evidence_names);
    for (const auto& n : entity::evidence_names(e.info.evidence))
        names->push_back(std::make_shared<tracker_element_string>(f_e_evidence_name, std::string(n)));
    m->insert(names);

    auto via = std::make_shared<tracker_element_vector>(f_e_via);
    for (size_t i = 0; i < e.info.n_via && i < entity::max_via; i++)
        via->push_back(std::make_shared<tracker_element_mac_addr>(f_e_via_mac, mac_from_u64(e.info.via[i])));
    m->insert(via);

    m->insert(std::make_shared<tracker_element_uint64>(f_e_first, static_cast<uint64_t>(e.first_time)));
    m->insert(std::make_shared<tracker_element_uint64>(f_e_last, static_cast<uint64_t>(e.last_time)));

    return m;
}

std::shared_ptr<tracker_element>
    entity_tracker::linked_endpoint(const std::shared_ptr<kis_net_beast_httpd_connection>& con) {
    auto ret = std::make_shared<tracker_element_map>();

    const auto raw = con->uri_params()[":key"];
    if (raw.length() > max_key_param) {
        con->set_status(400);
        return ret;
    }

    const device_key key(kis_net_beast_httpd::decode_uri(raw, false));
    if (key.get_error()) {
        con->set_status(400);
        return ret;
    }

    const entity::node self{key.get_spkey(), key.get_dkey()};

    std::vector<entity::edge> edges;
    uint64_t entity_id = 0;
    {
        kis_lock_guard<kis_mutex> lk(graph_mutex, "entity_tracker linked");
        graph->edges_of(self, edges);
        entity_id = graph->entity_of(self);
    }

    ret->insert(key_element(f_device_key, key));
    ret->insert(std::make_shared<tracker_element_uint64>(f_entity_id, entity_id));

    auto vec = std::make_shared<tracker_element_vector>(f_edges);

    // Peer records are fetched with no entity lock held, and serialized under their own lock.
    // Only the record the link was made with: one made again under its key isn't linked.
    for (const auto& e : edges) {
        auto rec = edge_record(e);
        const bool self_a = e.a == self;
        const auto& peer = self_a ? e.b : e.a;
        const uint64_t peer_iid = self_a ? e.b_iid : e.a_iid;
        const device_key pk(static_cast<uint32_t>(peer.spkey), peer.dkey);
        rec->insert(key_element(f_e_peer_key, pk));

        auto pv = std::make_shared<tracker_element_vector>(f_e_peer);
        auto pdev = devicetracker->fetch_device(pk);
        if (pdev != nullptr && !pdev->get_removed() && pdev->get_kis_internal_id() == peer_iid)
            pv->push_back(pdev);
        rec->insert(pv);

        vec->push_back(rec);
    }

    ret->insert(vec);
    return ret;
}

std::shared_ptr<tracker_element>
    entity_tracker::edges_endpoint(const std::shared_ptr<kis_net_beast_httpd_connection>& con) {
    // GET variables or a POST json body; anything malformed is a 400, not a default
    auto param = [&con](const char *name, std::string& out) -> bool {
        auto v = con->http_variables().find(name);
        if (v != con->http_variables().end()) {
            out = v->second;
            return true;
        }

        const auto& j = con->json();
        if (j.is_object() && j.contains(name)) {
            const auto& jv = j[name];
            if (jv.is_string())
                out = jv.get<std::string>();
            else if (jv.is_number_unsigned())
                out = std::to_string(jv.get<uint64_t>());
            else
                throw std::runtime_error("invalid parameter type");
            return true;
        }

        return false;
    };

    std::string s;
    bool by_mac = false;
    uint64_t mac = 0;
    unsigned int min_conf = 0;
    size_t start = 0, length = 100;

    try {
        if (param("mac", s)) {
            if (s.length() > 17)
                throw std::runtime_error("invalid mac");
            mac_addr m(s);
            if (m.error() || m.length() != 6)
                throw std::runtime_error("invalid mac");
            mac = m.longmac;
            by_mac = true;
        }

        if (param("min_confidence", s)) {
            min_conf = string_to_n<unsigned int>(s);
            if (min_conf > 100)
                throw std::runtime_error("invalid min_confidence; 0 to 100");
        }

        if (param("start", s)) {
            start = string_to_n<unsigned int>(s);
            if (start > max_page_start)
                throw std::runtime_error("invalid start");
        }

        if (param("length", s)) {
            length = string_to_n<unsigned int>(s);
            if (length == 0 || length > max_page_length)
                throw std::runtime_error("invalid length; 1 to 1000");
        }
    } catch (const std::exception&) {
        con->set_status(400);
        return std::make_shared<tracker_element_map>();
    }

    std::vector<entity::edge> out;
    size_t total = 0;

    {
        kis_lock_guard<kis_mutex> lk(graph_mutex, "entity_tracker edges");

        if (by_mac) {
            // Same-MAC links hang off the MAC's own two records: no walk over every link
            std::vector<entity::edge> es, matched;
            for (const auto& n : {node_for(wifi_hash, mac), node_for(wired_hash, mac)}) {
                graph->edges_of(n, es);
                for (const auto& e : es) {
                    if (e.info.confidence < min_conf)
                        continue;
                    if (std::find_if(matched.begin(), matched.end(), [&e](const entity::edge& x) {
                                return x.a == e.a && x.b == e.b;
                            }) == matched.end())
                        matched.push_back(e);
                }
            }

            total = matched.size();
            for (size_t i = start; i < matched.size() && out.size() < length; i++)
                out.push_back(matched[i]);
        } else {
            graph->page(start, length, static_cast<uint8_t>(min_conf), out, total);
        }
    }

    auto ret = std::make_shared<tracker_element_map>();
    auto vec = std::make_shared<tracker_element_vector>(f_edges);
    for (const auto& e : out)
        vec->push_back(edge_record(e));

    ret->insert(vec);
    ret->insert(std::make_shared<tracker_element_uint64>(f_total, total));
    ret->insert(std::make_shared<tracker_element_uint64>(f_start, start));

    return ret;
}
