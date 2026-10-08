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

#include <algorithm>
#include <cstring>
#include <chrono>
#include <mutex>
#include <shared_mutex>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <pthread.h>

#include <execution>

#include "alertracker.h"
#include "configfile.h"
#include "globalregistry.h"
#include "kis_datasource.h"
#include "messagebus.h"
#include "packet.h"
#include "packetchain.h"

#include "crc32.h"

class SortLinkPriority {
public:
    inline bool operator() (const packet_chain::pc_link& x,
                            const packet_chain::pc_link& y) const {
        if (x.priority < y.priority)
            return 1;
        return 0;
    }
};

namespace {
    // Chain snapshots held by the current thread (more than one if packets are injected from
    // inside a handler)
    thread_local std::vector<const void *> thread_held_chains;
}

void packet_chain::pc_chains_ref::set(pc_chains_ptr in_chains) {
    reset();

    chains = std::move(in_chains);

    if (chains != nullptr)
        thread_held_chains.push_back(chains.get());
}

void packet_chain::pc_chains_ref::reset() {
    if (chains == nullptr)
        return;

    auto held = std::find(thread_held_chains.rbegin(), thread_held_chains.rend(), chains.get());
    if (held != thread_held_chains.rend())
        thread_held_chains.erase(std::next(held).base());

    chains.reset();
}

packet_chain::packet_chain() {
    packetcomp_mutex.set_name("packetchain packet_comp");
    packetchain_mutex.set_name("packetchain packetchain");
    pack_no_mutex.set_name("packetchain packetno");

    unique_packet_no = 1;

    dedupe_hash.fill(0);
    dedupe_list_pos = 0;

    Globalreg::enable_pool_type<kis_tracked_packet>([](auto *a) { a->reset(); });

    next_componentid = 1;
	next_handlerid = 1;

    last_packet_queue_user_warning = 0;
    last_packet_drop_user_warning = 0;

    packet_queue_warning =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("packet_log_warning", 0);
    packet_queue_drop =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("packet_backlog_limit", 8192);

    auto entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();

    packet_peak_rrd_id =
        entrytracker->register_field("kismet.packetchain.peak_packets_rrd",
                tracker_element_factory<kis_tracked_rrd<kis_tracked_rrd_default_aggregator,
                    kis_tracked_rrd_prev_pos_extreme_aggregator,
                    kis_tracked_rrd_prev_pos_extreme_aggregator>>(),
                "incoming packets peak rrd");
    packet_peak_rrd =
        std::make_shared<kis_tracked_rrd<kis_tracked_rrd_default_aggregator,
            kis_tracked_rrd_prev_pos_extreme_aggregator,
            kis_tracked_rrd_prev_pos_extreme_aggregator>>(packet_peak_rrd_id);

    packet_rate_rrd_id =
        entrytracker->register_field("kismet.packetchain.packets_rrd",
                tracker_element_factory<kis_tracked_rrd<>>(),
                "total packet rate rrd");
    packet_rate_rrd =
        std::make_shared<kis_tracked_rrd<>>(packet_rate_rrd_id);

    packet_error_rrd_id =
        entrytracker->register_field("kismet.packetchain.error_packets_rrd",
                tracker_element_factory<kis_tracked_rrd<>>(),
                "error packet rate rrd");
    packet_error_rrd =
        std::make_shared<kis_tracked_rrd<>>(packet_error_rrd_id);

    packet_dupe_rrd_id =
        entrytracker->register_field("kismet.packetchain.dupe_packets_rrd",
                tracker_element_factory<kis_tracked_rrd<>>(),
                "duplicate packet rate rrd");
    packet_dupe_rrd =
        std::make_shared<kis_tracked_rrd<>>(packet_dupe_rrd_id);

    packet_queue_rrd_id =
        entrytracker->register_field("kismet.packetchain.queued_packets_rrd",
                tracker_element_factory<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>>(),
                "packet backlog queue rrd");
    packet_queue_rrd =
        std::make_shared<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>>(packet_queue_rrd_id);

    packet_drop_rrd_id =
        entrytracker->register_field("kismet.packetchain.dropped_packets_rrd",
                tracker_element_factory<kis_tracked_rrd<>>(),
                "lost packet / queue overfull rrd");
    packet_drop_rrd =
        std::make_shared<kis_tracked_rrd<>>(packet_drop_rrd_id);

    packet_processed_rrd_id =
        entrytracker->register_field("kismet.packetchain.processed_packets_rrd",
                tracker_element_factory<kis_tracked_rrd<>>(),
                "processed packet rrd");
    packet_processed_rrd =
        std::make_shared<kis_tracked_rrd<>>(packet_processed_rrd_id);

    packet_stats_map =
        std::make_shared<tracker_element_map>();
    packet_stats_map->insert(packet_peak_rrd);
    packet_stats_map->insert(packet_rate_rrd);
    packet_stats_map->insert(packet_error_rrd);
    packet_stats_map->insert(packet_dupe_rrd);
    packet_stats_map->insert(packet_queue_rrd);
    packet_stats_map->insert(packet_drop_rrd);
    packet_stats_map->insert(packet_processed_rrd);

    packet_pool.set_max(1024);
    packet_pool.set_reset([](kis_packet *p) { p->reset(); });

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    // We now protect RRDs from complex ops w/ internal mutexes, so we can just share these
    // out directly without protecting them behind our own mutex; required, because we're mixing
    // RRDs from different data sources, like chain-level packet processing and worker mutex
    // locked buffer queuing.
    httpd->register_route("/packetchain/packet_stats", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(packet_stats_map));
    httpd->register_route("/packetchain/packet_peak", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(packet_peak_rrd));
    httpd->register_route("/packetchain/packet_rate", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(packet_rate_rrd));
    httpd->register_route("/packetchain/packet_error", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(packet_error_rrd));
    httpd->register_route("/packetchain/packet_dupe", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(packet_dupe_rrd));
    httpd->register_route("/packetchain/packet_drop", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(packet_drop_rrd));
    httpd->register_route("/packetchain/packet_processed", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(packet_processed_rrd));

    packetchain_shutdown = false;

    timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();
    eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();

    event_timer_id =
        timetracker->register_timer(std::chrono::seconds(1), true,
                [this](int) -> int {

                auto evt = eventbus->get_eventbus_event(event_packetstats());
                evt->get_event_content()->insert(event_packetstats(), packet_stats_map);
                eventbus->publish(evt);

                return 1;
                });

	pack_comp_linkframe = register_packet_component("LINKFRAME");
	pack_comp_decap = register_packet_component("DECAP");
    pack_comp_l1_agg = register_packet_component("RADIODATA_AGG");
	pack_comp_datasource = register_packet_component("KISDATASRC");

    chains = std::make_shared<pc_chains>();
    chains_generation = 0;
}

packet_chain::~packet_chain() {
    timetracker->remove_timer(event_timer_id);

    {
        // Tell the packet thread we're dying and unlock it
        packetchain_shutdown = true;

        // packet_queue.enqueue(nullptr);

        for (size_t i = 0; i < n_packet_threads; i++) {
            auto t = packet_threads[i];

            if (t == nullptr)
                continue;

            t->packet_queue.enqueue(nullptr);

            if (t->packet_thread.joinable())
                t->packet_thread.join();

            delete(t);
            packet_threads[i] = nullptr;
        }

        delete[] packet_threads;
        packet_threads = nullptr;
    }

    {
        // kis_lock_guard<kis_shared_mutex> lk(packetchain_mutex, "~packet_chain");
        auto lk = std::unique_lock(packetchain_mutex);

        Globalreg::globalreg->remove_global("PACKETCHAIN");
        Globalreg::globalreg->packetchain = NULL;

        chains = std::make_shared<pc_chains>();
    }

}

void packet_chain::start_processing() {
    n_packet_threads = Globalreg::globalreg->kismet_config->fetch_opt_as<unsigned int>("kismet_packet_threads", 0);

    if (n_packet_threads == 0) {
        n_packet_threads = std::max(4, static_cast<int>(std::thread::hardware_concurrency() / 4));
    }

    packet_threads = new packet_thread*[n_packet_threads];

    for (unsigned int n = 0; n < n_packet_threads; n++) {
        packet_threads[n] = new packet_thread();
        packet_threads[n]->packet_thread =
            std::thread([this, n]() {
            auto name = fmt::format("PACKET {}/{}", n, n_packet_threads);
            thread_set_process_name(name);
            packet_queue_processor(&packet_threads[n]->packet_queue);
        });
    }
}

int packet_chain::register_packet_component(std::string in_component) {
    kis_shared_lock<kis_shared_mutex> lk(packetcomp_mutex, "register_packet_component");

    if (next_componentid >= MAX_PACKET_COMPONENTS) {
        _MSG_FATAL("Attempted to register more than the maximum defined number of "
                "packet components.  Report this to the kismet developers along "
                "with a list of any plugins you might be using.");
        Globalreg::globalreg->fatal_condition = 1;
        return -1;
    }

    if (component_str_map.find(str_lower(in_component)) != component_str_map.end()) {
        return component_str_map[str_lower(in_component)];
    }

    lk.unlock();

    kis_unique_lock<kis_shared_mutex> ulk(packetcomp_mutex, "register_packet_component");

    int num = next_componentid++;

    component_str_map[str_lower(in_component)] = num;
    component_id_map[num] = str_lower(in_component);

    return num;
}

std::string packet_chain::fetch_packet_component_name(int in_id) {
    kis_shared_lock<kis_shared_mutex> lk(packetcomp_mutex, "fetch_packet_component_name");

    if (component_id_map.find(in_id) == component_id_map.end()) {
		return "<UNKNOWN>";
    }

	return component_id_map[in_id];
}

std::shared_ptr<kis_packet> packet_chain::generate_packet() {
    return packet_pool.acquire();
    // return std::make_shared<kis_packet>();
}

void packet_chain::packet_queue_processor(packet_fifo *packet_queue) {
    std::deque<std::shared_ptr<kis_packet>> batch;

    // The chain snapshot this thread is running.  It is kept between packets and only
    // refreshed when the chains have changed, and released before waiting for more packets
    // so that remove_handler() does not wait for idle threads.
    pc_chains_ref cur_chains;

    while (true) {
        if (!packet_queue->try_dequeue_all(batch)) {
            cur_chains.reset();
            packet_queue->wait_dequeue_all(batch);
        }

        for (auto& packet : batch) {
            if (packet == nullptr ||
                    packetchain_shutdown ||
                    Globalreg::globalreg->spindown ||
                    Globalreg::globalreg->fatal_condition ||
                    Globalreg::globalreg->complete)
                return;

            if (cur_chains.get() == nullptr ||
                    cur_chains->generation != chains_generation.load(std::memory_order_acquire))
                cur_chains.set(fetch_chains());

            // Lock the individual packet to make sure no competing processing threads
            // manipulate it (such as via dupe packet collision) while we're processing
            packet->mutex.lock();

            const auto& chunk = packet->fetch<kis_datachunk>(pack_comp_decap, pack_comp_linkframe);

            if (chunk != nullptr && chunk->data() != nullptr && chunk->length() != 0) {
                packet->hash = crc32_fast(chunk->data(), chunk->length(), 0);
                dedupe_packet(packet, chunk);
            }

            // run the rest of the packet chain

            for (const auto& pcl : cur_chains->llcdissect) {
                if (pcl.callback != nullptr)
                    pcl.callback(pcl.auxdata, packet);
            }

            for (const auto& pcl : cur_chains->decrypt) {
                if (pcl.callback != nullptr)
                    pcl.callback(pcl.auxdata, packet);
            }

            for (const auto& pcl : cur_chains->datadissect) {
                if (pcl.callback != nullptr)
                    pcl.callback(pcl.auxdata, packet);
            }

            for (const auto& pcl : cur_chains->classifier) {
                if (pcl.callback != nullptr)
                    pcl.callback(pcl.auxdata, packet);
            }

            for (const auto& pcl : cur_chains->tracker) {
                if (pcl.callback != nullptr)
                    pcl.callback(pcl.auxdata, packet);
            }

            for (const auto& pcl : cur_chains->logging) {
                if (pcl.callback != nullptr)
                    pcl.callback(pcl.auxdata, packet);
            }

            packet->mutex.unlock();

            uint64_t now = Globalreg::globalreg->last_tv_sec;

            if (packet->error)
                packet_error_rrd->add_sample(1, now);

            if (packet->duplicate)
                packet_dupe_rrd->add_sample(1, now);

            packet_processed_rrd->add_sample(1, now);

            packet.reset();
            packet_queue->packet_done();
        }

        batch.clear();
    }
}

void packet_chain::dedupe_packet(const std::shared_ptr<kis_packet>& packet,
        const std::shared_ptr<kis_datachunk>& chunk) {
    // Earlier packets sharing this hash; per thread so we don't allocate per packet
    thread_local std::vector<std::shared_ptr<kis_packet>> candidates;
    candidates.clear();

    std::shared_ptr<kis_packet> evicted;

    {
        kis_lock_guard<kis_shared_mutex> lk(pack_no_mutex, "packetchain dedupe");

        for (size_t i = 0; i < dedupe_list_sz; i++) {
            if (dedupe_hash[i] == packet->hash && dedupe_pkt[i] != nullptr)
                candidates.push_back(dedupe_pkt[i]);
        }

        for (const auto& p : dedupe_pending) {
            if (p->hash == packet->hash)
                candidates.push_back(p);
        }

        if (candidates.empty()) {
            evicted = dedupe_insert(packet);
            packet->packet_no = unique_packet_no.fetch_add(1);
            return;
        }

        // Pending before we release the lock so a simultaneous identical packet finds us
        dedupe_pending.push_back(packet);
    }

    // A hash match only means a possible duplicate.  Wait for each candidate to finish its
    // chain (they were visible before us, so waits never cycle) and compare the frames.
    bool duplicate = false;

    for (const auto& c : candidates) {
        kis_lock_guard<kis_mutex> lg(c->mutex, "packetchain dedupe candidate");

        const auto& c_chunk = c->fetch<kis_datachunk>(pack_comp_decap, pack_comp_linkframe);

        if (c_chunk == nullptr || c_chunk->length() != chunk->length() ||
                memcmp(c_chunk->data(), chunk->data(), chunk->length()) != 0)
            continue;

        const auto& orig = (c->duplicate && c->original != nullptr) ? c->original : c;

        kis_lock_guard<kis_mutex> olg(orig->mutex, "packetchain dedupe original");

        packet->duplicate = true;
        packet->packet_no = orig->packet_no;
        packet->original = orig;

        // Borrow the original's decoded components so the duplicate isn't decoded again.
        // Everything the duplicate already has came from its own capture (raw frame,
        // signal, checksum, source) and is kept, so it's logged as it was captured.
        for (unsigned int i = 0; i < MAX_PACKET_COMPONENTS; i++) {
            const auto& cp = orig->content_vec[i];

            if (cp == nullptr || cp->unique() || packet->content_vec[i] != nullptr)
                continue;

            packet->content_vec[i] = cp;
        }

        // Merge the signal levels
        // TODO fix for new embedded l1 data
#if 0
        if (packet->has(pack_comp_l1) && packet->has(pack_comp_datasource)) {
            auto l1 = packet->original->fetch<kis_layer1_packinfo>(pack_comp_l1);
            auto radio_agg = packet->fetch_or_add<kis_layer1_aggregate_packinfo>(pack_comp_l1_agg);
            auto datasrc = packet->fetch<packetchain_comp_datasource>(pack_comp_datasource);
            radio_agg->source_l1_map[datasrc->ref_source->get_source_uuid()] = l1;
        }
#endif

        duplicate = true;
        break;
    }

    kis_lock_guard<kis_shared_mutex> lk(pack_no_mutex, "packetchain dedupe resolve");

    dedupe_pending.erase(std::find(dedupe_pending.begin(), dedupe_pending.end(), packet));

    // Hash collision with different frames; we're an original
    if (!duplicate) {
        evicted = dedupe_insert(packet);
        packet->packet_no = unique_packet_no.fetch_add(1);
    }
}

std::shared_ptr<kis_packet> packet_chain::dedupe_insert(const std::shared_ptr<kis_packet>& packet) {
    const auto slot = dedupe_list_pos;
    dedupe_list_pos = (dedupe_list_pos + 1) % dedupe_list_sz;

    auto evicted = std::move(dedupe_pkt[slot]);
    dedupe_hash[slot] = packet->hash;
    dedupe_pkt[slot] = packet;

    return evicted;
}

int packet_chain::process_packet(std::shared_ptr<kis_packet> in_pack) {
    if (in_pack == nullptr)
        return 1;

    time_t now = (time_t) Globalreg::globalreg->last_tv_sec;

    // Total packet rate always gets added, even when we drop, so we can compare
    packet_rate_rrd->add_sample(1, now);
    packet_peak_rrd->add_sample(1, now);

    // Run the post-capture processing
    {
        pc_chains_ref cur_chains;
        cur_chains.set(fetch_chains());

        for (const auto& pcl : cur_chains->postcap) {
            if (pcl.callback != nullptr)
                pcl.callback(pcl.auxdata, in_pack);
        }
    }

    // Packets with an assignment id go to a consistent thread; others are spread round
    // robin.  A busy key may spill to one alternate thread, so a hot device is shared by
    // at most two threads instead of contending across all of them.
    thread_local unsigned int unassigned_rr = 0;

    unsigned int processing_id;

    if (in_pack->assignment_id == 0)
        processing_id = unassigned_rr++ % n_packet_threads;
    else
        processing_id = in_pack->assignment_id % n_packet_threads;

    auto qsize = packet_threads[processing_id]->packet_queue.size_approx();

    if (qsize > assignment_spill_backlog && in_pack->assignment_id != 0 && n_packet_threads > 1) {
        auto alt = (in_pack->assignment_id >> 16) % n_packet_threads;

        if (alt == processing_id)
            alt = (alt + 1) % n_packet_threads;

        const auto asize = packet_threads[alt]->packet_queue.size_approx();

        if (asize < qsize) {
            qsize = asize;
            processing_id = alt;
        }
    }

    if (packet_queue_drop != 0 && qsize > packet_queue_drop) {
        time_t offt = now - last_packet_drop_user_warning;

        if (offt > 30) {
            last_packet_drop_user_warning = now;

            std::shared_ptr<alert_tracker> alertracker =
                Globalreg::fetch_mandatory_global_as<alert_tracker>();
            alertracker->raise_one_shot("PACKETLOST",
                    "SYSTEM", kis_alert_severity::high,
                    fmt::format("The packet queue has exceeded the maximum size of {}; Kismet "
                        "will start dropping packets.  Your system may not have enough CPU to keep "
                        "up with the packet rate in your environment or other processes may be "
                        "taking up the CPU.  You can increase the packet backlog with the "
                        "packet_backlog_limit configuration parameter.", packet_queue_drop), -1);
        }

        packet_drop_rrd->add_sample(1, now);

        return 1;
    }

    if (qsize > packet_queue_warning && packet_queue_warning != 0) {
        time_t offt = now - last_packet_queue_user_warning;

        if (offt > 30) {
            last_packet_queue_user_warning = now;

            auto alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>();
            alertracker->raise_one_shot("PACKETQUEUE",
                    "SYSTEM", kis_alert_severity::medium,
                    fmt::format("The packet queue has a backlog of {} packets; "
                    "your system may not have enough CPU to keep up with the packet rate "
                    "in your environment or you may have other processes taking up CPU.  "
                    "Kismet will continue to process packets, as this may be a momentary spike "
                    "in packet load.", packet_queue_warning), -1);
        }
    }


    // Queue the packet to the target thread
    packet_threads[processing_id]->packet_queue.enqueue(in_pack);
    packet_queue_rrd->add_sample(qsize, now);

    return 1;
}

bool packet_chain::backlog_high() const {
    // Pause well before a configured drop limit
    const size_t pause = packet_queue_drop == 0 ? reader_pause_backlog :
        std::min<size_t>(reader_pause_backlog, packet_queue_drop / 2);

    for (unsigned int i = 0; i < n_packet_threads; i++) {
        if (packet_threads[i]->packet_queue.size_approx() > pause)
            return true;
    }

    return false;
}

packet_chain::pc_chains_ptr packet_chain::fetch_chains() {
    kis_shared_lock<kis_shared_mutex> lk(packetchain_mutex, "fetch_chains");
    return chains;
}

std::vector<packet_chain::pc_link> *packet_chain::select_chain(pc_chains *in_chains, int in_chain) {
    switch (in_chain) {
        case CHAINPOS_POSTCAP:
            return &in_chains->postcap;
        case CHAINPOS_LLCDISSECT:
            return &in_chains->llcdissect;
        case CHAINPOS_DECRYPT:
            return &in_chains->decrypt;
        case CHAINPOS_DATADISSECT:
            return &in_chains->datadissect;
        case CHAINPOS_CLASSIFIER:
            return &in_chains->classifier;
        case CHAINPOS_TRACKER:
            return &in_chains->tracker;
        case CHAINPOS_LOGGING:
            return &in_chains->logging;
        default:
            return nullptr;
    }
}

void packet_chain::publish_chains(std::shared_ptr<pc_chains> in_chains) {
    in_chains->generation = chains->generation + 1;

    std::weak_ptr<const pc_chains> old_chains = chains;

    chains = std::move(in_chains);
    chains_generation.store(chains->generation, std::memory_order_release);

    // Keep track of the replaced snapshot for remove_handler(); a thread may still be running it
    std::lock_guard<std::mutex> rlk(retired_mutex);

    retired_chains.erase(std::remove_if(retired_chains.begin(), retired_chains.end(),
                [](const auto& r) { return r.expired(); }), retired_chains.end());

    if (!old_chains.expired())
        retired_chains.push_back(old_chains);
}

int packet_chain::register_int_handler(pc_callback in_cb, void *in_aux, int in_chain, int in_prio) {
    kis_lock_guard<kis_shared_mutex> lk(packetchain_mutex, "register_int_handler");

    auto new_chains = std::make_shared<pc_chains>(*chains);
    auto chain = select_chain(new_chains.get(), in_chain);

    if (chain == nullptr) {
        _MSG("packet_chain::register_handler requested unknown chain", MSGFLAG_ERROR);
        return -1;
    }

    pc_link link;
    link.priority = in_prio;
    link.callback = in_cb;
    link.auxdata = in_aux;
    link.id = next_handlerid++;

    chain->push_back(link);
    std::stable_sort(chain->begin(), chain->end(), SortLinkPriority());

    publish_chains(std::move(new_chains));

    return link.id;
}

int packet_chain::register_handler(pc_callback in_cb, void *in_aux, int in_chain, int in_prio) {
    return register_int_handler(in_cb, in_aux, in_chain, in_prio);
}

int packet_chain::remove_int_handler(const std::function<bool (const pc_link&)>& in_match, int in_chain) {
    {
        kis_lock_guard<kis_shared_mutex> lk(packetchain_mutex, "remove_handler");

        auto new_chains = std::make_shared<pc_chains>(*chains);
        auto chain = select_chain(new_chains.get(), in_chain);

        if (chain == nullptr) {
            _MSG("packet_chain::remove_handler requested unknown chain", MSGFLAG_ERROR);
            return -1;
        }

        auto removed = std::remove_if(chain->begin(), chain->end(), in_match);

        if (removed == chain->end())
            return 1;

        chain->erase(removed, chain->end());

        publish_chains(std::move(new_chains));
    }

    // Once we return, the caller may destroy whatever the handler uses, so wait until no
    // other thread can still be running it
    wait_for_retired_chains();

    return 1;
}

void packet_chain::wait_for_retired_chains() {
    // Snapshots held by this thread can't be waited for (we may have been called from a
    // handler); neither can those held by other threads waiting here, or two handlers removing
    // handlers at the same time would wait for each other.
    std::vector<const void *> own_chains = thread_held_chains;

    auto in_use = [&]() -> bool {
        for (const auto& r : retired_chains) {
            auto c = r.lock();

            if (c == nullptr)
                continue;

            if (std::find(own_chains.begin(), own_chains.end(), c.get()) != own_chains.end())
                continue;

            if (waiting_chains.find(c.get()) != waiting_chains.end())
                continue;

            return true;
        }

        return false;
    };

    std::unique_lock<std::mutex> rlk(retired_mutex);

    for (auto c : own_chains)
        waiting_chains.insert(c);

    // Packet threads finish their current packet and pick up the new chains with the next one,
    // so this normally takes milliseconds; don't hang forever if a handler is blocked on a lock
    // held by the caller.
    auto start = std::chrono::steady_clock::now();
    bool timed_out = false;

    while (in_use()) {
        if (std::chrono::steady_clock::now() - start > std::chrono::seconds(5)) {
            timed_out = true;
            break;
        }

        rlk.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        rlk.lock();
    }

    for (auto c : own_chains) {
        auto w = waiting_chains.find(c);
        if (w != waiting_chains.end())
            waiting_chains.erase(w);
    }

    rlk.unlock();

    if (timed_out)
        _MSG_ERROR("packet_chain::remove_handler timed out waiting for packet handlers to "
                "finish; a handler may be blocked on a lock held by the caller");
}

int packet_chain::remove_handler(int in_id, int in_chain) {
    return remove_int_handler([in_id](const pc_link& l) { return l.id == in_id; }, in_chain);
}

int packet_chain::remove_handler(pc_callback in_cb, int in_chain) {
    return remove_int_handler([in_cb](const pc_link& l) { return l.callback == in_cb; }, in_chain);
}
