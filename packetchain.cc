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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <pthread.h>

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
    inline bool operator() (const std::shared_ptr<packet_chain::pc_link>& x,
                            const std::shared_ptr<packet_chain::pc_link>& y) const {
        if (x->priority < y->priority)
            return 1;
        return 0;
    }
};

packet_chain::packet_chain() {
    packetcomp_mutex.set_name("packetchain packet_comp");
    packetchain_mutex.set_name("packetchain packetchain");
    pack_no_mutex.set_name("packetchain packetno");

    unique_packet_no = 1;

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
    pack_comp_l1 = register_packet_component("RADIODATA");
    pack_comp_l1_agg = register_packet_component("RADIODATA_AGG");
	pack_comp_datasource = register_packet_component("KISDATASRC");

    postcap_chain_update = false;
    llcdissect_chain_update = false;
    decrypt_chain_update = false;
    datadissect_chain_update = false;
    classifier_chain_update = false;
    tracker_chain_update = false;
    logging_chain_update = false;

    // Because dedupe has to actually store references to packets, we run it outside of the chain functions

#if 0
    // Checksum and dedupe function runs at the end of LLC dissection, which should be
    // after any phy demangling and DLT demangling; lock the packet for the rest of the 
    // packet chain
    register_handler([](void *auxdata, std::shared_ptr<kis_packet> in_pack) -> int {
			auto packetchain = reinterpret_cast<packet_chain *>(auxdata);

			// Lock the hash list, gating all hash comparisons 
			kis_lock_guard<kis_shared_mutex> lk(packetchain->pack_no_mutex, "hash handler");

			auto chunk = in_pack->fetch<kis_datachunk>(packetchain->pack_comp_decap, packetchain->pack_comp_linkframe);

			if (chunk == nullptr)
				return 1;

			if (chunk->data() == nullptr)
				return 1;

			if (chunk->length() == 0)
				return 1;

			in_pack->hash = crc32_fast(chunk->data(), chunk->length(), 0);

			for (unsigned int i = 0; i < 1024; i++) {
			if (packetchain->dedupe_list[i].hash == in_pack->hash) {
				in_pack->duplicate = true;
				in_pack->packet_no = packetchain->dedupe_list[i].packno;
				in_pack->original = packetchain->dedupe_list[i].original_pkt;

				// We have to wait until everything is done being changed in the packet
				// before we can copy the duplicate decoded state over, grab the lock that
				// is released at the end of the chain
				kis_lock_guard<kis_mutex> lg(packetchain->dedupe_list[i].original_pkt->mutex);
				for (unsigned int c = 0; c < MAX_PACKET_COMPONENTS; c++) {
					auto cp = packetchain->dedupe_list[i].original_pkt->content_vec[c];
					if (cp != nullptr) {
						if (cp->unique())
							continue;

						in_pack->content_vec[c] = cp;
					}
				}

				// Merge the signal levels
				if (in_pack->has(packetchain->pack_comp_l1) && in_pack->has(packetchain->pack_comp_datasource)) {
					auto l1 = in_pack->original->fetch<kis_layer1_packinfo>(packetchain->pack_comp_l1);
					auto radio_agg = in_pack->fetch_or_add<kis_layer1_aggregate_packinfo>(packetchain->pack_comp_l1_agg);
					auto datasrc = in_pack->fetch<packetchain_comp_datasource>(packetchain->pack_comp_datasource);
					radio_agg->source_l1_map[datasrc->ref_source->get_source_uuid()] = l1;
				}
			}
			}

			// Assign a new packet number and cache it in the dedupe
			if (!in_pack->duplicate) {
				auto listpos = packetchain->dedupe_list_pos++ % 1024;
				in_pack->packet_no = packetchain->unique_packet_no++;
				packetchain->dedupe_list[listpos].hash = in_pack->hash;
				packetchain->dedupe_list[listpos].packno = packetchain->unique_packet_no++;
				packetchain->dedupe_list[listpos].original_pkt = in_pack;
			}

			return 1;
		}, this, CHAINPOS_LLCDISSECT, -100000);
#endif

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
        kis_lock_guard<kis_shared_mutex> lk(packetchain_mutex, "~packet_chain");

        Globalreg::globalreg->remove_global("PACKETCHAIN");
        Globalreg::globalreg->packetchain = NULL;

        postcap_chain.clear();
        llcdissect_chain.clear();
        decrypt_chain.clear();
        datadissect_chain.clear();
        classifier_chain.clear();
        tracker_chain.clear();
        logging_chain.clear();

    }

}

void packet_chain::start_processing() {
    n_packet_threads = Globalreg::globalreg->kismet_config->fetch_opt_as<unsigned int>("kismet_packet_threads", 0);

    if (n_packet_threads == 0)
        n_packet_threads = static_cast<unsigned int>(std::thread::hardware_concurrency());

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
    kis_lock_guard<kis_mutex> lk(packetcomp_mutex);

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

    int num = next_componentid++;

    component_str_map[str_lower(in_component)] = num;
    component_id_map[num] = str_lower(in_component);

    return num;
}

int packet_chain::remove_packet_component(int in_id) {
    kis_lock_guard<kis_mutex> lk(packetcomp_mutex);

    std::string str;

    if (component_id_map.find(in_id) == component_id_map.end()) {
        return -1;
    }

    str = component_id_map[in_id];
    component_id_map.erase(component_id_map.find(in_id));
    component_str_map.erase(component_str_map.find(str));

    return 1;
}

std::string packet_chain::fetch_packet_component_name(int in_id) {
    kis_lock_guard<kis_mutex> lk(packetcomp_mutex);

    if (component_id_map.find(in_id) == component_id_map.end()) {
		return "<UNKNOWN>";
    }

	return component_id_map[in_id];
}

std::shared_ptr<kis_packet> packet_chain::generate_packet() {
    return packet_pool.acquire();
    // return std::make_shared<kis_packet>();
}

void packet_chain::packet_queue_processor(moodycamel::BlockingConcurrentQueue<std::shared_ptr<kis_packet>> *packet_queue) {
    std::shared_ptr<kis_packet> packet;

    while (!packetchain_shutdown && 
            !Globalreg::globalreg->spindown && 
            !Globalreg::globalreg->fatal_condition &&
            !Globalreg::globalreg->complete) {

        packet_queue->wait_dequeue(packet);

        if (packet == nullptr)
            break;


        // Lock the packet chain and update any processing queues by replacing
        // the old queue with the new one.

        kis_unique_lock<kis_shared_mutex> lk(packetchain_mutex, "packet processor");

        if (llcdissect_chain_update) {
            llcdissect_chain = llcdissect_chain_new;
            llcdissect_chain_new.clear();
            llcdissect_chain_update = false;
        }

        if (decrypt_chain_update) {
            decrypt_chain = decrypt_chain_new;
            decrypt_chain_new.clear();
            decrypt_chain_update = false;
        }

        if (datadissect_chain_update) {
            datadissect_chain = datadissect_chain_new;
            datadissect_chain_new.clear();
            datadissect_chain_update = false;
        }

        if (classifier_chain_update) {
            classifier_chain = classifier_chain_new;
            classifier_chain_new.clear();
            classifier_chain_update = false;
        }

        if (tracker_chain_update) {
            tracker_chain = tracker_chain_new;
            tracker_chain_new.clear();
            tracker_chain_update = false;
        }

        if (logging_chain_update) {
            logging_chain = logging_chain_new;
            logging_chain_new.clear();
            logging_chain_update = false;
        }

        lk.unlock();

        // These can only be perturbed inside a sync, which can only occur when
        // the worker thread is in the sync block above, so we shouldn't
        // need to worry about the integrity of these vectors while running

        /* Postcap is now handled before it gets into the per-thread chain
           for (const auto& pcl : postcap_chain) {
           if (pcl->callback != nullptr)
           pcl->callback(pcl->auxdata, packet);
           else if (pcl->l_callback != nullptr)
           pcl->l_callback(packet);
           }
           */

        // Lock the individual packet to make sure no competing processing threads
        // manipulate it while we're processing
        packet->mutex.lock();

        // Lock the hash list, gating all hash comparisons
        auto no_lk = kis_unique_lock<kis_shared_mutex>(pack_no_mutex, "hash handler");

        const auto& chunk = packet->fetch<kis_datachunk>(pack_comp_decap, pack_comp_linkframe);

        if (chunk != nullptr && chunk->data() != nullptr && chunk->length() != 0) {
            packet->hash = crc32_fast(chunk->data(), chunk->length(), 0);

            for (unsigned int i = 0; i < 1024; i++) {
                if (dedupe_list[i].hash == packet->hash) {
                    packet->duplicate = true;
                    packet->packet_no = dedupe_list[i].packno;
                    packet->original = dedupe_list[i].original_pkt;

                    // We have to wait until everything is done being changed in the packet
                    // before we can copy the duplicate decoded state over, grab the lock that
                    // is released at the end of the chain
                    kis_lock_guard<kis_mutex> lg(dedupe_list[i].original_pkt->mutex);
                    for (unsigned int c = 0; c < MAX_PACKET_COMPONENTS; c++) {
                        auto cp = dedupe_list[i].original_pkt->content_vec[c];
                        if (cp != nullptr) {
                            if (cp->unique())
                                continue;

                            packet->content_vec[c] = cp;
                        }
                    }

                    // Merge the signal levels
                    if (packet->has(pack_comp_l1) && packet->has(pack_comp_datasource)) {
                        auto l1 = packet->original->fetch<kis_layer1_packinfo>(pack_comp_l1);
                        auto radio_agg = packet->fetch_or_add<kis_layer1_aggregate_packinfo>(pack_comp_l1_agg);
                        auto datasrc = packet->fetch<packetchain_comp_datasource>(pack_comp_datasource);
                        radio_agg->source_l1_map[datasrc->ref_source->get_source_uuid()] = l1;
                    }
                }
            }

            // Assign a new packet number and cache it in the dedupe
            if (!packet->duplicate) {
                auto listpos = dedupe_list_pos++ % 1024;
                packet->packet_no = unique_packet_no++;
                dedupe_list[listpos].hash = packet->hash;
                dedupe_list[listpos].packno = unique_packet_no++;
                dedupe_list[listpos].original_pkt = packet;
            }
        }

        for (const auto& pcl : llcdissect_chain) {
            if (pcl->callback != nullptr)
                pcl->callback(pcl->auxdata, packet);
        }

        for (const auto& pcl : decrypt_chain) {
            if (pcl->callback != nullptr)
                pcl->callback(pcl->auxdata, packet);
        }

        for (const auto& pcl : datadissect_chain) {
            if (pcl->callback != nullptr)
                pcl->callback(pcl->auxdata, packet);
        }

        for (const auto& pcl : classifier_chain) {
            if (pcl->callback != nullptr)
                pcl->callback(pcl->auxdata, packet);
        }

        for (const auto& pcl : tracker_chain) {
            if (pcl->callback != nullptr)
                pcl->callback(pcl->auxdata, packet);
        }

        for (const auto& pcl : logging_chain) {
            if (pcl->callback != nullptr)
                pcl->callback(pcl->auxdata, packet);
        }

        packet->mutex.unlock();

        uint64_t now = Globalreg::globalreg->last_tv_sec;

        if (packet->error)
            packet_error_rrd->add_sample(1, now);

        if (packet->duplicate)
            packet_dupe_rrd->add_sample(1, now);

        packet_processed_rrd->add_sample(1, now);

        continue;
    }
}

int packet_chain::process_packet(std::shared_ptr<kis_packet> in_pack) {
    if (in_pack == nullptr)
        return 1;

    time_t now = (time_t) Globalreg::globalreg->last_tv_sec;

    // Total packet rate always gets added, even when we drop, so we can compare
    packet_rate_rrd->add_sample(1, now);
    packet_peak_rrd->add_sample(1, now);

    // Import the new postcap chain, if it has been modified
    kis_unique_lock<kis_shared_mutex> lk(packetchain_mutex, "process_packet");
    if (postcap_chain_update) {
        postcap_chain = postcap_chain_new;
        postcap_chain_new.clear();
        postcap_chain_update = false;
    }
    lk.unlock();

    // Run the post-capture processing
    for (const auto& pcl : postcap_chain) {
        if (pcl->callback != nullptr)
            pcl->callback(pcl->auxdata, in_pack);
    }

    // assign it to a thread
    unsigned int processing_id;

    // If there is no assignment id, randomly assign the packet to a thread.
    // Otherwise transform the assignment id to a consistent thread.
    // If the packet is a duplicate, assign it to the same thread as the original.
    if (in_pack->assignment_id == 0) {
        if (in_pack->original != nullptr) {
            processing_id = in_pack->original->assignment_id % n_packet_threads;
        } else {
            processing_id = rand() % n_packet_threads;
        }
    } else {
        processing_id = in_pack->assignment_id % n_packet_threads;
    }

    auto qsize = packet_threads[processing_id]->packet_queue.size_approx();

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

int packet_chain::register_int_handler(pc_callback in_cb, void *in_aux, int in_chain, int in_prio) {

    kis_lock_guard<kis_shared_mutex> lk(packetchain_mutex, "register_int_handler");

    auto link = std::make_shared<pc_link>();

    // Generate packet, we'll nuke it if it's invalid later
    link->priority = in_prio;
    link->callback = in_cb;
    link->auxdata = in_aux;
    link->id = next_handlerid++;

    switch (in_chain) {
        case CHAINPOS_POSTCAP:
            if (!postcap_chain_update) {
                postcap_chain_update = true;
                postcap_chain_new = postcap_chain;
            }

            postcap_chain_new.push_back(link);
            stable_sort(postcap_chain_new.begin(), postcap_chain_new.end(), 
                    SortLinkPriority());
            break;

        case CHAINPOS_LLCDISSECT:
            if (!llcdissect_chain_update) {
                llcdissect_chain_update = true;
                llcdissect_chain_new = llcdissect_chain;
            }

            llcdissect_chain_new.push_back(link);
            stable_sort(llcdissect_chain_new.begin(), llcdissect_chain_new.end(), 
                    SortLinkPriority());
            break;

        case CHAINPOS_DECRYPT:
            if (!decrypt_chain_update) {
                decrypt_chain_update = true;
                decrypt_chain_new = decrypt_chain;
            }

            decrypt_chain_new.push_back(link);
            stable_sort(decrypt_chain_new.begin(), decrypt_chain_new.end(), 
                    SortLinkPriority());
            break;

        case CHAINPOS_DATADISSECT:
            if (!datadissect_chain_update) {
                datadissect_chain_update = true;
                datadissect_chain_new = datadissect_chain;
            }

            datadissect_chain_new.push_back(link);
            stable_sort(datadissect_chain_new.begin(), datadissect_chain_new.end(), 
                    SortLinkPriority());
            break;

        case CHAINPOS_CLASSIFIER:
            if (!classifier_chain_update) {
                classifier_chain_update = true;
                classifier_chain_new = classifier_chain;
            }

            classifier_chain_new.push_back(link);
            stable_sort(classifier_chain_new.begin(), classifier_chain_new.end(), 
                    SortLinkPriority());
            break;

        case CHAINPOS_TRACKER:
            if (!tracker_chain_update) {
                tracker_chain_update = true;
                tracker_chain_new = tracker_chain;
            }

            tracker_chain_new.push_back(link);
            stable_sort(tracker_chain_new.begin(), tracker_chain_new.end(), 
                    SortLinkPriority());
            break;

        case CHAINPOS_LOGGING:
            if (!logging_chain_update) {
                logging_chain_update = true;
                logging_chain_new = logging_chain;
            }

            logging_chain_new.push_back(link);
            stable_sort(logging_chain_new.begin(), logging_chain_new.end(), 
                    SortLinkPriority());
            break;

        default:
            _MSG("packet_chain::register_handler requested unknown chain", MSGFLAG_ERROR);
            return -1;
    }

    return link->id;
}

int packet_chain::register_handler(pc_callback in_cb, void *in_aux, int in_chain, int in_prio) {
    return register_int_handler(in_cb, in_aux, in_chain, in_prio);
}

int packet_chain::remove_handler(int in_id, int in_chain) {
    kis_lock_guard<kis_shared_mutex> lk(packetchain_mutex, "remove_handler");

    unsigned int x;

    switch (in_chain) {
        case CHAINPOS_POSTCAP:
            if (!postcap_chain_update) {
                postcap_chain_update = true;
                postcap_chain_new = postcap_chain;
            }

            for (x = 0; x < postcap_chain_new.size(); x++) {
                if (postcap_chain_new[x]->id == in_id) {
                    postcap_chain_new.erase(postcap_chain_new.begin() + x);
                }
            }
            break;

        case CHAINPOS_LLCDISSECT:
            if (!llcdissect_chain_update) {
                llcdissect_chain_update = true;
                llcdissect_chain_new = llcdissect_chain;
            }

            for (x = 0; x < llcdissect_chain_new.size(); x++) {
                if (llcdissect_chain_new[x]->id == in_id) {
                    llcdissect_chain_new.erase(llcdissect_chain_new.begin() + x);
                }
            }
            break;

        case CHAINPOS_DECRYPT:
            if (!decrypt_chain_update) {
                decrypt_chain_update = true;
                decrypt_chain_new = decrypt_chain;
            }

            for (x = 0; x < decrypt_chain_new.size(); x++) {
                if (decrypt_chain_new[x]->id == in_id) {
                    decrypt_chain_new.erase(decrypt_chain_new.begin() + x);
                }
            }
            break;

        case CHAINPOS_DATADISSECT:
            if (!datadissect_chain_update) {
                datadissect_chain_update = true;
                datadissect_chain_new = datadissect_chain;
            }

            for (x = 0; x < datadissect_chain_new.size(); x++) {
                if (datadissect_chain_new[x]->id == in_id) {
                    datadissect_chain_new.erase(datadissect_chain_new.begin() + x);
                }
            }
            break;

        case CHAINPOS_CLASSIFIER:
            if (!classifier_chain_update) {
                classifier_chain_update = true;
                classifier_chain_new = classifier_chain;
            }

            for (x = 0; x < classifier_chain_new.size(); x++) {
                if (classifier_chain_new[x]->id == in_id) {
                    classifier_chain_new.erase(classifier_chain_new.begin() + x);
                }
            }
            break;

        case CHAINPOS_TRACKER:
            if (!tracker_chain_update) {
                tracker_chain_update = true;
                tracker_chain_new = tracker_chain;
            }

            for (x = 0; x < tracker_chain_new.size(); x++) {
                if (tracker_chain_new[x]->id == in_id) {
                    tracker_chain_new.erase(tracker_chain_new.begin() + x);
                }
            }
            break;

        case CHAINPOS_LOGGING:
            if (!logging_chain_update) {
                logging_chain_update = true;
                logging_chain_new = logging_chain;
            }

            for (x = 0; x < logging_chain_new.size(); x++) {
                if (logging_chain_new[x]->id == in_id) {
                    logging_chain_new.erase(logging_chain_new.begin() + x);
                }
            }
            break;

        default:
            _MSG("packet_chain::remove_handler requested unknown chain", 
                    MSGFLAG_ERROR);
            return -1;
    }

    return 1;
}

int packet_chain::remove_handler(pc_callback in_cb, int in_chain) {
    kis_lock_guard<kis_shared_mutex> lk(packetchain_mutex, "remove_handler");

    unsigned int x;

    switch (in_chain) {
        case CHAINPOS_POSTCAP:
            if (!postcap_chain_update) {
                postcap_chain_update = true;
                postcap_chain_new = postcap_chain;
            }

            for (x = 0; x < postcap_chain_new.size(); x++) {
                if (postcap_chain_new[x]->callback == in_cb) {
                    postcap_chain_new.erase(postcap_chain_new.begin() + x);
                }
            }
            break;

        case CHAINPOS_LLCDISSECT:
            if (!llcdissect_chain_update) {
                llcdissect_chain_update = true;
                llcdissect_chain_new = llcdissect_chain;
            }

            for (x = 0; x < llcdissect_chain_new.size(); x++) {
                if (llcdissect_chain_new[x]->callback == in_cb) {
                    llcdissect_chain_new.erase(llcdissect_chain_new.begin() + x);
                }
            }
            break;

        case CHAINPOS_DECRYPT:
            if (!decrypt_chain_update) {
                decrypt_chain_update = true;
                decrypt_chain_new = decrypt_chain;
            }

            for (x = 0; x < decrypt_chain_new.size(); x++) {
                if (decrypt_chain_new[x]->callback == in_cb) {
                    decrypt_chain_new.erase(decrypt_chain_new.begin() + x);
                }
            }
            break;

        case CHAINPOS_DATADISSECT:
            if (!datadissect_chain_update) {
                datadissect_chain_update = true;
                datadissect_chain_new = datadissect_chain;
            }

            for (x = 0; x < datadissect_chain_new.size(); x++) {
                if (datadissect_chain_new[x]->callback == in_cb) {
                    datadissect_chain_new.erase(datadissect_chain_new.begin() + x);
                }
            }
            break;

        case CHAINPOS_CLASSIFIER:
            if (!classifier_chain_update) {
                classifier_chain_update = true;
                classifier_chain_new = classifier_chain;
            }

            for (x = 0; x < classifier_chain_new.size(); x++) {
                if (classifier_chain_new[x]->callback == in_cb) {
                    classifier_chain_new.erase(classifier_chain_new.begin() + x);
                }
            }
            break;

        case CHAINPOS_TRACKER:
            if (!tracker_chain_update) {
                tracker_chain_update = true;
                tracker_chain_new = tracker_chain;
            }

            for (x = 0; x < tracker_chain_new.size(); x++) {
                if (tracker_chain_new[x]->callback == in_cb) {
                    tracker_chain_new.erase(tracker_chain_new.begin() + x);
                }
            }
            break;

        case CHAINPOS_LOGGING:
            if (!logging_chain_update) {
                logging_chain_update = true;
                logging_chain_new = logging_chain;
            }

            for (x = 0; x < logging_chain_new.size(); x++) {
                if (logging_chain_new[x]->callback == in_cb) {
                    logging_chain_new.erase(logging_chain_new.begin() + x);
                }
            }
            break;

        default:
            _MSG("packet_chain::remove_handler requested unknown chain", 
                    MSGFLAG_ERROR);
            return -1;
    }

    return 1;
}

