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
#include "messagebus.h"
#include "packet.h"
#include "packetchain.h"

class SortLinkPriority {
public:
    inline bool operator() (const packet_chain::pc_link *x, 
                            const packet_chain::pc_link *y) const {
        if (x->priority < y->priority)
            return 1;
        return 0;
    }
};

packet_chain::packet_chain() {
    next_componentid = 1;
	next_handlerid = 1;

    last_packet_queue_user_warning = 0;
    last_packet_drop_user_warning = 0;

    packetchain_mutex.set_name("packet_chain");

    packet_queue_warning = 
        Globalreg::globalreg->kismet_config->fetch_opt_uint("packet_log_warning", 0);
    packet_queue_drop =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("packet_backlog_limit", 8192);

    auto entrytracker = 
        Globalreg::fetch_mandatory_global_as<entry_tracker>();

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
    packet_stats_map->insert(packet_rate_rrd);
    packet_stats_map->insert(packet_error_rrd);
    packet_stats_map->insert(packet_dupe_rrd);
    packet_stats_map->insert(packet_queue_rrd);
    packet_stats_map->insert(packet_drop_rrd);
    packet_stats_map->insert(packet_processed_rrd);

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    // We now protect RRDs from complex ops w/ internal mutexes, so we can just share these out directly without
    // protecting them behind our own mutex; required, because we're mixing RRDs from different data sources,
    // like chain-level packet processing and worker mutex locked buffer queuing.
    httpd->register_route("/packetchain/packet_stats", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(packet_stats_map, nullptr));
    httpd->register_route("/packetchain/packet_rate", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(packet_rate_rrd, nullptr));
    httpd->register_route("/packetchain/packet_error", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(packet_error_rrd, nullptr));
    httpd->register_route("/packetchain/packet_dupe", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(packet_dupe_rrd, nullptr));
    httpd->register_route("/packetchain/packet_drop", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(packet_drop_rrd, nullptr));
    httpd->register_route("/packetchain/packet_processed", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(packet_processed_rrd, nullptr));

    packetchain_shutdown = false;

    for (auto nt = static_cast<int>(std::thread::hardware_concurrency()); nt > 0; nt--) {
        packet_threads.emplace_back(std::thread([this, nt]() {
                thread_set_process_name(fmt::format("packethandler {}", nt));
                packet_queue_processor();
                }));
    }

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
}

packet_chain::~packet_chain() {
    timetracker->remove_timer(event_timer_id);

    {
        // Tell the packet thread we're dying and unlock it
        packetchain_shutdown = true;
        packet_queue.enqueue(nullptr);

        for (auto& t: packet_threads) {
            if (t.joinable())
                t.join();
        }

        // packet_thread.join();
    }

    {
        // Stall until a sync is done
        local_eol_locker syncl(&packetchain_mutex);

        Globalreg::globalreg->remove_global("PACKETCHAIN");
        Globalreg::globalreg->packetchain = NULL;

        for (auto i : postcap_chain)
            delete(i);
        postcap_chain.clear();

        for (auto i : llcdissect_chain)
            delete(i);
        llcdissect_chain.clear();

        for (auto i : decrypt_chain)
            delete(i);
        decrypt_chain.clear();

        for (auto i : datadissect_chain)
            delete(i);
        datadissect_chain.clear();

        for (auto i : classifier_chain)
            delete(i);
        classifier_chain.clear();

        for (auto i : tracker_chain)
            delete(i);
        tracker_chain.clear();

        for (auto i : logging_chain)
            delete(i);
        logging_chain.clear();

    }

}

int packet_chain::register_packet_component(std::string in_component) {
    local_locker lock(&packetcomp_mutex);

    if (next_componentid >= MAX_PACKET_COMPONENTS) {
        _MSG("Attempted to register more than the maximum defined number of "
                "packet components.  Report this to the kismet developers along "
                "with a list of any plugins you might be using.", MSGFLAG_FATAL);
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
    local_locker lock(&packetcomp_mutex);

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
    local_shared_locker lock(&packetcomp_mutex);

    if (component_id_map.find(in_id) == component_id_map.end()) {
		return "<UNKNOWN>";
    }

	return component_id_map[in_id];
}

kis_packet *packet_chain::generate_packet() {
    kis_packet *newpack = new kis_packet(Globalreg::globalreg);

    return newpack;
}

void packet_chain::packet_queue_processor() {
    kis_packet *packet = NULL;

    while (!packetchain_shutdown && 
            !Globalreg::globalreg->spindown && 
            !Globalreg::globalreg->fatal_condition &&
            !Globalreg::globalreg->complete) {

        packet_queue.wait_dequeue(packet);

        if (packet == nullptr)
            break;

        // Lock the chain mutexes until we're done processing this packet
        local_locker chainl(&packetchain_mutex, "packet_chain::packet_queue_processor");

        // These can only be perturbed inside a sync, which can only occur when
        // the worker thread is in the sync block above, so we shouldn't
        // need to worry about the integrity of these vectors while running

        for (const auto& pcl : postcap_chain) {
            if (pcl->callback != NULL)
                pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
            else if (pcl->l_callback != NULL)
                pcl->l_callback(packet);
        }

        for (const auto& pcl : llcdissect_chain) {
            if (pcl->callback != NULL)
                pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
            else if (pcl->l_callback != NULL)
                pcl->l_callback(packet);
        }

        for (const auto& pcl : decrypt_chain) {
            if (pcl->callback != NULL)
                pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
            else if (pcl->l_callback != NULL)
                pcl->l_callback(packet);
        }

        for (const auto& pcl : datadissect_chain) {
            if (pcl->callback != NULL)
                pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
            else if (pcl->l_callback != NULL)
                pcl->l_callback(packet);
        }

        for (const auto& pcl : classifier_chain) {
            if (pcl->callback != NULL)
                pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
            else if (pcl->l_callback != NULL)
                pcl->l_callback(packet);
        }

        for (const auto& pcl : tracker_chain) {
            if (pcl->callback != NULL)
                pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
            else if (pcl->l_callback != NULL)
                pcl->l_callback(packet);
        }

        for (const auto& pcl : logging_chain) {
            if (pcl->callback != NULL)
                pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
            else if (pcl->l_callback != NULL)
                pcl->l_callback(packet);
        }

        if (packet->error)
            packet_error_rrd->add_sample(1, time(0));

        if (packet->duplicate)
            packet_dupe_rrd->add_sample(1, time(0));

        packet_processed_rrd->add_sample(1, time(0));

        destroy_packet(packet);

        continue;
    }
}

int packet_chain::process_packet(kis_packet *in_pack) {
    // Total packet rate always gets added, even when we drop, so we can compare
    packet_rate_rrd->add_sample(1, time(0));

    if (packet_queue_drop != 0 && packet_queue.size_approx() > packet_queue_drop) {
        time_t offt = time(0) - last_packet_drop_user_warning;

        if (offt > 30) {
            last_packet_drop_user_warning = time(0);

            std::shared_ptr<alert_tracker> alertracker =
                Globalreg::fetch_mandatory_global_as<alert_tracker>();
            alertracker->raise_one_shot("PACKETLOST", 
                    fmt::format("The packet queue has exceeded the maximum size of {}; Kismet "
                        "will start dropping packets.  Your system may not have enough CPU to keep "
                        "up with the packet rate in your environment or other processes may be "
                        "taking up the CPU.  You can increase the packet backlog with the "
                        "packet_backlog_limit configuration parameter.", packet_queue_drop), -1);
        }

        destroy_packet(in_pack);

        packet_drop_rrd->add_sample(1, time(0));

        return 1;
    }

    if (packet_queue.size_approx() > packet_queue_warning && packet_queue_warning != 0) {
        time_t offt = time(0) - last_packet_queue_user_warning;

        if (offt > 30) {
            last_packet_queue_user_warning = time(0);

            auto alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>();
            alertracker->raise_one_shot("PACKETQUEUE", 
                    fmt::format("The packet queue has a backlog of {} packets; "
                    "your system may not have enough CPU to keep up with the packet rate "
                    "in your environment or you may have other processes taking up CPU.  "
                    "Kismet will continue to process packets, as this may be a momentary spike "
                    "in packet load.", packet_queue_warning), -1);
        }
    }


    // Queue the packet
    packet_queue.enqueue(in_pack);

    packet_queue_rrd->add_sample(packet_queue.size_approx(), time(0));

    return 1;
}

void packet_chain::destroy_packet(kis_packet *in_pack) {

	delete in_pack;
}

int packet_chain::register_int_handler(pc_callback in_cb, void *in_aux,
        std::function<int (kis_packet *)> in_l_cb, 
        int in_chain, int in_prio) {

    local_locker l(&packetchain_mutex);

    pc_link *link = NULL;

    // Generate packet, we'll nuke it if it's invalid later
    link = new pc_link;
    link->priority = in_prio;
    link->callback = in_cb;
    link->l_callback = in_l_cb;
    link->auxdata = in_aux;
    link->id = next_handlerid++;

    switch (in_chain) {
        case CHAINPOS_POSTCAP:
            postcap_chain.push_back(link);
            stable_sort(postcap_chain.begin(), postcap_chain.end(), 
                    SortLinkPriority());
            break;

        case CHAINPOS_LLCDISSECT:
            llcdissect_chain.push_back(link);
            stable_sort(llcdissect_chain.begin(), llcdissect_chain.end(), 
                    SortLinkPriority());
            break;

        case CHAINPOS_DECRYPT:
            decrypt_chain.push_back(link);
            stable_sort(decrypt_chain.begin(), decrypt_chain.end(), 
                    SortLinkPriority());
            break;

        case CHAINPOS_DATADISSECT:
            datadissect_chain.push_back(link);
            stable_sort(datadissect_chain.begin(), datadissect_chain.end(), 
                    SortLinkPriority());
            break;

        case CHAINPOS_CLASSIFIER:
            classifier_chain.push_back(link);
            stable_sort(classifier_chain.begin(), classifier_chain.end(), 
                    SortLinkPriority());
            break;

        case CHAINPOS_TRACKER:
            tracker_chain.push_back(link);
            stable_sort(tracker_chain.begin(), tracker_chain.end(), 
                    SortLinkPriority());
            break;

        case CHAINPOS_LOGGING:
            logging_chain.push_back(link);
            stable_sort(logging_chain.begin(), logging_chain.end(), 
                    SortLinkPriority());
            break;

        default:
            delete link;
            _MSG("packet_chain::register_handler requested unknown chain", MSGFLAG_ERROR);
            return -1;
    }

    return link->id;
}

int packet_chain::register_handler(pc_callback in_cb, void *in_aux, int in_chain, int in_prio) {
    return register_int_handler(in_cb, in_aux, NULL, in_chain, in_prio);
}

int packet_chain::register_handler(std::function<int (kis_packet *)> in_cb, int in_chain, int in_prio) {
    return register_int_handler(NULL, NULL, in_cb, in_chain, in_prio);
}

int packet_chain::remove_handler(int in_id, int in_chain) {
    local_locker l(&packetchain_mutex);

    unsigned int x;

    switch (in_chain) {
        case CHAINPOS_POSTCAP:
            for (x = 0; x < postcap_chain.size(); x++) {
                if (postcap_chain[x]->id == in_id) {
                    postcap_chain.erase(postcap_chain.begin() + x);
                }
            }
            break;

        case CHAINPOS_LLCDISSECT:
            for (x = 0; x < llcdissect_chain.size(); x++) {
                if (llcdissect_chain[x]->id == in_id) {
                    llcdissect_chain.erase(llcdissect_chain.begin() + x);
                }
            }
            break;

        case CHAINPOS_DECRYPT:
            for (x = 0; x < decrypt_chain.size(); x++) {
                if (decrypt_chain[x]->id == in_id) {
                    decrypt_chain.erase(decrypt_chain.begin() + x);
                }
            }
            break;

        case CHAINPOS_DATADISSECT:
            for (x = 0; x < datadissect_chain.size(); x++) {
                if (datadissect_chain[x]->id == in_id) {
                    datadissect_chain.erase(datadissect_chain.begin() + x);
                }
            }
            break;

        case CHAINPOS_CLASSIFIER:
            for (x = 0; x < classifier_chain.size(); x++) {
                if (classifier_chain[x]->id == in_id) {
                    classifier_chain.erase(classifier_chain.begin() + x);
                }
            }
            break;

        case CHAINPOS_TRACKER:
            for (x = 0; x < tracker_chain.size(); x++) {
                if (tracker_chain[x]->id == in_id) {
                    tracker_chain.erase(tracker_chain.begin() + x);
                }
            }
            break;

        case CHAINPOS_LOGGING:
            for (x = 0; x < logging_chain.size(); x++) {
                if (logging_chain[x]->id == in_id) {
                    logging_chain.erase(logging_chain.begin() + x);
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
    local_locker l(&packetchain_mutex);

    unsigned int x;

    switch (in_chain) {
        case CHAINPOS_POSTCAP:
            for (x = 0; x < postcap_chain.size(); x++) {
                if (postcap_chain[x]->callback == in_cb) {
                    postcap_chain.erase(postcap_chain.begin() + x);
                }
            }
            break;

        case CHAINPOS_LLCDISSECT:
            for (x = 0; x < llcdissect_chain.size(); x++) {
                if (llcdissect_chain[x]->callback == in_cb) {
                    llcdissect_chain.erase(llcdissect_chain.begin() + x);
                }
            }
            break;

        case CHAINPOS_DECRYPT:
            for (x = 0; x < decrypt_chain.size(); x++) {
                if (decrypt_chain[x]->callback == in_cb) {
                    decrypt_chain.erase(decrypt_chain.begin() + x);
                }
            }
            break;

        case CHAINPOS_DATADISSECT:
            for (x = 0; x < datadissect_chain.size(); x++) {
                if (datadissect_chain[x]->callback == in_cb) {
                    datadissect_chain.erase(datadissect_chain.begin() + x);
                }
            }
            break;

        case CHAINPOS_CLASSIFIER:
            for (x = 0; x < classifier_chain.size(); x++) {
                if (classifier_chain[x]->callback == in_cb) {
                    classifier_chain.erase(classifier_chain.begin() + x);
                }
            }
            break;

        case CHAINPOS_TRACKER:
            for (x = 0; x < tracker_chain.size(); x++) {
                if (tracker_chain[x]->callback == in_cb) {
                    tracker_chain.erase(tracker_chain.begin() + x);
                }
            }
            break;

        case CHAINPOS_LOGGING:
            for (x = 0; x < logging_chain.size(); x++) {
                if (logging_chain[x]->callback == in_cb) {
                    logging_chain.erase(logging_chain.begin() + x);
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

