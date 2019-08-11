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

#include "globalregistry.h"
#include "messagebus.h"
#include "configfile.h"
#include "packetchain.h"
#include "alertracker.h"

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

    packet_queue_warning = 
        Globalreg::globalreg->kismet_config->fetch_opt_uint("packet_log_warning", 0);
    packet_queue_drop =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("packet_backlog_limit", 8192);

    packet_chain_pause = false;

    packetchain_shutdown = false;

#if 0
    auto num_chain_threads =
        Globalreg::globalreg->kismet_config->fetch_opt_int("packetprocess_max_threads", -1);

    if (num_chain_threads > 0) {
        _MSG_INFO("Limiting packet processing to {} threads max ({} cores available)",
                num_chain_threads, std::thread::hardware_concurrency());
    } else {
        num_chain_threads = std::thread::hardware_concurrency();
    }
#endif

    // Force to a single thread for now
    int num_chain_threads = 1;

    for (int i = 0; i < num_chain_threads; i++) {
        packet_threads.push_back(std::thread([this, i]() { 
            thread_set_process_name("packethandler");
            packet_queue_processor(i);
        }));
        packet_thread_cls.push_back(new conditional_locker<int>());
    }
}

packet_chain::~packet_chain() {
    {
        // Tell the packet thread we're dying and unlock it
        packetchain_shutdown = true;
        packetqueue_cv.notify_all();

        for (auto& t : packet_threads)
            t.join();
    }

    {
        // Stall until a sync is done
        local_eol_locker syncl(&packet_chain_sync_mutex);

        for (auto t : packet_thread_cls) {
            delete(t);
        }

        Globalreg::globalreg->RemoveGlobal("PACKETCHAIN");
        Globalreg::globalreg->packetchain = NULL;

        std::vector<packet_chain::pc_link *>::iterator i;

        for (i = postcap_chain.begin(); i != postcap_chain.end(); ++i) {
            delete(*i);
        }

        for (i = llcdissect_chain.begin(); i != llcdissect_chain.end(); ++i) {
            delete(*i);
        }

        for (i = decrypt_chain.begin(); i != decrypt_chain.end(); ++i) {
            delete(*i);
        }

        for (i = datadissect_chain.begin(); i != datadissect_chain.end(); ++i) {
            delete(*i);
        }

        for (i = classifier_chain.begin(); i != classifier_chain.end(); ++i) {
            delete(*i);
        }

        for (i = tracker_chain.begin(); i != tracker_chain.end(); ++i) {
            delete(*i);
        }

        for (i = logging_chain.begin(); i != logging_chain.end(); ++i) {
            delete(*i);
        }
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

    if (component_str_map.find(StrLower(in_component)) != component_str_map.end()) {
        return component_str_map[StrLower(in_component)];
    }

    int num = next_componentid++;

    component_str_map[StrLower(in_component)] = num;
    component_id_map[num] = StrLower(in_component);

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

int packet_chain::sync_service_threads(std::function<int (void)> fn) {
    local_locker syncl(&packet_chain_sync_mutex);

    // Lock all the requests to the threads, so the workers can tell us they've synced and
    // locked.
    for (auto cl : packet_thread_cls)
        cl->lock();

    // Lock the pause complete condition
    packet_chain_pause_cl.lock();

    // Tell all the threads to lock
    packet_chain_pause = true;

    packetqueue_cv.notify_all();

    // Wait for all the requests to unlock; we need them all to unlock so it doesn't matter
    // if they complete out of order, we'll get to it
    int num = 0;
    for (auto cl : packet_thread_cls) {
        cl->block_until();
        num++;
    }

    {
        // We're now locked, do work

        auto r = fn();

        packet_chain_pause = false;

        // Now lock all the conditionals again, and let the threads tell us they're DONE syncing
        for (auto cl : packet_thread_cls)
            cl->lock();

        packet_chain_pause_cl.unlock(0);

        int num = 0;
        for (auto cl : packet_thread_cls) {
            cl->block_until();
            num++;
        }

        return r;
    }

}

void packet_chain::packet_queue_processor(int slot_number) {
    std::unique_lock<std::mutex> lock(packetqueue_cv_mutex);

    kis_packet *packet = NULL;

    while (!packetchain_shutdown && 
            !Globalreg::globalreg->spindown && 
            !Globalreg::globalreg->fatal_condition &&
            !Globalreg::globalreg->complete) {

        packetqueue_cv.wait(lock, [this] {
            return (packet_queue.size() || packet_chain_pause);
            });

        // At this point we own lock, and it is locked, we need to re-lock it before we leave the loop

        // Do we need to pause?
        if (packet_chain_pause) {
            // Let go of the lock
            lock.unlock();

            // We've been asked to pause.  unlock the conditional to indicate we're in the sync block.
            packet_thread_cls[slot_number]->unlock();

            // Wait until we get the master unlock that all threads are synchronized

            // Block on the master unlock
            packet_chain_pause_cl.block_until();

            // We're done with the sync block; unlock the response
            packet_thread_cls[slot_number]->unlock();

            // Grab the lock again
            lock.lock();

            continue;
        }

        if (packet_queue.size() != 0) {
            // Get the next packet
            packet = packet_queue.front();
            packet_queue.pop();

            // Unlock the queue while we process that packet
            lock.unlock();

            // These can only be perturbed inside a sync, which can only occur when
            // the worker thread is in the sync block above, so we shouldn't
            // need to worry about the integrity of these vectors while running

            for (auto pcl : postcap_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            for (auto pcl : llcdissect_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            for (auto pcl : decrypt_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            for (auto pcl : datadissect_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            for (auto pcl : classifier_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            for (auto pcl : tracker_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            for (auto pcl : logging_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(Globalreg::globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            destroy_packet(packet);

            lock.lock();

            continue;
        }

        // No packets; fall through to blocking until we have them
        lock.lock();
    }
}

int packet_chain::process_packet(kis_packet *in_pack) {
    std::unique_lock<std::mutex> lock(packetqueue_cv_mutex);

    if (packet_queue.size() > packet_queue_warning &&
            packet_queue_warning != 0) {
        time_t offt = time(0) - last_packet_queue_user_warning;

        if (offt > 30) {
            last_packet_queue_user_warning = time(0);

            auto alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>();
            alertracker->raise_one_shot("PACKETQUEUE", 
                    "The packet queue has a backlog of " + IntToString(packet_queue.size()) + 
                    " packets; if you have multiple data sources it's possible that your "
                    "system is not fast enough.  Kismet will continue to process "
                    "packets, this may be a momentary spike in packet load.", -1);
        }
    }

    if (packet_queue_drop != 0 && packet_queue.size() > packet_queue_drop) {
        time_t offt = time(0) - last_packet_drop_user_warning;

        if (offt > 30) {
            last_packet_drop_user_warning = time(0);

            std::shared_ptr<alert_tracker> alertracker =
                Globalreg::fetch_mandatory_global_as<alert_tracker>();
            alertracker->raise_one_shot("PACKETLOST", 
                    "Kismet has started to drop packets; the packet queue has a backlog "
                    "of " + IntToString(packet_queue.size()) + " packets.  Your system "
                    "may not be fast enough to process the number of packets being seen. "
                    "You change this behavior in 'kismet_memory.conf'.", -1);
        }

        // Don't queue packets
        lock.unlock();
        return 1;
    }

    // Queue the packet
    packet_queue.push(in_pack);

    // Unlock and notify all workers
    lock.unlock();
    packetqueue_cv.notify_all();

    return 1;
}

void packet_chain::destroy_packet(kis_packet *in_pack) {

	delete in_pack;
}

int packet_chain::RegisterIntHandler(pc_callback in_cb, void *in_aux,
        std::function<int (kis_packet *)> in_l_cb, 
        int in_chain, int in_prio) {

    return sync_service_threads([&](void) -> int {
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
                _MSG("packet_chain::register_handler requested unknown chain", 
	    			 MSGFLAG_ERROR);
                return -1;
        }

        return link->id;

        });

}

int packet_chain::register_handler(pc_callback in_cb, void *in_aux, int in_chain, int in_prio) {
    return RegisterIntHandler(in_cb, in_aux, NULL, in_chain, in_prio);
}

int packet_chain::register_handler(std::function<int (kis_packet *)> in_cb, int in_chain, int in_prio) {
    return RegisterIntHandler(NULL, NULL, in_cb, in_chain, in_prio);
}

int packet_chain::remove_handler(int in_id, int in_chain) {
    return sync_service_threads([&](void) -> int {
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

        });

}

int packet_chain::remove_handler(pc_callback in_cb, int in_chain) {
    return sync_service_threads([&](void) -> int {
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
        });
}

