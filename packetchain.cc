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
    inline bool operator() (const Packetchain::pc_link *x, 
                            const Packetchain::pc_link *y) const {
        if (x->priority < y->priority)
            return 1;
        return 0;
    }
};

Packetchain::Packetchain() {
    fprintf(stderr, "Packetchain() called with no globalregistry\n");
	exit(-1);
}

Packetchain::Packetchain(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;
    next_componentid = 1;
	next_handlerid = 1;

    last_packet_queue_user_warning = 0;
    last_packet_drop_user_warning = 0;

    packet_queue_warning = 
        globalreg->kismet_config->FetchOptUInt("packet_log_warning", 0);
    packet_queue_drop =
        globalreg->kismet_config->FetchOptUInt("packet_backlog_limit", 8192);

    packetchain_shutdown = false;

    // Lock the packet conditional
    packet_condition.lock();

    for (unsigned int i = 0; i < std::thread::hardware_concurrency(); i++) {
        packet_threads.push_back(std::thread([this]() { 
            thread_set_process_name("packethandler");
            packet_queue_processor();
        }));
    }
}

Packetchain::~Packetchain() {
    {
        // Tell the packet thread we're dying and unlock it
        local_locker qlock(&packetqueue_mutex);
        packetchain_shutdown = true;
        packet_condition.unlock();

        for (auto& t : packet_threads)
            t.join();
    }

    {
        local_eol_locker lock(&packetchain_mutex);

        globalreg->RemoveGlobal("PACKETCHAIN");
        globalreg->packetchain = NULL;

        std::vector<Packetchain::pc_link *>::iterator i;

        for (i = genesis_chain.begin(); i != genesis_chain.end(); ++i) {
            delete(*i);
        }

        for (i = destruction_chain.begin(); i != destruction_chain.end(); ++i) {
            delete(*i);
        }

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

int Packetchain::RegisterPacketComponent(std::string in_component) {
    local_locker lock(&packetchain_mutex);

	if (next_componentid >= MAX_PACKET_COMPONENTS) {
		_MSG("Attempted to register more than the maximum defined number of "
			 "packet components.  Report this to the kismet developers along "
			 "with a list of any plugins you might be using.", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
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

int Packetchain::RemovePacketComponent(int in_id) {
    local_locker lock(&packetchain_mutex);

    std::string str;

    if (component_id_map.find(in_id) == component_id_map.end()) {
        return -1;
    }

    str = component_id_map[in_id];
    component_id_map.erase(component_id_map.find(in_id));
    component_str_map.erase(component_str_map.find(str));

    return 1;
}

std::string Packetchain::FetchPacketComponentName(int in_id) {
    local_locker lock(&packetchain_mutex);

    if (component_id_map.find(in_id) == component_id_map.end()) {
		return "<UNKNOWN>";
    }

	return component_id_map[in_id];
}

kis_packet *Packetchain::GeneratePacket() {
    local_locker lock(&packetchain_mutex);
    kis_packet *newpack = new kis_packet(globalreg);
    pc_link *pcl;

    // Run the frame through the genesis chain incase anything
    // needs to add something at the beginning
    for (unsigned int x = 0; x < genesis_chain.size(); x++) {
        pcl = genesis_chain[x];
   
        // Push it through the genesis chain and destroy it if we fail for some reason
        if (pcl->callback != NULL) {
            if ((*(pcl->callback))(globalreg, pcl->auxdata, newpack) < 0) {
                DestroyPacket(newpack);
                return NULL;
            } 
        } else if (pcl->l_callback != NULL) {
            if ((pcl->l_callback)(newpack) < 0) {
                DestroyPacket(newpack);
                return NULL;
            }
        } else {
            DestroyPacket(newpack);
            return NULL;
        }
    }

    return newpack;
}

void Packetchain::packet_queue_processor() {
    kis_packet *packet = NULL;
    local_demand_locker queue_lock(&(packetqueue_mutex));
    local_demand_locker chain_lock(&(packetchain_mutex));

    while (1) {
        queue_lock.lock();

        // Are we shutting down?
        if (packetchain_shutdown)
            return;
      
        if (packet_queue.size() != 0) {
            // Get the next packet
            packet = packet_queue.front();
            packet_queue.pop();

            // Unlock the queue while we process that packet
            queue_lock.unlock();

            // Lock the  packet chain itself because we need to have consistent
            // packet chain vectors
            
            for (auto pcl : postcap_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            for (auto pcl : llcdissect_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            for (auto pcl : decrypt_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            for (auto pcl : datadissect_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            for (auto pcl : classifier_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            for (auto pcl : tracker_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            for (auto pcl : logging_chain) {
                if (pcl->callback != NULL)
                    pcl->callback(globalreg, pcl->auxdata, packet);
                else if (pcl->l_callback != NULL)
                    pcl->l_callback(packet);
            }

            DestroyPacket(packet);

            // re-loop in case we have more packets
            continue;
        } else {
            // We have no packets, lock our conditional until something queues 
            // a new packet and fall out of the selector
            packet_condition.lock();
        }

        // No packets; fall through to blocking until we have them
        queue_lock.unlock();


        // Block until something pokes the conditional locker
        packet_condition.block_until();
    }
}

int Packetchain::ProcessPacket(kis_packet *in_pack) {
    local_locker qlock(&packetqueue_mutex);

    if (packet_queue.size() > packet_queue_warning &&
            packet_queue_warning != 0) {
        time_t offt = time(0) - last_packet_queue_user_warning;

        if (offt > 30) {
            last_packet_queue_user_warning = time(0);

            std::shared_ptr<Alertracker> alertracker =
                Globalreg::FetchMandatoryGlobalAs<Alertracker>(globalreg, "ALERTTRACKER");
            alertracker->RaiseOneShot("PACKETQUEUE", 
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

            std::shared_ptr<Alertracker> alertracker =
                Globalreg::FetchMandatoryGlobalAs<Alertracker>(globalreg, "ALERTTRACKER");
            alertracker->RaiseOneShot("PACKETLOST", 
                    "Kismet has started to drop packets; the packet queue has a backlog "
                    "of " + IntToString(packet_queue.size()) + " packets.  Your system "
                    "may not be fast enough to process the number of packets being seen. "
                    "You change this behavior in 'kismet_memory.conf'.", -1);
        }

        // Don't queue packets
        return 1;
    }

    packet_queue.push(in_pack);

    packet_condition.unlock();

    return 1;
}

void Packetchain::DestroyPacket(kis_packet *in_pack) {
    local_locker lock(&packetchain_mutex);

    pc_link *pcl;

    // Push it through the destructors if there are any, we don't care
    // about error conditions
    for (unsigned int x = 0; x < destruction_chain.size(); x++) {
        pcl = destruction_chain[x];
   
        (*(pcl->callback))(globalreg, pcl->auxdata, in_pack);
    }

	delete in_pack;
}

int Packetchain::RegisterIntHandler(pc_callback in_cb, void *in_aux,
        std::function<int (kis_packet *)> in_l_cb, 
        int in_chain, int in_prio) {

    pc_link *link = NULL;
    
    // Generate packet, we'll nuke it if it's invalid later
    link = new pc_link;
    link->priority = in_prio;
    link->callback = in_cb;
    link->l_callback = in_l_cb;
    link->auxdata = in_aux;
	link->id = next_handlerid++;
            
    switch (in_chain) {
        case CHAINPOS_GENESIS:
            genesis_chain.push_back(link);
            stable_sort(genesis_chain.begin(), genesis_chain.end(), 
						SortLinkPriority());
            break;

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

        case CHAINPOS_DESTROY:
            destruction_chain.push_back(link);
            stable_sort(destruction_chain.begin(), destruction_chain.end(), 
						SortLinkPriority());
            break;

        default:
            delete link;
            _MSG("Packetchain::RegisterHandler requested unknown chain", 
				 MSGFLAG_ERROR);
            return -1;
    }

    return link->id;
}

int Packetchain::RegisterHandler(pc_callback in_cb, void *in_aux, 
        int in_chain, int in_prio) {
    return RegisterIntHandler(in_cb, in_aux, NULL, in_chain, in_prio);
}

int Packetchain::RegisterHandler(std::function<int (kis_packet *)> in_cb, int in_chain,
        int in_prio) {
    return RegisterIntHandler(NULL, NULL, in_cb, in_chain, in_prio);
}

int Packetchain::RemoveHandler(int in_id, int in_chain) {
	unsigned int x;

    local_locker lock(&packetchain_mutex);

    switch (in_chain) {
        case CHAINPOS_GENESIS:
			for (x = 0; x < genesis_chain.size(); x++) {
				if (genesis_chain[x]->id == in_id) {
					genesis_chain.erase(genesis_chain.begin() + x);
				}
			}
            break;

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

        case CHAINPOS_DESTROY:
			for (x = 0; x < destruction_chain.size(); x++) {
				if (destruction_chain[x]->id == in_id) {
					destruction_chain.erase(destruction_chain.begin() + x);
				}
			}
            break;

        default:
            _MSG("Packetchain::RemoveHandler requested unknown chain", 
				 MSGFLAG_ERROR);
            return -1;
    }

    return 1;
}

int Packetchain::RemoveHandler(pc_callback in_cb, int in_chain) {
	unsigned int x;

    local_locker lock(&packetchain_mutex);

    switch (in_chain) {
        case CHAINPOS_GENESIS:
			for (x = 0; x < genesis_chain.size(); x++) {
				if (genesis_chain[x]->callback == in_cb) {
					genesis_chain.erase(genesis_chain.begin() + x);
				}
			}
            break;

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

        case CHAINPOS_DESTROY:
			for (x = 0; x < destruction_chain.size(); x++) {
				if (destruction_chain[x]->callback == in_cb) {
					destruction_chain.erase(destruction_chain.begin() + x);
				}
			}
            break;

        default:
            _MSG("Packetchain::RemoveHandler requested unknown chain", 
				 MSGFLAG_ERROR);
            return -1;
    }

    return 1;
}

