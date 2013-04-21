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

#include "globalregistry.h"
#include "messagebus.h"
#include "configfile.h"
#include "packetchain.h"

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

	pthread_mutex_init(&packetchain_mutex, NULL);
}

int Packetchain::RegisterPacketComponent(string in_component) {
	pthread_mutex_lock(&packetchain_mutex);
	if (next_componentid >= MAX_PACKET_COMPONENTS) {
		_MSG("Attempted to register more than the maximum defined number of "
			 "packet components.  Report this to the kismet developers along "
			 "with a list of any plugins you might be using.", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		pthread_mutex_unlock(&packetchain_mutex);
		return -1;
	}

    if (component_str_map.find(StrLower(in_component)) != component_str_map.end()) {
		pthread_mutex_unlock(&packetchain_mutex);
		return component_str_map[StrLower(in_component)];
    }

    int num = next_componentid++;

    component_str_map[StrLower(in_component)] = num;
    component_id_map[num] = StrLower(in_component);

	pthread_mutex_unlock(&packetchain_mutex);
    return num;
}

int Packetchain::RemovePacketComponent(int in_id) {
    string str;

	pthread_mutex_lock(&packetchain_mutex);
    if (component_id_map.find(in_id) == component_id_map.end()) {
		pthread_mutex_unlock(&packetchain_mutex);
        return -1;
    }

    str = component_id_map[in_id];
    component_id_map.erase(component_id_map.find(in_id));
    component_str_map.erase(component_str_map.find(str));

	pthread_mutex_unlock(&packetchain_mutex);
    return 1;
}

string Packetchain::FetchPacketComponentName(int in_id) {
    if (component_id_map.find(in_id) == component_id_map.end()) {
		return "<UNKNOWN>";
    }

	return component_id_map[in_id];
}

kis_packet *Packetchain::GeneratePacket() {
    kis_packet *newpack = new kis_packet(globalreg);
    pc_link *pcl;

    // Run the frame through the genesis chain incase anything
    // needs to add something at the beginning
	pthread_mutex_lock(&packetchain_mutex);
    for (unsigned int x = 0; x < genesis_chain.size(); x++) {
        pcl = genesis_chain[x];
   
        // Push it through the genesis chain and destroy it if we fail for some reason
        if ((*(pcl->callback))(globalreg, pcl->auxdata, newpack) < 0) {
			pthread_mutex_unlock(&packetchain_mutex);
            DestroyPacket(newpack);
            return NULL;
        }
    }
	pthread_mutex_unlock(&packetchain_mutex);

    return newpack;
}

int Packetchain::ProcessPacket(kis_packet *in_pack) {
	pthread_mutex_lock(&packetchain_mutex);
    // Run it through every chain vector, ignoring error codes
    pc_link *pcl;

    for (unsigned int x = 0; x < postcap_chain.size() && 
		 (pcl = postcap_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, in_pack);

    for (unsigned int x = 0; x < llcdissect_chain.size() && 
		 (pcl = llcdissect_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, in_pack);

    for (unsigned int x = 0; x < decrypt_chain.size() && 
		 (pcl = decrypt_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, in_pack);

    for (unsigned int x = 0; x < datadissect_chain.size() && 
		 (pcl = datadissect_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, in_pack);

    for (unsigned int x = 0; x < classifier_chain.size() && 
		 (pcl = classifier_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, in_pack);

    for (unsigned int x = 0; x < tracker_chain.size() && 
		 (pcl = tracker_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, in_pack);

    for (unsigned int x = 0; x < logging_chain.size() && 
		 (pcl = logging_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, in_pack);
	pthread_mutex_unlock(&packetchain_mutex);

    DestroyPacket(in_pack);

    return 1;
}

void Packetchain::DestroyPacket(kis_packet *in_pack) {
    pc_link *pcl;

    // Push it through the destructors if there are any, we don't care
    // about error conditions
	pthread_mutex_lock(&packetchain_mutex);
    for (unsigned int x = 0; x < destruction_chain.size(); x++) {
        pcl = destruction_chain[x];
   
        (*(pcl->callback))(globalreg, pcl->auxdata, in_pack);
    }
	pthread_mutex_unlock(&packetchain_mutex);

	delete in_pack;
}

int Packetchain::RegisterHandler(pc_callback in_cb, void *in_aux, 
                                 int in_chain, int in_prio) {
    pc_link *link = NULL;
    
    if (in_prio > 1000) {
        _MSG("Packetchain::RegisterHandler requested priority greater than 1000", 
			 MSGFLAG_ERROR);
        return -1;
    }

	pthread_mutex_lock(&packetchain_mutex);

    // Generate packet, we'll nuke it if it's invalid later
    link = new pc_link;
    link->priority = in_prio;
    link->callback = in_cb;
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
			pthread_mutex_unlock(&packetchain_mutex);
            delete link;
            _MSG("Packetchain::RegisterHandler requested unknown chain", 
				 MSGFLAG_ERROR);
            return -1;
    }
	pthread_mutex_unlock(&packetchain_mutex);

    return link->id;
}

int Packetchain::RemoveHandler(int in_id, int in_chain) {
	unsigned int x;

	pthread_mutex_lock(&packetchain_mutex);
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
			pthread_mutex_unlock(&packetchain_mutex);
            _MSG("Packetchain::RemoveHandler requested unknown chain", 
				 MSGFLAG_ERROR);
            return -1;
    }

	pthread_mutex_unlock(&packetchain_mutex);
    return 1;
}

int Packetchain::RemoveHandler(pc_callback in_cb, int in_chain) {
	unsigned int x;

	pthread_mutex_lock(&packetchain_mutex);
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
			pthread_mutex_unlock(&packetchain_mutex);
            _MSG("Packetchain::RemoveHandler requested unknown chain", 
				 MSGFLAG_ERROR);
            return -1;
    }

	pthread_mutex_unlock(&packetchain_mutex);
    return 1;

}

