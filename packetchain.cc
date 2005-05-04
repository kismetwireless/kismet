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

#include "Packetchain.h"

class SortLinkPriority {
public:
    inline bool operator() (const Packetchain::pc_link *x, 
                            const Packetchain::pc_link *y) const {
        if (x->priority > y->priority)
            return 1;
        return 0;
    }
};

Packetchain::Packetchain() {
    fprintf(stderr, "Packetchain() called with no globalregistry\n");
}

Packetchain::Packetchain(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;
    next_componentid = 1;

    // Convert the WEP mappings to our real map
    vector<string> raw_wepmap_vec;
    raw_wepmap_vec = conf->FetchOptVec("wepkey");
    for (size_t rwvi = 0; rwvi < raw_wepmap_vec.size(); rwvi++) {
        string wepline = raw_wepmap_vec[rwvi];

        size_t rwsplit = wepline.find(",");
        if (rwsplit == string::npos) {
            globalreg->messagebus->InjectMessage("Malformed 'wepkey' option in the "
												 "config file", MSGFLAG_FATAL);
            ErrorShutdown();
        }

        mac_addr bssid_mac = wepline.substr(0, rwsplit).c_str();

        if (bssid_mac.error == 1) {
            globalreg->messagebus->InjectMessage("Malformed 'wepkey' option in the "
												 "config file", MSGFLAG_FATAL);
            ErrorShutdown();
        }

        string rawkey = wepline.substr(rwsplit + 1, wepline.length() - (rwsplit + 1));

        unsigned char key[WEPKEY_MAX];
        int len = Hex2UChar((unsigned char *) rawkey.c_str(), key);

        if (len != 5 && len != 13 && len != 16) {
            snprintf(errstr, STATUS_MAX, "Invalid key '%s' length %d in a wepkey "
					 "option in the config file.\n", rawkey.c_str(), len);
			globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            ErrorShutdown();
        }

        wep_key_info *keyinfo = new wep_key_info;
        keyinfo->bssid = bssid_mac;
        keyinfo->fragile = 0;
        keyinfo->decrypted = 0;
        keyinfo->failed = 0;
        keyinfo->len = len;
        memcpy(keyinfo->key, key, sizeof(unsigned char) * WEPKEY_MAX);

        globalreg->bssid_wep_map.insert(bssid_mac, keyinfo);

        snprintf(errstr, STATUS_MAX, "Using key %s length %d for BSSID %s",
                rawkey.c_str(), len, bssid_mac.Mac2String().c_str());
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    }

    if (conf->FetchOpt("allowkeytransmit") == "true") {
        globalregistry->messagebus->InjectMessage("Allowing clients to fetch "
												  "WEP keys", MSGFLAG_INFO);
        globalregistry->client_wepkey_allowed = 1;
    }
}

int Packetchain::RegisterPacketComponent(string in_component) {
	if (next_componentid >= MAX_PACKET_COMPONENTS) {
		globalreg->messagebus->InjectMessage("Attempted to register more than "
											 "the maximum defined number of "
											 "packet components.  Report this "
											 "to the kismet developers along "
											 "with a list of any plugins "
											 "you might be using.",
											 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

    if (component_str_map.find(StrLower(in_component)) != component_str_map.end()) {
        return -1;
    }

    int num = next_componentid++;

    component_str_map[StrLower(in_component)] = num;
    component_id_map[num] = StrLower(in_component);

    return num;
}

int Packetchain::RemovePacketComponent(int in_id) {
    string str;

    if (component_id_map.find(in_id) != component_id_map.end()) {
        return -1;
    }

    str = component_id_map[in_id];
    component_id_map.erase(component_id_map.find(in_id));
    component_str_map.erase(component_str_map.find(str));

    return 1;
}

kis_packet Packetchain::GeneratePacket() {
    kis_packet *newpack = new kis_packet;
    pc_link *pcl;

    // Run the frame through the genesis chain incase anyhting
    // needs to add something at the beginning
    for (unsigned int x = 0; x < genesis_chain.size(); x++) {
        pcl = genesis_chain[x];
   
        // Push it through the genesis chain and destroy it if we fail for some reason
        if ((*(pcl->callback))(globalreg, pcl->auxdata, newpack) < 0) {
            DestroyPacket(newpack);
            return NULL;
        }
    }

    return newpack;
}

int Packetchain::ProcessPacket(kis_packet *in_pack) {
    // Run it through every chain vector, ignoring error codes

    pc_link *pcl;

    for (int x = 0; x < postcap_chain.size() && (pcl = postcap_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, newpack);

    for (int x = 0; x < llcdissect_chain.size() && (pcl = llcdissect_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, newpack);

    for (int x = 0; x < filter_chain.size() && (pcl = filter_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, newpack);

    for (int x = 0; x < decrypt_chain.size() && (pcl = decrypt_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, newpack);

    for (int x = 0; x < datadissect_chain.size() && (pcl = datadissect_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, newpack);

    for (int x = 0; x < classifier_chain.size() && (pcl = classifier_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, newpack);

    for (int x = 0; x < logging_chain.size() && (pcl = logging_chain[x]); x++)
        (*(pcl->callback))(globalreg, pcl->auxdata, newpack);

    DestroyPacket(in_pack);

    return 1;
}

void Packetchain::DestroyPacket(kis_packet *in_pack) {
    pc_link *pcl;

    // Push it through the destructors if there are any, we don't care
    // about error conditions
    for (unsigned int x = 0; x < destruction_chain.size(); x++) {
        pcl = destruction_chain[x];
   
        (*(pcl->callback))(globalreg, pcl->auxdata, newpack);
    }

    // Delete anything left if it's meant to self destruct
    for (map<int, void *>::iterator x = in_pack->content_map.begin();
         x != in_pack->content_map.end(); ++x) {
		if (x->second->self_destruct)
			delete x->second;
    }

}

int Packetchain::RegisterHandler(pc_callback in_cb, void *in_aux, 
                                 int in_chain, int in_prio) {
    pc_link *link = NULL;
    
    if (in_prio > 1000) {
        globalreg->messagebus->InjectMessage("Packetchain::RegisterHandler requested "
                                             "priority greater than 1000", MSGFLAG_ERROR);
        return -1;
    }

    // Generate packet, we'll nuke it if it's invalid later
    link = new pc_link;
    link->priority = in_prio;
    link->callback = in_cb;
    link->auxdata = in_aux;
            
    switch (in_chain) {
        case CHAINPOS_GENESIS:
            genesis_chain.push_back(link);
            stable_sort(genesis_chain.begin(), genesis_chain.end(), SortLinkPriority());
            break;

        case CHAINPOS_POSTCAP:
            postcap_chain.push_back(link);
            stable_sort(postcap_chain.begin(), postcap_chain.end(), SortLinkPriority());
            break;

        case CHAINPOS_LLCDISSECT:
            llcdissect_chain.push_back(link);
            stable_sort(llcdissect_chain.begin(), llcdissect_chain.end(), SortLinkPriority());
            break;

        case CHAINPOS_FILTER:
            filter_chain.push_back(link);
            stable_sort(filter_chain.begin(), filter_chain.end(), SortLinkPriority());
            break;

        case CHAINPOS_DECRYPT:
            decrypt_chain.push_back(link);
            stable_sort(decrypt_chain.begin(), decrypt_chain.end(), SortLinkPriority());
            break;
            
        case CHAINPOS_DATADISSECT:
            datadissect_chain.push_back(link);
            stable_sort(datadissect_chain.begin(), datadissect_chain.end(), SortLinkPriority());
            break;

        case CHAINPOS_CLASSIFIER:
            classifier_chain.push_back(link);
            stable_sort(classifier_chain.begin(), classifier_chain.end(), SortLinkPriority());
            break;

        case CHAINPOS_LOGGING:
            logging_chain.push_back(link);
            stable_sort(logging_chain.begin(), logging_chain.end(), SortLinkPriority());
            break;

        case CHAINPOS_DESTROY:
            destruction_chain.push_back(link);
            stable_sort(destruction_chain.begin(), destruction_chain.end(), SortLinkPriority());
            break;

        default:
            delete link;
            globalreg->messagebus->InjectMessage("Packetchain::RegisterHandler requested "
                                                 "unknown chain", MSGFLAG_ERROR);
            return -1;
    }

    return 1;
}

