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

#ifndef __GLOBALREGISTRY_H__
#define __GLOBALREGISTRY_H__

#include "config.h"

#include "util.h"
#include "macaddr.h"
#include "packet.h"

// Pre-defs for all the things we point to
class MessageBus;
class Packetsourcetracker;
class Packetracker;
class Alertracker;
class Timetracker;
class GPSDClient;
class KisNetFramework;
class ConfigFile;
class SpeechControl;
class SoundControl;

// Global registry of references to tracker objects and preferences.  This 
// should supplant the masses of globals and externs we'd otherwise need.
class GlobalRegistry {
public:
    // Fatal terminate condition, as soon as we detect this in the main code we
    // should initiate a shutdown
    int fatal_condition;
    
    MessageBus *messagebus;
    Packetsourcetracker *sourcetracker;
    Packetracker *packetracker;
    Alertracker *alertracker;
    Timetracker *timetracker;
    GPSDClient *gpsd;
    KisNetFramework *kisnetserver;
    ConfigFile *kismet_config;
    SpeechControl *speechctl;
    SoundControl *soundctl;

    time_t start_time;
    string servername;
    time_t timestamp;

    // Packetsourcetracker stuff
    int channel_hop;
    int channel_split;
    int channel_dwell;
    int channel_velocity;
    string named_sources;
    vector<string> source_input_vec;
    vector<string> src_initchannel_vec;
    int source_from_cmd;

    int gps_enable;
    int speech_enable;
    int sound_enable;
    
    unsigned int silent;
    unsigned int metric;
    unsigned int track_probenets;

    // Protocol references we don't want to keep looking up
    int kis_prot_ref, err_prot_ref, ack_prot_ref, pro_prot_ref, 
        cap_prot_ref, trm_prot_ref, tim_prot_ref, net_prot_ref,
        cli_prot_ref, crd_prot_ref, gps_prot_ref, alr_prot_ref,
        sta_prot_ref, ifo_prot_ref, rem_prot_ref, pkt_prot_ref,
        str_prot_ref;

    // WEP stuff
    unsigned int client_wepkey_allowed;
    macmap<wep_key_info *> bssid_wep_map;

    // Filter maps for the various filter types
    int filter_tracker;
    macmap<int> filter_tracker_bssid;
    macmap<int> filter_tracker_source;
    macmap<int> filter_tracker_dest;
    int filter_tracker_bssid_invert, filter_tracker_source_invert,
        filter_tracker_dest_invert;

    int filter_dump;
    macmap<int> filter_dump_bssid;
    macmap<int> filter_dump_source;
    macmap<int> filter_dump_dest;
    int filter_dump_bssid_invert, filter_dump_source_invert,
        filter_dump_dest_invert;

    int filter_export;
    macmap<int> filter_export_bssid;
    macmap<int> filter_export_source;
    macmap<int> filter_export_dest;
    int filter_export_bssid_invert, filter_export_source_invert,
        filter_export_dest_invert;
   
    mac_addr broadcast_mac;

    int alert_backlog;
    
    GlobalRegistry() { 
        fatal_condition = 0;

        next_ext_ref = 0;

        messagebus = NULL;
        sourcetracker = NULL;
        packetracker = NULL;
        alertracker = NULL;
        timetracker = NULL;
        gpsd = NULL;
        kisnetserver = NULL;
        kismet_config = NULL;
        speechctl = NULL;
        soundctl = NULL;

        start_time = time(0);
        timestamp = start_time;

        gps_enable = -1;
        speech_enable = -1;
        sound_enable = -1;

        channel_hop = -1;
        channel_split = 0;
        channel_dwell = 0;
        channel_velocity = 1;
        source_from_cmd = 0;
        
        silent = 0;
        metric = 0;
        track_probenets = 1;

        kis_prot_ref = -1;
        err_prot_ref = -1;
        ack_prot_ref = -1;
        pro_prot_ref = -1;
        cap_prot_ref = -1;
        trm_prot_ref = -1;
        tim_prot_ref = -1;
        net_prot_ref = -1;
        cli_prot_ref = -1;
        crd_prot_ref = -1;
        gps_prot_ref = -1;
        alr_prot_ref = -1;
        sta_prot_ref = -1;
        ifo_prot_ref = -1;
        rem_prot_ref = -1;
        pkt_prot_ref = -1;
        str_prot_ref = -1;

        client_wepkey_allowed = 0;

        filter_tracker = 0;
        filter_tracker_bssid_invert = -1;
        filter_tracker_source_invert = -1;
        filter_tracker_dest_invert = -1;

        filter_dump = 0;
        filter_dump_bssid_invert = -1;
        filter_dump_source_invert = -1;
        filter_dump_dest_invert = -1;

        filter_export = 0;
        filter_export_bssid_invert = -1;
        filter_export_source_invert = -1;
        filter_export_dest_invert = -1;

        broadcast_mac = mac_addr("FF:FF:FF:FF:FF:FF");

        alert_backlog = 0;
    }

    // External globals -- allow other things to tie structs to us
    int RegisterExternalGlobal(string in_name) {
        if (ext_name_map.find(StrLower(in_name)) != ext_name_map.end())
            return -1;
        
        ext_name_map[StrLower(in_name)] = next_ext_ref++;
    }

    int FetchExternalGlobalRef(string in_name) {
        if (ext_name_map.find(StrLower(in_name)) != ext_name_map.end())
            return -1;

        return ext_name_map[StrLower(in_name)];
    }

    void *FetchExternalGlobal(int in_ref) {
        if (ext_data_map.find(in_ref) == ext_data_map.end())
            return NULL;

        return ext_data_map[in_ref];
    }

    int InsertExternalGlobal(int in_ref, void *in_data) {
        if (ext_data_map.find(in_ref) == ext_data_map.end())
            return -1;

        ext_data_map[in_ref] = in_data;

        return 1;
    }

protected:
    // Exernal global references, string to intid
    map<string, int> ext_name_map;
    // External globals
    map<int, void *> ext_data_map;
    int next_ext_ref;
};

#endif

