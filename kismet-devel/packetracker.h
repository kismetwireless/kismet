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

#ifndef __PACKETRACKER_H__
#define __PACKETRACKER_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>

#include "gpsd.h"
#include "packet.h"
#include "tracktypes.h"
#include "manuf.h"
#include "alertracker.h"
#include "util.h"

class Packetracker {
public:
    Packetracker();
    ~Packetracker();

    // Do regular maintenance
    int Tick();

    // Get the error
    char *FetchError() { return errstr; }

    // Set up the gps
    void AddGPS(GPSD *in_gps);
    // Set up the alert handler
    void AddAlertracker(Alertracker *in_tracker);
    // Pass in enabled alerts from the config file
    int EnableAlert(string in_alname, alert_time_unit in_unit,
                    int in_rate, int in_burstrate);

    // Set up filters
    void AddExportFilters(map<mac_addr, int> *bssid_map, map<mac_addr, int> *source_map,
                          map<mac_addr, int> *dest_map, int *bssid_invert,
                          int *source_invert, int *dest_invert);

    // Set up filtering - removed.  we do this in the server now before processing
    // anything else.
    //    void AddFilter(string in_filter) { filter = in_filter; }

    // Packet tracker stuff
    void ProcessPacket(packet_info info);
    void ProcessDataPacket(packet_info info, wireless_network *net);

    void UpdateIpdata(wireless_network *net);

    // Get all the networks
    vector<wireless_network *> FetchNetworks();

    int WriteNetworks(string in_fname);
    int WriteCSVNetworks(string in_fname);
    int WriteXMLNetworks(string in_fname);
    int WriteCisco(string in_fname);

    int WriteGpsdriveWaypt(FILE *in_file);

    void WriteSSIDMap(FILE *in_file);
    void ReadSSIDMap(FILE *in_file);

    void WriteIPMap(FILE *in_file);
    void ReadIPMap(FILE *in_file);

    // Tell the tracker to load maps of the manufacturer info
    void ReadAPManufMap(FILE *in_file);
    void ReadClientManufMap(FILE *in_file);

    // Convert the MAC
    static string Mac2String(uint8_t *mac, char seperator);
    // Utility to find strings that are empty or contain all spaces
    static bool IsBlank(const char *s);

    int FetchNumNetworks() { return num_networks; }
    //int FetchNumNetworks() { return bssid_map.size(); }
    int FetchNumPackets() { return num_packets; }
    int FetchNumDropped() { return num_dropped; }
    int FetchNumNoise() { return num_noise; }
    int FetchNumCrypt() { return num_crypt; }
    int FetchNumInteresting() { return num_interesting; }
    int FetchNumCisco() { return num_cisco; }

    void RemoveNetwork(mac_addr in_bssid);

protected:
    string SanitizeCSV(string in_data);
    string SanitizeXML(string in_data);

    char errstr[1024];
    GPSD *gps;

    Alertracker *alertracker;

    int num_networks, num_packets, num_dropped, num_noise,
        num_crypt, num_interesting, num_cisco;

    // all the networks
    vector<wireless_network *> network_list;

    // Several maps to refer to networks
    map<mac_addr, wireless_network *> bssid_map;

    // Map BSSID's to SSID for storage and cloaking
    map<mac_addr, string> bssid_cloak_map;

    // Map BSSID's to IP ranges for storage
    map<mac_addr, net_ip_data> bssid_ip_map;

    // Map probe responses for clients so we know we need to merge
    map<mac_addr, mac_addr> probe_map;

    // Manufacturer maps
    map<mac_addr, manuf *> ap_manuf_map;
    map<mac_addr, manuf *> client_manuf_map;

    // Filters
    map<mac_addr, int> *filter_export_bssid;
    int *filter_export_bssid_invert;
    map<mac_addr, int> *filter_export_source;
    int *filter_export_source_invert;
    map<mac_addr, int> *filter_export_dest;
    int *filter_export_dest_invert;
    int filter_export;

    // Alert references
    int netstumbler_aref;
    int deauthflood_aref;
    int lucenttest_aref;
    int wellenreiter_aref;
    int chanchange_aref;

};

#endif

