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

#ifndef __TRACKTYPES_H__
#define __TRACKTYPES_H__

#include "config.h"

#include <string>
#include <map>

#include "packet.h"

#ifndef display_network
typedef struct display_network;
#endif

// Forward definition
class manuf;

const string NOSSID("<no ssid>");

enum wireless_network_type {
    network_ap,
    network_adhoc,
    network_probe,
    network_turbocell,
    network_data,
    network_remove
};

enum address_type {
    address_none,
    address_factory,
    address_udp,
    address_arp,
    address_tcp,
    address_dhcp,
    address_group
};

// IP info
// Tracks addresses for networks and clients, with minor duplication
// for each.
typedef struct {
    address_type atype;

    // How many address octets have we matched?
    int octets;

    // What IP range are we using?
    uint8_t range_ip[4];

    /*
    // What netmask are we using?
    uint8_t mask[4];
    // What's the gateway?
    uint8_t gate_ip[4];
    */

    // What's the ip, if we're a client?
    uint8_t ip[4];

    // Are we loaded from a file?
    int load_from_store;
} net_ip_data;

enum client_type {
    client_unknown,
    client_fromds,
    client_tods,
    client_interds,
    client_established,
	client_sendto
};

// Client info
typedef struct wireless_client {
    wireless_client() {
        type = client_unknown;

        first_time = 0;
        last_time = 0;

        manuf_score = 0;
        manuf_ref = NULL;

        channel = 0;
        crypt_set = 0;

        data_packets = crypt_packets = interesting_packets = 0;

        gps_fixed = -1;

        /* by setting the min to the highest possible values in the range and
         max to the lowest we ensure that the data is correct */
        min_lat = 90;
        max_lat = -90;
        min_lon = 180;
        max_lon = -180;

        /* since these are not limited, we just set to 0 */
        min_alt = min_spd = 0;
        max_alt = max_spd = 0;

        aggregate_lat = aggregate_lon = aggregate_alt = 0;
        aggregate_points = 0;

        maxrate = 0;
        maxseenrate = 0;

        metric = 0;

        signal = quality = noise = 0;
        best_signal = best_quality = best_noise = 0;
        rssi = 0; rssi_max = 100;
        best_lat = best_lon = best_alt = 0;

        memset(&ipdata, 0, sizeof(net_ip_data));

#ifdef __TCPCLIENT_H__
        tcpclient = NULL;
#endif

        uidata = NULL;

        datasize = 0;

        encoding_set = 0;

        last_sequence = 0;

        decrypted = 0;
    }

#if 0
	wireless_client& operator= (const wireless_client& op) {
		type = op.type;
		first_time = op.first_time;
		last_time = op.last_time;
		mac = op.mac;
		channel = op.channel;
		crypt_set = op.crypt_set;
		manuf_ref = op.manuf_ref;
		manuf_score = op.manuf_score;
		data_packets = op.data_packets;
		crypt_packets = op.crypt_packets;
		interesting_packets = op.interesting_packets;
		gps_fixed = op.gps_fixed;
		min_lat = op.min_lat;
		min_lon = op.min_lon;
		min_alt = op.min_alt;
		min_spd = op.min_spd;
		max_lat = op.max_lat;
		max_lon = op.max_lon;
		max_alt = op.max_alt;
		max_spd = op.max_spd;
		aggregate_lat = op.aggregate_lat;
		aggregate_lon = op.aggregate_lon;
		aggregate_alt = op.aggregate_alt;
		aggregate_points = op.aggregate_points;
		maxrate = op.maxrate;
		maxseenrate = op.maxseenrate;
		encoding_set = op.encoding_set;
		metric = op.metric;
		quality = op.quality;
		signal = op.signal;
		noise = op.noise;
		best_quality = op.best_quality;
		best_signal = op.best_signal;
		best_noise = op.best_noise;
		best_lat = op.best_lat;
		best_lon = op.best_lon;
		best_alt = op.best_alt;
		ipdata = op.ipdata;
#ifdef __TCP_CLIENT_H__
		tcpclient = op.tcpclient;
#endif
		uidata = op.uidata;
		datasize = op.datasize;
		last_sequence = op.last_sequence;
		decrypted = op.decrypted;

		return *this;
	}
#endif

    client_type type;

    time_t first_time;
    time_t last_time;

    // MAC of client
    mac_addr mac;

    int channel;
    int crypt_set;

    // Manufacturer info - mac address key to the manufacturer map and score for
    // easy-default maps
    manuf *manuf_ref;
    int manuf_score;

    // Packet counts
    int data_packets;
    int crypt_packets;
    int interesting_packets;

    // gps data
    int gps_fixed;
    float min_lat, min_lon, min_alt, min_spd;
    float max_lat, max_lon, max_alt, max_spd;
    double aggregate_lat, aggregate_lon, aggregate_alt;
    long aggregate_points;

    // How fast we can go
    double maxrate;
    // How fast we've been seen to go, in 100kbs units
    int maxseenrate;

    // Bitfield set of encoding types seen on this client
    int encoding_set;

    int metric;

    // Last seen quality for a packet from this client
    int quality, signal, noise, rssi, rssi_max;
    int best_quality, best_signal, best_noise;
    float best_lat, best_lon, best_alt;

    // ip data
    net_ip_data ipdata;

#ifdef __TCPCLIENT_H__
    // If we're included in the client, include a reference to the server connection
    // that spawned us
    TcpClient *tcpclient;
#endif

    // Generic pointer for frontends to use to track things
    void *uidata;

    // Data passed, in bytes
    unsigned long datasize;

    int last_sequence;

    // Did we decrypt this client?
    int decrypted;

};

// A network
typedef struct wireless_network {
    wireless_network() {
        type = network_data;

        ssid = NOSSID;

        manuf_score = 0;
        manuf_ref = NULL;

        memset(&ipdata, 0, sizeof(net_ip_data));

        llc_packets = data_packets = crypt_packets = interesting_packets = 0;

        channel = 0;
		crypt_set = 0;

        cloaked = 0;

        last_time = 0;
        first_time = 0;

        beacon = 0;
        listed = 0;

        gps_fixed = -1;

        /* by setting the min to the highest possible values in the range and
         max to the lowest we ensure that the data is correct */
        min_lat = 90;
        max_lat = -90;
        min_lon = 180;
        max_lon = -180;

        /* since these are not limited, we just set to 0 */
        min_alt = min_spd = 0;
        max_alt = max_spd = 0;

        aggregate_lat = aggregate_lon = aggregate_alt = 0;
        aggregate_points = 0;

        maxrate = 0;
        maxseenrate = 0;

        metric = 0;

        quality = signal = noise = 0;
        best_quality = best_signal = best_noise = 0;
        rssi = 0; rssi_max = 100;
        best_lat = best_lon = best_alt = 0;

        client_disconnects = 0;

        datasize = 0;

        carrier_set = 0;
        encoding_set = 0;

#ifdef __TCPCLIENT_H__
        tcpclient = NULL;
        idle_time = 0;
        dispnet = NULL;
#endif

        uidata = NULL;

        turbocell_nid = turbocell_sat = 0;
        turbocell_mode = turbocell_unknown;

        last_sequence = 0;

        decrypted = 0;

        dupeiv_packets = 0;

        bss_timestamp = 0;

		cisco_equip = NULL;

    }

    wireless_network_type type;

    string ssid;

    string beacon_info;

    // Manufacturer ID
    manuf *manuf_ref;
    int manuf_score;

    // Packet counts
    int llc_packets;
    int data_packets;
    int crypt_packets;
    int interesting_packets;

    // info extracted from packets
    //uint8_t bssid[MAC_LEN];
    int channel;
	int crypt_set;

    mac_addr bssid;

    // Are we a cloaked SSID?
    int cloaked;

    // Last time we saw a packet
    time_t last_time;

    // First packet
    time_t first_time;

    // beacon interval
    int beacon;

    // Are we in the list?
    int listed;

    // Bitmask set of carrier types seen in this network
    int carrier_set;
    // Bitmask set of encoding types seen in this network
    int encoding_set;

    // IP data
    net_ip_data ipdata;

	vector<cdp_packet> *cisco_equip;

    int gps_fixed;
    float min_lat, min_lon, min_alt, min_spd;
    float max_lat, max_lon, max_alt, max_spd;

    // Averaged center position
    double aggregate_lat, aggregate_lon, aggregate_alt;
    long aggregate_points;

    // How fast we can go
    double maxrate;

    int maxseenrate;

    // Are we metric? (used for loading from XML)
    int metric;

    // Connection information
    int quality, signal, noise, rssi, rssi_max;
    int best_quality, best_signal, best_noise;
    float best_lat, best_lon, best_alt;

    map<mac_addr, wireless_client *> client_map;
    vector<wireless_client *> client_vec;

    // State tracking stuff
    // Number of client disconnects (decayed per second by packetracker::tick)
    int client_disconnects;
    // Last sequence value
    int last_sequence;

#ifdef __TCPCLIENT_H__
    // If we're included in the client, include a reference to the server connection
    // that spawned us
    TcpClient *tcpclient;
    // And include some records for tracking the time in the virtual group networks
    time_t idle_time;
    // Display network pointer
    display_network *dispnet;
#endif

    // Generic pointer for frontends to use to track things
    void *uidata;

    // Amount of data, in bytes
    unsigned long datasize;

    // Turbocell info
    int turbocell_nid;
    turbocell_type turbocell_mode;
    int turbocell_sat;
    string turbocell_name;

    // Did we decrypt this network?
    int decrypted;

    // Used IVs in this BSSID
    map<uint32_t, int> iv_map;
    // number of duplicate IV counts
    int dupeiv_packets;

    // BSS timestamp
    uint64_t bss_timestamp;
};


// Channel power info
typedef struct {
    time_t last_time;
    int signal;
} channel_power;

#endif
