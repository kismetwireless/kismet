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

#define MAC_STR_LEN (MAC_LEN * 2) + 6

const string NOSSID("<no ssid>");

enum wireless_network_type {
    network_ap,
    network_adhoc,
    network_probe,
    network_lor,
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
    // What netmask are we using?
    uint8_t mask[4];
    // What's the gateway?
    uint8_t gate_ip[4];
    // What's the ip, if we're a client?
    uint8_t ip[4];

    // Are we loaded from a file?
    int load_from_store;
} net_ip_data;

enum client_type {
    client_unknown,
    client_fromds,
    client_tods,
    client_interfs,
    client_established
};

// Client info
typedef struct wireless_client {
    wireless_client() {
        type = client_unknown;
        memset(raw_mac, 0, MAC_LEN);

        first_time = 0;
        last_time = 0;

        manuf_id = 0;
        manuf_score = 0;

        data_packets = crypt_packets = interesting_packets = 0;

        gps_fixed = -1;
        min_lat = min_lon = min_alt = min_spd = 0;
        max_lat = max_lon = max_alt = max_spd = 0;
        aggregate_lat = aggregate_lon = aggregate_alt = 0;
        aggregate_points = 0;

        maxrate = 0;

        metric = 0;

        signal = quality = noise = 0;

        memset(&ipdata, 0, sizeof(net_ip_data));
    }

    client_type type;

    time_t first_time;
    time_t last_time;

    // MAC of client
    string mac;
    uint8_t raw_mac[MAC_LEN];

    // Manufacturer ID
    int manuf_id;
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

    int metric;

    // Last seen quality for a packet from this client
    int quality, signal, noise;

    // ip data
    net_ip_data ipdata;

};

// A network
typedef struct wireless_network {
    wireless_network() {
        type = network_data;

        manuf_id = -1;
        manuf_score = 0;

        memset(bssid_raw, 0, MAC_LEN);
        memset(&ipdata, 0, sizeof(net_ip_data));

        llc_packets = data_packets = crypt_packets = interesting_packets = 0;

        channel = 0;
        wep = 0;

        cloaked = 0;

        last_time = 0;
        first_time = 0;

        beacon = 0;
        listed = 0;

        gps_fixed = -1;
        min_lat = min_lon = min_alt = min_spd = 0;
        max_lat = max_lon = max_alt = max_spd = 0;

        aggregate_lat = aggregate_lon = aggregate_alt = 0;
        aggregate_points = 0;

        maxrate = 0;

        metric = 0;

        quality = signal = noise = 0;
        best_quality = best_signal = best_noise = 0;
        best_lat = best_lon = best_alt = 0;
    }

    wireless_network_type type;

    string ssid;

    string beacon_info;

    // Manufacturer ID
    int manuf_id;
    int manuf_score;

    // Packet counts
    int llc_packets;
    int data_packets;
    int crypt_packets;
    int interesting_packets;

    // info extracted from packets
    //uint8_t bssid[MAC_LEN];
    int channel;
    int wep;
    string bssid;

    uint8_t bssid_raw[MAC_LEN];

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

    // IP data
    net_ip_data ipdata;

    map<string, cdp_packet> cisco_equip;

    /*
    float gps_lat, gps_lon, gps_alt, gps_spd;
    int gps_mode;

    float first_lat, first_lon, first_alt, first_spd;
    int first_mode;
    */

    int gps_fixed;
    float min_lat, min_lon, min_alt, min_spd;
    float max_lat, max_lon, max_alt, max_spd;

    // Averaged center position
    double aggregate_lat, aggregate_lon, aggregate_alt;
    long aggregate_points;

    // How fast we can go
    double maxrate;

    // Are we metric? (used for loading from XML)
    int metric;

    // Connection information
    int quality, signal, noise;
    int best_quality, best_signal, best_noise;
    float best_lat, best_lon, best_alt;

    map<string, wireless_client *> client_map;

};


// Channel power info
typedef struct {
    time_t last_time;
    int signal;
} channel_power;

#endif
