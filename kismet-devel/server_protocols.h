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

#ifndef __PROTOCOLS_H__
#define __PROTOCOLS_H__

#include "config.h"
#include <stdio.h>
#include <string>
#include <vector>
#include "tracktypes.h"
#include "tcpserver.h"

// Builtin client/server field enums
enum NETWORK_fields {
    NETWORK_bssid, NETWORK_type, NETWORK_ssid, NETWORK_beaconinfo,
    NETWORK_llcpackets, NETWORK_datapackets, NETWORK_cryptpackets,
    NETWORK_weakpackets, NETWORK_channel, NETWORK_wep, NETWORK_firsttime,
    NETWORK_lasttime, NETWORK_atype, NETWORK_rangeip, NETWORK_gpsfixed,
    NETWORK_minlat, NETWORK_minlon, NETWORK_minalt, NETWORK_minspd,
    NETWORK_maxlat, NETWORK_maxlon, NETWORK_maxalt, NETWORK_maxspd,
    NETWORK_octets, NETWORK_cloaked, NETWORK_beaconrate, NETWORK_maxrate,
    NETWORK_manufkey, NETWORK_manufscore,
    NETWORK_quality, NETWORK_signal, NETWORK_noise,
    NETWORK_bestquality, NETWORK_bestsignal, NETWORK_bestnoise,
    NETWORK_bestlat, NETWORK_bestlon, NETWORK_bestalt,
    NETWORK_agglat, NETWORK_agglon, NETWORK_aggalt, NETWORK_aggpoints,
    NETWORK_datasize, NETWORK_tcnid, NETWORK_tcmode, NETWORK_tsat,
    NETWORK_carrierset, NETWORK_maxseenrate, NETWORK_encodingset
};

enum CLIENT_fields {
    CLIENT_bssid, CLIENT_mac, CLIENT_type, CLIENT_firsttime, CLIENT_lasttime,
    CLIENT_manufkey, CLIENT_manufscore,
    CLIENT_datapackets, CLIENT_cryptpackets, CLIENT_weakpackets,
    CLIENT_gpsfixed,
    CLIENT_minlat, CLIENT_minlon, CLIENT_minalt, CLIENT_minspd,
    CLIENT_maxlat, CLIENT_maxlon, CLIENT_maxalt, CLIENT_maxspd,
    CLIENT_agglat, CLIENT_agglon, CLIENT_aggalt, CLIENT_aggpoints,
    CLIENT_maxrate,
    CLIENT_quality, CLIENT_signal, CLIENT_noise,
    CLIENT_bestquality, CLIENT_bestsignal, CLIENT_bestnoise,
    CLIENT_bestlat, CLIENT_bestlon, CLIENT_bestalt,
    CLIENT_atype, CLIENT_ip, CLIENT_datasize, CLIENT_maxseenrate, CLIENT_encodingset
};

enum REMOVE_fields {
    REMOVE_bssid
};

enum STATUS_fields {
    STATUS_text
};

enum ALERT_fields {
    ALERT_sec, ALERT_usec, ALERT_header, ALERT_text
};

enum ERROR_fields {
    ERROR_text
};

enum ACK_fields {
    ACK_text
};

enum PACKET_fields {
    PACKET_type, PACKET_subtype, PACKET_timesec, PACKET_encrypted,
    PACKET_weak, PACKET_beaconrate, PACKET_sourcemac, PACKET_destmac,
    PACKET_bssid, PACKET_ssid, PACKET_prototype, PACKET_sourceip,
    PACKET_destip, PACKET_sourceport, PACKET_destport, PACKET_nbtype,
    PACKET_nbsource
};

enum STRING_fields {
    STRING_bssid, STRING_sourcemac, STRING_text
};

enum CISCO_fields {
    CISCO_placeholder
};

enum KISMET_fields {
    KISMET_version, KISMET_starttime, KISMET_servername, KISMET_timestamp
};

enum PROTOCOLS_fields {
    PROTOCOLS_protocols
};

enum CAPABILITY_fields {
    CAPABILITY_capabilities
};

enum TIME_fields {
    TIME_timesec
};

enum TERMINATE_fields {
    TERMINATE_text
};

enum GPS_fields {
    GPS_lat, GPS_lon, GPS_alt, GPS_spd, GPS_fix
};

enum INFO_fields {
    INFO_networks, INFO_packets, INFO_crypt, INFO_weak,
    INFO_noise, INFO_dropped, INFO_rate, INFO_signal
};

enum WEPKEY_fields {
    WEPKEY_origin, WEPKEY_bssid, WEPKEY_key, WEPKEY_decrypted, WEPKEY_failed
};

// Builtin client/server field contents
extern char *KISMET_fields_text[];
extern char *CAPABILITY_fields_text[];
extern char *PROTOCOLS_fields_text[];
extern char *ERROR_fields_text[];
extern char *NETWORK_fields_text[];
extern char *CLIENT_fields_text[];
extern char *GPS_fields_text[];
extern char *TIME_fields_text[];
extern char *INFO_fields_text[];
extern char *REMOVE_fields_text[];
extern char *STATUS_fields_text[];
extern char *ALERT_fields_text[];
extern char *ACK_fields_text[];
extern char *PACKET_fields_text[];
extern char *STRING_fields_text[];
extern char *TERMINATE_fields_text[];
extern char *CISCO_fields_text[];
extern char *WEPKEY_fields_text[];

// Client/server protocol data structures.  These get passed as void *'s to each of the
// protocol functions.
// These are all done in two main ways - a var for each field, or a vector in the
// same order as the field names.  For shorter ones, the code is a lot more maintainable
// to have named vars, for longer ones it just makes sense to use a big ordered vector

typedef struct KISMET_data {
    string version;
    string starttime;
    string servername;
    string timestamp;
};

typedef struct GPS_data {
    string lat, lon, alt, spd, mode;
};

typedef struct INFO_data {
    string networks, packets, crypt, weak, noise, dropped, rate, signal;
};

typedef struct NETWORK_data {
    vector<string> ndvec;
};

typedef struct CLIENT_data {
    vector<string> cdvec;
};

typedef struct ALERT_data {
    string header, sec, usec, text;
};

typedef struct PACKET_data {
    vector<string> pdvec;
};

typedef struct STRING_data {
    string bssid, sourcemac, text;
};

// Builtin client/server protocol handlers and what they expect *data to be
int Protocol_KISMET(PROTO_PARMS); // KISMET_data
int Protocol_PROTOCOLS(PROTO_PARMS); // Server protocol map
int Protocol_CAPABILITY(PROTO_PARMS); // Protocol field vector
int Protocol_ERROR(PROTO_PARMS); // string
int Protocol_ACK(PROTO_PARMS); // int
int Protocol_TIME(PROTO_PARMS); // int
int Protocol_TERMINATE(PROTO_PARMS); // string
int Protocol_GPS(PROTO_PARMS); // GPS_data
int Protocol_INFO(PROTO_PARMS); // INFO_data
int Protocol_REMOVE(PROTO_PARMS); // string
void Protocol_Network2Data(const wireless_network *net, NETWORK_data *data);  // Convert a network to NET_data
int Protocol_NETWORK(PROTO_PARMS); // NETWORK_data
void Protocol_Client2Data(const wireless_network *net, const wireless_client *cli, CLIENT_data *data); // Convert a client
int Protocol_CLIENT(PROTO_PARMS); // CLIENT_data
int Protocol_STATUS(PROTO_PARMS); // string
int Protocol_ALERT(PROTO_PARMS); // ALERT_data
void Protocol_Packet2Data(const packet_info *info, PACKET_data *data);
int Protocol_PACKET(PROTO_PARMS); // PACKET_data
int Protocol_STRING(PROTO_PARMS); // STRING_data
int Protocol_WEPKEY(PROTO_PARMS); // wep_key_info

#endif
