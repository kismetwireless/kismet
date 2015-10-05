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

	CODE IN BOTH phy_80211.cc AND phy_80211_dissectors.cc
*/

#ifndef __PHY_80211_H__
#define __PHY_80211_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "globalregistry.h"
#include "packetchain.h"
#include "kis_netframe.h"
#include "timetracker.h"
#include "filtercore.h"
#include "gpscore.h"
#include "packet.h"
#include "uuid.h"
#include "configfile.h"

#include "devicetracker.h"
#include "devicetracker_component.h"

/*
 * 802.11 PHY handlers
 * Uses new devicetracker code
 *
 * Re-implements networktracker, packetdissectors
 * Ultimately all 802.11 related code will live here, such as alerts, etc.
 */

#define PHY80211_MAC_LEN	6

enum dot11_ssid_type {
	dot11_ssid_beacon = 0,
	dot11_ssid_proberesp = 1,
	dot11_ssid_probereq = 2,
	dot11_ssid_file = 3,
};

class dot11_11d_tracked_range_info : public tracker_component {
    public:
        dot11_11d_tracked_range_info(GlobalRegistry *in_globalreg) : 
            tracker_component(in_globalreg) { }

        dot11_11d_tracked_range_info(GlobalRegistry *in_globalreg, int in_id) :
            tracker_component(in_globalreg, in_id) { }

        virtual TrackerElement *clone() {
            return new dot11_11d_tracked_range_info(globalreg, get_id());
        }

        dot11_11d_tracked_range_info(GlobalRegistry *in_globalreg, TrackerElement *e) :
            tracker_component(in_globalreg) {
                register_fields();
                reserve_fields(e);
        }

        __Proxy(startchan, int32_t, int, int, startchan);
        __Proxy(numchan, uint32_t, unsigned int, unsigned int, numchan);
        __Proxy(txpower, int32_t, int, int, txpower);

    protected:
        virtual void register_fields() {
            startchan_id =
                RegisterField("dot11.11d.start_channel", TrackerInt32,
                        "Starting channel of 11d range", (void **) &startchan);
            numchan_id =
                RegisterField("dot11.11d.num_channels", TrackerUInt32,
                        "Number of channels covered by range", (void **) &numchan);
            txpower_id =
                RegisterField("dot11.11d.tx_power", TrackerInt32,
                        "Maximum allowed transmit power", (void **) &txpower);
        }


        int startchan_id;
        TrackerElement *startchan;

        int numchan_id;
        TrackerElement *numchan;

        int txpower_id;
        TrackerElement *txpower;
};


// Dot11d struct
struct dot11_11d_range_info {
	dot11_11d_range_info() {
		startchan = 0;
		numchan = 0;
		txpower = 0;
	}

	int startchan, numchan, txpower;
};


class dot11_tracked_ssid : public tracker_component {
    public:
        dot11_tracked_ssid(GlobalRegistry *in_globalreg) : 
            tracker_component(in_globalreg) { }

        dot11_tracked_ssid(GlobalRegistry *in_globalreg, int in_id) :
            tracker_component(in_globalreg, in_id) { }

        virtual TrackerElement *clone() {
            return new dot11_tracked_ssid(globalreg, get_id());
        }

        dot11_tracked_ssid(GlobalRegistry *in_globalreg, TrackerElement *e) :
            tracker_component(in_globalreg) {
                register_fields();
                reserve_fields(e);
        }

        __Proxy(ssid_checksum, uint32_t, unsigned int, unsigned int, checksum);
        __Proxy(dot11_type, uint32_t, dot11_ssid_type, dot11_ssid_type, dot11_type);
        __Proxy(first_time, uint64_t, time_t, time_t, first_time);
        __Proxy(last_time, uint64_t, time_t, time_t, last_time);
        __Proxy(bssid, mac_addr, mac_addr, mac_addr, bssid);
        __Proxy(ssid, string, string, string, ssid);
        __Proxy(ssid_len, uint32_t, unsigned int, unsigned int, ssid_len);
        __Proxy(beacon_info, string, string, string, beacon_info);
        __Proxy(crypt_set, uint64_t, uint64_t, uint64_t, dot11_crypt_set);
        __Proxy(ssid_cloaked, uint8_t, bool, bool, ssid_cloaked);
        __Proxy(maxrate, double, double, double, maxrate);
        __Proxy(beaconrate, uint32_t, unsigned int, unsigned int, beaconrate);

        __Proxy(num_packets, uint64_t, uint64_t, uint64_t, num_packets);
        __ProxyIncDec(num_packets, uint64_t, uint64_t, num_packets);

        __Proxy(num_beacons, uint64_t, uint64_t, uint64_t, num_beacons);
        __ProxyIncDec(num_beacons, uint64_t, uint64_t, num_beacons);

        __Proxy(ietag_checksum, uint32_t, uint32_t, uint32_t, ietag_checksum);
        __Proxy(dot11_channel, uint32_t, uint32_t, uint32_t, dot11_channel);
        __Proxy(dot11d_country, string, string, string, dot11d_country);

        void clear_dot11d() {
            dot11d_vec->clear_vector();
        }

        void add_dot11d(dot11_11d_tracked_range_info *i) {
            dot11d_vec->add_vector(i);
        }

        bool get_dirty() { return dirty; }
        void set_dirty(bool d) { dirty = d; }

    protected:
        virtual void register_fields() {
            checksum_id =
                RegisterField("dot11.ssid.checksum", TrackerUInt32,
                        "checksum of SSID", (void **) &checksum);
            dot11_type_id =
                RegisterField("dot11.ssid.ssid_type", TrackerUInt32,
                        "SSID type enum", (void **) &dot11_type);
            first_time_id =
                RegisterField("dot11.ssid.first_time", TrackerUInt64,
                        "first time seen (time_t)", (void **) &first_time);
            last_time_id =
                RegisterField("dot11.ssid.last_time", TrackerUInt64,
                        "last time seen (time_t)", (void **) &last_time);
            bssid_id =
                RegisterField("dot11.ssid.bssid", TrackerMac,
                        "BSSID", (void **) &bssid);
            ssid_id =
                RegisterField("dot11.ssid.ssid", TrackerString,
                        "SSID", (void **) &ssid);
            ssid_len_id =
                RegisterField("dot11.ssid.ssid_len", TrackerUInt32,
                        "SSID length (bytes)", (void **) &ssid_len);
            beacon_info_id =
                RegisterField("dot11.ssid.beacon_info", TrackerString,
                        "beacon info string (optional)", (void **) &beacon_info);
            dot11_crypt_set_id =
                RegisterField("dot11.ssid.crypt_set", TrackerUInt64,
                        "bitset of advertised encryption", (void **) &dot11_crypt_set);
            ssid_cloaked_id =
                RegisterField("dot11.ssid.cloaked", TrackerUInt8,
                        "ssid was hidden/cloaked", (void **) &ssid_cloaked);
            maxrate_id =
                RegisterField("dot11.ssid.max_rate", TrackerDouble,
                        "maximum advertised rate", (void **) &maxrate);
            beaconrate_id =
                RegisterField("dot11.ssid.beacon_rate", TrackerUInt32,
                        "beacon rate", (void **) &beaconrate);
            num_packets_id =
                RegisterField("dot11.ssid.num_packets", TrackerUInt64,
                        "total packets linked to this ssid", (void **) &num_packets);
            num_beacons_id =
                RegisterField("dot11.ssid.num_beacons", TrackerUInt64,
                        "beacon packets", (void **) &num_beacons);
            ietag_checksum_id =
                RegisterField("dot11.ssid.ietag_checksum", TrackerUInt32,
                        "ie tagset checksum", (void **) &ietag_checksum);
            dot11_channel_id =
                RegisterField("dot11.ssid.dot11_channel", TrackerUInt32,
                        "channel", (void **) &dot11_channel);
            dot11d_country_id =
                RegisterField("dot11.ssid.dot11d_country", TrackerString,
                        "dot11d country", (void **) &dot11d_country);
            dot11d_vec_id =
                RegisterField("dot11.ssid.dot11d_list", TrackerVector,
                        "advertised dot11d records", (void **) &dot11d_vec);

            dot11_11d_tracked_range_info *dot11d_builder = 
                new dot11_11d_tracked_range_info(globalreg, 0);
            dot11d_country_entry_id =
                globalreg->entrytracker->RegisterField("dot11.ssid.dot11d_entry",
                        dot11d_builder, "dot11d entry");
        }


        int checksum_id;
        TrackerElement *checksum;

        int first_time_id;
        TrackerElement *first_time;

        int last_time_id;
        TrackerElement *last_time;

        int dot11_type_id;
        TrackerElement *dot11_type;

        int bssid_id;
        TrackerElement *bssid;

        int ssid_id;
        TrackerElement *ssid;

        int ssid_len_id;
        TrackerElement *ssid_len;

        int beacon_info_id;
        TrackerElement *beacon_info;

        int dot11_crypt_set_id;
        TrackerElement *dot11_crypt_set;

        int ssid_cloaked_id;
        TrackerElement *ssid_cloaked;

        int maxrate_id;
        TrackerElement *maxrate;

        int beaconrate_id;
        TrackerElement *beaconrate;

        int num_packets_id;
        TrackerElement *num_packets;

        int num_beacons_id;
        TrackerElement *num_beacons;

        int ietag_checksum_id;
        TrackerElement *ietag_checksum;

        int dot11_channel_id;
        TrackerElement *dot11_channel;

        int dot11d_country_id;
        TrackerElement *dot11d_country;

        int dot11d_vec_id;
        TrackerElement *dot11d_vec;

        // dot11d vec components
        int dot11d_country_entry_id;

        // internal dirty flag
        bool dirty;
};

class dot11_ssid {
public:
	dot11_ssid() {
		checksum = 0;
		type = dot11_ssid_beacon;
		mac = mac_addr(0);
		ssid = "";
		beacon_info = "";
		cryptset = 0;
		ssid_cloaked = 0;
		first_time = 0;
		last_time = 0;
		dirty = 0;
		maxrate = 0;
		beaconrate = 0;
		packets = 0;
		beacons = 0;
		ietag_csum = 0;
		channel = 0;
		dot11d_country = "";
	}

	inline dot11_ssid& operator= (const dot11_ssid& in) {
		checksum = in.checksum;
		type = in.type;
		mac = in.mac;
		ssid = in.ssid;
		ssid_cloaked = in.ssid_cloaked;
		beacon_info = in.beacon_info;
		cryptset = in.cryptset;
		first_time = in.first_time;
		last_time = in.last_time;
		dirty = in.dirty;
		maxrate = in.maxrate;
		beaconrate = in.beaconrate;
		packets = in.packets;
		channel = in.channel;

		beacons = in.beacons;

		dot11d_country = in.dot11d_country; 

		dot11d_vec = in.dot11d_vec;

		ietag_csum = in.ietag_csum;

		dirty = in.dirty;

		return *this;
	}

	uint32_t checksum;
	uint32_t ietag_csum;

	dot11_ssid_type type;

	mac_addr mac;

	string ssid;
	int ssid_len;
	string beacon_info;

	// Cryptset and decrypted
	uint64_t cryptset;

	// Is the SSID hidden
	int ssid_cloaked;

	// Advertised channel
	int channel;

	// First and last times we saw this SSID
	time_t first_time;
	time_t last_time;

	// Advertised maximum rate
	double maxrate;

	// Beacon rate in # of beacons per second
	unsigned int beaconrate;

	// Number of packets seen advertising this ssid
	unsigned int packets;

	// Number of beacons seen in the last second (for calculating loss)
	unsigned int beacons;

	string dot11d_country;
	vector<dot11_11d_range_info> dot11d_vec;

	// SSID is dirty and should be resent
	int dirty;
};

enum dot11_network_type {
	dot11_network_none = 0,
	// ess = 1
	dot11_network_ap = 1,
	// adhoc
	dot11_network_adhoc = (1 << 1),
	// wireless client
	dot11_network_client = (1 << 2),
	// Wired fromds client
	dot11_network_wired = (1 << 3),
	// WDS/interdistrib
	dot11_network_wds = (1 << 4),
	// Turbocell (though it's mostly gone and we don't dissect it right now)
	dot11_network_turbocell = (1 << 5),
	// Inferred flag, we've seen traffic to this device, but never from it
	dot11_network_inferred = (1 << 6),
	// Inferred wireless/wired
	dot11_network_inferred_wireless = (1 << 7),
	dot11_network_inferred_wired = (1 << 8),
	// legacy, slated to die?
	dot11_network_mixed = (1 << 9),
	dot11_network_remove = (1 << 10)
};

// Per-BSSID client record, tracked by the AP tracked_device/dot11_device record
class dot11_tracked_client : public tracker_component {
    public:
        dot11_tracked_client(GlobalRegistry *in_globalreg) : 
            tracker_component(in_globalreg) { }

        dot11_tracked_client(GlobalRegistry *in_globalreg, int in_id) :
            tracker_component(in_globalreg, in_id) { }

        virtual TrackerElement *clone() {
            return new dot11_tracked_client(globalreg, get_id());
        }

        dot11_tracked_client(GlobalRegistry *in_globalreg, TrackerElement *e) :
            tracker_component(in_globalreg) {
                register_fields();
                reserve_fields(e);
        }

        __Proxy(client_type, uint64_t, dot11_network_type, dot11_network_type, client_type);
        __Proxy(client_mac, mac_addr, mac_addr, mac_addr, client_mac);
        __Proxy(bssid, mac_addr, mac_addr, mac_addr, bssid);
        __Proxy(first_time, uint64_t, time_t, time_t, first_time);
        __Proxy(last_time, uint64_t, time_t, time_t, last_time);
        __Proxy(decrypted, uint8_t, bool, bool, decrypted);
        __Proxy(last_sequence, uint64_t, uint64_t, uint64_t, last_sequence);
        __Proxy(tx_cryptset, uint64_t, uint64_t, uint64_t, tx_cryptset);
        __Proxy(rx_cryptset, uint64_t, uint64_t, uint64_t, rx_cryptset);

        dot11_tracked_ssid *get_last_ssid() { return last_ssid; }
        void set_last_ssid(dot11_tracked_ssid *in) {
            if (last_ssid != NULL)
                last_ssid->unlink();

            last_ssid = in;
            last_ssid->link();
        }

        __Proxy(last_ssidstring, string, string, string, last_ssidstring);
        __Proxy(last_ssidstring_checksum, uint32_t, uint32_t, uint32_t, last_ssidstring_checksum);

        kis_tracked_ip_data *get_guess_ipdata() { return guess_ipdata; }
        void set_guess_ipdata(kis_tracked_ip_data *in) {
            if (guess_ipdata != NULL)
                guess_ipdata->unlink();
            guess_ipdata = in;
            guess_ipdata->link();
        }

        __Proxy(cdp_dev, string, string, string, cdp_dev);
        __Proxy(cdp_port, string, string, string, cdp_port);

        __Proxy(tx_datasize, uint64_t, uint64_t, uint64_t, tx_datasize);
        __ProxyIncDec(tx_datasize, uint64_t, uint64_t, tx_datasize);

        __Proxy(rx_datasize, uint64_t, uint64_t, uint64_t, rx_datasize);
        __ProxyIncDec(rx_datasize, uint64_t, uint64_t, rx_datasize);

        __Proxy(manuf, string, string, string, manuf);
        __Proxy(eap_ident, string, string, string, eap_ident);

    protected:
        virtual void register_fields() {
            client_type_id =
                RegisterField("dot11.client.type", TrackerUInt64,
                        "client type enum", (void **) &client_type);
            client_mac_id =
                RegisterField("dot11.client.mac", TrackerMac,
                        "client mac", (void **) &client_mac);
            bssid_id =
                RegisterField("dot11.client.bssid", TrackerMac,
                        "bssid", (void **) &bssid);
            first_time_id =
                RegisterField("dot11.client.first_time", TrackerUInt64,
                        "first time (time_t)", (void **) &first_time);
            last_time_id =
                RegisterField("dot11.client.last_time", TrackerUInt64,
                        "last time (time_t)", (void **) &last_time);
            decrypted_id =
                RegisterField("dot11.client.decrypted", TrackerUInt8,
                        "client data has been decrypted", (void **) &decrypted);
            last_sequence_id =
                RegisterField("dot11.client.last_sequence", TrackerUInt64,
                        "last sequence number", (void **) &last_sequence);
            tx_cryptset_id =
                RegisterField("dot11.client.tx_cryptset", TrackerUInt64,
                        "bitset of observed transmitted encryption", (void **) &tx_cryptset);
            rx_cryptset_id =
                RegisterField("dot11.client.rx_cryptset", TrackerUInt64,
                        "bitset of observed received encryption", (void **) &rx_cryptset);

            dot11_tracked_ssid *ssid_builder =
                new dot11_tracked_ssid(globalreg, 0);
            last_ssid_id =
                RegisterComplexField("dot11.client.last_ssid", ssid_builder, 
                        "last seen ssid record");

            last_ssidstring_id =
                RegisterField("dot11.client.last_ssid_string", TrackerString,
                        "last ssid string", (void **) &last_ssidstring);
            last_ssidstring_checksum_id =
                RegisterField("dot11.client.last_ssid_string_checksum", TrackerUInt32,
                        "last ssid string checksum", (void **) &last_ssidstring_checksum);

            kis_tracked_ip_data *ip_builder = 
                new kis_tracked_ip_data(globalreg, 0);
            guess_ipdata_id =
                RegisterComplexField("dot11.client.guess_ipdata", ip_builder,
                        "guessed IP data");

            cdp_dev_id =
                RegisterField("dot11.client.cdp_device", TrackerString,
                        "CDP device identifier", (void **) &cdp_dev);
            cdp_port_id =
                RegisterField("dot11.client.cdp_port", TrackerString,
                        "CDP port identifier", (void **) &cdp_port);
            tx_datasize_id =
                RegisterField("dot11.client.tx_datasize", TrackerUInt64,
                        "transmitted data in bytes", (void **) &tx_datasize);
            rx_datasize_id =
                RegisterField("dot11.client.rx_datasize", TrackerUInt64,
                        "received data in bytes", (void **) &rx_datasize);
            manuf_id =
                RegisterField("dot11.client.manuf", TrackerString,
                        "manufacturer name", (void **) &manuf);
            eap_ident_id =
                RegisterField("dot11.client.eap_ident", TrackerString,
                        "EAP identity", (void **) &eap_ident);
        }

        int client_type_id;
        TrackerElement *client_type;

        int client_mac_id;
        TrackerElement *client_mac;

        int bssid_id;
        TrackerElement *bssid;

        int first_time_id;
        TrackerElement *first_time;

        int last_time_id;
        TrackerElement *last_time;

        int decrypted_id;
        TrackerElement *decrypted;

        int last_sequence_id;
        TrackerElement *last_sequence;

        int tx_cryptset_id;
        TrackerElement *tx_cryptset;

        int rx_cryptset_id;
        TrackerElement *rx_cryptset;

        int last_ssid_id;
        dot11_tracked_ssid *last_ssid;

        int last_ssidstring_id;
        TrackerElement *last_ssidstring;

        int last_ssidstring_checksum_id;
        TrackerElement *last_ssidstring_checksum;

        int guess_ipdata_id;
        kis_tracked_ip_data *guess_ipdata;

        int cdp_dev_id;
        TrackerElement *cdp_dev;

        int cdp_port_id;
        TrackerElement *cdp_port;

        int dhcp_host_id;
        TrackerElement *dhcp_host;

        int dhcp_vendor_id;
        TrackerElement *dhcp_vendor;

        int tx_datasize_id;
        TrackerElement *tx_datasize;

        int rx_datasize_id;
        TrackerElement *rx_datasize;

        int manuf_id;
        TrackerElement *manuf;

        int eap_ident_id;
        TrackerElement *eap_ident;

};


// Dot11 AP / Network
//
// The network record tracks everything that happens on a BSSID.  It is generally
// correlated to the behavior of the AP; it will only be created to track AP
// behavior.
//
// An AP will have both a network and a client record, as the AP itself is also
// a client on the network.
class dot11_device : public tracker_component {
public:
	~dot11_device() {
		for (map<mac_addr, dot11_client *>::iterator c = client_map.begin();
			 c != client_map.end(); ++c) {
			delete c->second;
		}

		for (map<uint32_t, dot11_ssid *>::iterator s = ssid_map.begin();
			 s != ssid_map.end(); ++s) {
			delete s->second;
		}
	}

	mac_addr mac;

	// Set of types we've seen
	int type_set;

	// Client records seen
	map<mac_addr, dot11_client *> client_map;

	// Advertised and probed SSID data, by checksum
	map<uint32_t, dot11_ssid *> ssid_map;

	// Packets sent from this BSSID
	uint64_t tx_cryptset;
	// Packets sent to this bssid
	uint64_t rx_cryptset;

	// One of the SSIDs decrypted?
	unsigned int decrypted;

	// Best-guess IP
	kis_ip_data guess_ipdata;

	// State tracking elements
	// Number of client disconnects (decayed per second)
	unsigned int client_disconnects;
	// Last sequence
	unsigned int last_sequence;
	// Last BSS
	uint64_t bss_timestamp;

	// CDP data
	string cdp_dev_id;
	string cdp_port_id;

	// Fragments and retries
	unsigned int fragments;
	unsigned int retries;

	// Record is dirty
	int dirty;

	// Fields for the client to use
	void *groupptr;
	dot11_ssid *lastssid;

	string lastssid_str;
	uint32_t lastssid_csum;

	// Data sizes of network traffic
	uint64_t tx_datasize;
	uint64_t rx_datasize;

	// Who we most recently talked to if we're not an AP
	mac_addr last_bssid;

	// Who we've ever talked to
	vector<mac_addr> bssid_list;

	string dhcp_host, dhcp_vendor;

	// Count WPS M3 exchanges
	int wps_m3_count;
	time_t last_wps_m3;

	// Did we see an eap id?
	string eap_id;
	
	dot11_device() {
		type_set = dot11_network_none;

		tx_cryptset = 0L;
		rx_cryptset = 0L;
		decrypted = 0;

		client_disconnects = 0;
		last_sequence = 0;
		bss_timestamp = 0;

		tx_datasize = 0L;
		rx_datasize = 0L;

		groupptr = NULL;
		lastssid = NULL;
		lastssid_csum = 0;

		last_bssid = mac_addr(0);

		wps_m3_count = 0;
		last_wps_m3 = 0;

		fragments = retries = 0;

		dirty = 0;
	}
};

class dot11_ssid_alert {
public:
	dot11_ssid_alert() {
#ifdef HAVE_LIBPCRE
		ssid_re = NULL;
		ssid_study = NULL;
#endif
	}
	string name;

#ifdef HAVE_LIBPCRE
	pcre *ssid_re;
	pcre_extra *ssid_study;
	string filter;
#endif
	string ssid;

	macmap<int> allow_mac_map;
};

// Dot11 SSID max len
#define DOT11_PROTO_SSID_LEN	32

// Wep keys
#define DOT11_WEPKEY_MAX		32
#define DOT11_WEPKEY_STRMAX		((DOT11_WEPKEY_MAX * 2) + DOT11_WEPKEY_MAX)

class dot11_wep_key {
public:
    int fragile;
    mac_addr bssid;
    unsigned char key[DOT11_WEPKEY_MAX];
    unsigned int len;
    unsigned int decrypted;
    unsigned int failed;
};

// dot11 packet components

// Info from the IEEE 802.11 frame headers for kismet
class dot11_packinfo : public packet_component {
public:
    dot11_packinfo() {
		self_destruct = 1; // Our delete() handles this
        corrupt = 0;
        header_offset = 0;
        type = packet_unknown;
        subtype = packet_sub_unknown;
        mgt_reason_code = 0;
        ssid_len = 0;
		ssid_blank = 0;
        source_mac = mac_addr(0);
        dest_mac = mac_addr(0);
        bssid_mac = mac_addr(0);
        other_mac = mac_addr(0);
        distrib = distrib_unknown;
		cryptset = 0;
		decrypted = 0;
        fuzzywep = 0;
		fmsweak = 0;
        ess = 0;
		ibss = 0;
		channel = 0;
        encrypted = 0;
        beacon_interval = 0;
        maxrate = 0;
        timestamp = 0;
        sequence_number = 0;
        frag_number = 0;
		fragmented = 0;
		retry = 0;
        duration = 0;
        datasize = 0;
		qos = 0;
		ssid_csum = 0;
		dot11d_country = "";
		ietag_csum = 0;
    }

    // Corrupt 802.11 frame
    int corrupt;
   
    // Offset to data components in frame
    unsigned int header_offset;
    
    ieee_80211_type type;
    ieee_80211_subtype subtype;
  
    uint8_t mgt_reason_code;
    
    // Raw SSID
	string ssid;
	// Length of the SSID header field
    int ssid_len;
	// Is the SSID empty spaces?
	int ssid_blank;

    // Address set
    mac_addr source_mac;
    mac_addr dest_mac;
    mac_addr bssid_mac;
    mac_addr other_mac;
    
    ieee_80211_disttype distrib;
 
	uint64_t cryptset;
	int decrypted; // Might as well put this in here?
    int fuzzywep;
	int fmsweak;

    // Was it flagged as ess? (ap)
    int ess;
	int ibss;

	// What channel does it report
	int channel;

    // Is this encrypted?
    int encrypted;
    int beacon_interval;

	uint16_t qos;

    // Some cisco APs seem to fill in this info field
	string beacon_info;

    double maxrate;

    uint64_t timestamp;
    int sequence_number;
    int frag_number;
	int fragmented;
	int retry;

    int duration;

    int datasize;

	uint32_t ssid_csum;
	uint32_t ietag_csum;

	string dot11d_country;
	vector<dot11_11d_range_info> dot11d_vec;
};


class Kis_80211_Phy : public Kis_Phy_Handler {
public:
	// Stub
	Kis_80211_Phy() { }
	~Kis_80211_Phy();

	// Inherited functionality
	Kis_80211_Phy(GlobalRegistry *in_globalreg) :
		Kis_Phy_Handler(in_globalreg) { };

	// Build a strong version of ourselves
	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg,
											  Devicetracker *in_tracker,
											  int in_phyid) {
		return new Kis_80211_Phy(in_globalreg, in_tracker, in_phyid);
	}

	// Strong constructor
	Kis_80211_Phy(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
				  int in_phyid);

	int WPACipherConv(uint8_t cipher_index);
	int WPAKeyMgtConv(uint8_t mgt_index);

	// Dot11 decoders, wep decryptors, etc
	int PacketWepDecryptor(kis_packet *in_pack);
	int PacketDot11dissector(kis_packet *in_pack);

	// Special decoders, not called as part of a chain
	
	// Is packet a WPS M3 message?  Used to detect Reaver, etc
	int PacketDot11WPSM3(kis_packet *in_pack);

	// static incase some other component wants to use it
	static kis_datachunk *DecryptWEP(dot11_packinfo *in_packinfo,
									 kis_datachunk *in_chunk, 
									 unsigned char *in_key, int in_key_len,
									 unsigned char *in_id);

	// TODO - what do we do with the strings?  Can we make them phy-neutral?
	// int packet_dot11string_dissector(kis_packet *in_pack);

	// 802.11 packet classifier to common for the devicetracker layer
	int ClassifierDot11(kis_packet *in_pack);

	// Dot11 tracker for building phy-specific elements
	int TrackerDot11(kis_packet *in_pack);

	// Timer events passed from Devicetracker
	virtual int TimerKick();

	int AddFilter(string in_filter);
	int AddNetcliFilter(string in_filter);

	void SetStringExtract(int in_extr);

	void AddWepKey(mac_addr bssid, uint8_t *key, unsigned int len, int temp);

	virtual void BlitDevices(int in_fd, vector<kis_tracked_device *> *devlist);

	void EnableDot11Dev(int in_fd);
	void EnableDot11Ssid(int in_fd);
	void EnableDot11Client(int in_fd);

	virtual void ExportLogRecord(kis_tracked_device *in_device, string in_logtype, 
								 FILE *in_logfile, int in_lineindent);

	// We need to return something cleaner for xsd namespace
	virtual string FetchPhyXsdNs() {
		return "phy80211";
	}

	static string CryptToString(uint64_t cryptset);

protected:
	int LoadWepkeys();

	// Build a SSID record
	dot11_ssid *BuildSSID(uint32_t ssid_csum,
						  dot11_packinfo *packinfo,
						  kis_packet *in_pack);

	// Save the SSID cache
	void SaveSSID();

	map<mac_addr, string> bssid_cloak_map;

	string ssid_cache_path, ip_cache_path;
	int ssid_cache_track, ip_cache_track;

	// Device components
	int dev_comp_dot11, dev_comp_common;

	// Packet components
	int pack_comp_80211, pack_comp_basicdata, pack_comp_mangleframe,
		pack_comp_strings, pack_comp_checksum, pack_comp_linkframe,
		pack_comp_decap, pack_comp_common, pack_comp_datapayload;

	// Do we do any data dissection or do we hide it all (legal safety
	// cutout)
	int dissect_data;

	// Do we pull strings?
	int dissect_strings, dissect_all_strings;

	FilterCore *string_filter;
	macmap<int> string_nets;

	// Dissector alert references
	int alert_netstumbler_ref, alert_nullproberesp_ref, alert_lucenttest_ref,
		alert_msfbcomssid_ref, alert_msfdlinkrate_ref, alert_msfnetgearbeacon_ref,
		alert_longssid_ref, alert_disconinvalid_ref, alert_deauthinvalid_ref,
		alert_dhcpclient_ref;

	// Are we allowed to send wepkeys to the client (server config)
	int client_wepkey_allowed;
	// Map of wepkeys to BSSID (or bssid masks)
	macmap<dot11_wep_key *> wepkeys;

	// Generated WEP identity / base
	unsigned char wep_identity[256];

	// Tracker alert references
	int alert_chan_ref, alert_dhcpcon_ref, alert_bcastdcon_ref, alert_airjackssid_ref,
		alert_wepflap_ref, alert_dhcpname_ref, alert_dhcpos_ref, alert_adhoc_ref,
		alert_ssidmatch_ref, alert_dot11d_ref, alert_beaconrate_ref,
		alert_cryptchange_ref, alert_malformmgmt_ref, alert_wpsbrute_ref;

	// Command refs
	int addfiltercmd_ref, addnetclifiltercmd_ref;

	// Filter core for tracker
	FilterCore *track_filter;
	// Filter core for network client
	FilterCore *netcli_filter;

	int proto_ref_ssid, proto_ref_device, proto_ref_client;

	// SSID cloak file as a config file
	ConfigFile *ssid_conf;
	time_t conf_save;

	// probe assoc to owning network
	map<mac_addr, kis_tracked_device *> probe_assoc_map;

	vector<dot11_ssid_alert *> apspoof_vec;

};

#endif
