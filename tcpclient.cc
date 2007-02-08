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

#include "tcpclient.h"
#include "networksort.h"

TcpClient::TcpClient() {
    // Fill in the default protocol stuff
    protocol_default_map["INFO"] = "networks,packets,crypt,weak,noise,dropped,rate,signal";
    protocol_default_map["ALERT"] = "sec,usec,header,text";
    protocol_default_map["PACKET"] = "type,subtype,timesec,encrypted,weak,beaconrate,sourcemac,destmac,bssid,"
        "ssid,prototype,sourceip,destip,sourceport,destport,nbtype,"
        "nbsource";
    protocol_default_map["STRING"] = "bssid,sourcemac,text";
    protocol_default_map["KISMET"] = "version,starttime,servername,timestamp,"
        "channelhop,newversion";
    protocol_default_map["GPS"] = "lat,lon,alt,spd,heading,fix";
    protocol_default_map["NETWORK"] = "bssid,type,ssid,beaconinfo,llcpackets,datapackets,cryptpackets,"
        "weakpackets,channel,wep,firsttime,lasttime,atype,rangeip,gpsfixed,minlat,minlon,minalt,minspd,"
        "maxlat,maxlon,maxalt,maxspd,octets,cloaked,beaconrate,maxrate,"
        "quality,signal,noise,rssi,rssi_max,bestquality,bestsignal,bestnoise,bestlat,bestlon,bestalt,"
        "agglat,agglon,aggalt,aggpoints,datasize,turbocellnid,turbocellmode,turbocellsat,"
        "carrierset,maxseenrate,encodingset,decrypted,dupeivpackets,bsstimestamp";
    protocol_default_map["CLIENT"] = "bssid,mac,type,firsttime,lasttime,"
        "datapackets,cryptpackets,weakpackets,"
        "gpsfixed,minlat,minlon,minalt,minspd,maxlat,maxlon,maxalt,maxspd,"
        "agglat,agglon,aggalt,aggpoints,maxrate,quality,signal,noise,"
        "bestquality,bestsignal,bestnoise,bestlat,bestlon,bestalt,"
        "atype,ip,datasize,maxseenrate,encodingset,decrypted,wep";
    protocol_default_map["WEPKEY"] = "origin,bssid,key,encrypted,failed";
    protocol_default_map["CARD"] = "interface,type,username,channel,id,packets,hopping";

    sv_valid = 0;
    client_fd = 0;

    lat = lon = alt = spd = 0;
    mode = 0;

    num_networks = num_packets = num_crypt = num_interesting =
        num_noise = num_dropped = packet_rate = 0;

    old_num_networks = old_num_packets = old_num_crypt = old_num_interesting =
        old_num_noise = old_num_dropped = 0;

    start_time = 0;
    major[0] = '\0';
    minor[0] = '\0';
    tiny[0] = '\0';

    power = quality = noise = 0;

    maxstrings = 500;
    maxpackinfos = 1000;
    maxalerts = 500;

    memset(status, 0, STATUS_MAX);
    memset(channel_graph, 0, sizeof(channel_power) * CHANNEL_MAX);

    last_new_network = 0;

    servername[0] = '\0';

    network_dirty = 0;

    channel_hop = 0;

}

TcpClient::~TcpClient() {
    if (sv_valid)
        close(client_fd);

    sv_valid = 0;
}

void TcpClient::Disconnect() {
    if (sv_valid)
        close(client_fd);

    sv_valid = 0;
}

int TcpClient::Connect(short int in_port, char *in_host) {
    // Copy the port to our local data
    port = in_port;

    // Resolve the hostname we were given/found to see if it's actually
    // valid
    if ((client_host = gethostbyname(in_host)) == NULL) {
        snprintf(errstr, 1024, "TcpClient could not resolve host \"%s\"\n", in_host);
        return (-1);
    }

    strncpy(hostname, in_host, MAXHOSTNAMELEN);
    hostname[MAXHOSTNAMELEN-1] = '\0';

    // Set up our socket
    //bzero(&client_sock, sizeof(client_sock));
    memset(&client_sock, 0, sizeof(client_sock));
    client_sock.sin_family = client_host->h_addrtype;
    memcpy((char *) &client_sock.sin_addr.s_addr, client_host->h_addr_list[0],
           client_host->h_length);
    client_sock.sin_port = htons(in_port);

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        snprintf(errstr, 1024, "TcpClient socket() failed %d (%s)\n",
                 errno, strerror(errno));
        return (-2);
    }

    // Bind to the local half of the pair
    local_sock.sin_family = AF_INET;
    local_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    local_sock.sin_port = htons(0);

    if (bind(client_fd, (struct sockaddr *) &local_sock, sizeof(local_sock)) < 0) {
        snprintf(errstr, 1024, "FATAL: TcpClient bind() failed %d (%s)\n",
                 errno, strerror(errno));
        return (-3);
    }

    // Connect
    if (connect(client_fd, (struct sockaddr *) &client_sock, sizeof(client_sock)) < 0) {
        snprintf(errstr, 1024, "FATAL: TcpClient connect() failed %d (%s)\n",
                 errno, strerror(errno));
        return (-4);
    }

    int save_mode = fcntl(client_fd, F_GETFL, 0);
    if (save_mode == -1) {
        snprintf(errstr, 1024, "FATAL:  TcpClient connect() failed fcntl get %d (%s)\n",
                 errno, strerror(errno));
        return (-5);
    }
    if (fcntl(client_fd, F_SETFL, save_mode | O_NONBLOCK) < 0) {
        snprintf(errstr, 1024, "FATAL:  TcpClient connect() failed fcntl set %d (%s)\n",
                 errno, strerror(errno));
        return (-6);
    }

    sv_valid = 1;

    clientf = fdopen(client_fd, "r");

    // Turn on the protocols in our map, if we have any.  This is for reconnecting
    // to a server and preserving the requested protocols
    for (map<string, int>::iterator prot = protocol_map.begin();
         prot != protocol_map.end(); ++prot) {
        EnableProtocol(prot->first);
    }


    return 1;
}

int TcpClient::Poll() {

    if (!sv_valid) {
        snprintf(errstr, 1024, "TcpClient poll() on an inactive connection.");
        return -1;
    }

    // Clear the status
    memset(status, 0, STATUS_MAX);

    int selected;
    fd_set read_set;
    fd_set write_set;

    FD_ZERO(&read_set);
    FD_SET(client_fd, &read_set);
    FD_ZERO(&write_set);
    FD_SET(client_fd, &write_set);

    struct timeval tim;

    tim.tv_sec = 0;
    tim.tv_usec = 0;

    // Enter the select loop
    if ((selected = select(client_fd+1, &read_set, &write_set, NULL, &tim)) < 0) {
        if (errno != EINTR) {
            snprintf(errstr, 1024, "TcpServer select() returned %d (%s)\n",
                     errno, strerror(errno));
            sv_valid = 0;
            close(client_fd);
            return (-1);
        }
    }

    if (writebuf.length() > 0 && FD_ISSET(client_fd, &write_set)) {
        int res = write(client_fd, writebuf.c_str(), writebuf.length());

        if (res <= 0) {
            if (res == 0 || (errno != EAGAIN && errno != EINTR)) {
                snprintf(errstr, 1024, "Write error on socket (%d): %s", errno,
                         strerror(errno));
                sv_valid = 0;
                close(client_fd);
                return(-1);
            }
        } else {
            writebuf.erase(0, res);
        }
    }

    if (!FD_ISSET(client_fd, &read_set))
        return 0;

    char data[2048];
    memset(data, 0, 2048);

    //    while (1) {
    if (fgets(data, 2048, clientf) == NULL) {
        if (errno != 0 && errno != EAGAIN) {
            snprintf(errstr, 1024, "Read error %d (%s), closing the connection.",
                     errno, strerror(errno));
            sv_valid = 0;
            close(client_fd);
            return (-1);
        }

        if (feof(clientf)) {
            snprintf(errstr, 1024, "socket returned EOF, server has closed the connection.");
            sv_valid = 0;
            close(client_fd);
            return (-2);
        }

        return (0);
    }

    if (strlen(data) < 2)
        return 0;


	// Loop on lines of data
	int ret;
	char *post = data;
	while(1) {
		ret = ParseData(post);

		if (ret < 0) {
			return ret;
		}

		post = strchr(post, '\n');

		if (post == NULL)
			break;

		post++;
	}

    return ret;
}

void TcpClient::RemoveNetwork(mac_addr in_bssid) {
    map<mac_addr, wireless_network *>::iterator itr = net_map.find(in_bssid);

    if (itr != net_map.end()) {
        for (unsigned int x = 0; x < net_map_vec.size(); x++) {
            if (net_map_vec[x] == itr->second) {
                net_map_vec.erase(net_map_vec.begin() + x);
            }
        }
        delete(itr->second);
        net_map.erase(itr);
    }
}

int TcpClient::ParseData(char *in_data) {
    char header[65];
    char bssid_str[18];
    mac_addr bssid;
    int junkmajor, junkminor, junktiny;
    int	tmptime;	// HACK: should be some 64-bit type

    if (sscanf(in_data, "%64[^:]", header) < 1) {
        return 0;
    }

    unsigned int hdrlen = strlen(header) + 2;
    if (hdrlen >= strlen(in_data))
        return 0;

    if (!strncmp(header, "*TERMINATE", 64)) {
        sv_valid = 0;
        snprintf(errstr, 1024, "Server has terminated.\n");
        return -1;
    } else if (!strncmp(header, "*KISMET", 64)) {
        if (sscanf(in_data+hdrlen, "%d.%d.%d %d \001%32[^\001]\001 %24s %d "
                   "%24[^.].%24[^.].%24s",
                   &junkmajor, &junkminor, &junktiny, 
                   &tmptime, servername, 
                   build, &channel_hop,
                   major, minor, tiny) < 7)
            return 0;
		start_time = tmptime;
    } else if (!strncmp(header, "*TIME", 64)) {
        if (sscanf(in_data+hdrlen, "%d", &tmptime) < 1)
            return 0;
		serv_time = tmptime;
    } else if (!strncmp(header, "*NETWORK", 64)) {
        wireless_network *net;

        int scanned;

        char ssid[SSID_SIZE+1], beaconstr[256];
        short int range[4];
		address_type atype;
		int octets;

		// Copy of the network info
		wireless_network_type type;

		// Packet counts
		int llc_packets;
		int data_packets;
		int crypt_packets;
		int interesting_packets;

		// info extracted from packets
		//uint8_t bssid[MAC_LEN];
		int channel;
		int crypt_set;

		// Are we a cloaked SSID?
		int cloaked;

		// Last time we saw a packet
		time_t last_time;

		// First packet
		time_t first_time;

		// beacon interval
		int beacon;

		// Bitmask set of carrier types seen in this network
		int carrier_set;
		// Bitmask set of encoding types seen in this network
		int encoding_set;

		int gps_fixed;
		float min_lat, min_lon, min_alt, min_spd;
		float max_lat, max_lon, max_alt, max_spd;

		// Averaged center position
		double aggregate_lat, aggregate_lon, aggregate_alt;
		long aggregate_points;

		// How fast we can go
		float maxrate;

		int maxseenrate;

		// Connection information
        int quality, signal, noise, rssi, rssi_max;
        int best_quality, best_signal, best_noise;
		float best_lat, best_lon, best_alt;

		// Amount of data, in bytes
		unsigned long datasize;

		// Turbocell info
		int turbocell_nid;
		turbocell_type turbocell_mode;
		int turbocell_sat;

		// Did we decrypt this network?
		int decrypted;

		// number of duplicate IV counts
		int dupeiv_packets;

		// BSS timestamp
		uint64_t bss_timestamp;

        if (sscanf(in_data+hdrlen, "%17s", bssid_str) != 1)
            return 0;

        bssid = bssid_str;
        int newnet = 0;

        if (net_map.find(bssid) != net_map.end()) {
            net = net_map[bssid];
        } else {
            net = new wireless_network;
            net->bssid = bssid;
            net->tcpclient = this;
            newnet = 1;
        }

		int tmptype, tmpatype;
		int	tmpturbocell_mode;
		int	tmpfirst_time;	// HACK: should be some 64-bit type
		int	tmplast_time;	// HACK: should be some 64-bit type
		scanned = sscanf(in_data+hdrlen+18, "%d \001%255[^\001]\001 "
						 "\001%255[^\001]\001 "
						 "%d %d %d %d %d %d %d %d %d %hd.%hd.%hd.%hd "
						 "%d %f %f %f %f %f %f %f %f %d %d %d %f %d %d %d %d %d %d %d %d"
						 "%f %f %f %lf %lf %lf %ld %ld"
						 "%d %d %d %d %d %d %d %d %lld",
						 &tmptype, ssid, beaconstr,
						 &llc_packets, &data_packets, &crypt_packets, 
						 &interesting_packets, &channel, &crypt_set, 
						 &tmpfirst_time, &tmplast_time,
						 &tmpatype, &range[0], &range[1], &range[2], 
						 &range[3], &gps_fixed, &min_lat, &min_lon, 
						 &min_alt, &min_spd, &max_lat, &max_lon, 
						 &max_alt, &max_spd, &octets, 
						 &cloaked, &beacon, &maxrate, &quality, 
						 &signal, &noise, &rssi, &rssi_max,
						 &best_quality, &best_signal, &best_noise,
						 &best_lat, &best_lon, &best_alt,
						 &aggregate_lat, &aggregate_lon, &aggregate_alt,
						 &aggregate_points, &datasize,
						 &turbocell_nid, &tmpturbocell_mode, 
						 &turbocell_sat, &carrier_set, &maxseenrate, 
						 &encoding_set, &decrypted, &dupeiv_packets, &bss_timestamp);
		type = static_cast<wireless_network_type>(tmptype);
		first_time = tmpfirst_time;
		last_time = tmplast_time;
		atype = static_cast<address_type>(tmpatype);
		turbocell_mode = static_cast<turbocell_type>(tmpturbocell_mode);

		if (scanned < 54) {
			// Can't delete us out of the tracker offhand if we're not a new network,
			// remove us cleanly.
			if (newnet == 1)
				delete net;

			return 0;
		}

		// Set the network list as dirty
		network_dirty = 1;

		if (newnet == 1) {
			net_map[bssid] = net;
			net_map_vec.push_back(net);
			last_new_network = net;
		}

		if (ssid[0] != '\002')
			net->ssid = ssid;
		if (beaconstr[0] != '\002')
			net->beacon_info = beaconstr;
		net->ipdata.atype = atype;
		net->ipdata.octets = octets;
		for (int x = 0; x < 4; x++) {
			net->ipdata.range_ip[x] = (uint8_t) range[x];
		}

		net->type = type;
		net->llc_packets = llc_packets;
		net->data_packets = data_packets;
		net->crypt_packets = crypt_packets;
		net->interesting_packets = interesting_packets;
		net->channel = channel;
		net->crypt_set = crypt_set;
		net->cloaked = cloaked;
		net->last_time = last_time;
		net->first_time = first_time;
		net->beacon = beacon;
		net->carrier_set = carrier_set;
		net->encoding_set = encoding_set;
		net->gps_fixed = gps_fixed;
		net->min_lat = min_lat;
		net->min_lon = min_lon;
		net->min_alt = min_alt;
		net->min_spd = min_spd;
		net->max_lat = max_lat;
		net->max_lon = max_lon;
		net->max_alt = max_alt;
		net->max_spd = max_spd;
        net->maxrate = maxrate;
		net->maxseenrate = maxseenrate;
		net->quality = quality;
		net->signal = signal;
		net->noise = noise;
        net->rssi = rssi;
        net->rssi_max = rssi_max;
		net->best_quality = best_quality;
		net->best_signal = best_signal;
		net->best_noise = best_noise;
		net->best_lat = best_lat;
		net->best_lon = best_lon;
		net->best_alt = best_alt;
		net->aggregate_points = aggregate_points;
		net->aggregate_lat = aggregate_lat;
		net->aggregate_lon = aggregate_lon;
		net->aggregate_alt = aggregate_alt;
		net->datasize = datasize;
		net->dupeiv_packets = dupeiv_packets;
		net->bss_timestamp = bss_timestamp;
		net->decrypted = decrypted;

    } else if (!strncmp(header, "*CLIENT", 64)) {
        short int ip[4];

        mac_addr cmac;
        char cmac_str[18];

        int scanned;

		// Copy of all the data we're populating in the client record
		client_type type;

		time_t first_time;
		time_t last_time;

		int crypt_set;

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
		float maxrate;
		// How fast we've been seen to go, in 100kbs units
		int maxseenrate;

		// Bitfield set of encoding types seen on this client
		int encoding_set;

		// Last seen quality for a packet from this client
		int quality, signal, noise;
		int best_quality, best_signal, best_noise;
		float best_lat, best_lon, best_alt;

		// ip data
		address_type atype;

		// Data passed, in bytes
		unsigned long datasize;

		// Did we decrypt this client?
		int decrypted;


        // Find the bssid and mac so we can fill in our client or make a new one
        if (sscanf(in_data+hdrlen, "%17s %17s", bssid_str, cmac_str) != 2)
            return 0;

        bssid = bssid_str;
        wireless_client *client = NULL;
        int nclient = 0;

        map<mac_addr, wireless_network *>::iterator nmi = net_map.find(bssid);
        if (nmi != net_map.end()) {
            cmac = cmac_str;
            map<mac_addr, wireless_client *>::iterator wci = 
                nmi->second->client_map.find(cmac);
			if (wci != nmi->second->client_map.end()) {
				client = wci->second;
			} else {
				nclient = 1;
				client = new wireless_client;
			}
		} else {
			return 0;
		}

		int	tmptype, tmpatype;
		int	tmpfirst_time;	// HACK: should be some 64-bit type
		int	tmplast_time;	// HACK: should be some 64-bit type
		scanned = sscanf(in_data+hdrlen+36, "%d %d %d %d %d %d %d "
						 "%f %f %f %f %f %f %f %f %lf %lf "
						 "%lf %ld %f %d %d %d %d %d %d "
						 "%f %f %f %d %hd.%hd.%hd.%hd %ld %d %d %d %d",
						 &tmptype,
						 &tmpfirst_time, &tmplast_time,
						 &data_packets, &crypt_packets,
						 &interesting_packets,
						 &gps_fixed, &min_lat, &min_lon,
						 &min_alt, &min_spd,
						 &max_lat, &max_lon, &max_alt,
						 &max_spd, &aggregate_lat, 
						 &aggregate_lon,
						 &aggregate_alt, &aggregate_points,
						 &maxrate, &quality, &signal, &noise,
						 &best_quality, &best_signal, 
						 &best_noise,
						 &best_lat, &best_lon, &best_alt,
						 &tmpatype, &ip[0], &ip[1], &ip[2], &ip[3],
						 &datasize, &maxseenrate, &encoding_set,
						 &decrypted, &crypt_set);
		type = static_cast<client_type>(tmptype);
		first_time = tmpfirst_time;
		last_time  = tmplast_time;
		atype = static_cast<address_type>(tmpatype);

		if (scanned < 39) {
			if (nclient)
				delete client;
			return 0;
		}

		// Set the network list to be dirty
		network_dirty = 1;

		bssid = bssid_str;
		client->mac = cmac;
		client->maxrate = maxrate;

		client->tcpclient = this;

		for (unsigned int x = 0; x < 4; x++)
			client->ipdata.ip[x] = ip[x];
		client->ipdata.atype = atype;

		client->type = type;
		client->data_packets = data_packets;
		client->crypt_packets = crypt_packets;
		client->interesting_packets = interesting_packets;
		client->crypt_set = crypt_set;
		client->last_time = last_time;
		client->first_time = first_time;
		client->encoding_set = encoding_set;
		client->gps_fixed = gps_fixed;
		client->min_lat = min_lat;
		client->min_lon = min_lon;
		client->min_alt = min_alt;
		client->min_spd = min_spd;
		client->max_lat = max_lat;
		client->max_lon = max_lon;
		client->max_alt = max_alt;
		client->max_spd = max_spd;
        client->maxrate = maxrate;
		client->maxseenrate = maxseenrate;
		client->quality = quality;
		client->signal = signal;
		client->noise = noise;
		client->best_quality = best_quality;
		client->best_signal = best_signal;
		client->best_noise = best_noise;
		client->best_lat = best_lat;
		client->best_lon = best_lon;
		client->best_alt = best_alt;
		client->aggregate_lat = aggregate_lat;
		client->aggregate_lon = aggregate_lon;
		client->aggregate_alt = aggregate_alt;
		client->aggregate_points = aggregate_points;
		client->datasize = datasize;
		client->decrypted = decrypted;

        // Add it to the map, if its a new client.
        if (nclient) {
            net_map[bssid]->client_map[cmac] = client;
            net_map[bssid]->client_vec.push_back(client);
        }

    } else if (!strncmp(header, "*REMOVE", 64)) {

        // If we get a remove request flag it to die and the group code will
        // destroy it after ungrouping it
        if (sscanf(in_data+hdrlen, "%17s", bssid_str) < 0)
            return 0;

        bssid = bssid_str;

        if (net_map.find(bssid) != net_map.end()) {
            net_map[bssid]->type = network_remove;
        }

    } else if (!strncmp(header, "*GPS", 64)) {
        if (sscanf(in_data+hdrlen, "%f %f %f %f %f %d", 
				   &lat, &lon, &alt, &spd, &heading, &mode) < 5)
            return 0;

    } else if (!strncmp(header, "*INFO", 64)) {
        char chan_details[1024];
        char chan_details_sec[1024];

        memset(chan_details, 0, 1024);
        memset(chan_details_sec, 0, 1024);

        old_num_networks = num_networks;
        old_num_packets = num_packets;
        old_num_crypt = num_crypt;
        old_num_interesting = num_interesting;
        old_num_noise = num_noise;
        old_num_dropped = num_dropped;

        unsigned int numchan;
        if (sscanf(in_data+hdrlen, "%d %d %d %d %d %d %d %d %d %d %d%1023[^\n]\n",
                   &num_networks, &num_packets,
                   &num_crypt, &num_interesting,
                   &num_noise, &num_dropped, &packet_rate,
                   &quality, &power, &noise, &numchan,
                   chan_details) < 11)
            return 0;

        for (unsigned int x = 0; x < CHANNEL_MAX && x < numchan; x++) {
            if (sscanf(chan_details, "%d %1023[^\n]\n",
                       &channel_graph[x].signal, chan_details_sec) < 1)
                break;
            strncpy(chan_details, chan_details_sec, 1024);
        }

    } else if (!strncmp(header, "*CISCO", 64)) {
        cdp_packet cdp;
        memset(&cdp, 0, sizeof(cdp_packet));
        int cap0, cap1, cap2, cap3, cap4, cap5, cap6;
        short int cdpip[4];

        if (sscanf(in_data+hdrlen, "%17s \001%s\001 %hd.%hd.%hd.%hd \001%s\001 "
                   "%d:%d:%d:%d;%d;%d;%d \001%s\001 \001%s\001\n",
                   bssid_str, cdp.dev_id,
                   &cdpip[0], &cdpip[1], &cdpip[2], &cdpip[3],
                   cdp.interface, &cap0, &cap1, &cap2, &cap3, &cap4, &cap5, &cap6,
                   cdp.software, cdp.platform) < 16)
            return 0;

        bssid = bssid_str;

        cdp.ip[0] = cdpip[0];
        cdp.ip[1] = cdpip[1];
        cdp.ip[2] = cdpip[2];
        cdp.ip[3] = cdpip[3];

        if (net_map.find(bssid) == net_map.end())
            return 0;

        net_map[bssid]->cisco_equip[cdp.dev_id] = cdp;

    } else if (!strncmp(header, "*STATUS", 64)) {
        if (sscanf(in_data+hdrlen, "%1023[^\n]\n", status) != 1)
            return 0;
        return CLIENT_NOTIFY;
    } else if (!strncmp(header, "*ERROR", 64)) {
        int discard;
        if (sscanf(in_data+hdrlen, "%d %1023[^\n]\n", &discard, status) != 2)
            return 0;
        return CLIENT_NOTIFY;
    } else if (!strncmp(header, "*ALERT", 64)) {
        char alrmstr[2048];
        char atype[128];
        alert_info alrm;
        long int in_tv_sec, in_tv_usec;
        if (sscanf(in_data+hdrlen, "%ld %ld %127s \001%2047[^\001]\001\n", &in_tv_sec,
                   &in_tv_usec, atype, alrmstr) < 3)
            return 0;
        alrm.alert_ts.tv_sec = in_tv_sec;
        alrm.alert_ts.tv_usec = in_tv_usec;
        alrm.alert_text = string(atype) + string(" ") + string(alrmstr);
        alerts.push_back(alrm);
        if (alerts.size() > maxalerts)
            alerts.erase(alerts.begin());
        snprintf(status, STATUS_MAX, "ALERT: %s", alrmstr);
        return CLIENT_ALERT;
    } else if (!strncmp(header, "*STRING", 64)) {
        char netstr[2048];
        char bssid_str[18];
        char source_str[18];
        string_info strng;
        if (sscanf(in_data+hdrlen, "%17s %17s %2047[^\n]\n", 
				   bssid_str, source_str, netstr) != 3)
            return 0;

        gettimeofday(&strng.string_ts, NULL);

        strng.bssid = bssid_str;
        strng.source = source_str;

        strng.text = netstr;

        strings.push_back(strng);
        if (strings.size() > maxstrings)
            strings.erase(strings.begin());
    } else if (!strncmp(header, "*PACKET", 64)) {
        packet_info packinfo;
        memset(&packinfo, 0, sizeof(packet_info));
        char smac[18], dmac[18], bmac[18];
        short int sip[4], dip[4];
        int sport, dport;

	{
	int	tmptype, tmpsubtype, tmptvsec;
	int	tmpproto_type, tmpsport, tmpdport, tmpproto_nbtype;  
        if (sscanf(in_data+hdrlen, "%d %d %d %d %d %d %17s %17s %17s "
                   "\001%32[^\001]\001 %d %hd.%hd.%hd.%hd %hd.%hd.%hd.%hd %d %d %d "
                   "\001%16[^\001]\001\n",
                   &tmptype,
                   &tmpsubtype,
                   &tmptvsec,
                   &packinfo.encrypted, &packinfo.interesting, &packinfo.beacon,
                   smac, dmac, bmac,
                   packinfo.ssid,
		   &tmpproto_type,
                   &sip[0], &sip[1], &sip[2], &sip[3], &dip[0], &dip[1], &dip[2], &dip[3],
                   &tmpsport, &tmpdport,
                   &tmpproto_nbtype, packinfo.proto.netbios_source) < 22)
            return 0;
	packinfo.type       = static_cast<packet_type>(tmptype);
	packinfo.subtype    = static_cast<packet_sub_type>(tmpsubtype);
	packinfo.ts.tv_sec  = tmptvsec;
	packinfo.proto.type = static_cast<protocol_info_type>(tmpproto_type);
	sport               = tmpsport;
	dport               = tmpdport;
	packinfo.proto.nbtype = static_cast<protocol_netbios_type>(tmpproto_nbtype);
	}

        packinfo.source_mac = smac;
        packinfo.dest_mac = dmac;
        packinfo.bssid_mac = bmac;

        packinfo.proto.sport = sport;
        packinfo.proto.dport = dport;

        for (unsigned int x = 0; x < 4; x++) {
            packinfo.proto.source_ip[x] = sip[x];
            packinfo.proto.dest_ip[x] = dip[x];
        }

        packinfos.push_back(packinfo);
        if (packinfos.size() > maxpackinfos)
            packinfos.erase(packinfos.begin());

    } else if (!strncmp(header, "*CARD", 64)) {
        card_info *cinfo;

        char cinfo_interface[64];
        char cinfo_type[64];
        char cinfo_username[128];
        int cinfo_channel;
        int cinfo_id;
        int cinfo_packets;
        int cinfo_hopping;

        if (sscanf(in_data+hdrlen, "%63s %63s \001%127[^\001]\001 %d %d %d %d\n",
                   cinfo_interface, cinfo_type, cinfo_username, &cinfo_channel,
                   &cinfo_id, &cinfo_packets, &cinfo_hopping) < 7)
            return 0;

        map<string, card_info *>::iterator ciitr = card_map.find(cinfo_username);
        if (ciitr == card_map.end()) {
            cinfo = new card_info;
            cinfo->interface = cinfo_interface;
            cinfo->type = cinfo_type;
            cinfo->username = cinfo_username;
            cinfo->channel = cinfo_channel;
            cinfo->id = cinfo_id;
            cinfo->packets = cinfo_packets;
            cinfo->hopping = cinfo_hopping;

            card_map[cinfo_username] = cinfo;
            card_map_vec.push_back(cinfo);
        } else {
            cinfo = ciitr->second;
            cinfo->channel = cinfo_channel;
            cinfo->packets = cinfo_packets;
            cinfo->hopping = cinfo_hopping;
        }

    } else {

//        fprintf(stderr, "%ld we can't handle our header\n", this);
        return 0;
    }

    return 1;
}

time_t TcpClient::FetchServTime() {
    return serv_time;
}

int TcpClient::FetchLoc(float *in_lat, float *in_lon, float *in_alt, float *in_spd, float *in_hed, int *in_mode) {
    *in_lat = lat; *in_lon = lon;
    *in_alt = alt; *in_spd = spd;
    *in_hed = heading;
    *in_mode = mode;
    return mode;
}

vector<TcpClient::card_info *> TcpClient::FetchCardList() {
    return card_map_vec;
}

vector<wireless_network *> TcpClient::FetchNetworkList() {
    network_dirty = 0;
    return net_map_vec;
}

vector<wireless_network *> TcpClient::FetchNthRecent(unsigned int n) {
    vector<wireless_network *> vec = FetchNetworkList();

    // XXX
    // This is much easier now that we use vectors.  We're already ordered
    // by time since we're inserted in order, so we can just erase...
    // XXX
    stable_sort(vec.begin(), vec.end(), SortLastTimeLT());

    int drop = vec.size() - n;

    if (drop > 0) {
        vec.erase(vec.begin(), vec.begin() + drop);
    }

    stable_sort(vec.begin(), vec.end(), SortFirstTimeLT());

    return vec;
}

int TcpClient::FetchChannelPower(int in_channel) {
    if (in_channel > 0 && in_channel < CHANNEL_MAX)
        return channel_graph[in_channel - 1].signal;

    return -1;
}

int TcpClient::Send(const char *in_data) {
    if (!sv_valid) {
        snprintf(errstr, 1024, "TcpClient send() on an inactive connection.");
        return -1;
    }

    writebuf += in_data;

    return 1;
}

void TcpClient::SendRaw(const char *in_data) {
    char data[1024];

    // We on't really care about acks or errors...
    snprintf(data, 1024, "!0 %s\n", in_data);
    Send(data);
}

void TcpClient::EnableProtocol(string in_protocol) {
    char data[1024];
    string fields;

    if (protocol_default_map.find(in_protocol) != protocol_default_map.end())
        fields = protocol_default_map[in_protocol];
    else
        fields = "*";

    // We don't care about ACKS or even errors, so we just don't give an ID number
    snprintf(data, 1024, "!0 ENABLE %s %s\n", in_protocol.c_str(), fields.c_str());

    Send(data);

    protocol_map[in_protocol] = 1;

}

void TcpClient::RemoveProtocol(string in_protocol) {
    char data[1024];

    // We also don't care about acks or errors here
    snprintf(data, 1024, "!0 REMOVE %s\n", in_protocol.c_str());

    Send(data);

    map<string, int>::iterator pritr = protocol_map.find(in_protocol);
    if (pritr != protocol_map.end())
        protocol_map.erase(pritr);
}

int TcpClient::FetchNetworkDirty() {
    return network_dirty;
}

