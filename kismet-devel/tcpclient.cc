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
    protocol_default_map["KISMET"] = "version,starttime,servername,timestamp";
    protocol_default_map["GPS"] = "lat,lon,alt,spd,heading,fix";
    protocol_default_map["NETWORK"] = "bssid,type,ssid,beaconinfo,llcpackets,datapackets,cryptpackets,"
        "weakpackets,channel,wep,firsttime,lasttime,atype,rangeip,gpsfixed,minlat,minlon,minalt,minspd,"
        "maxlat,maxlon,maxalt,maxspd,octets,cloaked,beaconrate,maxrate,"
        "quality,signal,noise,bestquality,bestsignal,bestnoise,bestlat,bestlon,bestalt,"
        "agglat,agglon,aggalt,aggpoints,datasize,turbocellnid,turbocellmode,turbocellsat,"
        "carrierset,maxseenrate,encodingset,decrypted,dupeivpackets";
    protocol_default_map["CLIENT"] = "bssid,mac,type,firsttime,lasttime,"
        "datapackets,cryptpackets,weakpackets,"
        "gpsfixed,minlat,minlon,minalt,minspd,maxlat,maxlon,maxalt,maxspd,"
        "agglat,agglon,aggalt,aggpoints,maxrate,quality,signal,noise,"
        "bestquality,bestsignal,bestnoise,bestlat,bestlon,bestalt,"
        "atype,ip,datasize,maxseenrate,encodingset,decrypted";
    protocol_default_map["WEPKEY"] = "origin,bssid,key,encrypted,failed";
    protocol_default_map["CARD"] = "interface,type,username,channel,id,packets";

    sv_valid = 0;
    client_fd = 0;

    lat = lon = alt = spd = 0;
    mode = 0;

    num_networks = num_packets = num_crypt = num_interesting =
        num_noise = num_dropped = packet_rate = 0;

    old_num_networks = old_num_packets = old_num_crypt = old_num_interesting =
        old_num_noise = old_num_dropped = 0;

    start_time = 0;
    major = minor = tiny = 0;

    power = quality = noise = 0;

    maxstrings = 500;
    maxpackinfos = 1000;
    maxalerts = 500;

    memset(status, 0, STATUS_MAX);
    memset(channel_graph, 0, sizeof(channel_power) * CHANNEL_MAX);

    last_new_network = 0;

    servername[0] = '\0';

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

    // Drop out now on a status event so we can get drawn
    int ret = ParseData(data);

    /*
    if (ret == 2)
        return 1;
        */

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
        if (sscanf(in_data+hdrlen, "%d.%d.%d %d \001%32[^\001]\001 %24s",
                   &major, &minor, &tiny, (int *) &start_time, servername, build) < 6)
            return 0;
    } else if (!strncmp(header, "*TIME", 64)) {
        if (sscanf(in_data+hdrlen, "%d", (int *) &serv_time) < 1)
            return 0;

    } else if (!strncmp(header, "*NETWORK", 64)) {
        wireless_network *net;

        int scanned;

        char ssid[256], beacon[256];
        short int range[4];

        float maxrate;

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

        scanned = sscanf(in_data+hdrlen+18, "%d \001%255[^\001]\001 \001%255[^\001]\001 "
                         "%d %d %d %d %d %d %d %d %d %hd.%hd.%hd.%hd "
                         "%d %f %f %f %f %f %f %f %f %d %d %d %f %d %d %d %d %d %d %f %f %f "
                         "%lf %lf %lf %ld %ld"
                         "%d %d %d %d %d %d %d %d",
                         (int *) &net->type, ssid, beacon,
                         &net->llc_packets, &net->data_packets, &net->crypt_packets, &net->interesting_packets,
                         &net->channel, &net->wep, (int *) &net->first_time, (int *) &net->last_time,
                         (int *) &net->ipdata.atype, &range[0], &range[1], &range[2], &range[3],
                         &net->gps_fixed, &net->min_lat, &net->min_lon, &net->min_alt, &net->min_spd,
                         &net->max_lat, &net->max_lon, &net->max_alt, &net->max_spd,
                         &net->ipdata.octets, &net->cloaked, &net->beacon,
                         &maxrate,
                         &net->quality, &net->signal, &net->noise,
                         &net->best_quality, &net->best_signal, &net->best_noise,
                         &net->best_lat, &net->best_lon, &net->best_alt,
                         &net->aggregate_lat, &net->aggregate_lon, &net->aggregate_alt,
                         &net->aggregate_points, &net->datasize,
                         &net->turbocell_nid, (int *) &net->turbocell_mode, &net->turbocell_sat,
                         &net->carrier_set, &net->maxseenrate, &net->encoding_set,
                         &net->decrypted, &net->dupeiv_packets);

        if (scanned < 47) {
            // fprintf(stderr, "Flubbed network, discarding...\n");
            delete net;
            return 0;
        }

        if (newnet == 1) {
            net_map[bssid] = net;
            net_map_vec.push_back(net);
            last_new_network = net;
        }

        if (ssid[0] != '\002')
            net->ssid = ssid;
        if (beacon[0] != '\002')
            net->beacon_info = beacon;
        for (int x = 0; x < 4; x++) {
            net->ipdata.range_ip[x] = (uint8_t) range[x];
        }

        net->maxrate = maxrate;

    } else if (!strncmp(header, "*CLIENT", 64)) {
        short int ip[4];

        mac_addr cmac;
        char cmac_str[18];

        int scanned;
        float maxrate;

        // Find the bssid and mac so we can fill in our client or make a new one
        if (sscanf(in_data+hdrlen, "%17s %17s", bssid_str, cmac_str) != 2)
            return 0;

        bssid = bssid_str;
        wireless_client *client = NULL;
        int nclient = 0;

        map<mac_addr, wireless_network *>::iterator nmi = net_map.find(bssid);
        if (nmi != net_map.end()) {
            cmac = cmac_str;
            map<mac_addr, wireless_client *>::iterator wci = nmi->second->client_map.find(cmac);
            if (wci != nmi->second->client_map.end()) {
                client = wci->second;
            } else {
                nclient = 1;
                client = new wireless_client;
            }
        } else {
            return 0;
        }

        scanned = sscanf(in_data+hdrlen+36, "%d %d %d %d %d %d %d "
                         "%f %f %f %f %f %f %f %f %lf %lf "
                         "%lf %ld %f %d %d %d %d %d %d %d "
                         "%f %f %f %d %hd.%hd.%hd.%hd %ld %d %d %d",
                         (int *) &client->type,
                         (int *) &client->first_time, (int *) &client->last_time,
                         &client->data_packets, &client->crypt_packets,
                         &client->interesting_packets,
                         &client->gps_fixed, &client->min_lat, &client->min_lon,
                         &client->min_alt, &client->min_spd,
                         &client->max_lat, &client->max_lon, &client->max_alt,
                         &client->max_spd, &client->aggregate_lat, &client->aggregate_lon,
                         &client->aggregate_alt, &client->aggregate_points,
                         &maxrate, &client->metric,
                         &client->quality, &client->signal, &client->noise,
                         &client->best_quality, &client->best_signal, &client->best_noise,
                         &client->best_lat, &client->best_lon, &client->best_alt,
                         (int *) &client->ipdata.atype, &ip[0], &ip[1], &ip[2], &ip[3],
                         &client->datasize, &client->maxseenrate, &client->encoding_set,
                         &client->decrypted);

        if (scanned < 38) {
            if (nclient)
                delete client;
            return 0;
        }

        bssid = bssid_str;
        client->mac = cmac;
        client->maxrate = maxrate;

        client->tcpclient = this;

        for (unsigned int x = 0; x < 4; x++)
            client->ipdata.ip[x] = ip[x];

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
        if (sscanf(in_data+hdrlen, "%f %f %f %f %f %d", &lat, &lon, &alt, &spd, &heading, &mode) < 5)
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
        if (sscanf(in_data+hdrlen, "%ld %ld %128s \001%2047[^\001]\001\n", &in_tv_sec,
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
        if (sscanf(in_data+hdrlen, "%17s %17s %2047[^\n]\n", bssid_str, source_str, netstr) != 3)
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

        if (sscanf(in_data+hdrlen, "%d %d %d %d %d %d %17s %17s %17s "
                   "\001%32[^\001]\001 %d %hd.%hd.%hd.%hd %hd.%hd.%hd.%hd %d %d %d "
                   "\001%16[^\001]\001\n",
                   (int *) &packinfo.type,
                   (int *) &packinfo.subtype,
                   (int *) &packinfo.ts.tv_sec,
                   &packinfo.encrypted, &packinfo.interesting, &packinfo.beacon,
                   smac, dmac, bmac,
                   packinfo.ssid,
                   (int *) &packinfo.proto.type,
                   &sip[0], &sip[1], &sip[2], &sip[3], &dip[0], &dip[1], &dip[2], &dip[3],
                   (int *) &sport, (int *) &dport,
                   (int *) &packinfo.proto.nbtype, packinfo.proto.netbios_source) < 22)
            return 0;

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

        if (sscanf(in_data+hdrlen, "%64s %64s \001%128[^\001]\001 %d %d %d\n",
                   cinfo_interface, cinfo_type, cinfo_username, &cinfo_channel,
                   &cinfo_id, &cinfo_packets) < 6)
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

            card_map[cinfo_username] = cinfo;
            card_map_vec.push_back(cinfo);
        } else {
            cinfo = ciitr->second;
            cinfo->channel = cinfo_channel;
            cinfo->packets = cinfo_packets;
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

