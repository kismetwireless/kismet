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
#include "kis_netclient.h"
#include "configfile.h"
#include "speechcontrol.h"
#include "soundcontrol.h"

KismetClient::KismetClient() {
    fprintf(stderr, "*** kismetclient called with no global registry reference\n");
    globalreg = NULL;
    tcpcli = NULL;
}

KismetClient::KismetClient(GlobalRegistry *in_globalreg) : ClientFramework(in_globalreg) {
    // The only connection type we support right now is TCP so just make it manually
    // this could be parsed from the config file when we support other transport
    // layers
    tcpcli = new TcpClient(globalreg);

    // Attach it to ourselves and opposite
    RegisterNetworkClient(tcpcli);
    tcpcli->RegisterClientFramework(this);

    // Initialize all our stuff
    cmdid = 1;

    reconnect_attempt = -1;

    server_identified = 0;
    
    lat = lon = alt = spd = heading = 0;
    mode = 0;
    num_networks = num_packets = num_crypt = num_interesting =
        num_noise = num_dropped = 0;
    old_num_networks = old_num_packets = old_num_crypt = old_num_interesting =
        old_num_noise = old_num_dropped = 0;
    
    major = "\0";
    minor = "\0";
    tiny = "\0";
    build = "\0";

    start_time = 0;

    power = qualiy = noise = 0;

    maxstrings = 500;
    maxpackinfos = 1000;
    maxalerts = 500;

    network_dirty = 0;

    channel_hop = 0;

    last_new_network = NULL;

    memset(channel_graph, 0, sizeof(channel_power) * CHANNEL_MAX);

    // Fill in the protocol default field lists
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
    protocol_default_map["CARD"] = "interface,type,username,channel,id,packets,hopping";

    // Parse the config file and enable the tcpclient
    
    char temphost[128];
    if (sscanf(globalreg->kismetui_config->FetchOpt("host").c_str(), "%128[^:]:%d", 
               temphost, &port) != 2) {
        globalreg->messagebus->InjectMessage("Invalid Kismet host in config, host:port required",
                                             MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return;
    }
    snprintf(host, MAXHOSTNAMELEN, "%s", temphost);

    if (globalreg->kismet_config->FetchOpt("reconnect") == "true") {
        globalreg->messagebus->InjectMessage("Enabling reconnection to the Kismet server "
                                             "if the link is lost", MSGFLAG_INFO);
        reconnect_attempt = 0;
    }

    if (tcpcli->Connect(host, port) < 0) {
        globalreg->messagebus->InjectMessage("Could not create initial connection to "
                                             "the Kismet server", MSGFLAG_ERROR);
        if (reconnect_attempt < 0) {
            globalreg->messagebus->InjectMessage("Kismet server ceconnection not enabled, "
                                                 "unable to connect.", MSGFLAG_ERROR);
            return;
        }

        last_disconnect = time(0);
    } else {
        // Turn on the protocols in our map, if we have any.  This is for reconnecting
        // to a server and preserving the requested protocols
        for (map<string, int>::iterator prot = protocol_map.begin();
             prot != protocol_map.end(); ++prot) {
            EnableProtocol(prot->first);

            if (globalreg->fatal_condition)
                return;
        }
    }

    snprintf(errstr, STATUS_MAX, "Using Kismet server on %s:%d", host, port);
    globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
}

KismetClient::~KismetClient() {
    if (tcpcli != NULL) {
        tcpcli->KillConnection();
        delete tcpcli;
    }
}

int KismetClient::KillConnection() {
    if (tcpcli != NULL)
        tcpcli->KillConnection();

    return 1;
}

int KismetClient::Shutdown() {
    if (tcpcli != NULL) {
        tcpcli->FlushRings();
        tcpcli->KillConnection();
    }

    return 1;
}

int KismetClient::InjectCommand(string in_cmd) {
    // Timed backoff up to 30 seconds
    if (netcli->Valid() == 0 && reconnect_attempt &&
        (time(0) - last_disconnect >= (kismin(reconnect_attempt, 6) * 5))) {
        if (Reconnect() <= 0)
            return 0;
    }

    int curid = cmdid++;
    char cmdheader[32];

    snprintf(cmdheader, 32, "!%d ", curid);
    string fullcmd = string(cmdheader) + in_cmd;

    if (netcli->Valid() && netcli->WriteData((void *) fullcmd.c_str(), fullcmd->length()) < 0 ||
        globalreg->fatal_condition) {
        last_disconnect = time(0);
        return -1;
    }

    return curid;
}

int KismetClient::Reconnect() {
    if (netcli->Connect(host, port) < 0) {
        snprintf(errstr, STATUS_MAX, "Could not connect to the Kismet server, will "
                 "reconnect in %d seconds", kismin(reconnect_attempt + 1, 6) * 5);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        reconnect_attempt++;
        last_disconnect = time(0);
        return 0;
    }
    
    return 1;
}

int KismetClient::ParseData() {
    int len, rlen;
    char *buf;
    string strbuf;

    // Scratch variables for parsing data
    char header[65];
    char bssid_str[18];
    mac_addr bssid;
    int junkmajor, junkminor, junktiny;

    len = netclient->FetchReadLen();
    buf = new char[len + 1];
    
    if (netclient->ReadData(buf, len, &rlen) < 0) {
        globalreg->messagebus->InjectMessage("KismetClient::ParseData failed to fetch data from "
                                             "the tcp connection.", MSGFLAG_ERROR);
        return -1;
    }
    buf[len] = '\0';

    // Parse without including partials, so we don't get a fragmented command 
    // out of the buffer
    vector<string> inptok = StrTokenize(buf, "\n", 0);
    delete[] buf;

    // Bail on no useful data
    if (inptok.size() < 1) {
        return 0;
    }

    for (unsigned int it = 0; it < inptok.size(); it++) {
        // No matter what we've dealt with this data block
        netclient->MarkRead(inptok[it].length() + 1);

        // Pull the header out to save time -- cheaper to parse the header and then the
        // data than to try to parse an entire data string just to find out what protocol
        // we are
        // 
        // Protocol parsers should be dynamic so that we can have plugins in the framework
        // able to handle a proto, but right now thats a hassle

        if (sscanf(inptok[it].c_str(), "*%64[^:]", header) < 1) {
            continue;
        }

        // Nuke the header off the string
        inptok[it].erase(inptok[it].begin(), strlen(header));

        if (!strncmp(header, "TERMINATE", 64)) {
            snprintf(errstr, STATUS_MAX, "Kismet server terminated.");
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
           
            netclient->KillConnection();
            
            continue;
        } else if (!strncmp(header, "KISMET", 64)) {
            // Parse kismet protocol or skip
            if (sscanf(inptok[it].c_str(), "%d.%d.%d %d \001%32[^\001]\001 %24s %d "
                       "%24[^.].%24[^.].%24s",
                       &junkmajor, &junkminor, &junktiny, 
                       (int *) &start_time, servername, 
                       build, &channel_hop,
                       major, minor, tiny) < 7)
                continue;

            server_identified = 1;
        } else if (!strncmp(header, "TIME", 64)) {
            // Parse time protocol.  We don't care if we fail
            sscanf(inptok[it].c_str(), "%d", (int *) &serv_time);
        } else if (!strncmp(header, "NETWORK", 64)) {
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
                             "%d %f %f %f %f %f %f %f %f %d %d %d %f %d %d %d %d %d %d %f "
                             "%f %f "
                             "%lf %lf %lf %ld %ld"
                             "%d %d %d %d %d %d %d %d",
                             (int *) &net->type, ssid, beacon,
                             &net->llc_packets, &net->data_packets, &net->crypt_packets, 
                             &net->interesting_packets, &net->channel, &net->wep, 
                             (int *) &net->first_time, (int *) &net->last_time,
                             (int *) &net->ipdata.atype, &range[0], &range[1], &range[2], 
                             &range[3], &net->gps_fixed, &net->min_lat, &net->min_lon, 
                             &net->min_alt, &net->min_spd, &net->max_lat, &net->max_lon, 
                             &net->max_alt, &net->max_spd, &net->ipdata.octets, 
                             &net->cloaked, &net->beacon, &maxrate, &net->quality, 
                             &net->signal, &net->noise, &net->best_quality, 
                             &net->best_signal, &net->best_noise,
                             &net->best_lat, &net->best_lon, &net->best_alt,
                             &net->aggregate_lat, &net->aggregate_lon, &net->aggregate_alt,
                             &net->aggregate_points, &net->datasize,
                             &net->turbocell_nid, (int *) &net->turbocell_mode, 
                             &net->turbocell_sat, &net->carrier_set, &net->maxseenrate, 
                             &net->encoding_set, &net->decrypted, &net->dupeiv_packets);

            if (scanned < 47) {
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
            if (beacon[0] != '\002')
                net->beacon_info = beacon;
            for (int x = 0; x < 4; x++) {
                net->ipdata.range_ip[x] = (uint8_t) range[x];
            }

            net->maxrate = maxrate;

        } else if (!strncmp(header, "REMOVE", 64)) {
            // If we get a remove request flag it to die and the group code will
            // destroy it after ungrouping it
            if (sscanf(in_data+hdrlen, "%17s", bssid_str) < 0)
                continue;

            bssid = bssid_str;

            if (net_map.find(bssid) != net_map.end()) {
                net_map[bssid]->type = network_remove;
            }
        } else if (!strncmp(header, "GPS", 64)) {
            // GPS info.  We don't care if we don't parse it cleanly
            sscanf(in_data+hdrlen, "%f %f %f %f %f %d", &lat, &lon, &alt, 
                   &spd, &heading, &mode);
        } else if (!strncmp(header, "INFO", 64)) {
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
        } else if (!strncmp(header, "CISCO", 64)) {
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
        }

    }

    return 1;
}

