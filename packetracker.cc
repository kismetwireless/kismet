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

#include "packetracker.h"
#include "networksort.h"
#include "kismet_server.h"
#include "packetsignatures.h"

// State shift bits used to tell when we've raised an alert on a given network
#define RAISED_NETSTUMBLER_ALERT     1
#define RAISED_DEAUTHFLOOD_ALERT     2
#define RAISED_LUCENT_ALERT          4

Packetracker::Packetracker() {
    gps = NULL;

    num_networks = num_packets = num_dropped = num_noise =
        num_crypt = num_interesting = num_cisco = 0;

    errstr[0] = '\0';
}

Packetracker::~Packetracker() {
    for (unsigned int x = 0; x < network_list.size(); x++) {
        for (unsigned int y = 0; y < network_list[x]->client_vec.size(); y++)
            delete network_list[x]->client_vec[y];
        delete network_list[x];
    }
}

void Packetracker::AddGPS(GPSD *in_gps) {
    gps = in_gps;
}

vector<wireless_network *> Packetracker::FetchNetworks() {
    vector<wireless_network *> ret_vec = network_list;

    return ret_vec;
}

// Convert a net to string
string Packetracker::Net2String(wireless_network *in_net) {
    string ret;
    char output[2048];

    snprintf(output, 2048, "%s %d \001%s\001 \001%s\001 %d %d %d %d %d %d %d %d %d "
             "%d.%d.%d.%d %d %f %f %f %f %f %f %f %f %d %d %d %2.1f "
             "%s %d %d %d %d %d %d %d %f %f %f %f %f %f %ld",
             in_net->bssid.Mac2String().c_str(),
             (int) in_net->type,
             in_net->ssid.size() > 0 ? in_net->ssid.c_str() : "\002",
             in_net->beacon_info.size() > 0 ? in_net->beacon_info.c_str() : "\002",
             in_net->llc_packets, in_net->data_packets,
             in_net->crypt_packets, in_net->interesting_packets,
             in_net->channel, in_net->wep,
             (int) in_net->first_time, (int) in_net->last_time,
             (int) in_net->ipdata.atype,
             in_net->ipdata.range_ip[0], in_net->ipdata.range_ip[1],
             in_net->ipdata.range_ip[2], in_net->ipdata.range_ip[3],

             in_net->gps_fixed,
             in_net->min_lat, in_net->min_lon, in_net->min_alt, in_net->min_spd,
             in_net->max_lat, in_net->max_lon, in_net->max_alt, in_net->max_spd,

             in_net->ipdata.octets,
             in_net->cloaked, in_net->beacon, in_net->maxrate,

             in_net->manuf_key.Mac2String().c_str(), in_net->manuf_score,
	     
             in_net->quality, in_net->signal, in_net->noise,
             in_net->best_quality, in_net->best_signal, in_net->best_noise,
             in_net->best_lat, in_net->best_lon, in_net->best_alt,

             in_net->aggregate_lat, in_net->aggregate_lon, in_net->aggregate_alt,
             in_net->aggregate_points);

    ret = output;

    return ret;
}

string Packetracker::Client2String(wireless_network *net, wireless_client *client) {
    string ret;
    char output[2048];

    snprintf(output, 2048,
             "%s %s %d %d %d %s %d %d %d %d %d "
             "%f %f %f %f %f %f %f %f %f %f "
             "%f %ld %2.1f %d %d %d %d %d %d %d "
             "%f %f %f %d %d.%d.%d.%d",
             net->bssid.Mac2String().c_str(),
             client->mac.Mac2String().c_str(),
             client->type,
             (int) client->first_time, (int) client->last_time,
             client->manuf_key.Mac2String().c_str(), client->manuf_score,
             client->data_packets, client->crypt_packets, client->interesting_packets,
             client->gps_fixed, client->min_lat, client->min_lon, client->min_alt, client->min_spd,
             client->max_lat, client->max_lon, client->max_alt, client->max_spd,
             client->aggregate_lat, client->aggregate_lon, client->aggregate_alt,
             client->aggregate_points,
             client->maxrate, client->metric,
             client->quality, client->signal, client->noise,
             client->best_quality, client->best_signal, client->best_noise,
             client->best_lat, client->best_lon, client->best_alt,
             client->ipdata.atype,
             client->ipdata.ip[0], client->ipdata.ip[1],
             client->ipdata.ip[2], client->ipdata.ip[3]);

    ret = output;

    return ret;
}

string Packetracker::CDP2String(cdp_packet *in_cdp) {
    string ret;
    char output[2048];

    // Transform the data fields \n's into \003's for easy transfer
    for (unsigned int i = 0; i < strlen(in_cdp->dev_id); i++)
        if (in_cdp->dev_id[i] == '\n') in_cdp->dev_id[i] = '\003';
    for (unsigned int i = 0; i < strlen(in_cdp->interface); i++)
        if (in_cdp->interface[i] == '\n') in_cdp->interface[i] = '\003';
    for (unsigned int i = 0; i < strlen(in_cdp->software); i++)
        if (in_cdp->software[i] == '\n') in_cdp->software[i] = '\003';
    for (unsigned int i = 0; i < strlen(in_cdp->platform); i++)
        if (in_cdp->platform[i] == '\n') in_cdp->platform[i] = '\003';

    snprintf(output, 2048, "\001%s\001 %d.%d.%d.%d \001%s\001 "
             "%d:%d:%d:%d:%d:%d:%d \001%s\001 \001%s\001",
             in_cdp->dev_id[0] != '\0' ? in_cdp->dev_id : "\002",
             in_cdp->ip[0], in_cdp->ip[1], in_cdp->ip[2], in_cdp->ip[3],
             in_cdp->interface[0] != '\0' ? in_cdp->interface : "\002",
             in_cdp->cap.level1, in_cdp->cap.igmp_forward, in_cdp->cap.nlp, in_cdp->cap.level2_switching,
             in_cdp->cap.level2_sourceroute, in_cdp->cap.level2_transparent, in_cdp->cap.level3,
             in_cdp->software[0] != '\0' ? in_cdp->software : "\002",
             in_cdp->platform[0] != '\0' ? in_cdp->platform : "\002");

    ret = output;
    return ret;
}
// Is a string blank?
bool Packetracker::IsBlank(const char *s) {
    int len, i;
    if (NULL == s) { return true; }
    if (0 == (len = strlen(s))) { return true; }
    for (i = 0; i < len; ++i) {
        if (' ' != s[i]) { return false; }
    }
    return true;
}

// Periodic tick to handle events.  We expect this once a second.
int Packetracker::Tick() {
    for (unsigned int x = 0; x < network_list.size(); x++) {
        wireless_network *net = network_list[x];

        // Decay 10 disconnects per second
        if (net->client_disconnects != 0) {
            net->client_disconnects -= 10;
            if (net->client_disconnects < 0)
                net->client_disconnects = 0;
        }

    }

    return 1;
}

int Packetracker::ProcessPacket(packet_info info, char *in_status) {
    wireless_network *net;
    int ret = 0;
    map<mac_addr, wireless_network *>::iterator bsmapitr;

    // string bssid_mac;

    // GPS info
    float lat = 0, lon = 0, alt = 0, spd = 0;
    int fix = 0;

    num_packets++;

    // Junk unknown and noise packets
    if (info.type == packet_noise) {
        num_dropped++;
        num_noise++;
        return(0);
    } else if (info.type == packet_unknown) {
        // If we can't figure out what it is
        // or if FromDS and ToDS are set, we can't make much sense of it so don't
        // try to make a network out of it -- toss it.
        num_dropped++;
        return(0);
    }

    // If it's a broadcast (From and To DS == 1) try to match it to an existing
    // network
    bsmapitr = bssid_map.find(info.bssid_mac);

    if (info.type == packet_ap_broadcast && bsmapitr == bssid_map.end()) {
        if ((bsmapitr = bssid_map.find(info.source_mac)) != bssid_map.end()) {
            info.bssid_mac = info.source_mac;
        } else if ((bsmapitr = bssid_map.find(info.dest_mac)) != bssid_map.end()) {
            info.bssid_mac = info.dest_mac;
        } else {
            num_dropped++;
            return(0);
        }
    }

    if (info.bssid_mac == NUL_MAC) {
        num_dropped++;
        return(0);
    }

    // If it's a probe request, see if we already know who it should belong to
    if (info.type == packet_probe_req) {
        if (probe_map.find(info.bssid_mac) != probe_map.end())
            info.bssid_mac = probe_map[info.bssid_mac];
    }

    // Find out if we have this network -- Every network that actually
    // gets added has a bssid, so we'll use that to search.  We've filtered
    // everything else out by this point so we're safe to just work off bssid
    if (bsmapitr == bssid_map.end()) {
        // Make a network for them
        net = new wireless_network;

        if (bssid_ip_map.find(info.bssid_mac) != bssid_ip_map.end())
            memcpy(&net->ipdata, &bssid_ip_map[info.bssid_mac], sizeof(net_ip_data));

        if (IsBlank(info.ssid)) {
            if (bssid_cloak_map.find(info.bssid_mac) != bssid_cloak_map.end()) {
                net->ssid = bssid_cloak_map[info.bssid_mac];

                // If it's a beacon and empty then we're cloaked and we found our
                // ssid so fill it in
                if (info.type == packet_beacon) {
                    net->cloaked = 1;
                } else {
                    net->cloaked = 0;
                }
            } else {
                net->ssid = NOSSID;
                net->cloaked = 0;
            }
        } else {
            net->ssid = info.ssid;
            net->cloaked = 0;
            bssid_cloak_map[info.bssid_mac] = info.ssid;
        }

        net->bssid = info.bssid_mac;

        net->channel = info.channel;

        if (info.ap == 1)
            net->type = network_ap;

        if (info.type == packet_probe_req)
            net->type = network_probe;

        net->wep = info.wep;

        net->beacon = info.beacon;

        //net->bssid = Mac2String(info.bssid_mac, ':');

        // Put us in the master list
        network_list.push_back(net);
        net->listed = 1;

        net->first_time = time(0);

        net->sequence = info.sequence_number;

        net->maxrate = info.maxrate;

        if (strlen(info.beacon_info) != 0)
            net->beacon_info = info.beacon_info;

        if (net->type == network_probe) {
            snprintf(in_status, STATUS_MAX, "Found new probed network bssid %s",
                     net->bssid.Mac2String().c_str());
        } else {
            snprintf(in_status, STATUS_MAX, "Found new network \"%s\" bssid %s WEP %c Ch %d @ %.2f mbit",
                     net->ssid.c_str(), net->bssid.Mac2String().c_str(), net->wep ? 'Y' : 'N',
                     net->channel, net->maxrate);
        }

        if (gps != NULL) {
            gps->FetchLoc(&lat, &lon, &alt, &spd, &fix);

            if (fix >= 2) {
                net->gps_fixed = fix;
                net->min_lat = net->max_lat = lat;
                net->min_lon = net->max_lon = lon;
                net->min_alt = net->max_alt = alt;
                net->min_spd = net->max_spd = spd;

                net->aggregate_lat = lat;
                net->aggregate_lon = lon;
                net->aggregate_alt = alt;
                net->aggregate_points = 1;
            }

        }

        // Find out what we can from what we know now...
        if (net->type != network_adhoc && net->type != network_probe) {
            MatchBestManuf(ap_manuf_map, net->bssid, net->ssid, net->channel,
                           net->wep, net->cloaked,
                           &net->manuf_key, &net->manuf_score);
            if (net->manuf_score == manuf_max_score)
                memcpy(&net->ipdata, &ap_manuf_map[net->manuf_key]->ipdata, sizeof(net_ip_data));
        } else {
            MatchBestManuf(client_manuf_map, net->bssid, net->ssid, net->channel,
                           net->wep, net->cloaked,
                           &net->manuf_key, &net->manuf_score);
        }

        num_networks++;

        // And add us to the map
        bssid_map[net->bssid] = net;

        // Return 1 if we make a new network entry
        ret = TRACKER_NEW;
    } else {
        net = bssid_map[info.bssid_mac];
        if (net->listed == 0) {
            network_list.push_back(net);
            net->listed = 1;
        }
        ret = TRACKER_NONE;
    }

    net->last_time = time(0);

    if (info.quality >= 0 && info.signal >= 0) {
        net->quality = info.quality;
        if (info.quality > net->best_quality)
            net->best_quality = info.quality;
        net->signal = info.signal;

        if (info.signal > net->best_signal) {
            net->best_signal = info.signal;
            if (gps != NULL && fix >= 2) {
                net->best_lat = lat;
                net->best_lon = lon;
                net->best_alt = alt;
            }
        }

        net->noise = info.noise;
        if ((info.noise < net->best_noise && info.noise != 0) || net->best_noise == 0)
            net->best_noise = info.noise;
    }

    if (gps != NULL) {
        gps->FetchLoc(&lat, &lon, &alt, &spd, &fix);

        if (fix > 1) {
            net->aggregate_lat += lat;
            net->aggregate_lon += lon;
            net->aggregate_alt += alt;
            net->aggregate_points += 1;

            net->gps_fixed = fix;

            if (lat < net->min_lat || net->min_lat == 0)
                net->min_lat = lat;
            else if (lat > net->max_lat)
                net->max_lat = lat;

            if (lon < net->min_lon || net->min_lon == 0)
                net->min_lon = lon;
            else if (lon > net->max_lon)
                net->max_lon = lon;

            if (alt < net->min_alt || net->min_alt == 0)
                net->min_alt = alt;
            else if (alt > net->max_alt)
                net->max_alt = alt;

            if (spd < net->min_spd || net->min_spd == 0)
                net->min_spd = spd;
            else if (spd > net->max_spd)
                net->max_spd = spd;

        } else {
            net->gps_fixed = 0;
        }

    }

    if (info.type != packet_data && info.type != packet_ap_broadcast &&
        info.type != packet_adhoc_data) {

        net->llc_packets++;

        // If it's a probe request shortcut to handling it like a client once we've
        // established what network it belongs to
        if (info.type == packet_probe_req) {
            if (net->ssid != info.ssid) {
                if (IsBlank(info.ssid))
                    net->ssid = NOSSID;
                else
                    net->ssid = info.ssid;
            }

            ret = ProcessDataPacket(info, net, in_status);
            return ret;
        }

        if (info.type == packet_beacon && strlen(info.beacon_info) != 0 &&
            IsBlank(net->beacon_info.c_str())) {
            net->beacon_info = info.beacon_info;
        }

        if (info.type == packet_deauth || info.type == packet_disassociation) {
            net->client_disconnects++;

            if (net->client_disconnects > 10) {
                if ((net->alertmap & RAISED_DEAUTHFLOOD_ALERT) == 0) {
                    net->alertmap |= RAISED_DEAUTHFLOOD_ALERT;

                    snprintf(in_status, STATUS_MAX, "Deauthenticate/Disassociate flood on %s",
                             net->bssid.Mac2String().c_str());
                    return TRACKER_ALERT;
                }
            }
        }

        // Update the ssid record if we got a beacon for a data network
        if (info.type == packet_beacon) {
            // If we're updating the network record, update the manufacturer info -
            // if we just "became" an AP or if we've changed channel, we may have
            // changed state as well
            if (net->channel != info.channel || net->type != network_ap ||
                (net->ssid != info.ssid && !IsBlank(info.ssid))) {
                MatchBestManuf(ap_manuf_map, net->bssid, info.ssid, info.channel,
                               net->wep, net->cloaked,
                               &net->manuf_key, &net->manuf_score);
                // Update our IP range info too if we're a default
                if (net->manuf_score == manuf_max_score && net->ipdata.atype == address_none)
                    memcpy(&net->ipdata, &ap_manuf_map[net->manuf_key]->ipdata, sizeof(net_ip_data));
            }

            if (net->ssid != info.ssid && !IsBlank(info.ssid)) {
                net->ssid = info.ssid;
                bssid_cloak_map[net->bssid] = info.ssid;

                snprintf(in_status, STATUS_MAX, "Found SSID \"%s\" for network BSSID %s",
                         net->ssid.c_str(), net->bssid.Mac2String().c_str());

                ret = TRACKER_NOTICE;
            }

            net->channel = info.channel;
            net->wep = info.wep;

            net->type = network_ap;
        }


        // If this is a probe response and the ssid we have is blank, update it.
        // With "closed" networks, this is our chance to see the real ssid.
        // (Thanks to Jason Luther <jason@ixid.net> for this "closed network" detection)
        if (info.type == packet_probe_response || info.type == packet_reassociation &&
            (strlen(info.ssid) > 0) && !IsBlank(info.ssid)) {

            if (net->ssid == NOSSID) {
                net->cloaked = 1;
                net->ssid = info.ssid;
                net->channel = info.channel;
                net->wep = info.wep;

                MatchBestManuf(ap_manuf_map, net->bssid, net->ssid, net->channel,
                               net->wep, net->cloaked,
                               &net->manuf_key, &net->manuf_score);
                // Update our IP range info too if we're a default
                if (net->manuf_score == manuf_max_score && net->ipdata.atype == address_none)
                    memcpy(&net->ipdata, &ap_manuf_map[net->manuf_key]->ipdata, sizeof(net_ip_data));

                bssid_cloak_map[net->bssid] = info.ssid;

                snprintf(in_status, STATUS_MAX, "Found SSID \"%s\" for cloaked network BSSID %s",
                         net->ssid.c_str(), net->bssid.Mac2String().c_str());

                ret = TRACKER_NOTICE;
            } else if (info.ssid != bssid_cloak_map[net->bssid]) {
                bssid_cloak_map[net->bssid] = info.ssid;
                net->ssid = info.ssid;
                net->wep = info.wep;

                MatchBestManuf(ap_manuf_map, net->bssid, net->ssid, net->channel,
                               net->wep, net->cloaked,
                               &net->manuf_key, &net->manuf_score);
                // Update our IP range info too if we're a default
                if (net->manuf_score == manuf_max_score && net->ipdata.atype == address_none)
                    memcpy(&net->ipdata, &ap_manuf_map[net->manuf_key]->ipdata, sizeof(net_ip_data));
            }

            // If we have a probe request network, absorb it into the main network
            //string resp_mac = Mac2String(info.dest_mac, ':');
            //probe_map[resp_mac] = net->bssid;
            probe_map[info.dest_mac] = net->bssid;

            // If we have any networks that match the response already in existance,
            // we should add them to the main network and kill them off
            if (bssid_map.find(info.dest_mac) != bssid_map.end()) {
                wireless_network *pnet = bssid_map[info.dest_mac];
                if (pnet->type == network_probe) {

                    net->llc_packets += pnet->llc_packets;
                    net->data_packets += pnet->data_packets;
                    net->crypt_packets += pnet->crypt_packets;
                    net->interesting_packets += pnet->interesting_packets;
                    pnet->type = network_remove;
                    pnet->last_time = time(0);

                    snprintf(in_status, STATUS_MAX, "Associated probe network \"%s\".",
                             pnet->bssid.Mac2String().c_str());

                    num_networks--;

                    ret = TRACKER_ASSOCIATE;
                }
            }

        }

        if (net->type != network_ap && info.type == packet_adhoc) {
            net->type = network_adhoc;
        }

    } else {

        // Process data packets

        // We feed them into the data packet processor along with the network
        // they belong to, so that clients can be tracked.
        ret = ProcessDataPacket(info, net, in_status);

    } // data packet

    return ret;
}

int Packetracker::ProcessDataPacket(packet_info info, wireless_network *net, char *in_status) {
    int ret = 0;
    wireless_client *client = NULL;

    // GPS info
    float lat = 0, lon = 0, alt = 0, spd = 0;
    int fix = 0;

    // Find the client or make one
    if (net->client_map.find(info.source_mac) == net->client_map.end()) {
        client = new wireless_client;

        // Add it to the map
        net->client_map[info.source_mac] = client;
        // Add it to the vec
        net->client_vec.push_back(client);

        client->first_time = time(0);
        client->mac = info.source_mac;
        MatchBestManuf(client_manuf_map, client->mac, "", 0, 0, 0,
                       &client->manuf_key, &client->manuf_score);

        client->metric = net->metric;

        if (gps != NULL) {
            gps->FetchLoc(&lat, &lon, &alt, &spd, &fix);

            if (fix >= 2) {
                client->gps_fixed = fix;
                client->min_lat = client->max_lat = lat;
                client->min_lon = client->max_lon = lon;
                client->min_alt = client->max_alt = alt;
                client->min_spd = client->max_spd = spd;

                client->aggregate_lat = lat;
                client->aggregate_lon = lon;
                client->aggregate_alt = alt;
                client->aggregate_points = 1;
            }

        }

        // Classify the client.  We'll call no-distrib packets (lucent)
        // inter-distrib clients since it's not an end-user bridge into the
        // network, it's a lucent AP talking to another one.
        if (info.distrib == from_distribution)
            client->type = client_fromds;
        else if (info.distrib == to_distribution)
            client->type = client_tods;
        else if (info.distrib == inter_distribution)
            client->type = client_interds;
        else if (info.distrib == no_distribution)
            client->type = client_interds;

    } else {
        client = net->client_map[info.source_mac];

        if ((client->type == client_fromds && info.distrib == to_distribution) ||
            (client->type == client_tods && info.distrib == from_distribution)) {
            client->type = client_established;
        }
    }

    if (gps != NULL) {
        gps->FetchLoc(&lat, &lon, &alt, &spd, &fix);

        if (fix > 1) {
            client->aggregate_lat += lat;
            client->aggregate_lon += lon;
            client->aggregate_alt += alt;
            client->aggregate_points += 1;

            client->gps_fixed = fix;

            if (lat < client->min_lat || client->min_lat == 0)
                client->min_lat = lat;
            else if (lat > client->max_lat)
                client->max_lat = lat;

            if (lon < client->min_lon || client->min_lon == 0)
                client->min_lon = lon;
            else if (lon > client->max_lon)
                client->max_lon = lon;

            if (alt < client->min_alt || client->min_alt == 0)
                client->min_alt = alt;
            else if (alt > client->max_alt)
                client->max_alt = alt;

            if (spd < client->min_spd || client->min_spd == 0)
                client->min_spd = spd;
            else if (spd > client->max_spd)
                client->max_spd = spd;

        } else {
            client->gps_fixed = 0;
        }
    }

    if (info.quality >= 0 && info.signal >= 0) {
        client->quality = info.quality;
        if (info.quality > client->best_quality)
            client->best_quality = info.quality;
        client->signal = info.signal;

        if (info.signal > client->best_signal) {
            client->best_signal = info.signal;
            if (gps != NULL && fix >= 2) {
                client->best_lat = lat;
                client->best_lon = lon;
                client->best_alt = alt;
            }
        }

        net->noise = info.noise;
        if ((info.noise < net->best_noise && info.noise != 0) || net->best_noise == 0)
            net->best_noise = info.noise;
    }

    if (info.type == packet_probe_req) {
        if (info.maxrate > client->maxrate)
            client->maxrate = info.maxrate;
    }

    client->last_time = time(0);

    // We modify our client and our network concurrently to save on CPU cycles.
    // Easier to update them in sync than it is to process the map as a list.
    if (info.encrypted) {
        net->crypt_packets++;
        client->crypt_packets++;
        num_crypt++;
    }

    if (info.interesting) {
        net->interesting_packets++;
        client->interesting_packets++;
        num_interesting++;
    }

    if (info.type != packet_probe_req) {
        net->data_packets++;
        client->data_packets++;
    }

    // Record a cisco device
    if (info.proto.type == proto_cdp) {
        net->cisco_equip[info.proto.cdp.dev_id] = info.proto.cdp;
        num_cisco++;
    }

    unsigned int ipdata_dirty = 0;
    char *means = NULL;

    if (info.proto.type == proto_dhcp_server && (client->ipdata.atype < address_dhcp ||
                                                 client->ipdata.load_from_store == 1)) {
        // If we have a DHCP packet and we didn't before, turn it into a full record
        // in the client and flag us dirty.
        client->ipdata.atype = address_dhcp;

        // We only care about the source in the actual client record, but we need to
        // record the rest so that we can form a network record
        memcpy(client->ipdata.ip, info.proto.misc_ip, 4);

        means = "DHCP";
        ipdata_dirty = 1;
    } else if (info.proto.type == proto_arp && (client->ipdata.atype < address_arp ||
                                                client->ipdata.load_from_store == 1) &&
               info.proto.source_ip[0] != 0x00) {
        client->ipdata.atype = address_arp;

        memcpy(client->ipdata.ip, info.proto.source_ip, 4);
        means = "ARP";
        ipdata_dirty = 1;
    } else if ((info.proto.type == proto_udp || info.proto.type == proto_netbios) &&
               (client->ipdata.atype < address_udp || client->ipdata.load_from_store == 1) &&
               info.proto.source_ip[0] != 0x00) {
        client->ipdata.atype = address_udp;
        memcpy(client->ipdata.ip, info.proto.source_ip, 4);
        means = "UDP";
        ipdata_dirty = 1;
    } else if ((info.proto.type == proto_misc_tcp || info.proto.type == proto_netbios_tcp) &&
               (client->ipdata.atype < address_tcp || client->ipdata.load_from_store == 1) &&
               info.proto.source_ip[0] != 0x00) {
        client->ipdata.atype = address_tcp;
        memcpy(client->ipdata.ip, info.proto.source_ip, 4);
        means = "TCP";
        ipdata_dirty = 1;
    }

    if (ipdata_dirty) {
        snprintf(in_status, STATUS_MAX, "Found IP %d.%d.%d.%d for %s::%s via %s",
                 client->ipdata.ip[0], client->ipdata.ip[1],
                 client->ipdata.ip[2], client->ipdata.ip[3],
                 net->ssid.c_str(), info.source_mac.Mac2String().c_str(), means);

        client->ipdata.load_from_store = 0;

        UpdateIpdata(net);
        ret = TRACKER_NOTICE;
    }

    if (info.proto.type == proto_lor) {
        // Handle lucent outdoor routers
        net->cloaked = 1;
        net->ssid = "Lucent Outdoor Router";
        net->type = network_lor;
    } else if (info.proto.type == proto_netstumbler) {
        // Handle netstumbler packets

        // Only raise an alert when we haven't raised one for this client
        // before.
        if ((net->alertmap & RAISED_NETSTUMBLER_ALERT) == 0) {
            net->alertmap |= RAISED_NETSTUMBLER_ALERT;
            char *nsversion;

            switch (info.proto.prototype_extra) {
            case 22:
                nsversion = "3.22";
                break;
            case 23:
                nsversion = "3.23";
                break;
            case 30:
                nsversion = "3.30";
                break;
            default:
                nsversion = "unknown";
                break;
            }

            snprintf(in_status, STATUS_MAX, "NetStumbler (%s) probe detected from %s",
                     nsversion, client->mac.Mac2String().c_str());

            ret = TRACKER_ALERT;
        }

    } else if (info.proto.type == proto_lucenttest) {
        // Handle lucent test packets

        // only raise a status when we ahven't raised one before
        if ((net->alertmap & RAISED_LUCENT_ALERT) == 0) {
            net->alertmap |= RAISED_LUCENT_ALERT;

            snprintf(in_status, STATUS_MAX, "Lucent link test detected from %s",
                     client->mac.Mac2String().c_str());

            ret = TRACKER_NOTICE;
        }
    }

    return ret;
}

void Packetracker::UpdateIpdata(wireless_network *net) {
    memset(&net->ipdata, 0, sizeof(net_ip_data));

    wireless_client *client = NULL;

    if (net->client_map.size() == 0)
        return;

    // Zero out our range knowledge.  This will get grafted in from the client
    // aggregates.  Keep us if we're a factory config, we get handled specially.
    if (net->ipdata.atype != address_factory)
        memset(&net->ipdata, 0, sizeof(net->ipdata));

    for (unsigned int y = 0; y < net->client_vec.size(); y++) {
        client = net->client_vec[y];

        // We treat all non-dhcp client addresses equally.  We compare what we have
        // already (net->ipdata.range_ip) to the client source address to see what the
        // difference is, and form the new address range.  If the new address range
        // takes precedence, we set the network address type appropriately.
        // We favor the IP of the previous clients, for no good reason.

        uint8_t new_range[4];

        memset(new_range, 0, 4);

        if (client->ipdata.ip[0] != 0x00) {
            if (net->ipdata.atype == address_factory) {
                memset(&net->ipdata, 0, sizeof(net_ip_data));
            }

            int oct;
            for (oct = 0; oct < 4; oct++) {
                if (net->ipdata.range_ip[oct] != client->ipdata.ip[oct] &&
                    net->ipdata.range_ip[oct] != 0x00) {
                    break;
                }

                new_range[oct] = client->ipdata.ip[oct];
            }

            if (oct < net->ipdata.octets || net->ipdata.octets == 0) {
                net->ipdata.octets = oct;
                net->ipdata.atype = client->ipdata.atype;
                memcpy(net->ipdata.range_ip, new_range, 4);
                bssid_ip_map[net->bssid] = net->ipdata;
            }

        }
    }

#if 0
    if (ipdata_dirty) {
        if (net->ipdata.atype < address_dhcp && client->ipdata.atype == address_dhcp) {
            net->ipdata.atype = address_dhcp;

            memcpy(&client->ipdata, &net->ipdata, sizeof(net->ipdata));
            net->ipdata.range_ip[0] = net->ipdata.ip[0] & net->ipdata.mask[0];
            net->ipdata.range_ip[1] = net->ipdata.ip[1] & net->ipdata.mask[1];
            net->ipdata.range_ip[2] = net->ipdata.ip[2] & net->ipdata.mask[2];
            net->ipdata.range_ip[3] = net->ipdata.ip[3] & net->ipdata.mask[3];

            snprintf(in_status, STATUS_MAX, "Found IP range for \"%s\" via DHCP %d.%d.%d.%d mask %d.%d.%d.%d",
                 net->ssid.c_str(), net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                 net->ipdata.range_ip[2], net->ipdata.range_ip[3],
                 net->ipdata.mask[0], net->ipdata.mask[1],
                 net->ipdata.mask[2], net->ipdata.mask[3]);

            net->ipdata.octets = 0;

            net->ipdata.load_from_store = 0;

            ret = TRACKER_NOTICE;

        } else if (net->ipdata.atype < address_arp && client->ipdata.atype == address_arp) {
            net->ipdata.atype = address_arp;



        } else if (net->ipdata.atype < address_tcp && client->ipdata.atype == address_tcp) {
            net->ipdata.atype = address_tcp;


        } else if (net->ipdata.atype < address_udp && client->ipdata.atype == address_udp) {
            net->ipdata.atype = address_udp;

        }

    } else if (info.proto.type == proto_arp && (net->ipdata.atype < address_arp ||
                                                net->ipdata.load_from_store == 1)) {

        uint8_t new_range[4];

        memset(new_range, 0, 4);

        if (info.proto.source_ip[0] != 0x00 &&
            info.proto.misc_ip[0] != 0x00) {

            int oct;
            for (oct = 0; oct < 4; oct++) {
                if (info.proto.source_ip[oct] != info.proto.misc_ip[oct])
                    break;

                new_range[oct] = info.proto.source_ip[oct];
            }

            if (oct < net->ipdata.octets || net->ipdata.octets == 0) {
                net->ipdata.octets = oct;
                memcpy(net->ipdata.range_ip, new_range, 4);
                snprintf(in_status, STATUS_MAX, "Found IP range for \"%s\" via ARP %d.%d.%d.%d",
                         net->ssid.c_str(), net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                         net->ipdata.range_ip[2], net->ipdata.range_ip[3]);
                //gui->WriteStatus(status);

                net->ipdata.atype = address_arp;

                bssid_ip_map[net->bssid] = net->ipdata;
                net->ipdata.load_from_store = 0;

                ret = TRACKER_NOTICE;
            }
        } // valid arp
    } else if (info.proto.type == proto_udp && (net->ipdata.atype <= address_udp ||
                                                net->ipdata.load_from_store == 1)) {
        uint8_t new_range[4];

        memset(new_range, 0, 4);

        // Not 0.x.x.x.  Not 255.x.x.x.  At least first octet must
        // match.
        if (info.proto.source_ip[0] != 0x00 &&
            info.proto.dest_ip[0] != 0x00 &&
            info.proto.dest_ip[0] != 0xFF &&
            info.proto.source_ip[0] == info.proto.dest_ip[0]) {

            int oct;
            for (oct = 0; oct < 4; oct++) {
                if (info.proto.source_ip[oct] != info.proto.dest_ip[oct])
                    break;

                new_range[oct] = info.proto.source_ip[oct];
            }

            if (oct < net->ipdata.octets || net->ipdata.octets == 0) {
                net->ipdata.octets = oct;
                memcpy(net->ipdata.range_ip, new_range, 4);
                snprintf(in_status, STATUS_MAX, "Found IP range for \"%s\" via UDP %d.%d.%d.%d",
                         net->ssid.c_str(), net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                         net->ipdata.range_ip[2], net->ipdata.range_ip[3]);

                net->ipdata.atype = address_udp;

                bssid_ip_map[net->bssid] = net->ipdata;
                net->ipdata.load_from_store = 0;

                ret = TRACKER_NOTICE;
            }
        }
    }  else if (info.proto.type == proto_misc_tcp && (net->ipdata.atype <= address_tcp ||
                                                      net->ipdata.load_from_store == 1)) {
        uint8_t new_range[4];

        memset(new_range, 0, 4);

        // Not 0.x.x.x.  Not 255.x.x.x.  At least first octet must
        // match.
        if (info.proto.source_ip[0] != 0x00 &&
            info.proto.dest_ip[0] != 0x00 &&
            info.proto.dest_ip[0] != 0xFF &&
            info.proto.source_ip[0] == info.proto.dest_ip[0]) {

            int oct;
            for (oct = 0; oct < 4; oct++) {
                if (info.proto.source_ip[oct] != info.proto.dest_ip[oct])
                    break;

                new_range[oct] = info.proto.source_ip[oct];
            }

            if (oct < net->ipdata.octets || net->ipdata.octets == 0) {
                net->ipdata.octets = oct;
                memcpy(net->ipdata.range_ip, new_range, 4);
                snprintf(in_status, STATUS_MAX, "Found IP range for \"%s\" via TCP %d.%d.%d.%d",
                         net->ssid.c_str(), net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                         net->ipdata.range_ip[2], net->ipdata.range_ip[3]);

                net->ipdata.atype = address_tcp;

                bssid_ip_map[net->bssid] = net->ipdata;
                net->ipdata.load_from_store = 0;

                ret = TRACKER_NOTICE;
            }
        }
    }
#endif
}

int Packetracker::WriteNetworks(string in_fname) {
    string fname_temp = in_fname + ".temp";

    FILE *netfile;

    if ((netfile = fopen(in_fname.c_str(), "w+")) == NULL) {
        snprintf(errstr, 1024, "Could not open %s for writing: %s", in_fname.c_str(),
                 strerror(errno));
        return -1;
    }

    fclose(netfile);

    if (unlink(fname_temp.c_str()) == -1) {
        if (errno != ENOENT) {
            snprintf(errstr, 1024, "Could not unlink temp file %s: %s", fname_temp.c_str(),
                     strerror(errno));
            return -1;
        }
    }

    if ((netfile = fopen(fname_temp.c_str(), "w")) == NULL) {
        snprintf(errstr, 1024, "Could not open %s for writing even though we could unlink it: %s",
                 fname_temp.c_str(), strerror(errno));
        return -1;
    }

    /*
     fseek(in_file, 0L, SEEK_SET);
     ftruncate(fileno(in_file), 0);
     */

    int netnum = 1;
    vector<wireless_network *> bssid_vec;

    // Convert the map to a vector and sort it
    for (map<mac_addr, wireless_network *>::const_iterator i = bssid_map.begin();
         i != bssid_map.end(); ++i)
        bssid_vec.push_back(i->second);

    sort(bssid_vec.begin(), bssid_vec.end(), SortFirstTimeLT());

    for (unsigned int i = 0; i < bssid_vec.size(); i++) {
        wireless_network *net = bssid_vec[i];

        char lt[25];
        char ft[25];

        snprintf(lt, 25, "%s", ctime(&net->last_time));
        snprintf(ft, 25, "%s", ctime(&net->first_time));

        char type[15];

        if (net->type == network_ap)
            snprintf(type, 15, "infrastructure");
        else if (net->type == network_adhoc)
            snprintf(type, 15, "ad-hoc");
        else if (net->type == network_probe)
            snprintf(type, 15, "probe");
        else if (net->type == network_data)
            snprintf(type, 15, "data");
        else if (net->type == network_lor)
            snprintf(type, 15, "lucent");
        else
            snprintf(type, 15, "unknown");


        fprintf(netfile, "Network %d: \"%s\" BSSID: \"%s\"\n"
                "    Type     : %s\n"
                "    Info     : \"%s\"\n"
                "    Channel  : %02d\n"
                "    WEP      : \"%s\"\n"
                "    Maxrate  : %2.1f\n"
                "    LLC      : %d\n"
                "    Data     : %d\n"
                "    Crypt    : %d\n"
                "    Weak     : %d\n"
                "    Total    : %d\n"
                "    First    : \"%s\"\n"
                "    Last     : \"%s\"\n",
                netnum,
                net->ssid.c_str(), net->bssid.Mac2String().c_str(), type,
                net->beacon_info == "" ? "None" : net->beacon_info.c_str(),
                net->channel, net->wep ? "Yes" : "No",
                net->maxrate,
                net->llc_packets, net->data_packets,
                net->crypt_packets, net->interesting_packets,
                (net->llc_packets + net->data_packets),
                ft, lt);

        if (net->gps_fixed != -1)
            fprintf(netfile,
                    "    Min Loc: Lat %f Lon %f Alt %f Spd %f\n"
                    "    Max Loc: Lat %f Lon %f Alt %f Spd %f\n",
                    net->min_lat, net->min_lon,
                    metric ? net->min_alt / 3.3 : net->min_alt,
                    metric ? net->min_spd * 1.6093 : net->min_spd,
                    net->max_lat, net->max_lon,
                    metric ? net->max_alt / 3.3 : net->max_alt,
                    metric ? net->max_spd * 1.6093 : net->max_spd);

        if (net->ipdata.atype == address_dhcp)
            fprintf(netfile, "    Address found via DHCP %d.%d.%d.%d \n",
                    net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                    net->ipdata.range_ip[2], net->ipdata.range_ip[3]
                   );
        else if (net->ipdata.atype == address_arp)
            fprintf(netfile, "    Address found via ARP %d.%d.%d.%d\n",
                    net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                    net->ipdata.range_ip[2], net->ipdata.range_ip[3]);
        else if (net->ipdata.atype == address_udp)
            fprintf(netfile, "    Address found via UDP %d.%d.%d.%d\n",
                    net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                    net->ipdata.range_ip[2], net->ipdata.range_ip[3]);
        else if (net->ipdata.atype == address_tcp)
            fprintf(netfile, "    Address found via TCP %d.%d.%d.%d\n",
                    net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                    net->ipdata.range_ip[2], net->ipdata.range_ip[3]);
        fprintf(netfile, "\n");
        netnum++;
    }

    fclose(netfile);

    if (unlink(in_fname.c_str()) == -1) {
        if (errno != ENOENT) {
            snprintf(errstr, 1024, "Unable to unlink %s even though we could write to it: %s",
                     in_fname.c_str(), strerror(errno));
            return -1;
        }
    }

    if (rename(fname_temp.c_str(), in_fname.c_str()) == -1) {
        snprintf(errstr, 1024, "Unable to rename %s to %s: %s", fname_temp.c_str(), in_fname.c_str(),
                 strerror(errno));
        return -1;
    }

    return 1;
}

// Write out the cisco information
int Packetracker::WriteCisco(string in_fname) {
    string fname_temp = in_fname + ".temp";

    FILE *netfile;

    if ((netfile = fopen(in_fname.c_str(), "w+")) == NULL) {
        snprintf(errstr, 1024, "Could not open %s for writing: %s", in_fname.c_str(),
                 strerror(errno));
        return -1;
    }

    fclose(netfile);

    if (unlink(fname_temp.c_str()) == -1) {
        if (errno != ENOENT) {
            snprintf(errstr, 1024, "Could not unlink temp file %s: %s", fname_temp.c_str(),
                     strerror(errno));
            return -1;
        }
    }

    if ((netfile = fopen(fname_temp.c_str(), "w")) == NULL) {
        snprintf(errstr, 1024, "Could not open %s for writing even though we could unlink it: %s",
                 fname_temp.c_str(), strerror(errno));
        return -1;
    }

    /*
    fseek(in_file, 0L, SEEK_SET);
    ftruncate(fileno(in_file), 0);
    */

    vector<wireless_network *> bssid_vec;

    // Convert the map to a vector and sort it
    for (map<mac_addr, wireless_network *>::const_iterator i = bssid_map.begin();
         i != bssid_map.end(); ++i)
        bssid_vec.push_back(i->second);

    sort(bssid_vec.begin(), bssid_vec.end(), SortFirstTimeLT());

    for (unsigned int i = 0; i < bssid_vec.size(); i++) {
        wireless_network *net = bssid_vec[i];

        if (net->cisco_equip.size() == 0)
            continue;


        fprintf(netfile, "Network: \"%s\" BSSID: \"%s\"\n",
                net->ssid.c_str(), net->bssid.Mac2String().c_str());

        int devnum = 1;
        for (map<string, cdp_packet>::const_iterator x = net->cisco_equip.begin();
             x != net->cisco_equip.end(); ++x) {
            cdp_packet cdp = x->second;

            fprintf(netfile, "CDP Broadcast Device %d\n", devnum);
            fprintf(netfile, "    Device ID : %s\n", cdp.dev_id);
            fprintf(netfile, "    Capability: %s%s%s%s%s%s%s\n",
                    cdp.cap.level1 ? "Level 1 " : "" ,
                    cdp.cap.igmp_forward ? "IGMP forwarding " : "",
                    cdp.cap.nlp ? "Network-layer protocols " : "",
                    cdp.cap.level2_switching ? "Level 2 switching " : "",
                    cdp.cap.level2_sourceroute ? "Level 2 source-route bridging " : "",
                    cdp.cap.level2_transparent ? "Level 2 transparent bridging " : "",
                    cdp.cap.level3 ? "Level 3 routing " : "");
            fprintf(netfile, "    Interface : %s\n", cdp.interface);
            fprintf(netfile, "    IP        : %d.%d.%d.%d\n",
                    cdp.ip[0], cdp.ip[1], cdp.ip[2], cdp.ip[3]);
            fprintf(netfile, "    Platform  : %s\n", cdp.platform);
            fprintf(netfile, "    Software  : %s\n", cdp.software);
            fprintf(netfile, "\n");
            devnum++;
        } // cdp
    } // net

    fclose(netfile);

    if (unlink(in_fname.c_str()) == -1) {
        if (errno != ENOENT) {
            snprintf(errstr, 1024, "Unable to unlink %s even though we could write to it: %s",
                     in_fname.c_str(), strerror(errno));
            return -1;
        }
    }

    if (rename(fname_temp.c_str(), in_fname.c_str()) == -1) {
        snprintf(errstr, 1024, "Unable to rename %s to %s: %s", fname_temp.c_str(), in_fname.c_str(),
                 strerror(errno));
        return -1;
    }

    return 1;
}

// Sanitize data not to contain ';'.
string Packetracker::SanitizeCSV(string in_data) {
    string ret;

    for (unsigned int x = 0; x < in_data.length(); x++) {
        if (in_data[x] == ';')
            ret += ' ';
        else
            ret += in_data[x];
    }

    return ret;
}

/* CSV support 
 * Author: Reyk Floeter <reyk@synack.de>
 * Date:   2002/03/13
 */
int Packetracker::WriteCSVNetworks(string in_fname) {

    string fname_temp = in_fname + ".temp";

    FILE *netfile;

    if ((netfile = fopen(in_fname.c_str(), "w+")) == NULL) {
        snprintf(errstr, 1024, "Could not open %s for writing: %s", in_fname.c_str(),
                 strerror(errno));
        return -1;
    }

    fclose(netfile);

    if (unlink(fname_temp.c_str()) == -1) {
        if (errno != ENOENT) {
            snprintf(errstr, 1024, "Could not unlink temp file %s: %s", fname_temp.c_str(),
                     strerror(errno));
            return -1;
        }
    }

    if ((netfile = fopen(fname_temp.c_str(), "w")) == NULL) {
        snprintf(errstr, 1024, "Could not open %s for writing even though we could unlink it: %s",
                 fname_temp.c_str(), strerror(errno));
        return -1;
    }

    /*
    fseek(in_file, 0L, SEEK_SET);
    ftruncate(fileno(in_file), 0);
    */

    int netnum = 1;
    vector<wireless_network *> bssid_vec;

    // Convert the map to a vector and sort it
    for (map<mac_addr, wireless_network *>::const_iterator i = bssid_map.begin();
         i != bssid_map.end(); ++i)
        bssid_vec.push_back(i->second);

    sort(bssid_vec.begin(), bssid_vec.end(), SortFirstTimeLT());

    fprintf(netfile, "Network;NetType;ESSID;BSSID;Info;Channel;Maxrate;WEP;LLC;Data;Crypt;Weak;Total;"
			"First;Last;BestQuality;BestSignal;BestNoise;"
            "GPSMinLat;GPSMinLon;GPSMinAlt;GPSMinSpd;"
            "GPSMaxLat;GPSMaxLon;GPSMaxAlt;GPSMaxSpd;"
            "DHCP;ARP;UDP;TCP;\r\n");

    for (unsigned int i = 0; i < bssid_vec.size(); i++) {
        wireless_network *net = bssid_vec[i];

        char lt[25];
        char ft[25];

        snprintf(lt, 25, "%s", ctime(&net->last_time));
        snprintf(ft, 25, "%s", ctime(&net->first_time));

        char type[15];
        if (net->type == network_ap)
            snprintf(type, 15, "infrastructure");
        else if (net->type == network_adhoc)
            snprintf(type, 15, "ad-hoc");
        else if (net->type == network_probe)
            snprintf(type, 15, "probe");
        else if (net->type == network_data)
            snprintf(type, 15, "data");
        else if (net->type == network_lor)
            snprintf(type, 15, "lucent");
        else
            snprintf(type, 15, "unknown");


        fprintf(netfile, "%d;%s;%s;%s;%s;%02d;%2.1f;%s;%d;%d;%d;%d;%d;%s;%s;%d;%d;%d;",
                netnum, type,
                SanitizeCSV(net->ssid).c_str(), net->bssid.Mac2String().c_str(),
                net->beacon_info == "" ? "None" : SanitizeCSV(net->beacon_info).c_str(),
                net->channel, 
                net->maxrate,
                net->wep ? "Yes" : "No",
                net->llc_packets, net->data_packets,
                net->crypt_packets, net->interesting_packets,
                (net->llc_packets + net->data_packets),
                ft, lt,
                net->best_quality, net->best_signal, net->best_noise);

        if (net->gps_fixed != -1) {
            fprintf(netfile,
                    "%f;%f;%f;%f;"
                    "%f;%f;%f;%f;",
                    net->min_lat, net->min_lon,
                    metric ? net->min_alt / 3.3 : net->min_alt,
                    metric ? net->min_spd * 1.6093 : net->min_spd,
                    net->max_lat, net->max_lon,
                    metric ? net->max_alt / 3.3 : net->max_alt,
                    metric ? net->max_spd * 1.6093 : net->max_spd);
        } else {
            fprintf(netfile, ";;;;;;;;");
        }

        if (net->ipdata.atype == address_dhcp)
            fprintf(netfile, "%d.%d.%d.%d;;;;\r\n",
                    net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                    net->ipdata.range_ip[2], net->ipdata.range_ip[3]
                   );
        else if (net->ipdata.atype == address_arp)
            fprintf(netfile, ";;;%d.%d.%d.%d;;;\r\n",
                    net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                    net->ipdata.range_ip[2], net->ipdata.range_ip[3]);
        else if (net->ipdata.atype == address_udp)
            fprintf(netfile, ";;;;%d.%d.%d.%d;;\r\n",
                    net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                    net->ipdata.range_ip[2], net->ipdata.range_ip[3]);
        else if (net->ipdata.atype == address_tcp)
            fprintf(netfile, ";;;;;%d.%d.%d.%d;\r\n",
                    net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                    net->ipdata.range_ip[2], net->ipdata.range_ip[3]);
        else
            fprintf(netfile, ";;;;;;\r\n");
        netnum++;
    }

    fclose(netfile);

    if (unlink(in_fname.c_str()) == -1) {
        if (errno != ENOENT) {
            snprintf(errstr, 1024, "Unable to unlink %s even though we could write to it: %s",
                     in_fname.c_str(), strerror(errno));
            return -1;
        }
    }

    if (rename(fname_temp.c_str(), in_fname.c_str()) == -1) {
        snprintf(errstr, 1024, "Unable to rename %s to %s: %s", fname_temp.c_str(), in_fname.c_str(),
                 strerror(errno));
        return -1;
    }

    return 1;
}

string Packetracker::SanitizeXML(string in_data) {
    string ret;

    for (unsigned int x = 0; x < in_data.length(); x++) {
        if (in_data[x] == '&')
            ret += "&amp;";
        else if (in_data[x] == '<')
            ret += "&lt;";
        else if (in_data[x] == '>')
            ret += "&gt;";
        else
            ret += in_data[x];
    }

    return ret;
}

// Write an XML-formatted output conforming to our DTD at
// http://kismetwireless.net/kismet-1.0.dtd
int Packetracker::WriteXMLNetworks(string in_fname) {
    string fname_temp = in_fname + ".temp";

    FILE *netfile;

    if ((netfile = fopen(in_fname.c_str(), "w+")) == NULL) {
        snprintf(errstr, 1024, "Could not open %s for writing: %s", in_fname.c_str(),
                 strerror(errno));
        return -1;
    }

    fclose(netfile);

    if (unlink(fname_temp.c_str()) == -1) {
        if (errno != ENOENT) {
            snprintf(errstr, 1024, "Could not unlink temp file %s: %s", fname_temp.c_str(),
                     strerror(errno));
            return -1;
        }
    }

    if ((netfile = fopen(fname_temp.c_str(), "w")) == NULL) {
        snprintf(errstr, 1024, "Could not open %s for writing even though we could unlink it: %s",
                 fname_temp.c_str(), strerror(errno));
        return -1;
    }

    /*
    fseek(in_file, 0L, SEEK_SET);
    ftruncate(fileno(in_file), 0);
    */

    int netnum = 1;
    vector<wireless_network *> bssid_vec;

    fprintf(netfile, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");
    fprintf(netfile, "<!DOCTYPE detection-run SYSTEM \"http://kismetwireless.net/kismet-1.5.dtd\">\n");

    fprintf(netfile, "\n\n");

    char lt[25];
    char ft[25];

    snprintf(ft, 25, "%s", ctime(&start_time));
    time_t cur_time = time(0);
    snprintf(lt, 25, "%s", ctime(&cur_time));

    fprintf(netfile, "<detection-run kismet-version=\"%d.%d.%d\" start-time=\"%s\" end-time=\"%s\">\n",
            VERSION_MAJOR, VERSION_MINOR, VERSION_TINY, ft, lt);

    // Convert the map to a vector and sort it
    for (map<mac_addr, wireless_network *>::const_iterator i = bssid_map.begin();
         i != bssid_map.end(); ++i)
        bssid_vec.push_back(i->second);

    sort(bssid_vec.begin(), bssid_vec.end(), SortFirstTimeLT());

    for (unsigned int i = 0; i < bssid_vec.size(); i++) {
        wireless_network *net = bssid_vec[i];

        snprintf(lt, 25, "%s", ctime(&net->last_time));
        snprintf(ft, 25, "%s", ctime(&net->first_time));
        char type[15];

        if (net->type == network_ap)
            snprintf(type, 15, "infrastructure");
        else if (net->type == network_adhoc)
            snprintf(type, 15, "ad-hoc");
        else if (net->type == network_probe)
            snprintf(type, 15, "probe");
        else if (net->type == network_data)
            snprintf(type, 15, "data");
        else if (net->type == network_lor)
            snprintf(type, 15, "lucent");
        else
            snprintf(type, 15, "unknown");

        fprintf(netfile, "  <wireless-network number=\"%d\" type=\"%s\" wep=\"%s\" cloaked=\"%s\" first-time=\"%s\" last-time=\"%s\">\n",
                netnum, type, net->wep ? "true" : "false", net->cloaked ? "true" : "false",
                ft, lt);

        if (net->ssid != NOSSID)
            fprintf(netfile, "    <SSID>%s</SSID>\n", SanitizeXML(net->ssid).c_str());

        fprintf(netfile, "    <BSSID>%s</BSSID>\n", net->bssid.Mac2String().c_str());
        if (net->beacon_info != "")
            fprintf(netfile, "    <info>%s</info>\n", SanitizeXML(net->beacon_info).c_str());
        fprintf(netfile, "    <channel>%d</channel>\n", net->channel);
        fprintf(netfile, "    <maxrate>%2.1f</maxrate>\n", net->maxrate);
        fprintf(netfile, "    <packets>\n");
        fprintf(netfile, "      <LLC>%d</LLC>\n", net->llc_packets);
        fprintf(netfile, "      <data>%d</data>\n", net->data_packets);
        fprintf(netfile, "      <crypt>%d</crypt>\n", net->crypt_packets);
        fprintf(netfile, "      <weak>%d</weak>\n", net->interesting_packets);
        fprintf(netfile, "      <total>%d</total>\n",
                (net->llc_packets + net->data_packets));
        fprintf(netfile, "    </packets>\n");

        if (net->gps_fixed != -1) {
            fprintf(netfile, "    <gps-info unit=\"%s\">\n", metric ? "metric" : "english");
            fprintf(netfile, "      <min-lat>%f</min-lat>\n", net->min_lat);
            fprintf(netfile, "      <min-lon>%f</min-lon>\n", net->min_lon);
            fprintf(netfile, "      <min-alt>%f</min-alt>\n",
                    metric ? net->min_alt / 3.3 : net->min_alt);
            fprintf(netfile, "      <min-spd>%f</min-spd>\n",
                    metric ? net->min_alt * 1.6093 : net->min_spd);
            fprintf(netfile, "      <max-lat>%f</max-lat>\n", net->max_lat);
            fprintf(netfile, "      <max-lon>%f</max-lon>\n", net->max_lon);
            fprintf(netfile, "      <max-alt>%f</max-alt>\n",
                    metric ? net->max_alt / 3.3 : net->max_alt);
            fprintf(netfile, "      <max-spd>%f</max-spd>\n",
                    metric ? net->max_spd * 1.6093 : net->max_spd);
            fprintf(netfile, "    </gps-info>\n");
        }

        if (net->ipdata.atype > address_factory) {
            char *addrtype;
            switch (net->ipdata.atype) {
            case address_dhcp:
                addrtype = "dhcp";
                break;
            case address_arp:
                addrtype = "arp";
                break;
            case address_udp:
                addrtype = "udp";
                break;
            case address_tcp:
                addrtype = "tcp";
                break;
            default:
                addrtype = "unknown";
                break;
            }

            fprintf(netfile, "    <ip-address type=\"%s\">\n", addrtype);
            fprintf(netfile, "      <ip-range>%d.%d.%d.%d</ip-range>\n",
                    net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                    net->ipdata.range_ip[2], net->ipdata.range_ip[3]);
            fprintf(netfile, "    </ip-address>\n");
        }
        netnum++;

        if (net->cisco_equip.size() == 0) {
        	fprintf(netfile, "  </wireless-network>\n");
            continue;
		}

        int devnum = 1;
        for (map<string, cdp_packet>::const_iterator x = net->cisco_equip.begin();
             x != net->cisco_equip.end(); ++x) {
            cdp_packet cdp = x->second;

            fprintf(netfile, "    <cisco number=\"%d\">\n", devnum);
            fprintf(netfile, "      <cdp-device-id>%s</cdp-device-id>\n",
                    cdp.dev_id);
            fprintf(netfile, "      <cdp-capability level1=\"%s\" igmp-forward=\"%s\" netlayer=\"%s\" "
                    "level2-switching=\"%s\" level2-sourceroute=\"%s\" level2-transparent=\"%s\" "
                    "level3-routing=\"%s\"/>\n",
                    cdp.cap.level1 ? "true" : "false",
                    cdp.cap.igmp_forward ? "true" : "false",
                    cdp.cap.nlp ? "true" : "false",
                    cdp.cap.level2_switching ? "true" : "false",
                    cdp.cap.level2_sourceroute ? "true" : "false",
                    cdp.cap.level2_transparent ? "true" : "false",
                    cdp.cap.level3 ? "true" : "false");
            fprintf(netfile, "      <cdp-interface>%s</cdp-interface>\n", cdp.interface);
            fprintf(netfile, "      <cdp-ip>%d.%d.%d.%d</cdp-ip>\n",
                    cdp.ip[0], cdp.ip[1], cdp.ip[2], cdp.ip[3]);
            fprintf(netfile, "      <cdp-platform>%s</cdp-platform>\n", cdp.platform);
            fprintf(netfile, "      <cdp-software>%s</cdp-software>\n", cdp.software);
            fprintf(netfile, "    </cisco>\n");
            devnum++;
        } // cdp

        fprintf(netfile, "  </wireless-network>\n");

    } // net

    fprintf(netfile, "</detection-run>\n");

    fclose(netfile);

    if (unlink(in_fname.c_str()) == -1) {
        if (errno != ENOENT) {
            snprintf(errstr, 1024, "Unable to unlink %s even though we could write to it: %s",
                     in_fname.c_str(), strerror(errno));
            return -1;
        }
    }

    if (rename(fname_temp.c_str(), in_fname.c_str()) == -1) {
        snprintf(errstr, 1024, "Unable to rename %s to %s: %s", fname_temp.c_str(), in_fname.c_str(),
                 strerror(errno));
        return -1;
    }

    return 1;
}

void Packetracker::ReadSSIDMap(FILE *in_file) {
    char dline[8192];
    mac_addr bssid;
    char name[1024];
    char bssid_str[18];

    while (!feof(in_file)) {
        fgets(dline, 8192, in_file);

        if (feof(in_file)) break;

        if (sscanf(dline, "%17s %1024[^\n]\n",
                   bssid_str, name) < 2)
            continue;

        bssid = bssid_str;

        bssid_cloak_map[bssid] = name;

    }

    return;
}

void Packetracker::WriteSSIDMap(FILE *in_file) {
    fseek(in_file, 0L, SEEK_SET);
    ftruncate(fileno(in_file), 0);

    char format[64];
    snprintf(format, 64, "%%.%ds %%.%ds\n", MAC_STR_LEN, SSID_SIZE);

    for (map<mac_addr, string>::iterator x = bssid_cloak_map.begin();
         x != bssid_cloak_map.end(); ++x) {

        // Find us in the map - if we don't have a current record, we get written out,
        // if we do have a current record and it's not something we like, we don't get
        // written out
        map<mac_addr, wireless_network *>::iterator wnitr = bssid_map.find(x->first);
        if (wnitr != bssid_map.end())
            if (wnitr->second->type != network_ap && wnitr->second->type != network_data)
                continue;

        fprintf(in_file, format, x->first.Mac2String().c_str(), x->second.c_str());
    }

    return;
}

void Packetracker::ReadIPMap(FILE *in_file) {
    char dline[8192];
    mac_addr bssid;
    char bssid_str[18];

    net_ip_data dat;

    while (!feof(in_file)) {
        fgets(dline, 8192, in_file);

        if (feof(in_file)) break;

        memset(&dat, 0, sizeof(net_ip_data));

        short int range[4];
        /*
         , mask[4], gate[4];
         */

        // Fetch the line and continue if we're invalid...
        if (sscanf(dline, "%17s %d %d %hd %hd %hd %hd",
                   bssid_str,
                   (int *) &dat.atype, &dat.octets,
                   &range[0], &range[1], &range[2], &range[3]
                  ) < 15)
            continue;

        for (int x = 0; x < 4; x++) {
            dat.range_ip[x] = (uint8_t) range[x];
        }

        dat.load_from_store = 1;

        bssid = bssid_str;

        memcpy(&bssid_ip_map[bssid], &dat, sizeof(net_ip_data));
    }

    return;

}

void Packetracker::WriteIPMap(FILE *in_file) {
    fseek(in_file, 0L, SEEK_SET);
    ftruncate(fileno(in_file), 0);

    for (map<mac_addr, net_ip_data>::iterator x = bssid_ip_map.begin();
         x != bssid_ip_map.end(); ++x) {

        if (x->second.atype <= address_factory || x->second.octets == 0)
            continue;

        fprintf(in_file, "%s %d %d %hd %hd %hd %hd\n",
                x->first.Mac2String().c_str(),
                x->second.atype, x->second.octets,
                x->second.range_ip[0], x->second.range_ip[1],
                x->second.range_ip[2], x->second.range_ip[3]
               );
    }

    return;
}

// These are just dropthroughs to the manuf stuff
void Packetracker::ReadAPManufMap(FILE *in_file) {
    ap_manuf_map = ReadManufMap(in_file, 1);
}

void Packetracker::ReadClientManufMap(FILE *in_file) {
    client_manuf_map = ReadManufMap(in_file, 0);
}

void Packetracker::RemoveNetwork(mac_addr in_bssid) {
    for (unsigned int x = 0; x < network_list.size(); x++) {
        if (network_list[x]->bssid == in_bssid) {
            network_list.erase(network_list.begin() + x);
            break;
        }
    }

}

// Write a gpsdrive compatable waypoint file
int Packetracker::WriteGpsdriveWaypt(FILE *in_file) {
    fseek(in_file, 0L, SEEK_SET);
    ftruncate(fileno(in_file), 0);

    // Convert the map to a vector and sort it
    for (map<mac_addr, wireless_network *>::const_iterator i = bssid_map.begin();
         i != bssid_map.end(); ++i) {
        wireless_network *net = i->second;

        float lat, lon;
        lat = (net->min_lat + net->max_lat) / 2;
        lon = (net->min_lon + net->max_lon) / 2;
        fprintf(in_file, "%s\t%f  %f\n", net->bssid.Mac2String().c_str(), lat, lon);
    }

    fflush(in_file);

    return 1;
}

string Packetracker::Packet2String(const packet_info *in_info) {
    char ret[2048];
    string rets;

    // type, encrypted, weak, beacon, source, dest, bssid
    snprintf(ret, 2048, "%d %d %d %d %d %s %s %s \001%s\001 ",
             in_info->type, (int) in_info->time, in_info->encrypted,
             in_info->interesting, in_info->beacon,
             in_info->source_mac.Mac2String().c_str(),
             in_info->dest_mac.Mac2String().c_str(),
             in_info->bssid_mac.Mac2String().c_str(),
             strlen(in_info->ssid) == 0 ? " " : in_info->ssid);
    rets += ret;

    if (in_info->proto.type != proto_unknown) {
        // type source dest sport dport
        uint8_t dip[4];
        if (in_info->proto.type == proto_arp)
            memcpy(dip, in_info->proto.misc_ip, 4);
        else
            memcpy(dip, in_info->proto.dest_ip, 4);

        snprintf(ret, 2048, "%d %d.%d.%d.%d %d.%d.%d.%d %d %d %d \001%s\001\n",
                 in_info->proto.type,
                 in_info->proto.source_ip[0], in_info->proto.source_ip[1],
                 in_info->proto.source_ip[2], in_info->proto.source_ip[3],
                 dip[0], dip[1], dip[2], dip[3],
                 in_info->proto.sport, in_info->proto.dport,
                 in_info->proto.nbtype,
                 strlen(in_info->proto.netbios_source) == 0 ? " " : in_info->proto.netbios_source);
    } else {
        snprintf(ret, 2048, "0 0.0.0.0 0.0.0.0 0 0 0 \001 \001\n");
    }

    rets += ret;

    return rets;
}
