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
#include "server_globals.h"
#include "kismet_server.h"
#include "packetsignatures.h"

// Aref array indexes
#define NETSTUMBLER_AREF   0
#define DEAUTHFLOOD_AREF   1
#define LUCENTTEST_AREF    2
#define WELLENREITER_AREF  3
#define CHANCHANGE_AREF    4
#define BCASTDISCON_AREF   5
#define AIRJACKSSID_AREF   6
#define NULLPROBERESP_AREF 7
#define MAX_AREF           8

Packetracker::Packetracker() {
    alertracker = NULL;

    num_networks = num_packets = num_dropped = num_noise =
        num_crypt = num_interesting = num_cisco = 0;

    errstr[0] = '\0';

    filter_export_bssid = filter_export_source = filter_export_dest = NULL;

    filter_export_bssid_invert = filter_export_source_invert = filter_export_dest_invert = NULL;

    filter_export = 0;

    arefs = new int[MAX_AREF];
    for (unsigned int ref = 0; ref < MAX_AREF; ref++)
        arefs[ref] = -1;

}

Packetracker::~Packetracker() {
    for (unsigned int x = 0; x < network_list.size(); x++) {
        for (unsigned int y = 0; y < network_list[x]->client_vec.size(); y++)
            delete network_list[x]->client_vec[y];
        delete network_list[x];
    }

    delete[] arefs;
}

vector<wireless_network *> Packetracker::FetchNetworks() {
    vector<wireless_network *> ret_vec = network_list;

    return ret_vec;
}


void Packetracker::AddAlertracker(Alertracker *in_tracker) {
    alertracker = in_tracker;
}

int Packetracker::EnableAlert(string in_alname, alert_time_unit in_unit,
                              int in_rate, int in_burstrate) {
    if (alertracker == NULL) {
        snprintf(errstr, 1024, "No registered alert tracker.");
        return -1;
    }

    int ret = -1;

    string lname = StrLower(in_alname);
    if (lname == "netstumbler") {
        // register netstumbler alert
        ret = arefs[NETSTUMBLER_AREF] = alertracker->RegisterAlert("NETSTUMBLER", in_unit, in_rate, in_burstrate);
    } else if (lname == "deauthflood") {
        // register deauth flood
        ret = arefs[DEAUTHFLOOD_AREF] = alertracker->RegisterAlert("DEAUTHFLOOD", in_unit, in_rate, in_burstrate);
    } else if (lname == "lucenttest") {
        // register lucent test
        ret = arefs[LUCENTTEST_AREF] = alertracker->RegisterAlert("LUCENTTEST", in_unit, in_rate, in_burstrate);
    } else if (lname == "wellenreiter") {
        // register wellenreiter test
        ret = arefs[WELLENREITER_AREF] = alertracker->RegisterAlert("WELLENREITER", in_unit, in_rate, in_burstrate);
    } else if (lname == "chanchange") {
        // register channel changing
        ret = arefs[CHANCHANGE_AREF] = alertracker->RegisterAlert("CHANCHANGE", in_unit, in_rate, in_burstrate);
    } else if (lname == "bcastdiscon") {
        // Register broadcast disconnect
        ret = arefs[BCASTDISCON_AREF] = alertracker->RegisterAlert("BCASTDISCON", in_unit, in_rate, in_burstrate);
    } else if (lname == "airjackssid") {
        // Register airjack SSID alert
        ret = arefs[AIRJACKSSID_AREF] = alertracker->RegisterAlert("AIRJACKSSID", in_unit, in_rate, in_burstrate);
    } else if (lname == "nullproberesp") {
        // Register 0-len probe response alert
        ret = arefs[NULLPROBERESP_AREF] = alertracker->RegisterAlert("NULLPROBERESP", in_unit, in_rate, in_burstrate);
    } else if (lname == "probenojoin") {
        ProbeNoJoinAutomata *pnja = new ProbeNoJoinAutomata(this, alertracker, in_unit, in_rate, in_burstrate);
        fsa_vec.push_back(pnja);
        ret = pnja->FetchAlertRef();
    } else if (lname == "disassoctraffic") {
        DisassocTrafficAutomata *dta = new DisassocTrafficAutomata(this, alertracker, in_unit, in_rate, in_burstrate);
        fsa_vec.push_back(dta);
        ret = dta->FetchAlertRef();
    } else {
        snprintf(errstr, 1024, "Unknown alert type %s, not processing.", lname.c_str());
        return 0;
    }

    if (ret == -1)
        snprintf(errstr, 1024, "Alert '%s' already processed, duplicate.", in_alname.c_str());

    return ret;
}

void Packetracker::AddExportFilters(macmap<int> *bssid_map,
                                    macmap<int> *source_map,
                                    macmap<int> *dest_map, int *bssid_invert,
                                    int *source_invert, int *dest_invert) {
    filter_export = 1;
    filter_export_bssid = bssid_map;
    filter_export_bssid_invert = bssid_invert;
    filter_export_source = source_map;
    filter_export_source_invert = source_invert;
    filter_export_dest = dest_map;
    filter_export_dest_invert = dest_invert;
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

wireless_network *Packetracker::MatchNetwork(const packet_info *info) {
    map<mac_addr, wireless_network *>::iterator bsmapitr;

    bsmapitr = bssid_map.find(info->bssid_mac);

    // If it's a broadcast (From and To DS == 1) try to match it to an existing network
    if ((info->type == packet_data && info->subtype == packet_sub_data) &&
        info->distrib == inter_distribution && bsmapitr == bssid_map.end()) {

        if ((bsmapitr = bssid_map.find(info->source_mac)) != bssid_map.end()) {
            // info->bssid_mac = info->source_mac;
            bsmapitr = bssid_map.find(info->source_mac);
        } else if ((bsmapitr = bssid_map.find(info->dest_mac)) != bssid_map.end()) {
            // info->bssid_mac = info->dest_mac;
            bsmapitr = bssid_map.find(info->dest_mac);
        }

    } else if (info->type == packet_management && 
               info->subtype == packet_sub_probe_req) {
        // If it's a probe request, see if we already know who it should belong to
        if (probe_map.find(info->bssid_mac) != probe_map.end()) {
            // info->bssid_mac = probe_map[info->bssid_mac];
            bsmapitr = bssid_map.find(probe_map[info->bssid_mac]);
        }
    }

    if (bsmapitr != bssid_map.end())
        return bsmapitr->second;

    return NULL;
}

wireless_client *Packetracker::CreateClient(const packet_info *info, 
                                            wireless_network *net) {

    map<mac_addr, wireless_client *>::iterator cmi;
    if ((cmi = net->client_map.find(info->source_mac)) != net->client_map.end())
        return cmi->second;
        
    wireless_client *client = new wireless_client;

    // Add it to the map
    net->client_map[info->source_mac] = client;
    // Add it to the vec
    net->client_vec.push_back(client);

    client->first_time = time(0);
    client->mac = info->source_mac;
    client->manuf_ref = MatchBestManuf(client_manuf_map, client->mac, "", 0, 0, 0,
                                       &client->manuf_score);

    client->metric = net->metric;

    if (info->gps_fix >= 2) {
        client->gps_fixed = info->gps_fix;
        client->min_lat = client->max_lat = info->gps_lat;
        client->min_lon = client->max_lon = info->gps_lon;
        client->min_alt = client->max_alt = info->gps_alt;
        client->min_spd = client->max_spd = info->gps_spd;

        client->aggregate_lat = info->gps_lat;
        client->aggregate_lon = info->gps_lon;
        client->aggregate_alt = info->gps_alt;
        client->aggregate_points = 1;
    }

    // Classify the client.  We'll call no-distrib packets (lucent)
    // inter-distrib clients since it's not an end-user bridge into the
    // network, it's a lucent AP talking to another one.
    if (info->distrib == from_distribution)
        client->type = client_fromds;
    else if (info->distrib == to_distribution)
        client->type = client_tods;
    else if (info->distrib == inter_distribution)
        client->type = client_interds;
    else if (info->distrib == no_distribution)
        client->type = client_interds;

    if (bssid_ip_map.find(info->source_mac) != bssid_ip_map.end()) {
        memcpy(&net->ipdata, &bssid_ip_map[info->source_mac], sizeof(net_ip_data));
    }

    KisLocalNewclient(client, net);

    return client;
}

void Packetracker::ProcessPacket(packet_info info) {
    wireless_network *net;
    char status[STATUS_MAX];
    int newnet = 0;

    // string bssid_mac;

    num_packets++;

    // Feed it through the finite state alert processors
    for (unsigned int x = 0; x < fsa_vec.size(); x++) {
        fsa_vec[x]->ProcessPacket(&info);
    }

    // Junk unknown, pure noise, and corrupt packets
    if (info.type == packet_noise || info.corrupt == 1) {
        num_dropped++;
        num_noise++;
        return;
    } else if (info.type == packet_unknown || info.type == packet_phy) {
        // If we didn't know what it was junk it
        // We unceremoniously junk phy layer packets for now too
        num_dropped++;
        return;
    }

    net = MatchNetwork(&info);

    // Find out if we have this network -- Every network that actually
    // gets added has a bssid, so we'll use that to search.  We've filtered
    // everything else out by this point so we're safe to just work off bssid
    if (net == NULL) {
        // Make a network for them
        net = new wireless_network;

        if (bssid_ip_map.find(info.bssid_mac) != bssid_ip_map.end()) {
            memcpy(&net->ipdata, &bssid_ip_map[info.bssid_mac], sizeof(net_ip_data));
        }

        if (info.type == packet_management && 
            (info.subtype == packet_sub_beacon ||
             info.subtype == packet_sub_probe_req ||
             info.subtype == packet_sub_probe_resp)) {

            if (info.subtype == packet_sub_probe_req)

            if (IsBlank(info.ssid)) {
                if (bssid_cloak_map.find(info.bssid_mac) != bssid_cloak_map.end()) {
                    net->ssid = bssid_cloak_map[info.bssid_mac];

                    // If it's a beacon and empty then we're cloaked and we found our
                    // ssid so fill it in
                    if (info.type == packet_management && 
                        info.subtype == packet_sub_beacon) {
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
        } else {
            net->ssid = NOSSID;
            net->cloaked = 0;
        }

        net->bssid = info.bssid_mac;

        net->channel = info.channel;


        if (info.type == packet_management && info.subtype == packet_sub_probe_req) {
            net->type = network_probe;
        } else if (info.distrib == adhoc_distribution) {
            net->type = network_adhoc;
        } else {
            net->type = network_ap;
        }

        net->wep = info.wep;

        net->beacon = info.beacon;

        //net->bssid = Mac2String(info.bssid_mac, ':');

        // Put us in the master list
        network_list.push_back(net);
        net->listed = 1;

        net->first_time = time(0);

        net->maxrate = info.maxrate;

        if (strlen(info.beacon_info) != 0)
            net->beacon_info = info.beacon_info;

        newnet = 1;

        if (net->type == network_probe) {
            snprintf(status, STATUS_MAX, "Found new probed network \"%s\" bssid %s",
                     net->ssid.c_str(), net->bssid.Mac2String().c_str());
            KisLocalStatus(status);
        } else {
            snprintf(status, STATUS_MAX, "Found new network \"%s\" bssid %s WEP %c Ch "
                     "%d @ %.2f mbit",
                     net->ssid.c_str(), net->bssid.Mac2String().c_str(), 
                     net->wep ? 'Y' : 'N',
                     net->channel, net->maxrate);
            KisLocalStatus(status);
        }

        // Do this after we process other stuff so that counts on one-packet networks
        // are correct
//        KisLocalNewnet(net);

        if (info.gps_fix >= 2) {
            net->gps_fixed = info.gps_fix;
            net->min_lat = net->max_lat = info.gps_lat;
            net->min_lon = net->max_lon = info.gps_lon;
            net->min_alt = net->max_alt = info.gps_alt;
            net->min_spd = net->max_spd = info.gps_spd;

            net->aggregate_lat = info.gps_lat;
            net->aggregate_lon = info.gps_lon;
            net->aggregate_alt = info.gps_alt;
            net->aggregate_points = 1;
        }

        // Find out what we can from what we know now...
        if (net->type != network_adhoc && net->type != network_probe) {
            net->manuf_ref = MatchBestManuf(ap_manuf_map, net->bssid, net->ssid, net->channel,
                                            net->wep, net->cloaked, &net->manuf_score);
            if (net->manuf_score == manuf_max_score)
                memcpy(&net->ipdata, &net->manuf_ref->ipdata, sizeof(net_ip_data));
        } else {
            net->manuf_ref = MatchBestManuf(client_manuf_map, net->bssid, net->ssid, net->channel,
                                            net->wep, net->cloaked, &net->manuf_score);
        }

        num_networks++;

        // And add us to the map
        bssid_map[net->bssid] = net;

    } else {
        if (net->listed == 0) {
            network_list.push_back(net);
            net->listed = 1;
        }
    }

    net->last_time = time(0);

    // update the sequence for the owner of the bssid
    if (info.source_mac == net->bssid)
        net->last_sequence = info.sequence_number;

    if (info.quality >= 0 && info.signal >= 0) {
        net->quality = info.quality;
        if (info.quality > net->best_quality)
            net->best_quality = info.quality;
        net->signal = info.signal;

        if (info.signal > net->best_signal) {
            net->best_signal = info.signal;
            if (info.gps_fix >= 2) {
                net->best_lat = info.gps_lat;
                net->best_lon = info.gps_lon;
                net->best_alt = info.gps_alt;
            }
        }

        net->noise = info.noise;
        if ((info.noise < net->best_noise && info.noise != 0) || net->best_noise == 0)
            net->best_noise = info.noise;
    }

    if (info.gps_fix >= 2) {
        // Don't aggregate slow-moving packets to prevent average "pulling"..
        if (info.gps_spd <= 0.3) {
            net->aggregate_lat += info.gps_lat;
            net->aggregate_lon += info.gps_lon;
            net->aggregate_alt += info.gps_alt;
            net->aggregate_points += 1;
        }

        net->gps_fixed = info.gps_fix;

        if (info.gps_lat < net->min_lat || net->min_lat == -90)
            net->min_lat = info.gps_lat;
        if (info.gps_lat > net->max_lat || net->max_lat == 90)
            net->max_lat = info.gps_lat;

        if (info.gps_lon < net->min_lon || net->min_lon == -180)
            net->min_lon = info.gps_lon;
        if (info.gps_lon > net->max_lon || net->max_lon == 180)
            net->max_lon = info.gps_lon;

        if (info.gps_alt < net->min_alt || net->min_alt == 0)
            net->min_alt = info.gps_alt;
        if (info.gps_alt > net->max_alt || net->max_alt == 0)
            net->max_alt = info.gps_alt;

        if (info.gps_spd < net->min_spd || net->min_spd == 0)
            net->min_spd = info.gps_spd;
        if (info.gps_spd > net->max_spd || net->max_spd == 0)
            net->max_spd = info.gps_spd;

    } else {
        net->gps_fixed = 0;
    }

    // Handle the IV sets.  4-byte compare IV is fine
    if (info.encrypted) {
        map<uint32_t, int>::iterator ivitr = net->iv_map.find(info.ivset);
        if (ivitr != net->iv_map.end()) {
            ivitr->second++;
            net->dupeiv_packets++;
        } else {
            net->iv_map[info.ivset] = 1;
        }
    }

    // Assign the carrier types in this network.  There will likely be only one, but you
    // never know...
    net->carrier_set |= (1 << (int) info.carrier);

    // Assign the encoding types in this network, there can quite likely be more than
    // one...
    net->encoding_set |= (1 << (int) info.encoding);

    // Assign the highest seen datarate
    if (info.datarate > net->maxseenrate)
        net->maxseenrate = info.datarate;

    if (info.type == packet_management && info.subtype == packet_sub_beacon &&
        !strncmp(info.ssid, "AirJack", SSID_SIZE)) {
        if (alertracker->PotentialAlert(arefs[AIRJACKSSID_AREF])) {
            snprintf(status, STATUS_MAX, "Beacon for SSID 'AirJack' from %s",
                     info.source_mac.Mac2String().c_str());
            alertracker->RaiseAlert(arefs[AIRJACKSSID_AREF], status);
        }
    }

    if (info.type == packet_management &&
        (info.subtype == packet_sub_disassociation ||
         info.subtype == packet_sub_deauthentication) &&
        info.dest_mac == mac_addr("FF:FF:FF:FF:FF:FF")) {

        if (alertracker->PotentialAlert(arefs[BCASTDISCON_AREF]) > 0) {
            snprintf(status, STATUS_MAX, "Broadcast %s on %s",
                     info.subtype == packet_sub_disassociation ? "disassociation" : "deauthentication",
                     net->bssid.Mac2String().c_str());
            alertracker->RaiseAlert(arefs[BCASTDISCON_AREF], status);
        }

    }

    if ((info.type == packet_management) || (info.proto.type == proto_iapp)) {
        if (info.type == packet_management)
            net->llc_packets++;

        // If it's a probe request shortcut to handling it like a client once we've
        // established what network it belongs to
        if (info.subtype == packet_sub_probe_req && net->type == network_probe) {
            if (net->ssid != info.ssid) {
                if (IsBlank(info.ssid))
                    net->ssid = NOSSID;
                else
                    net->ssid = info.ssid;
            }

            if (probe_map.find(info.source_mac) != probe_map.end()) {
                ProcessDataPacket(info, net);
                if (newnet == 1)
                    KisLocalNewnet(net);
                return;
            }
        }

        if (info.subtype == packet_sub_beacon && strlen(info.beacon_info) != 0 &&
            IsBlank(net->beacon_info.c_str())) {
            net->beacon_info = info.beacon_info;
        }

        if (info.subtype == packet_sub_deauthentication ||
            info.subtype == packet_sub_disassociation) {
            net->client_disconnects++;

            if (net->client_disconnects > 10) {
                if (alertracker->PotentialAlert(arefs[DEAUTHFLOOD_AREF]) > 0) {
                    snprintf(status, STATUS_MAX, "Deauthenticate/Disassociate flood on %s",
                             net->bssid.Mac2String().c_str());
                    alertracker->RaiseAlert(arefs[DEAUTHFLOOD_AREF], status);
                }
            }
        }

        // Update the ssid record if we got a beacon for a data network
        if (info.subtype == packet_sub_beacon) {
            // If we have a beacon for an established AP network and it's not the
            // right channel, raise an alert.

            if (net->type == network_ap && info.channel != net->channel &&
                net->channel != 0 && info.channel != 0) {
                if (alertracker->PotentialAlert(arefs[CHANCHANGE_AREF]) > 0) {
                    snprintf(status, STATUS_MAX, "Beacon on %s (%s) for channel %d, network previously detected on channel %d",
                             net->bssid.Mac2String().c_str(), net->ssid.c_str(),
                             info.channel, net->channel);
                    alertracker->RaiseAlert(arefs[CHANCHANGE_AREF], status);
                }
            }

            // If we're updating the network record, update the manufacturer info -
            // if we just "became" an AP or if we've changed channel, we may have
            // changed state as well
            if (net->channel != info.channel || net->type != network_ap ||
                (net->ssid != info.ssid && !IsBlank(info.ssid))) {
                net->manuf_ref = MatchBestManuf(ap_manuf_map, net->bssid, info.ssid, info.channel,
                                                net->wep,net->cloaked, &net->manuf_score);
                // Update our IP range info too if we're a default
                if (net->manuf_score == manuf_max_score && net->ipdata.atype == address_none)
                    memcpy(&net->ipdata, &net->manuf_ref->ipdata, sizeof(net_ip_data));
            }

            if (net->ssid != info.ssid && !IsBlank(info.ssid)) {
                net->ssid = info.ssid;
                bssid_cloak_map[net->bssid] = info.ssid;

                snprintf(status, STATUS_MAX, "Found SSID \"%s\" for network BSSID %s",
                         net->ssid.c_str(), net->bssid.Mac2String().c_str());
                KisLocalStatus(status);
            }

            net->channel = info.channel;
            net->wep = info.wep;

            if (info.distrib != adhoc_distribution)
                net->type = network_ap;
        }

        // If it's a probe response with no SSID, something funny is happening, raise an alert
        if (info.subtype == packet_sub_probe_resp && info.ssid_len == 0) {
            if (alertracker->PotentialAlert(arefs[NULLPROBERESP_AREF]) > 0) {
                snprintf(status, STATUS_MAX, "Probe response with 0-length SSID detected from %s",
                         info.source_mac.Mac2String().c_str());
                alertracker->RaiseAlert(arefs[NULLPROBERESP_AREF], status);
            }
        }

        // If this is a probe response and the ssid we have is blank, update it.
        // With "closed" networks, this is our chance to see the real ssid.
        // (Thanks to Jason Luther <jason@ixid.net> for this "closed network" detection)
        if ((info.subtype == packet_sub_probe_resp ||
             info.subtype == packet_sub_reassociation_resp ||
	     info.proto.type == proto_iapp) && !IsBlank(info.ssid)) {

            if (net->ssid == NOSSID) {
                net->cloaked = 1;
                net->ssid = info.ssid;
                net->channel = info.channel;
                net->wep = info.wep;

                net->manuf_ref = MatchBestManuf(ap_manuf_map, net->bssid, net->ssid, net->channel,
                                                net->wep, net->cloaked, &net->manuf_score);
                // Update our IP range info too if we're a default
                if (net->manuf_score == manuf_max_score && net->ipdata.atype == address_none)
                    memcpy(&net->ipdata, &net->manuf_ref->ipdata, sizeof(net_ip_data));

                bssid_cloak_map[net->bssid] = info.ssid;

                snprintf(status, STATUS_MAX, "Found SSID \"%s\" for cloaked network BSSID %s",
                         net->ssid.c_str(), net->bssid.Mac2String().c_str());
                KisLocalStatus(status);
            } else if (info.ssid != bssid_cloak_map[net->bssid]) {
                bssid_cloak_map[net->bssid] = info.ssid;
                net->ssid = info.ssid;
                net->wep = info.wep;

                net->manuf_ref = MatchBestManuf(ap_manuf_map, net->bssid, net->ssid, net->channel,
                                                net->wep, net->cloaked, &net->manuf_score);
                // Update our IP range info too if we're a default
                if (net->manuf_score == manuf_max_score && net->ipdata.atype == address_none)
                    memcpy(&net->ipdata, &net->manuf_ref->ipdata, sizeof(net_ip_data));
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

                    snprintf(status, STATUS_MAX, "Associated probe network \"%s\" "
                             "with \"%s\" via probe response.",
                             pnet->bssid.Mac2String().c_str(),
                             net->bssid.Mac2String().c_str());
                    KisLocalStatus(status);

                    CreateClient(&info, net);

                    num_networks--;
                }
            }

        }

        if (net->type != network_ap && info.distrib == adhoc_distribution) {
            net->type = network_adhoc;
        }

    }
    
    if (info.type != packet_management) {
        // Process data packets

        // We feed them into the data packet processor along with the network
        // they belong to, so that clients can be tracked.
        ProcessDataPacket(info, net);

    } // data packet

    if (newnet == 1) {
        KisLocalNewnet(net);

        // Put it in itself as a client... I don't like defining the client 
        // all the way down here, but it does need to have the network in the
        // client records first, so....  such it goes.
        if (net->type == network_probe)
            CreateClient(&info, net);
    }

    return;
}

void Packetracker::ProcessDataPacket(packet_info info, wireless_network *net) {
    wireless_client *client = NULL;
    char status[STATUS_MAX];

    // Try to match up orphan probe networks
    wireless_network *pnet = NULL;

    if (info.type == packet_management && info.subtype == packet_sub_probe_req) {
        if (probe_map.find(info.source_mac) != probe_map.end()) {
            info.dest_mac = probe_map[info.source_mac];
            info.bssid_mac = info.dest_mac;
        } else {
            return;
        }
    } 

    if (bssid_map.find(info.dest_mac) != bssid_map.end()) {
        pnet = bssid_map[info.dest_mac];
        probe_map[info.source_mac] = pnet->bssid;
    } else if (bssid_map.find(info.source_mac) != bssid_map.end()) { 
        pnet = bssid_map[info.source_mac];
        probe_map[info.dest_mac] = pnet->bssid;
    }

    if (pnet != NULL) {
        if (pnet->type == network_probe) {

            net->llc_packets += pnet->llc_packets;
            net->data_packets += pnet->data_packets;
            net->crypt_packets += pnet->crypt_packets;
            net->interesting_packets += pnet->interesting_packets;
            pnet->type = network_remove;
            pnet->last_time = time(0);

            snprintf(status, STATUS_MAX, "Associated probe network \"%s\" with "
                     "\"%s\" via data.", pnet->bssid.Mac2String().c_str(),
                     net->bssid.Mac2String().c_str());
            KisLocalStatus(status);

            CreateClient(&info, net);

            num_networks--;
        }
    }
    
    // Find the client or make one
    if (net->client_map.find(info.source_mac) == net->client_map.end()) {
        client = CreateClient(&info, net); 
    } else {
        client = net->client_map[info.source_mac];

        if ((client->type == client_fromds && info.distrib == to_distribution) ||
            (client->type == client_tods && info.distrib == from_distribution)) {
            client->type = client_established;
        }
    }

    if (info.gps_fix >= 2) {
        if (info.gps_spd <= 0.3) {
            client->aggregate_lat += info.gps_lat;
            client->aggregate_lon += info.gps_lon;
            client->aggregate_alt += info.gps_alt;
            client->aggregate_points += 1;
        }

        client->gps_fixed = info.gps_fix;

        if (info.gps_lat < client->min_lat || client->min_lat == -90)
            client->min_lat = info.gps_lat;
        if (info.gps_lat > client->max_lat || client->max_lat == 90)
            client->max_lat = info.gps_lat;

        if (info.gps_lon < client->min_lon || client->min_lon == -180)
            client->min_lon = info.gps_lon;
        if (info.gps_lon > client->max_lon == 180)
            client->max_lon = info.gps_lon;

        if (info.gps_alt < client->min_alt || client->min_alt == 0)
            client->min_alt = info.gps_alt;
        if (info.gps_alt > client->max_alt || client->min_alt == 0)
            client->max_alt = info.gps_alt;

        if (info.gps_spd < client->min_spd || client->min_spd == 0)
            client->min_spd = info.gps_spd;
        if (info.gps_spd > client->max_spd || client->max_spd == 0)
            client->max_spd = info.gps_spd;

    } else {
        client->gps_fixed = 0;
    }

    if (info.quality >= 0 && info.signal >= 0) {
        client->quality = info.quality;
        if (info.quality > client->best_quality)
            client->best_quality = info.quality;
        client->signal = info.signal;

        if (info.signal > client->best_signal) {
            client->best_signal = info.signal;
            if (info.gps_fix >= 2) {
                client->best_lat = info.gps_lat;
                client->best_lon = info.gps_lon;
                client->best_alt = info.gps_alt;
            }
        }

        net->noise = info.noise;
        if ((info.noise < net->best_noise && info.noise != 0) || net->best_noise == 0)
            net->best_noise = info.noise;
    }

    if (info.type == packet_management &&
        (info.subtype == packet_sub_probe_req || info.subtype == packet_sub_association_req)) {
        if (info.maxrate > client->maxrate)
            client->maxrate = info.maxrate;
    }

    client->last_time = time(0);

    client->last_sequence = info.sequence_number;

    // Add data to the owning network and to the client
    net->datasize += info.datasize;
    client->datasize += info.datasize;

    // We modify our client and our network concurrently to save on CPU cycles.
    // Easier to update them in sync than it is to process the map as a list.
    if (info.encrypted) {
        net->crypt_packets++;
        client->crypt_packets++;
        num_crypt++;
    }

    // Flag the client and network as decrypted if we decrypted the packet
    if (info.decoded) {
        client->decrypted = 1;
        net->decrypted = 1;
    }

    if (info.interesting) {
        net->interesting_packets++;
        client->interesting_packets++;
        num_interesting++;
    }

    if (info.type != packet_management) {
        net->data_packets++;
        client->data_packets++;
    }

    // Assign the encoding types in this network, there can quite likely be more than
    // one...
    client->encoding_set |= (1 << (int) info.encoding);

    if (info.datarate > client->maxseenrate)
        client->maxseenrate = info.datarate;

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
    } else if ((info.proto.type == proto_udp || info.proto.type == proto_netbios ||
		info.proto.type == proto_iapp) &&
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
        snprintf(status, STATUS_MAX, "Found IP %d.%d.%d.%d for %s::%s via %s",
                 client->ipdata.ip[0], client->ipdata.ip[1],
                 client->ipdata.ip[2], client->ipdata.ip[3],
                 net->ssid.c_str(), info.source_mac.Mac2String().c_str(), means);
        KisLocalStatus(status);

        client->ipdata.load_from_store = 0;

        UpdateIpdata(net);
    }

    if (info.proto.type == proto_turbocell) {
        // Handle lucent outdoor routers
        net->cloaked = 1;

        if (info.turbocell_mode != turbocell_unknown) {
            net->turbocell_mode = info.turbocell_mode;
            net->turbocell_sat = info.turbocell_sat;
            net->turbocell_nid = info.turbocell_nid;

            if (!IsBlank(info.ssid))
                net->turbocell_name = info.ssid;
        }

        char turbossid[32];
        snprintf(turbossid, 32, "%d %s", net->turbocell_nid,
                 (net->turbocell_name.length() > 0) ? net->turbocell_name.c_str() : "Unknown");
        net->ssid = turbossid;

        net->type = network_turbocell;
    } else if (info.proto.type == proto_netstumbler) {
        // Handle netstumbler packets

        if (alertracker->PotentialAlert(arefs[NETSTUMBLER_AREF]) > 0) {
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

            snprintf(status, STATUS_MAX, "NetStumbler (%s) probe detected from %s",
                     nsversion, client->mac.Mac2String().c_str());
            alertracker->RaiseAlert(arefs[NETSTUMBLER_AREF], status);
        }

    } else if (info.proto.type == proto_lucenttest) {
        // Handle lucent test packets

        if (alertracker->PotentialAlert(arefs[LUCENTTEST_AREF]) > 0) {
            snprintf(status, STATUS_MAX, "Lucent link test detected from %s",
                     client->mac.Mac2String().c_str());
            alertracker->RaiseAlert(arefs[LUCENTTEST_AREF], status);
        }


    } else if (info.proto.type == proto_wellenreiter) {
        // Handle wellenreiter packets

        if (alertracker->PotentialAlert(arefs[WELLENREITER_AREF]) > 0) {
            snprintf(status, STATUS_MAX, "Wellenreiter probe detected from %s",
                     client->mac.Mac2String().c_str());
            alertracker->RaiseAlert(arefs[WELLENREITER_AREF], status);
        }

    }

    return;
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

    int netnum = 1;

    stable_sort(network_list.begin(), network_list.end(), SortFirstTimeLT());

    for (unsigned int i = 0; i < network_list.size(); i++) {
        wireless_network *net = network_list[i];

        if (filter_export) {
            macmap<int>::iterator fitr = filter_export_bssid->find(net->bssid);
            // In the list and we've got inverted filtering - kill it
            if (fitr != filter_export_bssid->end() &&
                *filter_export_bssid_invert == 1)
                continue;
            // Not in the list and we've got normal filtering - kill it
            if (fitr == filter_export_bssid->end() &&
                *filter_export_bssid_invert == 0)
                continue;
        }

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
        else if (net->type == network_turbocell)
            snprintf(type, 15, "turbocell");
        else
            snprintf(type, 15, "unknown");

        char carrier[15];
        if (net->carrier_set & (1 << (int) carrier_80211b))
            snprintf(carrier, 15, "802.11b");
        else if (net->carrier_set & (1 << (int) carrier_80211bplus))
            snprintf(carrier, 15, "802.11b+");
        else if (net->carrier_set & (1 << (int) carrier_80211a))
            snprintf(carrier, 15, "802.11a");
        else if (net->carrier_set & (1 << (int) carrier_80211g))
            snprintf(carrier, 15, "802.11g");
        else if (net->carrier_set & (1 << (int) carrier_80211fhss))
            snprintf(carrier, 15, "802.11 FHSS");
        else if (net->carrier_set & (1 << (int) carrier_80211dsss))
            snprintf(carrier, 15, "802.11 DSSS");
        else
            snprintf(carrier, 15, "unknown");

        fprintf(netfile, "Network %d: \"%s\" BSSID: \"%s\"\n"
                "    Type     : %s\n"
                "    Carrier  : %s\n"
                "    Info     : \"%s\"\n"
                "    Channel  : %02d\n"
                "    WEP      : \"%s\"\n"
                "    Maxrate  : %2.1f\n"
                "    LLC      : %d\n"
                "    Data     : %d\n"
                "    Crypt    : %d\n"
                "    Weak     : %d\n"
                "    Dupe IV  : %d\n"
                "    Total    : %d\n"
                "    First    : \"%s\"\n"
                "    Last     : \"%s\"\n",
                netnum,
                net->ssid.c_str(), net->bssid.Mac2String().c_str(), type, carrier,
                net->beacon_info == "" ? "None" : net->beacon_info.c_str(),
                net->channel, net->wep ? "Yes" : "No",
                net->maxrate,
                net->llc_packets, net->data_packets,
                net->crypt_packets, net->interesting_packets,
                net->dupeiv_packets,
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

    /*
    vector<wireless_network *> bssid_vec;

    // Convert the map to a vector and sort it
    for (map<mac_addr, wireless_network *>::const_iterator i = bssid_map.begin();
         i != bssid_map.end(); ++i)
        bssid_vec.push_back(i->second);

        stable_sort(bssid_vec.begin(), bssid_vec.end(), SortFirstTimeLT());
        */

    stable_sort(network_list.begin(), network_list.end(), SortFirstTimeLT());

    for (unsigned int i = 0; i < network_list.size(); i++) {
        wireless_network *net = network_list[i];

        if (net->cisco_equip.size() == 0)
            continue;

        if (filter_export) {
            macmap<int>::iterator fitr = filter_export_bssid->find(net->bssid);
            // In the list and we've got inverted filtering - kill it
            if (fitr != filter_export_bssid->end() &&
                *filter_export_bssid_invert == 1)
                continue;
            // Not in the list and we've got normal filtering - kill it
            if (fitr == filter_export_bssid->end() &&
                *filter_export_bssid_invert == 0)
                continue;
        }

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
    /*
    vector<wireless_network *> bssid_vec;

    // Convert the map to a vector and sort it
    for (map<mac_addr, wireless_network *>::const_iterator i = bssid_map.begin();
         i != bssid_map.end(); ++i)
        bssid_vec.push_back(i->second);

        stable_sort(bssid_vec.begin(), bssid_vec.end(), SortFirstTimeLT());
        */

    fprintf(netfile, "Network;NetType;ESSID;BSSID;Info;Channel;Cloaked;WEP;Decrypted;MaxRate;MaxSeenRate;Beacon;"
            "LLC;Data;Crypt;Weak;Total;Carrier;Encoding;FirstTime;LastTime;BestQuality;BestSignal;BestNoise;"
            "GPSMinLat;GPSMinLon;GPSMinAlt;GPSMinSpd;GPSMaxLat;GPSMaxLon;GPSMaxAlt;GPSMaxSpd;"
            "GPSBestLat;GPSBestLon;GPSBestAlt;DataSize;IPType;IP;\n\r");

    stable_sort(network_list.begin(), network_list.end(), SortFirstTimeLT());

    for (unsigned int i = 0; i < network_list.size(); i++) {
        wireless_network *net = network_list[i];

        if (filter_export) {
            macmap<int>::iterator fitr = filter_export_bssid->find(net->bssid);
            // In the list and we've got inverted filtering - kill it
            if (fitr != filter_export_bssid->end() &&
                *filter_export_bssid_invert == 1)
                continue;
            // Not in the list and we've got normal filtering - kill it
            if (fitr == filter_export_bssid->end() &&
                *filter_export_bssid_invert == 0)
                continue;
        }

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
        else if (net->type == network_turbocell)
            snprintf(type, 15, "turbocell");
        else
            snprintf(type, 15, "unknown");

        string carrier;
        if (net->carrier_set & (1 << (int) carrier_80211b)) {
            carrier += "IEEE 802.11b";
        }
        if (net->carrier_set & (1 << (int) carrier_80211bplus)) {
            if (carrier != "")
                carrier += ",";
            carrier += "TI 802.11b+";
        }
        if (net->carrier_set & (1 << (int) carrier_80211a)) {
            if (carrier != "")
                carrier += ",";
            carrier += "IEEE 802.11a";
        }
        if (net->carrier_set & (1 << (int) carrier_80211g)) {
            if (carrier != "")
                carrier += ",";
            carrier += "IEEE 802.11g";
        }
        if (net->carrier_set & (1 << (int) carrier_80211fhss)) {
            if (carrier != "")
                carrier += ",";
            carrier += "IEEE 802.11 FHSS";
        }
        if (net->carrier_set & (1 << (int) carrier_80211dsss)) {
            if (carrier != "")
                carrier += ",";
            carrier += "IEEE 802.11 DSSS";
        }

        string encoding;
        if (net->encoding_set & (1 << (int) encoding_cck)) {
            encoding = "CCK";
        }
        if (net->encoding_set & (1 << (int) encoding_pbcc)) {
            if (encoding != "")
                encoding += ",";
            encoding += "PBCC";
        }
        if (net->encoding_set & (1 << (int) encoding_ofdm)) {
            if (encoding != "")
                encoding += ",";
            encoding += "OFDM";
        }

        string iptype = "None";
        if (net->ipdata.atype == address_dhcp)
            iptype = "DHCP";
        else if (net->ipdata.atype == address_arp)
            iptype = "ARP";
        else if (net->ipdata.atype == address_udp)
            iptype = "UDP";
        else if (net->ipdata.atype == address_tcp)
            iptype = "TCP";

        fprintf(netfile,
                "%d;%s;%s;%s;%s;"
                "%d;%s;%s;%s;"
                "%2.1f;%ld;%d;"
                "%d;%d;%d;%d;%d;"
                "%s;%s;%s;%s;"
                "%d;%d;%d;"
                "%f;%f;%f;%f;"
                "%f;%f;%f;%f;"
                "%f;%f;%f;"
                "%ld;%s;"
                "%hd.%hd.%hd.%hd;\n\r",
                netnum, type, SanitizeCSV(net->ssid).c_str(), net->bssid.Mac2String().c_str(), SanitizeCSV(net->beacon_info).c_str(),
                net->channel, net->cloaked ? "Yes" : "No", net->wep ? "Yes" : "No", net->decrypted ? "Yes" : "No",
                net->maxrate, (long) net->maxseenrate * 100, net->beacon,
                net->llc_packets, net->data_packets, net->crypt_packets, net->interesting_packets, (net->llc_packets + net->interesting_packets),
                carrier.c_str(), encoding.c_str(), ft, lt,
                net->best_quality, net->best_signal, net->best_noise,
                net->min_lat, net->min_lon, net->min_alt, net->min_spd,
                net->max_lat, net->max_lon, net->max_alt, net->max_spd,
                net->best_lat, net->best_lon, net->best_alt,
                net->datasize, iptype.c_str(),
                net->ipdata.range_ip[0], net->ipdata.range_ip[1], net->ipdata.range_ip[2], net->ipdata.range_ip[3]);

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
    //vector<wireless_network *> bssid_vec;

    fprintf(netfile, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");
    fprintf(netfile, "<!DOCTYPE detection-run SYSTEM \"http://kismetwireless.net/kismet-3.1.0.dtd\">\n");

    fprintf(netfile, "\n\n");

    char lt[25];
    char ft[25];

    snprintf(ft, 25, "%s", ctime(&start_time));
    time_t cur_time = time(0);
    snprintf(lt, 25, "%s", ctime(&cur_time));

    fprintf(netfile, "<detection-run kismet-version=\"%d.%d.%d\" start-time=\"%s\" end-time=\"%s\">\n",
            VERSION_MAJOR, VERSION_MINOR, VERSION_TINY, ft, lt);

    /*
    // Convert the map to a vector and sort it
    for (map<mac_addr, wireless_network *>::const_iterator i = bssid_map.begin();
         i != bssid_map.end(); ++i)
        bssid_vec.push_back(i->second);

        stable_sort(bssid_vec.begin(), bssid_vec.end(), SortFirstTimeLT());
        */

    stable_sort(network_list.begin(), network_list.end(), SortFirstTimeLT());

    for (unsigned int i = 0; i < network_list.size(); i++) {
        wireless_network *net = network_list[i];

        if (filter_export) {
            macmap<int>::iterator fitr = filter_export_bssid->find(net->bssid);
            // In the list and we've got inverted filtering - kill it
            if (fitr != filter_export_bssid->end() &&
                *filter_export_bssid_invert == 1)
                continue;
            // Not in the list and we've got normal filtering - kill it
            if (fitr == filter_export_bssid->end() &&
                *filter_export_bssid_invert == 0)
                continue;
        }

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
        else if (net->type == network_turbocell)
            snprintf(type, 15, "turbocell");
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
        fprintf(netfile, "    <maxseenrate>%ld</maxseenrate>\n", (long) net->maxseenrate * 100);

        if (net->carrier_set & (1 << (int) carrier_80211b))
            fprintf(netfile, "    <carrier>IEEE 802.11b</carrier>\n");
        if (net->carrier_set & (1 << (int) carrier_80211bplus))
            fprintf(netfile, "    <carrier>TI 802.11b+</carrier>\n");
        if (net->carrier_set & (1 << (int) carrier_80211a))
            fprintf(netfile, "    <carrier>IEEE 802.11a</carrier>\n");
        if (net->carrier_set & (1 << (int) carrier_80211g))
            fprintf(netfile, "    <carrier>IEEE 802.11g</carrier>\n");
        if (net->carrier_set & (1 << (int) carrier_80211fhss))
            fprintf(netfile, "    <carrier>IEEE 802.11 FHSS</carrier>\n");
        if (net->carrier_set & (1 << (int) carrier_80211dsss))
            fprintf(netfile, "    <carrier>IEEE 802.11 FSSS</carrier>\n");

        if (net->encoding_set & (1 << (int) encoding_cck))
            fprintf(netfile, "    <encoding>CCK</encoding>\n");
        if (net->encoding_set & (1 << (int) encoding_pbcc))
            fprintf(netfile, "    <encoding>PBCC</encoding>\n");
        if (net->encoding_set & (1 << (int) encoding_ofdm))
            fprintf(netfile, "    <encoding>OFDM</encoding>\n");

        fprintf(netfile, "    <packets>\n");
        fprintf(netfile, "      <LLC>%d</LLC>\n", net->llc_packets);
        fprintf(netfile, "      <data>%d</data>\n", net->data_packets);
        fprintf(netfile, "      <crypt>%d</crypt>\n", net->crypt_packets);
        fprintf(netfile, "      <weak>%d</weak>\n", net->interesting_packets);
        fprintf(netfile, "      <dupeiv>%d</dupeiv>\n", net->dupeiv_packets);
        fprintf(netfile, "      <total>%d</total>\n",
                (net->llc_packets + net->data_packets));
        fprintf(netfile, "    </packets>\n");

        fprintf(netfile, "    <datasize>%ld</datasize>\n", net->datasize);

        if (net->gps_fixed != -1) {
            fprintf(netfile, "    <gps-info unit=\"%s\">\n", metric ? "metric" : "english");
            fprintf(netfile, "      <min-lat>%f</min-lat>\n", net->min_lat);
            fprintf(netfile, "      <min-lon>%f</min-lon>\n", net->min_lon);
            fprintf(netfile, "      <min-alt>%f</min-alt>\n",
                    metric ? net->min_alt / 3.3 : net->min_alt);
            fprintf(netfile, "      <min-spd>%f</min-spd>\n",
                    metric ? net->min_spd * 1.6093 : net->min_spd);
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

        int clinum = 1;
        for (unsigned int cltr = 0; cltr < net->client_vec.size(); cltr++) {
            wireless_client *cli = net->client_vec[cltr];

            char *clitype;
            switch (cli->type) {
            case client_fromds:
                clitype = "fromds";
                break;
            case client_tods:
                clitype = "tods";
                break;
            case client_interds:
                clitype = "interds";
                break;
            case client_established:
                clitype = "established";
                break;
            default:
                clitype = "unknown";
                break;
            }

            snprintf(lt, 25, "%s", ctime(&cli->last_time));
            snprintf(ft, 25, "%s", ctime(&cli->first_time));

            fprintf(netfile, "    <wireless-client number=\"%d\" type=\"%s\" "
                    "wep=\"%s\" first-time=\"%s\" last-time=\"%s\">\n",
                    clinum, clitype, cli->wep ? "true" : "false", ft, lt);

            fprintf(netfile, "      <client-mac>%s</client-mac>\n", cli->mac.Mac2String().c_str());
            fprintf(netfile, "      <client-packets>\n");
            fprintf(netfile, "        <client-data>%d</client-data>\n", cli->data_packets);
            fprintf(netfile, "        <client-crypt>%d</client-crypt>\n", cli->crypt_packets);
            fprintf(netfile, "        <client-weak>%d</client-weak>\n", cli->interesting_packets);
            fprintf(netfile, "      </client-packets>\n");

            if (cli->gps_fixed != -1) {
                fprintf(netfile, "      <client-gps-info unit=\"%s\">\n", metric ? "metric" : "english");
                fprintf(netfile, "        <client-min-lat>%f</client-min-lat>\n", cli->min_lat);
                fprintf(netfile, "        <client-min-lon>%f</client-min-lon>\n", cli->min_lon);
                fprintf(netfile, "        <client-min-alt>%f</client-min-alt>\n",
                        metric ? cli->min_alt / 3.3 : cli->min_alt);
                fprintf(netfile, "        <client-min-spd>%f</client-min-spd>\n",
                        metric ? cli->min_spd * 1.6093 : cli->min_spd);
                fprintf(netfile, "        <client-max-lat>%f</client-max-lat>\n", cli->max_lat);
                fprintf(netfile, "        <client-max-lon>%f</client-max-lon>\n", cli->max_lon);
                fprintf(netfile, "        <client-max-alt>%f</client-max-alt>\n",
                        metric ? cli->max_alt / 3.3 : cli->max_alt);
                fprintf(netfile, "        <client-max-spd>%f</client-max-spd>\n",
                        metric ? cli->max_spd * 1.6093 : cli->max_spd);
                fprintf(netfile, "      </client-gps-info>\n");
            }

            fprintf(netfile, "      <client-datasize>%ld</client-datasize>\n", cli->datasize);
            fprintf(netfile, "      <client-maxrate>%2.1f</client-maxrate>\n", cli->maxrate);
            fprintf(netfile, "      <client-maxseenrate>%ld</client-maxseenrate>\n", (long) cli->maxseenrate * 100);

            if (net->encoding_set & (1 << (int) encoding_cck))
                fprintf(netfile, "      <client-encoding>CCK</client-encoding>\n");
            if (net->encoding_set & (1 << (int) encoding_pbcc))
                fprintf(netfile, "      <client-encoding>PBCC</client-encoding>\n");
            if (net->encoding_set & (1 << (int) encoding_ofdm))
                fprintf(netfile, "      <client-encoding>OFDM</client-encoding>\n");



            if (cli->ipdata.atype > address_factory) {
                char *addrtype;
                switch (cli->ipdata.atype) {
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

                fprintf(netfile, "      <client-ip-address type=\"%s\">%hd.%hd.%hd.%hd</client-ip-address>\n",
                        addrtype, cli->ipdata.ip[0], cli->ipdata.ip[1], cli->ipdata.ip[2], cli->ipdata.ip[3]);
            }

            fprintf(netfile, "    </wireless-client>\n");

            clinum++;
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
                  ) < 7)
            continue;

        for (int x = 0; x < 4; x++) {
            dat.range_ip[x] = (uint8_t) range[x];
        }

        dat.load_from_store = 1;

        bssid = bssid_str;

        if (bssid.error == 1)
            continue;

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
                x->second.range_ip[2], x->second.range_ip[3]);
    }

    for (unsigned int x = 0; x < network_list.size(); x++) {
        for (unsigned int y = 0; y < network_list[x]->client_vec.size(); y++) {
            wireless_client *cli = network_list[x]->client_vec[y];

            if (cli->ipdata.atype <= address_factory)
                continue;

            fprintf(in_file, "%s %d %d %hd %hd %hd %hd\n",
                    cli->mac.Mac2String().c_str(),
                    cli->ipdata.atype, cli->ipdata.octets,
                    cli->ipdata.ip[0], cli->ipdata.ip[1],
                    cli->ipdata.ip[2], cli->ipdata.ip[3]);
        }
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
    // Remove us from the vector the slow and painful way
    for (unsigned int x = 0; x < network_list.size(); x++) {
        if (network_list[x]->bssid == in_bssid) {
            network_list.erase(network_list.begin() + x);
            break;
        }
    }

    // Remove us from the hash
    map<mac_addr, wireless_network *>::iterator bmi = bssid_map.find(in_bssid);
    if (bmi != bssid_map.end()) {
        delete bmi->second;
        bssid_map.erase(bmi);
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
