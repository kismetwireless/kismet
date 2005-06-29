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

#include <math.h>
#include "frontend.h"

void Frontend::PopulateGroups(TcpClient *in_client) {
    vector<wireless_network *> clientlist;

    clientlist = in_client->FetchNetworkList();

    // Convert the list
    for (unsigned int x = 0; x < clientlist.size(); x++) {
        wireless_network *net = clientlist[x];

        // Handle networks tagged for removal
        if (net->type == network_remove) {
            if (net->dispnet != NULL) {
                display_network *ganet = net->dispnet;

                // Otherwise we have to unlink it and track it down
                for (unsigned int y = 0; y < ganet->networks.size(); y++) {
                    if (ganet->networks[y] == net) {
                        ganet->networks.erase(ganet->networks.begin() + y);
                        break;
                    }
                }

                if (ganet->networks.size() == 0) {
                    DestroyGroup(ganet);
                } else {
                    group_assignment_map.erase(group_assignment_map.find(net->bssid));
                }
            }

            in_client->RemoveNetwork(net->bssid);

            continue;
        }

        // Now, see if we've been assigned, if we have we can just keep going
        if (net->dispnet != NULL)
            continue;

        int newgroup = 0;
        int persistent = 0;
        display_network *group;
        string grouptag;

        // If they haven't been assigned, see if they belong to a group we know about
        map<mac_addr, string>::iterator bsgmitr = bssid_group_map.find(net->bssid);
        if (bsgmitr != bssid_group_map.end()) {
            grouptag = bsgmitr->second;

            // And see if the group has been created - if it hasn't and it's a group 
            // we knew about before, then we make a new persistent group
            if (group_tag_map.find(grouptag) == group_tag_map.end()) {
                newgroup = 1;
                persistent = 1;
            } else {
                group = group_tag_map[grouptag];
            }
        } else {
            // Tell them to make a group, set the bssid as the tag and the SSID
            // as the name of the group
            grouptag = net->bssid.Mac2String();
            newgroup = 1;
        }

        // If we're making a new group, create it
        if (newgroup) {
            group = new display_network;

            map<string, string>::iterator gnmitr = group_name_map.find(grouptag);
            if (gnmitr != group_name_map.end()) {
                group->name = gnmitr->second;
            }
            /*
             else {
                group->name = net->ssid;
                group_name_map[grouptag] = net->ssid;
                }
                */

            group->tag = grouptag;
            group->type = group_host;
            group->tagged = 0;
            group->expanded = 0;
            group->persistent = persistent;
            // group->virtnet = NULL;
			group->virtnet = new wireless_network;
			*(group->virtnet) = *(net);

            // Register it
            group_tag_map[group->tag] = group;
            bssid_group_map[net->bssid] = group->tag;
            // Push it into our main vector
            group_vec.push_back(group);
        }

        // Push the network onto the group and change the type if needed
        group->networks.push_back(net);

        if (group->networks.size() > 1)
            group->type = group_bundle;
        else
            group->type = group_host;

        // Register that we're known
        group_assignment_map[net->bssid] = group;
        net->dispnet = group;
    }

    // Update us
    // UpdateGroups();

}

void Frontend::UpdateGroups() {
    list<display_network *> discard;
    time_t curtime = 0;

    for (unsigned int x = 0; x < group_vec.size(); x++) {
        display_network *dnet = group_vec[x];

        if (dnet->networks.size() < 1 || dnet->type == group_empty) {
            discard.push_back(dnet);
            dnet->type = group_empty;
            continue;
        }

        // Groups just get copied over from the first element if we're not a group
        // or if, somehow, we're a subhost
        if (dnet->type == group_host || dnet->type == group_sub) {
            // dnet->virtnet = dnet->networks[0];
			if (dnet->virtnet == NULL) {
				dnet->virtnet = new wireless_network;
			}
			*(dnet->virtnet) = *(dnet->networks[0]);

			if (dnet->virtnet->tcpclient != NULL) {
				if (dnet->virtnet->tcpclient->Valid()) 
					curtime = dnet->virtnet->tcpclient->FetchTime();
			}

            dnet->virtnet->idle_time = curtime - dnet->virtnet->last_time;

            if (dnet->virtnet->manuf_ref == NULL)
                dnet->virtnet->manuf_ref = MatchBestManuf(ap_manuf_map, 
                                                          dnet->virtnet->bssid, 
                                                          dnet->virtnet->ssid,
                                                          dnet->virtnet->channel, 
                                                          dnet->virtnet->crypt_set, 
                                                          dnet->virtnet->cloaked,
                                                          &dnet->virtnet->manuf_score);

            for (unsigned int clnum = 0; clnum < dnet->virtnet->client_vec.size(); 
                 clnum++) {
                wireless_client *cl = dnet->virtnet->client_vec[clnum];
                if (cl->manuf_ref == NULL)
                    cl->manuf_ref = MatchBestManuf(client_manuf_map, cl->mac, "", 
												   0, 0, 0, &cl->manuf_score);
            }

            continue;
        }

        if (dnet->type == group_empty) {
            discard.push_back(dnet);
            continue;
        }

        // Otherwise we need to destroy the old virtual network and make a new one
        if (dnet->virtnet != NULL)
            delete dnet->virtnet;
        dnet->virtnet = new wireless_network;

        unsigned int bssid_matched = MAC_LEN;

        for (unsigned int y = 0; y < dnet->networks.size(); y++) {
            wireless_network *wnet = dnet->networks[y];

			// safety net this
			if (wnet->tcpclient != NULL) {
				if (wnet->tcpclient->Valid())
					curtime = wnet->tcpclient->FetchTime();
			}

            // Mask the bssid out
            for (unsigned int mask = 0; mask < bssid_matched; mask++) {
                if (dnet->virtnet->bssid[mask] != wnet->bssid[mask]) {
                    bssid_matched = mask;
                    break;
                }
            }

            // If we don't have a SSID get the first non-null one we encounter
            if (dnet->virtnet->ssid.length() == 0)
                dnet->virtnet->ssid = wnet->ssid;

            // If we don't have beacon info, get the first one we encounter
            if (dnet->virtnet->beacon_info == "" && wnet->beacon_info != "")
                dnet->virtnet->beacon_info = wnet->beacon_info;

            if ((curtime - wnet->last_time) < dnet->virtnet->idle_time ||
                dnet->virtnet->idle_time == 0)
                dnet->virtnet->idle_time = curtime - wnet->last_time;

            // Take the highest overall signal and power levels.  Noise just
            // tags along for the ride.  Only do this if the network has been touched
            // within the decay period
            if (curtime - wnet->last_time <= (decay * 2)) {
                if (wnet->signal >= dnet->virtnet->signal) {
                    dnet->virtnet->signal = wnet->signal;
                    dnet->virtnet->noise = wnet->noise;
                }

                if (wnet->quality > dnet->virtnet->best_quality)
                    dnet->virtnet->best_quality = wnet->quality;

                if (wnet->signal > dnet->virtnet->best_signal) {
                    dnet->virtnet->best_signal = wnet->signal;
                    dnet->virtnet->best_lat = wnet->best_lat;
                    dnet->virtnet->best_lon = wnet->best_lon;
                    dnet->virtnet->best_alt = wnet->best_alt;
                }

                if ((wnet->noise < dnet->virtnet->best_noise && wnet->noise != 0) ||
                    dnet->virtnet->best_noise == 0)
                    dnet->virtnet->best_noise = wnet->noise;

            }

            // Aggregate the GPS data
            if (wnet->aggregate_points > 0) {
                dnet->virtnet->aggregate_lat += wnet->aggregate_lat;
                dnet->virtnet->aggregate_lon += wnet->aggregate_lon;
                dnet->virtnet->aggregate_alt += wnet->aggregate_alt;
                dnet->virtnet->aggregate_points += wnet->aggregate_points;
            }

            if (wnet->gps_fixed > dnet->virtnet->gps_fixed)
                dnet->virtnet->gps_fixed = wnet->gps_fixed;
            if (wnet->min_lat < dnet->virtnet->min_lat || dnet->virtnet->min_lat == 0)
                dnet->virtnet->min_lat = wnet->min_lat;
            if (wnet->min_lon < dnet->virtnet->min_lon || dnet->virtnet->min_lon == 0)
                dnet->virtnet->min_lon = wnet->min_lon;
            if (wnet->min_alt < dnet->virtnet->min_alt || dnet->virtnet->min_alt == 0)
                dnet->virtnet->min_alt = wnet->min_alt;
            if (wnet->min_spd < dnet->virtnet->min_spd || dnet->virtnet->min_spd == 0)
                dnet->virtnet->min_spd = wnet->min_spd;
            if (wnet->max_lat > dnet->virtnet->max_lat || dnet->virtnet->max_lat == 0)
                dnet->virtnet->max_lat = wnet->max_lat;
            if (wnet->max_lon > dnet->virtnet->max_lon || dnet->virtnet->max_lon == 0)
                dnet->virtnet->max_lon = wnet->max_lon;
            if (wnet->max_alt > dnet->virtnet->max_alt || dnet->virtnet->max_alt == 0)
                dnet->virtnet->max_alt = wnet->max_alt;
            if (wnet->max_spd > dnet->virtnet->max_spd || dnet->virtnet->max_spd == 0)
                dnet->virtnet->max_spd = wnet->max_spd;

            // Aggregate the carriers and encodings
            dnet->virtnet->carrier_set |= wnet->carrier_set;
            dnet->virtnet->encoding_set |= wnet->encoding_set;

            // Aggregate the packets
            dnet->virtnet->llc_packets += wnet->llc_packets;
            dnet->virtnet->data_packets += wnet->data_packets;
            dnet->virtnet->crypt_packets += wnet->crypt_packets;
            dnet->virtnet->interesting_packets += wnet->interesting_packets;
            dnet->virtnet->dupeiv_packets += wnet->dupeiv_packets;

            // Aggregate the data
            dnet->virtnet->datasize += wnet->datasize;

            // Add all the clients
            for (map<mac_addr, wireless_client *>::iterator cli = 
                 wnet->client_map.begin(); cli != wnet->client_map.end(); ++cli)
                dnet->virtnet->client_map[cli->second->mac] = cli->second;

            // Negative the channel if we can't agree.  Any channel takes precedence
            // over channel 0.
            if (dnet->virtnet->channel == 0 && wnet->channel != 0)
                dnet->virtnet->channel = wnet->channel;
            else if (dnet->virtnet->channel > 0 && 
                     dnet->virtnet->channel != wnet->channel &&
                     wnet->channel != 0)
                dnet->virtnet->channel = 0;

            // If one channel isn't wep'ed, the group isn't wep'd
            if (wnet->crypt_set == 0)
                dnet->virtnet->crypt_set = 0;
			else
				dnet->virtnet->crypt_set = (dnet->virtnet->crypt_set &
											wnet->crypt_set);

            // If one channel is cloaked, the group is cloaked
            if (dnet->virtnet->cloaked == -1)
                dnet->virtnet->cloaked = wnet->cloaked;
            else if (wnet->cloaked == 1)
                dnet->virtnet->cloaked = 1;

            // We get the oldest and latest for last and first
            if (dnet->virtnet->last_time == 0 || dnet->virtnet->last_time < 
                wnet->last_time)
                dnet->virtnet->last_time = wnet->last_time;
            if (dnet->virtnet->first_time == 0 || dnet->virtnet->first_time > 
                wnet->first_time)
                dnet->virtnet->first_time = wnet->first_time;

            // We get the smallest beacon interval
            if (dnet->virtnet->beacon == 0 || dnet->virtnet->beacon > wnet->beacon)
                dnet->virtnet->beacon = wnet->beacon;

            // We get the highest maxrate
            if (dnet->virtnet->maxrate == 0 || dnet->virtnet->maxrate < wnet->maxrate)
                dnet->virtnet->maxrate = wnet->maxrate;

            // Highest max seen rate
            if (wnet->maxseenrate > dnet->virtnet->maxseenrate)
                dnet->virtnet->maxseenrate = wnet->maxseenrate;

            if (wnet->ipdata.atype > address_none) {
                int oct;
                for (oct = 0; oct < dnet->virtnet->ipdata.octets &&
                     oct < wnet->ipdata.octets && oct < 4; oct++) {
                    if (dnet->virtnet->ipdata.range_ip[oct] == 0 &&
                        wnet->ipdata.range_ip[oct] != 0)
                        dnet->virtnet->ipdata.range_ip[oct] = wnet->ipdata.range_ip[oct];
                    else if (dnet->virtnet->ipdata.range_ip[oct] != 
                             wnet->ipdata.range_ip[oct] ||
                             wnet->ipdata.range_ip[oct] == 0) {
                        dnet->virtnet->ipdata.range_ip[oct] = 0;
                        if (oct != 0)
                            oct--;
                        break;
                    }
                }

                dnet->virtnet->ipdata.octets = oct;
                dnet->virtnet->ipdata.atype = address_group;
            }

        }

        // Catch incase we didn't get a ssid
        if (dnet->virtnet->ssid.length() == 0)
            dnet->virtnet->ssid = NOSSID;

        dnet->virtnet->manuf_ref = MatchBestManuf(ap_manuf_map, dnet->virtnet->bssid, 
                                                  dnet->virtnet->ssid,
                                                  dnet->virtnet->channel, 
                                                  dnet->virtnet->crypt_set, 
                                                  dnet->virtnet->cloaked,
                                                  &dnet->virtnet->manuf_score);

        // convert our map into a vector
        for (map<mac_addr, wireless_client *>::iterator cli = 
             dnet->virtnet->client_map.begin();
             cli != dnet->virtnet->client_map.end(); ++cli) {
            if (cli->second->manuf_ref == NULL)
                cli->second->manuf_ref = MatchBestManuf(client_manuf_map, 
                                                        cli->second->mac,
                                                        "", 0, 0, 0, 
                                                        &cli->second->manuf_score);
            dnet->virtnet->client_vec.push_back(cli->second);
        }

        // Update the group name if it's <no ssid> and the ssid is set
        /*
        if (dnet->name == NOSSID && dnet->virtnet->ssid != NOSSID) {
            dnet->name = dnet->virtnet->ssid;
            group_name_map[dnet->tag] = dnet->name;
            }
            */

    }

    // Destroy any marked for discard
    for (list<display_network *>::iterator x = discard.begin(); 
         x != discard.end(); ++x) {
        DestroyGroup(*x);
    }

}

// Clean out all the associated groups when we change what servers we listen to.
// Keep all the association data, just wipe the contents so the next Populate
// fills us in with good data.
void Frontend::PurgeGroups() {

    map<mac_addr, display_network *>::iterator x;
    for (x = group_assignment_map.begin(); x != group_assignment_map.end(); ++x) {
        x->second->networks.clear();
    }

    group_assignment_map.clear();

}

// Create a display group based off core that may or may not be saved
display_network *Frontend::CreateGroup(int in_persistent, string in_tag, string in_name) {

    display_network *core = new display_network;

    core->tagged = 0;
    core->persistent = in_persistent;
    core->tag = in_tag;
    core->name = in_name;
    core->expanded = 0;
    core->type = group_host;
	core->virtnet = NULL;

    // Register it
    group_tag_map[core->tag] = core;
    group_vec.push_back(core);
    group_name_map[core->tag] = core->name;

    return core;
}

// Add a display network to a specific core group
display_network *Frontend::AddToGroup(display_network *core, 
									  display_network *merger) {
    // We need to do this nasty loop to find its posiition in the vector
    for (unsigned int x = 0; x < group_vec.size(); x++) {
        display_network *dnet = group_vec[x];

        if (dnet != merger)
            continue;

        // Go through all the networks, this will work for host groups and for
        // merging bundles

        for (unsigned int y = 0; y < dnet->networks.size(); y++) {
            wireless_network *snet = dnet->networks[y];

            // Destroy our assignment
            map<mac_addr, display_network *>::iterator gamitr = 
				group_assignment_map.find(snet->bssid);
            if (gamitr != group_assignment_map.end()) {
                group_assignment_map.erase(gamitr);
			}

            // So far so good.  Now we see if we're supposed to be in any 
			// other networks, and remove the reference
            map<mac_addr, string>::iterator bsgmitr = 
				bssid_group_map.find(snet->bssid);
            if (bsgmitr != bssid_group_map.end()) {
                bssid_group_map.erase(bsgmitr);
			}

            // Now we tell them we belong to the new network
            bssid_group_map[snet->bssid] = core->tag;

            // Register that we're assigned...
            group_assignment_map[snet->bssid] = core;

            // Assign our display net
            snet->dispnet = core;

            // Update our virtnet since updategroups() needs it to be valid...
			/*
            if (core->networks.size() == 0)
                core->virtnet = snet;
				*/
			if (core->networks.size() == 0) {
				if (core->virtnet == NULL) {
					core->virtnet = new wireless_network;
				}
				*(core->virtnet) = *(snet);
			}

            // And add us to the core network list
            core->networks.push_back(snet);
        }

        // Now we find all the pointers to this network from networks that aren't
        // currently live, and move them.  This keeps us from breaking grouping.
        for (map<mac_addr, string>::iterator iter = bssid_group_map.begin();
             iter != bssid_group_map.end(); ++iter) {
            if (iter->second == dnet->tag)
                bssid_group_map[iter->first] = core->tag;
        }

        // Now we destroy the pointer to the old host group -- we assume we have to
        // exist since we (can't/shouldn't) ever make a network that isn't in the
        // name map
        group_tag_map.erase(group_tag_map.find(dnet->tag));
        map<string, string>::iterator gnmitr = group_name_map.find(dnet->tag);
        if (gnmitr != group_name_map.end())
            group_name_map.erase(gnmitr);

        // And remove it from the vector, and compensate the for loop
        group_vec.erase(group_vec.begin() + x);

        // And free the group
        delete dnet;

        break;
    }

	if (core->networks.size() > 1) {
		core->type = group_bundle;
	} else {
		core->type = group_host;
	}

    return core;

}


display_network *Frontend::GroupTagged() {
    display_network *core = NULL;

    for (unsigned int x = 0; x < group_vec.size(); x++) {
        display_network *dnet = group_vec[x];

        if (!dnet->tagged)
            continue;

        // The first display group we find becomes the core, all the others
        // get added to it, so we set it and don't do much else with it here.
        if (core == NULL) {
            core = dnet;
            core->tagged = 0;
            core->persistent = 1;
            continue;
        }

        // Go through all the networks, this will work for host groups and for
        // merging bundles

        for (unsigned int y = 0; y < dnet->networks.size(); y++) {
            wireless_network *snet = dnet->networks[y];

            // Destroy our assignment
            map<mac_addr, display_network *>::iterator gamitr = group_assignment_map.find(snet->bssid);
            if (gamitr != group_assignment_map.end())
                group_assignment_map.erase(gamitr);

            // So far so good.  Now we see if we're supposed to be in any other networks,
            // and remove the reference
            map<mac_addr, string>::iterator bsgmitr = bssid_group_map.find(snet->bssid);
            if (bsgmitr != bssid_group_map.end())
                bssid_group_map.erase(bsgmitr);

            // Now we tell them we belong to the new network
            bssid_group_map[snet->bssid] = core->tag;

            // Register that we're assigned...
            group_assignment_map[snet->bssid] = core;

            // Assign our display net
            snet->dispnet = core;

            // And add us to the core network list
            core->networks.push_back(snet);
        }

        // Now we find all the pointers to this network from networks that aren't
        // currently live, and move them.  This keeps us from breaking grouping.
        for (map<mac_addr, string>::iterator iter = bssid_group_map.begin();
             iter != bssid_group_map.end(); ++iter) {
            if (iter->second == dnet->tag)
                bssid_group_map[iter->first] = core->tag;
        }

        // Now we destroy the pointer to the old host group -- we assume we have to
        // exist since we (can't/shouldn't) ever make a network that isn't in the
        // name map
        group_tag_map.erase(group_tag_map.find(dnet->tag));
        map<string, string>::iterator gnmitr = group_name_map.find(dnet->tag);
        if (gnmitr != group_name_map.end())
            group_name_map.erase(gnmitr);

        // And remove it from the vector, and compensate the for loop
        group_vec.erase(group_vec.begin() + x);
        x--;

        // And free the group
        delete dnet;
    }

    if (core != NULL) {
        if (core->networks.size() > 1)
            core->type = group_bundle;
        else
            core->type = group_host;
    }

    return core;
}

void Frontend::DestroyGroup(display_network *in_group) {

    /*
    if (in_group->type != group_bundle)
    return;
    */

    // Destroy the assignments of all the groups inside
    for (unsigned int x = 0; x < in_group->networks.size(); x++) {
        wireless_network *snet = in_group->networks[x];

        // Destroy our assignment
        map<mac_addr, display_network *>::iterator gamitr = 
            group_assignment_map.find(snet->bssid);
        if (gamitr != group_assignment_map.end())
            group_assignment_map.erase(gamitr);

        // So far so good.  Now we see if we're supposed to be in any other networks,
        // and remove the reference
        map<mac_addr, string>::iterator bsgmitr = bssid_group_map.find(snet->bssid);
        if (bsgmitr != bssid_group_map.end())
            bssid_group_map.erase(bsgmitr);

        // Remove our assignment
        snet->dispnet = NULL;
    }

    // We've unassigned all the sub networks, so remove us from the tag map
    map<string, display_network *>::iterator gtmitr = group_tag_map.find(in_group->tag);
    if (gtmitr != group_tag_map.end())
        group_tag_map.erase(gtmitr);
    map<string, string>::iterator gnmitr = group_name_map.find(in_group->tag);
    if (gnmitr != group_name_map.end())
        group_name_map.erase(gnmitr);

    // Remove us from the vector
    for (unsigned int x = 0; x < group_vec.size(); x++) {
        if (group_vec[x] == in_group) {
            group_vec.erase(group_vec.begin() + x);
            break;
        }
    }

    // And free the memory
    delete in_group;
}

void Frontend::ReadGroupMap(FILE *in_file) {
    char dline[8192];

    char type[6];

    char parm1[MAC_STR_LEN];
    char parm2[1024];
    mac_addr bssid;


    // We have two formats:
    // GROUP: TAG NAME
    // LINK: BSSID TAG

    char format[64];
    // stupid sscanf not taking dynamic sizes
    snprintf(format, 64, "%%6[^:]: %%%d[^ ] %%1024[^\n]\n", MAC_STR_LEN);

    while (!feof(in_file)) {
        fgets(dline, 8192, in_file);

        if (feof(in_file)) break;

        // Fetch the line and continue if we're invalid...
        if (sscanf(dline, format, type, parm1, parm2) < 3)
            continue;

        if (!strncmp(type, "GROUP", 64)) {
            group_name_map[parm1] = parm2;
        } else if (!strncmp(type, "LINK", 64)) {
            bssid = parm1;
            if (bssid.error == 1)
                continue;
            bssid_group_map[bssid] = parm2;
        }

    }

    return;
}

void Frontend::WriteGroupMap(FILE *in_file) {
    char format[64];

    map<string, int> saved_groups;

    snprintf(format, 64, "GROUP: %%.%ds %%.1024s\n", MAC_STR_LEN);

    for (unsigned int x = 0; x < group_vec.size(); x++) {
        display_network *dnet = group_vec[x];

        // Don't save non-persistent groups
        if (dnet->persistent == 0)
            continue;

        // Don't save null virtnet
        if (dnet->virtnet == NULL)
            continue;

        // Don't save single-network groups that don't have custom names
        if (dnet->type != group_bundle && dnet->name == dnet->virtnet->ssid)
            continue;

        saved_groups[dnet->tag] = 1;
        fprintf(in_file, format, dnet->tag.c_str(), dnet->name.c_str());
    }

    // Now save groups that weren't live this run
    for (map<string, string>::iterator x = group_name_map.begin();
         x != group_name_map.end(); ++x) {

        if (saved_groups.find(x->first) != saved_groups.end())
            continue;

        if (group_tag_map.find(x->first) != group_tag_map.end()) {
            if (group_tag_map[x->first]->virtnet == NULL)
                continue;

            if (group_tag_map[x->first]->persistent == 0)
                continue;

            if (group_tag_map[x->first]->type != group_bundle &&
                group_tag_map[x->first]->name == group_tag_map[x->first]->virtnet->ssid)
                continue;
        }

        saved_groups[x->first] = 1;
        fprintf(in_file, format, x->first.c_str(), x->second.c_str());
    }

    snprintf(format, 64, "LINK: %%.%ds %%.%ds\n", MAC_STR_LEN, MAC_STR_LEN);
    for (map<mac_addr, string>::iterator x = bssid_group_map.begin();
         x != bssid_group_map.end(); ++x) {

        if (saved_groups.find(x->second) != saved_groups.end())
            fprintf(in_file, format, x->first.Mac2String().c_str(), x->second.c_str());
    }


    return;
}

void Frontend::ReadAPManufMap(FILE *in_file) {
    ap_manuf_map = ReadManufMap(in_file, 1);
}

void Frontend::ReadClientManufMap(FILE *in_file) {
    client_manuf_map = ReadManufMap(in_file, 0);
}

