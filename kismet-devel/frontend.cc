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

                if (ganet->type == group_host) {
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
        display_network *group;
        string grouptag;

        // If they haven't been assigned, see if they belong to a group we know about
        map<mac_addr, string>::iterator bsgmitr = bssid_group_map.find(net->bssid);
        if (bsgmitr != bssid_group_map.end()) {
            grouptag = bsgmitr->second;

            // And see if the group has been created
            if (group_tag_map.find(grouptag) == group_tag_map.end())
                newgroup = 1;
            else
                group = group_tag_map[grouptag];
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
            } else {
                group->name = net->ssid;
                group_name_map[grouptag] = net->ssid;
            }

            group->tag = grouptag;
            group->type = group_host;
            group->tagged = 0;
            group->expanded = 0;
            group->virtnet = NULL;

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
            dnet->virtnet = dnet->networks[0];

            curtime = dnet->virtnet->tcpclient->FetchTime();

            dnet->virtnet->idle_time = curtime - dnet->virtnet->last_time;

            // Update the group name if it's <no ssid> and the ssid is set
            if (dnet->name == NOSSID && dnet->virtnet->ssid != NOSSID) {
                dnet->name = dnet->virtnet->ssid;
                group_name_map[dnet->tag] = dnet->name;
            }

            // Take the highest overall signal and power levels.  Noise just
            // tags along for the ride.  Only do this if the network has been touched
            // within the decay period
            if (curtime - dnet->virtnet->last_time > (decay * 2)) {
                dnet->virtnet->signal = 0;
                dnet->virtnet->quality = 0;
                dnet->virtnet->noise = 0;
            }

            continue;
        }

        if (dnet->type == group_empty) {
            discard.push_back(dnet);
            continue;
        }

        // Otherwise we need to destroy the old virtual network and make a new one
        if (dnet->virtnet != dnet->networks[0])
            delete dnet->virtnet;
        dnet->virtnet = new wireless_network;

        unsigned int bssid_matched = MAC_LEN;

        for (unsigned int y = 0; y < dnet->networks.size(); y++) {
            wireless_network *wnet = dnet->networks[y];

            curtime = wnet->tcpclient->FetchTime();

            // Mask the bssid out
            for (unsigned int mask = 0; mask < bssid_matched; mask++) {
                if (dnet->virtnet->bssid[mask] != wnet->bssid[mask]) {
                    bssid_matched = mask;
                    break;
                }
            }

            // If we don't have a SSID get the first one we encounter
            if (dnet->virtnet->ssid == "" && wnet->ssid != "")
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
                if (wnet->signal >= dnet->virtnet->signal &&
                    wnet->quality >= dnet->virtnet->quality) {
                    dnet->virtnet->signal = wnet->signal;
                    dnet->virtnet->quality = wnet->quality;
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

            // Aggregate the packets
            dnet->virtnet->llc_packets += wnet->llc_packets;
            dnet->virtnet->data_packets += wnet->data_packets;
            dnet->virtnet->crypt_packets += wnet->crypt_packets;
            dnet->virtnet->interesting_packets += wnet->interesting_packets;

            // Aggregate the data
            dnet->virtnet->datasize += wnet->datasize;

            // Add all the clients
            for (map<mac_addr, wireless_client *>::iterator cli = wnet->client_map.begin();
                 cli != wnet->client_map.end(); ++cli)
                dnet->virtnet->client_map[cli->second->mac] = cli->second;

            // Negative the channel if we can't agree.  Any channel takes precedence
            // over channel 0.
            if (dnet->virtnet->channel == 0 && wnet->channel != 0)
                dnet->virtnet->channel = wnet->channel;
            else if (dnet->virtnet->channel > 0 && dnet->virtnet->channel != wnet->channel &&
                     wnet->channel != 0)
                dnet->virtnet->channel = 0;

            // If one channel isn't wep'ed, the group isn't wep'd
            if (dnet->virtnet->wep == -1)
                dnet->virtnet->wep = wnet->wep;
            else if (wnet->wep == 0)
                dnet->virtnet->wep = 0;

            // If one channel is cloaked, the group is cloaked
            if (dnet->virtnet->cloaked == -1)
                dnet->virtnet->cloaked = wnet->cloaked;
            else if (wnet->cloaked == 1)
                dnet->virtnet->cloaked = 1;

            // We get the oldest and latest for last and first
            if (dnet->virtnet->last_time == 0 || dnet->virtnet->last_time < wnet->last_time)
                dnet->virtnet->last_time = wnet->last_time;
            if (dnet->virtnet->first_time == 0 || dnet->virtnet->first_time > wnet->first_time)
                dnet->virtnet->first_time = wnet->first_time;

            // We get the smallest beacon interval
            if (dnet->virtnet->beacon == 0 || dnet->virtnet->beacon > wnet->beacon)
                dnet->virtnet->beacon = wnet->beacon;

            // We get the highest maxrate
            if (dnet->virtnet->maxrate == 0 || dnet->virtnet->maxrate < wnet->maxrate)
                dnet->virtnet->maxrate = wnet->maxrate;

            if (wnet->ipdata.atype > address_none) {
                int oct;
                for (oct = 0; oct < dnet->virtnet->ipdata.octets &&
                     oct < wnet->ipdata.octets && oct < 4; oct++) {
                    if (dnet->virtnet->ipdata.range_ip[oct] == 0 &&
                        wnet->ipdata.range_ip[oct] != 0)
                        dnet->virtnet->ipdata.range_ip[oct] = wnet->ipdata.range_ip[oct];
                    else if (dnet->virtnet->ipdata.range_ip[oct] != wnet->ipdata.range_ip[oct] ||
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

        dnet->virtnet->bssid.mask = bssid_matched;
        MatchBestManuf(client_manuf_map, dnet->virtnet->bssid, dnet->virtnet->ssid,
                       dnet->virtnet->channel, dnet->virtnet->wep, dnet->virtnet->cloaked,
                       &dnet->virtnet->manuf_key, &dnet->virtnet->manuf_score);

        // convert our map into a vector
        for (map<mac_addr, wireless_client *>::iterator cli = dnet->virtnet->client_map.begin();
             cli != dnet->virtnet->client_map.end(); ++cli) {

            if (curtime - cli->second->last_time > (decay * 2)) {
                cli->second->signal = 0;
                cli->second->quality = 0;
                cli->second->noise = 0;
            }

            dnet->virtnet->client_vec.push_back(cli->second);
        }

        // Update the group name if it's <no ssid> and the ssid is set
        if (dnet->name == NOSSID && dnet->virtnet->ssid != NOSSID) {
            dnet->name = dnet->virtnet->ssid;
            group_name_map[dnet->tag] = dnet->name;
        }

    }

    // Destroy any marked for discard
    for (list<display_network *>::iterator x = discard.begin(); x != discard.end(); ++x) {
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
        group_name_map.erase(group_name_map.find(dnet->tag));

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
        map<mac_addr, display_network *>::iterator gamitr = group_assignment_map.find(snet->bssid);
        if (gamitr != group_assignment_map.end())
            group_assignment_map.erase(gamitr);

        // So far so good.  Now we see if we're supposed to be in any other networks,
        // and remove the reference
        map<mac_addr, string>::iterator bsgmitr = bssid_group_map.find(snet->bssid);
        if (bsgmitr != bssid_group_map.end())
            bssid_group_map.erase(bsgmitr);
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
    // We're pretty selective here.  IF they don't exist in the group assignment
    // map, save them on the assumption they're an old record that didn't get activated
    // this run.  Otherwise, if they're not a group or if they don't have a custom name,
    // don't save them.
    for (map<string, string>::iterator x = group_name_map.begin();
         x != group_name_map.end(); ++x) {

        if (group_tag_map.find(x->first) != group_tag_map.end()) {
            if (group_tag_map[x->first]->virtnet == NULL)
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


/* Earth Distance and CalcRad stolen from gpsdrive.  Finds the distance between
 two points. */

double Frontend::Rad2Deg(double x) {
    return x*M_PI/180.0;
}


double Frontend::EarthDistance(double lat1, double lon1, double lat2, double lon2) {
    double x1 = CalcRad(lat1) * cos(Rad2Deg(lon1)) * sin(Rad2Deg(90-lat1));
    double x2 = CalcRad(lat2) * cos(Rad2Deg(lon2)) * sin(Rad2Deg(90-lat2));
    double y1 = CalcRad(lat1) * sin(Rad2Deg(lon1)) * sin(Rad2Deg(90-lat1));
    double y2 = CalcRad(lat2) * sin(Rad2Deg(lon2)) * sin(Rad2Deg(90-lat2));
    double z1 = CalcRad(lat1) * cos(Rad2Deg(90-lat1));
    double z2 = CalcRad(lat2) * cos(Rad2Deg(90-lat2));
    double a = acos((x1*x2 + y1*y2 + z1*z2)/pow(CalcRad((double) (lat1+lat2)/2),2));
    return CalcRad((double) (lat1+lat2) / 2) * a;
}

double Frontend::CalcRad(double lat)
{
    double a = 6378.137, r, sc, x, y, z;
    double e2 = 0.081082 * 0.081082;
    /*
     the radius of curvature of an ellipsoidal Earth in the plane of the
     meridian is given by

     R' = a * (1 - e^2) / (1 - e^2 * (sin(lat))^2)^(3/2)

     where a is the equatorial radius,
     b is the polar radius, and
     e is the eccentricity of the ellipsoid = sqrt(1 - b^2/a^2)

     a = 6378 km (3963 mi) Equatorial radius (surface to center distance)
     b = 6356.752 km (3950 mi) Polar radius (surface to center distance)
     e = 0.081082 Eccentricity
     */

    lat = lat * M_PI / 180.0;
    sc = sin (lat);
    x = a * (1.0 - e2);
    z = 1.0 - e2 * sc * sc;
    y = pow (z, 1.5);
    r = x / y;

    r = r * 1000.0;
    return r;
}

