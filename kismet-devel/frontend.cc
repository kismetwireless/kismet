#include "config.h"

#include <math.h>
#include "frontend.h"

void Frontend::PopulateGroups() {
    vector<wireless_network *> clientlist;

    clientlist = client->FetchNetworkList();

    // Convert the list
    for (unsigned int x = 0; x < clientlist.size(); x++) {
        wireless_network *net = clientlist[x];

        // Handle networks tagged for removal
        if (net->type == network_remove) {

            if (group_assignment_map.find(net->bssid) != group_assignment_map.end()) {
                // Otherwise we have to unlink it and track it down
                for (unsigned int y = 0; y < group_assignment_map[net->bssid]->networks.size(); y++) {
                    if (group_assignment_map[net->bssid]->networks[y] == net) {
                        group_assignment_map[net->bssid]->networks.erase(group_assignment_map[net->bssid]->networks.begin() + y);
                        break;
                    }
                }

                // So far so good.  Now we see if we're supposed to be in any other networks,
                // and remove the reference
                if (bssid_group_map.find(net->bssid) != bssid_group_map.end()) {
                    bssid_group_map.erase(bssid_group_map.find(net->bssid));
                }

                if (group_assignment_map[net->bssid]->type == group_host) {
                    DestroyGroup(group_assignment_map[net->bssid]);
                } else {
                    group_assignment_map.erase(group_assignment_map.find(net->bssid));
                }
            }

            client->RemoveNetwork(net->bssid);

            continue;
        }

        // Now, see if we've been assigned, if we have we can just keep going
        if (group_assignment_map.find(net->bssid) != group_assignment_map.end())
            continue;

        int newgroup = 0;
        display_network *group;
        string grouptag;

        // If they haven't been assigned, see if they belong to a group we know about
        if (bssid_group_map.find(net->bssid) != bssid_group_map.end()) {
            grouptag = bssid_group_map[net->bssid];

            // And see if the group has been created
            if (group_tag_map.find(grouptag) == group_tag_map.end())
                newgroup = 1;
            else
                group = group_tag_map[grouptag];
        } else {
            // Tell them to make a group, set the bssid as the tag and the SSID
            // as the name of the group
            grouptag = net->bssid;
            newgroup = 1;
        }

        // If we're making a new group, create it
        if (newgroup) {
            group = new display_network;

            if (group_name_map.find(grouptag) != group_name_map.end()) {
                group->name = group_name_map[grouptag];
            } else {
                group->name = net->ssid;
                group_name_map[grouptag] = net->ssid;
            }

            group->tag = grouptag;
            group->type = group_host;
            group->tagged = 0;
            group->expanded = 0;

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
    }

}

void Frontend::UpdateGroups() {
    list<display_network *> discard;

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
            dnet->virtnet = *dnet->networks[0];
            // Update the group name if it's <no ssid> and the ssid is set
            if (dnet->name == NOSSID && dnet->virtnet.ssid != NOSSID) {
                dnet->name = dnet->virtnet.ssid;
                group_name_map[dnet->tag] = dnet->name;
            }

            // Take the highest overall signal and power levels.  Noise just
            // tags along for the ride.  Only do this if the network has been touched
            // within the decay period
            if (time(0) - dnet->virtnet.last_time > decay) {
                dnet->virtnet.signal = 0;
                dnet->virtnet.quality = 0;
                dnet->virtnet.noise = 0;
            }


            continue;
        }

        if (dnet->type == group_empty) {
            discard.push_back(dnet);
            continue;
        }

        // Zero out the virtual network
        dnet->virtnet.ssid = "";
        dnet->virtnet.beacon_info = "";
        dnet->virtnet.llc_packets = dnet->virtnet.data_packets = dnet->virtnet.crypt_packets =
            dnet->virtnet.interesting_packets = dnet->virtnet.channel =
            dnet->virtnet.beacon = 0;
        dnet->virtnet.wep = -1;
        dnet->virtnet.cloaked = -1;

        dnet->virtnet.ipdata.atype = address_none;
        memset(dnet->virtnet.ipdata.range_ip, 0, 4);
        memset(dnet->virtnet.ipdata.mask, 0, 4);
        memset(dnet->virtnet.ipdata.gate_ip, 0, 4);
        dnet->virtnet.ipdata.octets = 4;
        dnet->virtnet.last_time = dnet->virtnet.first_time = 0;
        dnet->virtnet.bssid = "";
        dnet->virtnet.maxrate = 0;
        dnet->virtnet.quality = dnet->virtnet.signal = dnet->virtnet.noise = 0;

        memcpy(dnet->virtnet.bssid_raw, dnet->networks[0]->bssid_raw, MAC_LEN);
        unsigned int bssid_matched = MAC_LEN;

        for (unsigned int y = 0; y < dnet->networks.size(); y++) {
            wireless_network *wnet = dnet->networks[y];

            // Mask the bssid out
            for (unsigned int mask = 0; mask < bssid_matched; mask++) {
                if (dnet->virtnet.bssid_raw[mask] != wnet->bssid_raw[mask]) {
                    bssid_matched = mask;
                    break;
                }
            }

            // If we don't have a SSID get the first one we encounter
            if (dnet->virtnet.ssid == "" && wnet->ssid != "")
                dnet->virtnet.ssid = wnet->ssid;

            // If we don't have beacon info, get the first one we encounter
            if (dnet->virtnet.beacon_info == "" && wnet->beacon_info != "")
                dnet->virtnet.beacon_info = wnet->beacon_info;

            // Take the highest overall signal and power levels.  Noise just
            // tags along for the ride.  Only do this if the network has been touched
            // within the decay period
            if (time(0) - wnet->last_time <= decay) {
                if (wnet->signal >= dnet->virtnet.signal &&
                    wnet->quality >= dnet->virtnet.quality) {
                    dnet->virtnet.signal = wnet->signal;
                    dnet->virtnet.quality = wnet->quality;
                    dnet->virtnet.noise = wnet->noise;
                }
            }

            // Aggregate the packets
            dnet->virtnet.llc_packets += wnet->llc_packets;
            dnet->virtnet.data_packets += wnet->data_packets;
            dnet->virtnet.crypt_packets += wnet->crypt_packets;
            dnet->virtnet.interesting_packets += wnet->interesting_packets;

            // Negative the channel if we can't agree.  Any channel takes precedence
            // over channel 0.
            if (dnet->virtnet.channel == 0 && wnet->channel != 0)
                dnet->virtnet.channel = wnet->channel;
            else if (dnet->virtnet.channel > 0 && dnet->virtnet.channel != wnet->channel &&
                     wnet->channel != 0)
                dnet->virtnet.channel = 0;

            // If one channel isn't wep'ed, the group isn't wep'd
            if (dnet->virtnet.wep == -1)
                dnet->virtnet.wep = wnet->wep;
            else if (wnet->wep == 0)
                dnet->virtnet.wep = 0;

            // If one channel is cloaked, the group is cloaked
            if (dnet->virtnet.cloaked == -1)
                dnet->virtnet.cloaked = wnet->cloaked;
            else if (wnet->cloaked == 1)
                dnet->virtnet.cloaked = 1;

            // We get the oldest and latest for last and first
            if (dnet->virtnet.last_time == 0 || dnet->virtnet.last_time < wnet->last_time)
                dnet->virtnet.last_time = wnet->last_time;
            if (dnet->virtnet.first_time == 0 || dnet->virtnet.first_time > wnet->first_time)
                dnet->virtnet.first_time = wnet->first_time;

            // We get the smallest beacon interval
            if (dnet->virtnet.beacon == 0 || dnet->virtnet.beacon > wnet->beacon)
                dnet->virtnet.beacon = wnet->beacon;

            // We get the highest maxrate
            if (dnet->virtnet.maxrate == 0 || dnet->virtnet.maxrate < wnet->maxrate)
                dnet->virtnet.maxrate = wnet->maxrate;

            if (wnet->ipdata.atype > address_none) {
                int oct;
                for (oct = 0; oct < dnet->virtnet.ipdata.octets && oct < wnet->ipdata.octets && oct < 4; oct++) {
                    if (dnet->virtnet.ipdata.range_ip[oct] == 0 &&
                        wnet->ipdata.range_ip[oct] != 0)
                        dnet->virtnet.ipdata.range_ip[oct] = wnet->ipdata.range_ip[oct];
                    else if (dnet->virtnet.ipdata.range_ip[oct] != wnet->ipdata.range_ip[oct] ||
                             wnet->ipdata.range_ip[oct] == 0) {
                        dnet->virtnet.ipdata.range_ip[oct] = 0;
                        if (oct != 0)
                            oct--;
                        break;
                    }
                }

                dnet->virtnet.ipdata.octets = oct;
                dnet->virtnet.ipdata.atype = address_group;
            }

        }

        // Convert the masked semi-mac into something that looks real
        for (unsigned int macbit = 0; macbit < MAC_LEN; macbit++) {
            char adr[3];
            if (macbit < bssid_matched)
                snprintf(adr, 3, "%02X", dnet->virtnet.bssid_raw[macbit]);
            else
                snprintf(adr, 3, "**");

            dnet->virtnet.bssid += adr;
            dnet->virtnet.bssid += ":";

        }

        MatchBestManuf(&dnet->virtnet, 0);

        // Update the group name if it's <no ssid> and the ssid is set
        if (dnet->name == NOSSID && dnet->virtnet.ssid != NOSSID) {
            dnet->name = dnet->virtnet.ssid;
            group_name_map[dnet->tag] = dnet->name;
        }

    }

    // Destroy any marked for discard
    for (list<display_network *>::iterator x = discard.begin(); x != discard.end(); ++x) {
        DestroyGroup(*x);
    }

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
            if (group_assignment_map.find(snet->bssid) != group_assignment_map.end())
                group_assignment_map.erase(group_assignment_map.find(snet->bssid));

            // So far so good.  Now we see if we're supposed to be in any other networks,
            // and remove the reference
            if (bssid_group_map.find(snet->bssid) != bssid_group_map.end())
                bssid_group_map.erase(bssid_group_map.find(snet->bssid));

            // Now we tell them we belong to the new network
            bssid_group_map[snet->bssid] = core->tag;

            // Register that we're assigned...
            group_assignment_map[snet->bssid] = core;

            // And add us to the core network list
            core->networks.push_back(snet);
        }

        // Now we find all the pointers to this network from networks that aren't
        // currently live, and move them.  This keeps us from breaking grouping.
        for (map<string, string>::iterator iter = bssid_group_map.begin();
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
        if (group_assignment_map.find(snet->bssid) != group_assignment_map.end())
            group_assignment_map.erase(group_assignment_map.find(snet->bssid));

        // So far so good.  Now we see if we're supposed to be in any other networks,
        // and remove the reference
        if (bssid_group_map.find(snet->bssid) != bssid_group_map.end())
            bssid_group_map.erase(bssid_group_map.find(snet->bssid));
    }

    // We've unassigned all the sub networks, so remove us from the tag map
    group_tag_map.erase(group_tag_map.find(in_group->tag));
    group_name_map.erase(group_name_map.find(in_group->tag));

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
            bssid_group_map[parm1] = parm2;
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
            if (group_tag_map[x->first]->type != group_bundle &&
                group_tag_map[x->first]->name == group_tag_map[x->first]->virtnet.ssid)
                continue;
        }

        saved_groups[x->first] = 1;
        fprintf(in_file, format, x->first.c_str(), x->second.c_str());
    }

    snprintf(format, 64, "LINK: %%.%ds %%.%ds\n", MAC_STR_LEN, MAC_STR_LEN);
    for (map<string, string>::iterator x = bssid_group_map.begin();
         x != bssid_group_map.end(); ++x) {

        if (saved_groups.find(x->second) != saved_groups.end())
            fprintf(in_file, format, x->first.c_str(), x->second.c_str());
    }


    return;
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

