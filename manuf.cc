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

#include <stdio.h>

#include "manuf.h"
#include "packetracker.h"

int manuf_max_score = 8;

map<mac_addr, manuf *> ReadManufMap(FILE *in_file, int ap_map) {
    map<mac_addr, manuf *> ret;
    manuf *manf;

    manf = new manuf;
    manf->name = "Unknown";
    manf->model = "Unknown";
    manf->mac_tag = "00:00:00:00:00:00";
    manf->ssid_default = "";
    manf->channel_default = 0;
    memset(&manf->ipdata, 0, sizeof(net_ip_data));
    ret[manf->mac_tag] = manf;

    // Read from the file
    char dline[8192];
    while (!feof(in_file)) {
        manf = new manuf;
        manf->name = "";
        manf->model = "";
        manf->mac_tag = "";
        manf->ssid_default = "";
        manf->channel_default = 0;
        memset(&manf->ipdata, 0, sizeof(net_ip_data));

        fgets(dline, 8192, in_file);
        if (feof(in_file)) break;

        char tmac[18];
        vector<string> line_vec;
        char *pos = dline;
        char *nextpos, *nl;
        while ((nextpos = strchr(pos, '\t')) != NULL) {
            *nextpos++ = 0;
            if ((nl = strchr(pos, '\n')) != NULL)
                *nl = 0;
            line_vec.push_back(pos);
            pos = nextpos;
        }
        if ((nl = strchr(pos, '\n')) != NULL)
            *nl = 0;
        line_vec.push_back(pos);

        if (ap_map) {
            // If we're loading a AP manuf map, we handle it this way

            // Now convert our vector into the fields for manf... This is ugly as hell
            // but reasonably efficient, it works, and it only happens once.
            if (line_vec.size() < 2) {
                delete manf;
                continue;
            }

            // Turn our incoming fragment into a real MAC.  We can cheat and use
            // snprintf to automatically trim it appropriately.
            snprintf(tmac, 18, "%s:00:00:00", line_vec[0].c_str());
            manf->mac_tag = tmac;
            if (manf->mac_tag.longmac == 0) {
                delete manf;
                continue;
            }

            // Screen out dupes
            if (ret.find(manf->mac_tag) != ret.end()) {
                delete manf;
                continue;
            }

            manf->name = line_vec[1];
            if (line_vec.size() >= 3) {
                manf->model = line_vec[2];
                if (line_vec.size() >= 4) {
                    manf->ssid_default = line_vec[3];
                    if (line_vec.size() >= 5) {
                        int chan;
                        if (sscanf(line_vec[4].c_str(), "%d", &chan) == 1)
                            manf->channel_default = chan;
                        if (line_vec.size() >= 6) {
                            short int ipr[4];
                            if (sscanf(line_vec[5].c_str(), "%hd.%hd.%hd.%hd",
                                       &ipr[0], &ipr[1], &ipr[2], &ipr[3]) == 4) {
                                manf->ipdata.atype = address_factory;
                                manf->ipdata.octets = 4;
                                memcpy(manf->ipdata.range_ip, ipr, 4);
                            }
                        }
                    }
                }
            }
            ret[manf->mac_tag] = manf;

        } else {
            // Otherwise we handle clients this way
            if (line_vec.size() < 2) {
                delete manf;
                continue;
            }

            snprintf(tmac, 18, "%s:00:00:00", line_vec[0].c_str());
            manf->mac_tag = tmac;

            if (ret.find(manf->mac_tag) != ret.end()) {
                delete manf;
                continue;
            }

            manf->name = line_vec[1];
            if (line_vec.size() >= 3)
                manf->model = line_vec[2];
            ret[manf->mac_tag] = manf;
        }
    }

    return ret;
}

// Find the best match for a likely manufacturer, based on tags (for clients) and
// default SSIDs, channel, etc (for access points)
// Returned in the parameters are the pointers to the best manufacturer record, the
// score, and the modified mac address which matched it
void MatchBestManuf(map<mac_addr, manuf *> in_manuf, mac_addr in_mac, string in_ssid,
                    int in_channel, int in_wep, int in_cloaked,
                    mac_addr *manuf_mac, int *manuf_score) {
    mac_addr best_mac;
    manuf *likely_manuf;

    // Our incoming MAC sliced into 3 and 4 pairs - it's a lot more efficient to
    // do this once here than keep doing strcmp's!
    uint8_t tmac[6];
    mac_addr mac4, mac3;
    tmac[0] = in_mac[0];
    tmac[1] = in_mac[1];
    tmac[2] = in_mac[2];
    tmac[3] = in_mac[3];
    tmac[4] = 0x00;
    tmac[5] = 0x00;
    mac4 = tmac;
    tmac[3] = 0x00;
    mac3 = tmac;

    int score = 0;

    // Our best find is a 4-pair MAC, so look for one of those first...
    map<mac_addr, manuf *>::const_iterator mitr = in_manuf.find(mac4);
    if (mitr != in_manuf.end()) {
        likely_manuf = mitr->second;
        best_mac = mac4;
        score += 6;
        if (in_ssid != "" && in_ssid == likely_manuf->ssid_default)
            score += 1;
        if (in_channel != 0 && in_channel == likely_manuf->channel_default)
            score += 1;
        if (in_wep)
            score -= 1;
        if (in_cloaked)
            score -= 1;
    } else if ((mitr = in_manuf.find(mac3)) != in_manuf.end()) {
        // If we didn't get a 4-pair, look for a 3-pair to at least give some
        // inkling of what we are...
        likely_manuf = mitr->second;
        best_mac = mac3;
        score += 6;
        if (in_ssid != "" && in_ssid == likely_manuf->ssid_default)
            score += 1;
        if (in_channel != 0 && in_channel == likely_manuf->channel_default)
            score += 1;
        if (in_wep)
            score -= 1;
        if (in_cloaked)
            score -= 1;

    }

    *manuf_score = score;
    memcpy(manuf_mac, &best_mac, sizeof(mac_addr));
}

