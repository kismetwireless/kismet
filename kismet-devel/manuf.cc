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

macmap<vector<manuf *> > ReadManufMap(FILE *in_file, int ap_map) {
    macmap<vector<manuf *> > ret;
    vector<manuf *> rvec;

    manuf *manf;

    // Push an unknown record
    manf = new manuf;
    manf->name = "Unknown";
    manf->model = "Unknown";
    manf->ssid_default = "";
    manf->mac_tag = "00:00:00:00:00:00";
    manf->channel_default = 0;
    memset(&manf->ipdata, 0, sizeof(net_ip_data));

    rvec.push_back(manf);
    ret.insert(manf->mac_tag, rvec);

    int linenum = 0;

    // Read from the file
    char dline[8192];
    while (!feof(in_file)) {
        fgets(dline, 8192, in_file);
        if (feof(in_file)) break;

        linenum++;

        // Cut the newline
        dline[strlen(dline) - 1] = '\0';

        vector<string> line_vec = StrTokenize(dline, "\t");

        manf = new manuf;
        manf->name = "";
        manf->model = "";
        manf->mac_tag = "";
        manf->ssid_default = "";
        manf->channel_default = 0;
        memset(&manf->ipdata, 0, sizeof(net_ip_data));

        // If we're loading a AP manuf map, we handle it this way
        if (line_vec.size() < 2) {
            delete manf;
            continue;
        }

        if (ap_map) {
            // If we're loading a AP manuf map, we handle it this way
            manf->mac_tag = line_vec[0].c_str();

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
                                for (unsigned int x = 0; x < 4; x++)
                                    manf->ipdata.range_ip[x] = ipr[x];
                            }
                        }
                    }
                }
            }

            if (ret.find(manf->mac_tag) != ret.end()) {
                ret[manf->mac_tag].push_back(manf);
            } else {
                rvec.clear();
                rvec.push_back(manf);
                ret.insert(manf->mac_tag, rvec);
            }
        } else {
            // Otherwise we handle clients this way

            manf->mac_tag = line_vec[0].c_str();

            manf->name = line_vec[1];
            if (line_vec.size() >= 3)
                manf->model = line_vec[2];

            if (ret.find(manf->mac_tag) != ret.end()) {
                ret[manf->mac_tag].push_back(manf);
            } else {
                rvec.clear();
                rvec.push_back(manf);
                ret.insert(manf->mac_tag, rvec);
            }

        }
    }

    ret.reindex();
    return ret;
}

// Find the best match for a likely manufacturer, based on tags (for clients) and
// default SSIDs, channel, etc (for access points)
// Returned in the parameters are the pointers to the best manufacturer record, the
// score, and the modified mac address which matched it
manuf *MatchBestManuf(macmap<vector<manuf *> > in_manuf, mac_addr in_mac, string in_ssid,
                      int in_channel, int in_wep, int in_cloaked, int *manuf_score) {
    manuf *best_manuf = NULL;
    int best_score = 0;
    int best_pos = 0;

    macmap<vector<manuf *> >::iterator mitr = in_manuf.find(in_mac);

    if (mitr != in_manuf.end()) {
        vector<manuf *> manuf_list = *(mitr->second);

        for (unsigned int x = 0; x < manuf_list.size(); x++) {
            manuf *likely_manuf = manuf_list[x];
            int score = 0;

            score += 6;
            if (in_ssid != "" && in_ssid == likely_manuf->ssid_default)
                score += 1;
            if (in_channel != 0 && in_channel == likely_manuf->channel_default)
                score += 1;
            if (in_wep)
                score -= 1;
            if (in_cloaked)
                score -= 1;

            if (score > best_score) {
                best_score = score;
                best_pos = x;
                best_manuf = likely_manuf;
            }
        }

    }

    *manuf_score = best_score;
    return best_manuf;
}

