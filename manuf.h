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

#ifndef __MANUF_H__
#define __MANUF_H__

#include "config.h"

#include <string>
#include <vector>
#include <map>
#include "packet.h"
#include "tracktypes.h"

// What we need to know about a manufacturer
class manuf {
public:
    string name;
    string model;

    mac_addr mac_tag;
    string ssid_default;
    int channel_default;

    net_ip_data ipdata;
};

extern int manuf_max_score;

// Read a manuf file
macmap<vector<manuf *> > ReadManufMap(FILE *in_file, int ap_map);
// Match the best manufacturer given a vector and pertinent info, returning the index to
// the matching manufacturer and the score in the parameters.  NULL's are acceptable.
manuf *MatchBestManuf(macmap<vector<manuf *> > in_manuf, mac_addr in_mac, string in_ssid,
                      int in_channel, int in_wep, int in_cloaked, int *manuf_score);

#endif
