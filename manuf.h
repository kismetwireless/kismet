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
#include "tracktypes.h"

// What we need to know about a manufacturer
typedef struct {
    string name;
    string short_manuf;

    const uint8_t *mac_tag;
    unsigned int tag_len;

    string ssid_default;
    int channel_default;
    int wep_default;
    int cloaked_default;

    const net_ip_data *ipdata;

} manuf;

extern const manuf manuf_list[];

extern const int manuf_num;
extern const int manuf_max_score;

int MatchBestManuf(wireless_network *in_net, int in_set);
int MatchBestClientManuf(wireless_client *in_cli, int in_set);

#endif
