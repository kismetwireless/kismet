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

#endif
