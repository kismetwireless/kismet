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

#include "manuf.h"
#include "packetracker.h"

// Mostly taken from wi2600's ssid_defaults list
const uint8_t baystack_tag[] = {0x00, 0x20, 0x28};
const uint8_t intel_tag[] = {0x00, 0xA0, 0xF8};
const uint8_t intel2_tag[] = {0x00, 0x03, 0x47};
const uint8_t intel3_tag[] = {0x00, 0x02, 0xB3};
const uint8_t linksys_tag[] = {0x00, 0x04, 0x5A};
const uint8_t linksys2_tag[] = {0x00, 0x06, 0x25};
const uint8_t netgear_tag[] = {0x00, 0x30, 0xab};
const uint8_t smc_tag[] = {0x00, 0x90, 0xD1};
const uint8_t smc2_tag[] = {0x00, 0x04, 0xe2};
const uint8_t soho_tag[] = {0x00, 0x80, 0xc6};
const uint8_t symbol_tag[] = {0x00, 0xa0, 0x0f};
const uint8_t symbol2_tag[] = {0x00, 0xa0, 0xf8};
const uint8_t aironet_tag[] = {0x00, 0x40, 0x96};
const uint8_t agere_tag[] = {0x00, 0x02, 0x2d};
const uint8_t lucent_tag[] = {0x00, 0x60, 0x1d};
const uint8_t delta_tag[] = {0x00, 0x30, 0xAB};
const uint8_t gemtek_tag[] = {0x00, 0x90, 0x4B};
const uint8_t apple_tag[] = {0x00, 0x30, 0x65};
const uint8_t entera_tag[] = {0x00, 0x01, 0xF4};
const uint8_t acer_tag[] = {0x00, 0x01, 0x24};
const uint8_t trendware_tag[] = {0x00, 0x40, 0x05};
const uint8_t tcom_tag[] = {0x00, 0x50, 0xDA};
const uint8_t tcom2_tag[] = {0x00, 0xD0, 0xD8};
const uint8_t tcom3_tag[] = { 0x00, 0x04, 0x76};
const uint8_t tcom4_tag[] = {0x00, 0x04, 0x75};
const uint8_t tcom5_tag[] = {0x00, 0x01, 0x03};
const uint8_t cisco_tag[] = {0x00, 0x01, 0x64};
const uint8_t compaq_tag[] = {0x00, 0x02, 0xA5};
const uint8_t compaq2_tag[] = {0x00, 0x50, 0x8B};
const uint8_t dlink_tag[] = {0x00, 0x90, 0x91};
const uint8_t dlink2_tag[] = {0x00, 0x05, 0x5D};
const uint8_t umax_tag[] = {0x00, 0x10, 0x2B};
const uint8_t cabletron_tag[] = {0x00, 0xE0, 0x63};
const uint8_t accton_tag[] = {0x00, 0x30, 0xF1};
const uint8_t amit_tag[] = {0x00, 0x50, 0x18};
const uint8_t netwave_tag[] = {0x00, 0x20, 0xD8};
const uint8_t nexland_tag[] = {0x00, 0xA0, 0x65};
const uint8_t sony_tag[] = {0x08, 0x00, 0x46};
const uint8_t breezecom_tag[] = {0x00, 0x10, 0xE7};
const uint8_t xerox_tag[] = {0x00, 0x00, 0xAA};
const uint8_t zcom_tag[] = {0x00, 0x60, 0xB3};

const net_ip_data linksys_ip = {
    address_factory,
    3,
    { 192, 168, 0, 0 } ,
    { 255, 255, 255, 0 },
    { 0, 0, 0, 0 },
    { 192, 168, 0, 1 },
    0
};

const net_ip_data netgear_ip = {
    address_factory,
    3,
    { 192, 168, 0, 0 } ,
    { 255, 255, 255, 0 } ,
    { 0, 0, 0, 0 },
    { 192, 168, 0, 5 },
    0
};

const net_ip_data smc_ip = {
    address_factory,
    3,
    { 192, 168, 0, 0 } ,
    { 255, 255, 255, 0 },
    { 0, 0, 0, 0 },
    { 192, 168, 0, 254 },
    0
};

const net_ip_data dlink_ip = {
    address_factory,
    3,
    { 192, 168, 0, 0 } ,
    { 255, 255, 255, 0 },
    { 0, 0, 0, 0 },
    { 192, 168, 0, 1 },
    0
};

// Don't forget to update the count at the bottom when you change this!!
const manuf manuf_list[] = {
    { "3com Airconnect", "3com", tcom_tag, 3, "comcomcom", 0, 0, 0, NULL },
    { "3com Airconnect", "3com", tcom2_tag, 3, "comcomcom", 0, 0, 0, NULL },
    { "3com Airconnect", "3com", tcom3_tag, 3, "comcomcom", 0, 0, 0, NULL },
    { "3com Airconnect", "3com", tcom4_tag, 3, "comcomcom", 0, 0, 0, NULL },
    { "3com Airconnect", "3com", tcom5_tag, 3, "comcomcom", 0, 0, 0, NULL },
    { "Acer", "Acer", acer_tag, 3, "", 0, 0, 0, NULL },
    { "Accton", "Accton", accton_tag, 3, "", 0, 0, 0, NULL },
    { "Advanced Multimedia", "AMIT", amit_tag, 3, "", 0, 0, 0, NULL },
    { "Apple Airport", "Apple", apple_tag, 3, "", 0, 0, 0, NULL },
    { "Aironet BRxxxx", "Aironet", aironet_tag, 3, "2", 0, 0, 0, NULL },
    { "Aironet BRxxxx", "Aironet", aironet_tag, 3, "tsunami", 0, 0, 0, NULL },
    { "Baystack 650/660", "Baystack", baystack_tag, 3, "Default SSID", 1, 0, 0, NULL },
    { "BreezeCom", "Breezecom", breezecom_tag, 3, "", 0, 0, 0, NULL },
    { "Cabletron", "Cabletron", cabletron_tag, 3, "", 0, 0, 0, NULL },
    { "Cisco", "Cisco", cisco_tag, 3, "", 0, 0, 0, NULL },
    { "Compaq Wl-100", "Compaq", compaq_tag, 3, "Compaq", 0, 0, 0, NULL },
    { "Compaq Wl-100", "Compaq", compaq2_tag, 3, "Compaq", 0, 0, 0, NULL },
    { "Dlink DL-713", "Dlink", dlink_tag, 3, "WLAN", 11, 0, 0, &dlink_ip },
    { "Dlink DL-713", "Dlink", dlink2_tag, 3, "WLAN", 11, 0, 0, &dlink_ip },
    { "Dlink", "Dlink", dlink_tag, 3, "default", 6, 0, 0, &dlink_ip },
    { "Dlink", "Dlink", dlink2_tag, 3, "default", 6, 0, 0, &dlink_ip },
    { "Entera", "Entera", entera_tag, 3, "", 0, 0, 0, NULL },
    { "Gemtek", "Gemtek", gemtek_tag, 3, "default", 6, 0, 0, NULL },
    { "Intel Pro/Wireless 2011", "Intel", intel_tag, 3, "101", 3, 0, 0, NULL },
    { "Intel Pro/Wireless 2011", "Intel", intel_tag, 3, "xlan", 3, 0, 0, NULL },
    { "Intel Pro/Wireless 2011", "Intel", intel_tag, 3, "intel", 3, 0, 0, NULL },
    { "Intel Pro/Wireless 2011", "Intel", intel_tag, 3, "195", 3, 0, 0, NULL },
    { "Intel Pro/Wireless 2011", "Intel", intel2_tag, 3, "101", 3, 0, 0, NULL },
    { "Intel Pro/Wireless 2011", "Intel", intel2_tag, 3, "xlan", 3, 0, 0, NULL },
    { "Intel Pro/Wireless 2011", "Intel", intel2_tag, 3, "intel", 3, 0, 0, NULL },
    { "Intel Pro/Wireless 2011", "Intel", intel2_tag, 3, "195", 3, 0, 0, NULL },
    { "Intel Pro/Wireless 2011", "Intel", intel3_tag, 3, "101", 3, 0, 0, NULL },
    { "Intel Pro/Wireless 2011", "Intel", intel3_tag, 3, "xlan", 3, 0, 0, NULL },
    { "Intel Pro/Wireless 2011", "Intel", intel3_tag, 3, "intel", 3, 0, 0, NULL },
    { "Intel Pro/Wireless 2011", "Intel", intel3_tag, 3, "195", 3, 0, 0, NULL },
    { "Linksys", "Linksys", linksys_tag, 3, "linksys",  6, 0, 0, &linksys_ip },
    { "Linksys", "Linksys", linksys2_tag, 3, "linksys", 6, 0, 0, &linksys_ip },
    { "Netgear ME102/MA401", "Netgear", netgear_tag, 3, "Wireless", 6, 0, 0, &netgear_ip },
    { "Netwave", "Netwave", netwave_tag, 3, "", 0, 0, 0, NULL },
    { "NexLand", "NexLand", nexland_tag, 3, "NexLand", 5, 0, 0, NULL },
    { "SMC", "SMC", smc_tag, 3, "WLAN", 11, 0, 0, &smc_ip },
    { "SMC", "SMC", smc2_tag, 3, "WLAN", 11, 0, 0, &smc_ip },
    { "SMC EZ-Connect Bridge", "SMC", smc_tag, 3, "BRIDGE", 11, 0, 0, &smc_ip },
    { "Sony", "Sony", sony_tag, 3, "", 0, 0, 0, NULL},
    { "SOHOware Netblaster II", "SOHO", soho_tag, 3, "", 8, 0, 0, NULL },
    { "Symbol AP41x1/LA41x1", "Symbol", symbol_tag, 3, "101", 11, 0, 0, NULL },
    { "Symbol AP41x1/LA41x1", "Symbol", symbol2_tag, 3, "101", 11, 0, 0, NULL },
    { "Trendware", "Trendware", trendware_tag, 3, "", 0, 0, 0, NULL },
    { "Wavelan", "Agere", agere_tag, 3, "WaveLAN Network", 3, 0, 0, NULL },
    { "Wavelan", "Lucent", lucent_tag, 3, "WaveLAN Network", 3, 0, 0, NULL },
    { "Z-Com", "Zcom", NULL, 0, "", 0, 0, 0, NULL },
    { "ZCOMAX 2mbit", "ZCOMAX", NULL, 0, "any", 0, 0, 0, NULL },
    { "ZCOMAX 2mbit", "ZCOMAX", NULL, 0, "mello", 0, 0, 0, NULL },
    { "ZCOMAX 2mbit", "ZCOMAX", NULL, 0, "Test", 0, 0, 0, NULL },
    { "ZYXEL Prestige 316", "ZYXEL", delta_tag, 3, "Wireless", 1, 0, 0, NULL },
    { "ZYXEL Prestige 316", "ZYXEL", delta_tag, 3, "Wireless", 6, 0, 0, NULL },
};

const int manuf_num = 56;
const int manuf_max_score = 9;


// Find the best match for a manufacturer, based on manufacturer tags, default SSIDs, etc.
// This score also determines if we are a default configuration or not.
//
// The most important ID method is MAC owner blocks (5 points)
// SSID, channel, and wep are each worth 1 point
// if a network has a max score, its completely default
// Further tests can be integrated later.
int MatchBestManuf(wireless_network *in_net, int in_set) { /*FOLD00*/
    int best_score = in_net->manuf_score;
    int best_match = in_net->manuf_id;

    for (int x = 0; x < manuf_num; x++) {
        int score = 0;

        if (manuf_list[x].tag_len > 0) {
            int tagmatch = 1;
            for (unsigned int y = 0; y < manuf_list[x].tag_len; y++) {
                if (in_net->bssid[y] != manuf_list[x].mac_tag[y]) {
                    tagmatch = 0;
                    break;
                }
            }

            if (tagmatch)
                score += 5;
        }

        if (in_net->ssid == manuf_list[x].ssid_default && manuf_list[x].ssid_default != "")
            score += 1;

        if (in_net->channel == manuf_list[x].channel_default && manuf_list[x].channel_default != 0)
            score += 1;

        if (in_net->wep == manuf_list[x].wep_default)
            score += 1;

        if (in_net->cloaked == manuf_list[x].cloaked_default)
            score += 1;

        if (score > best_score && score >= 5) {
            best_score = score;
            best_match = x;
            if (best_score == manuf_max_score)
                break;
        }

    }

    if (in_set) {
        in_net->manuf_score = best_score;
        in_net->manuf_id = best_match;

        if (best_score == manuf_max_score) {
            if (manuf_list[best_match].ipdata != NULL && in_net->ipdata.atype == address_none) {
                memcpy(&in_net->ipdata, manuf_list[best_match].ipdata, sizeof(net_ip_data));
            }
        }
    }

    return best_match;
}
