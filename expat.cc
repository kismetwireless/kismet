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

#ifdef HAVE_EXPAT

#include <stdio.h>
#include <string.h>
#include <string>

#include <expat.h>

#include "tracktypes.h"

#include "expat.h"

// THIS IS NOT MULTITHREAD SAFE BY ANY STRETCH OF THE IMAGINATION.  UNDER NO
// CIRCUMSTANCES SHOULD ANY FUNCTIONS IN THIS MODULE BE CALLED CONCURRENTLY.

// This would be a class, but expat needs C callbacks, which is annoying, so
// C it is.  Theres probably a better way to do this but this will suffice for now.
// It's only used in one or two segments of code.

#define BUFFSIZE    8192

// Reading buffer
char Buff[BUFFSIZE];

// Network we're building
wireless_network *building_net;
cdp_packet *building_cdp;

// Vector of networks
vector<wireless_network *> netvec;

float net_kisversion;
time_t net_run_start, net_run_end;

// Every fricking possible XML node.
enum net_xml_node {
    net_node_none,
    net_node_detection_run,
    net_node_comment,
    net_node_wireless_network,
    net_node_wn_expired, // An expired XML tag we don't use anymore
    net_node_wn_SSID, net_node_wn_BSSID, net_node_wn_info,
    net_node_wn_channel, net_node_wn_maxrate, net_node_wn_maxseenrate,
    net_node_wn_carrier, net_node_wn_encoding, net_node_wn_datasize,
    net_node_packdata,
    net_node_pk_LLC, net_node_pk_data, net_node_pk_crypt, net_node_pk_weak, net_node_pk_total, net_node_pk_dupeiv,
    net_node_gpsdata,
    net_node_gps_expired,
    net_node_gps_min_lat, net_node_gps_max_lat, net_node_gps_min_lon, net_node_gps_max_lon,
    net_node_gps_min_alt, net_node_gps_max_alt, net_node_gps_min_spd, net_node_gps_max_spd,
    net_node_ipdata,
    net_node_ip_range, net_node_ip_mask, net_node_ip_gateway,
    net_node_cisco,
    net_node_cdp_cap, net_node_cdp_device_id, net_node_cdp_interface, net_node_cdp_ip,
    net_node_cdp_platform, net_node_cdp_software,
    net_node_wireless_client,
    net_node_wc_mac, net_node_wc_datasize, net_node_wc_maxrate, net_node_wc_maxseenrate,
    net_node_wc_encoding, net_node_wc_channel,
    net_node_wc_ip_address,
    net_node_wc_packdata,
    net_node_wc_pk_data, net_node_wc_pk_crypt, net_node_wc_pk_weak,
    net_node_wc_gpsdata,
    net_node_wc_gps_min_lat, net_node_wc_gps_max_lat, net_node_wc_gps_min_lon, net_node_wc_gps_max_lon,
    net_node_wc_gps_min_alt, net_node_wc_gps_max_alt, net_node_wc_gps_min_spd, net_node_wc_gps_max_spd,
    net_xml_node_maxnode
};

// What type of node are we working on right now
net_xml_node netnode;

#define net_node_numnodes net_xml_node_maxnode
string xmlstrnodes[net_node_numnodes];

// Does a string consist of anything but whitespace?
int XMLIsBlank(string s) {
    if (s.length() == 0)
        return 1;

    for (unsigned int i = 0; i < s.length(); i++) {
        if (' ' != s[i] && '\t' != s[i] && '\n' != s[i] && '\r' != s[i]) {
            return 0;
        }
    }

    return 1;
}

// Convert an ascii time string into a time_t
time_t XMLAsc2Time(const char *in_asctime) {
    // "Tue May 21 20:32:51 2002"

    char dow[4], mon[4];
    struct tm broketime;

    if (sscanf(in_asctime, "%3s %3s %d %d:%d:%d %d", dow, mon,
               &broketime.tm_mday, &broketime.tm_hour, &broketime.tm_min, &broketime.tm_sec,
               &broketime.tm_year) < 7)
        return 0;

    // Convert the year down
    broketime.tm_year -= 1900;

    // Translate the month
    // Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec
    // F  Mar May Ap Au Ja Jun Jul S O  N  D
    // 1  2   4   3  7  0  5   6   8 9  10 11
    if (mon[0] == 'F')
        broketime.tm_mon = 1;
    else if (mon[0] == 'S')
        broketime.tm_mon = 8;
    else if (mon[0] == 'O')
        broketime.tm_mon = 9;
    else if (mon[0] == 'N')
        broketime.tm_mon = 10;
    else if (mon[0] == 'D')
        broketime.tm_mon = 11;
    else if (memcmp(mon, "Ap", 2) == 0)
        broketime.tm_mon = 3;
    else if (memcmp(mon, "Au", 2) == 0)
        broketime.tm_mon = 7;
    else if (memcmp(mon, "Ja", 2) == 0)
        broketime.tm_mon = 0;
    else if (memcmp(mon, "Mar", 3) == 0)
        broketime.tm_mon = 2;
    else if (memcmp(mon, "May", 3) == 0)
        broketime.tm_mon = 4;
    else if (memcmp(mon, "Jun", 3) == 0)
        broketime.tm_mon = 5;
    else if (memcmp(mon, "Jul", 3) == 0)
        broketime.tm_mon = 6;

    time_t timet = mktime(&broketime);

    return timet;

}

// Convert a network from the string structs to a wireless network struct
int NetXmlStr2Struct(wireless_network *in_net) {
    if (XMLIsBlank(xmlstrnodes[net_node_wn_SSID]))
        in_net->ssid = NOSSID;
    else
        in_net->ssid = xmlstrnodes[net_node_wn_SSID];

    if (XMLIsBlank(xmlstrnodes[net_node_wn_BSSID])) {
        fprintf(stderr, "WARNING:  Invalid (blank) BSSID, rest of network will not be processed.\n");
        return -1;
    } else {
        in_net->bssid = xmlstrnodes[net_node_wn_BSSID].c_str();

        if (in_net->bssid.longmac == 0) {
            fprintf(stderr, "WARNING:  Illegal BSSID '%s', skipping rest of network.\n",
                    xmlstrnodes[net_node_wn_BSSID].c_str());
            return -1;
        }
    }

    if (XMLIsBlank(xmlstrnodes[net_node_wn_info]))
        in_net->beacon_info = "";
    else
        in_net->beacon_info = xmlstrnodes[net_node_wn_info];

    if (sscanf(xmlstrnodes[net_node_wn_channel].c_str(), "%d", &in_net->channel) < 1) {
        fprintf(stderr, "WARNING:  Illegal channel '%s', skipping rest of network.\n",
                xmlstrnodes[net_node_wn_channel].c_str());
        return -1;
    }

    if (sscanf(xmlstrnodes[net_node_wn_maxrate].c_str(), "%f", (float *) &in_net->maxrate) < 1) {
        fprintf(stderr, "WARNING:  Illegal maxrate '%s', skipping rest of network.\n",
                xmlstrnodes[net_node_wn_maxrate].c_str());
        return -1;
    }

    if (sscanf(xmlstrnodes[net_node_pk_LLC].c_str(), "%d", &in_net->llc_packets) < 1) {
        fprintf(stderr, "WARNING:  Illegal LLC packet count '%s', skipping rest of network.\n",
                xmlstrnodes[net_node_pk_LLC].c_str());
        return -1;
    }

    if (sscanf(xmlstrnodes[net_node_pk_data].c_str(), "%d", &in_net->data_packets) < 1) {
        fprintf(stderr, "WARNING:  Illegal data packet count '%s', skipping rest of network.\n",
                xmlstrnodes[net_node_pk_data].c_str());
        return -1;
    }

    if (sscanf(xmlstrnodes[net_node_pk_crypt].c_str(), "%d", &in_net->crypt_packets) < 1) {
        fprintf(stderr, "WARNING:  Illegal crypt packet count '%s', skipping rest of network.\n",
                xmlstrnodes[net_node_pk_crypt].c_str());
        return -1;
    }

    if (sscanf(xmlstrnodes[net_node_pk_weak].c_str(), "%d", &in_net->interesting_packets) < 1) {
        fprintf(stderr, "WARNING:  Illegal weak packet count '%s', skipping rest of network.\n",
                xmlstrnodes[net_node_pk_weak].c_str());
        return -1;
    }

    if (xmlstrnodes[net_node_pk_dupeiv].length() > 0) {
        if (sscanf(xmlstrnodes[net_node_pk_dupeiv].c_str(), "%d", &in_net->dupeiv_packets) < 1) {
            fprintf(stderr, "WARNING:  Illegal dupeiv packet count '%s', skipping rest of network.\n",
                    xmlstrnodes[net_node_pk_dupeiv].c_str());
            return -1;
        }
    }

    if (in_net->gps_fixed && xmlstrnodes[net_node_gps_min_lat] != "") {
        if (sscanf(xmlstrnodes[net_node_gps_min_lat].c_str(), "%f", &in_net->min_lat) < 1) {
            fprintf(stderr, "WARNING:  Illegal min lat '%s', skipping rest of network.\n",
                    xmlstrnodes[net_node_gps_min_lat].c_str());
            return -1;
        }

        if (sscanf(xmlstrnodes[net_node_gps_max_lat].c_str(), "%f", &in_net->max_lat) < 1) {
            fprintf(stderr, "WARNING:  Illegal max lat '%s', skipping rest of network.\n",
                    xmlstrnodes[net_node_gps_max_lat].c_str());
            return -1;
        }

        if (sscanf(xmlstrnodes[net_node_gps_min_lon].c_str(), "%f", &in_net->min_lon) < 1) {
            fprintf(stderr, "WARNING:  Illegal min lon '%s', skipping rest of network.\n",
                    xmlstrnodes[net_node_gps_min_lon].c_str());
            return -1;
        }

        if (sscanf(xmlstrnodes[net_node_gps_max_lon].c_str(), "%f", &in_net->max_lon) < 1) {
            fprintf(stderr, "WARNING:  Illegal max lon '%s', skipping rest of network.\n",
                    xmlstrnodes[net_node_gps_max_lon].c_str());
            return -1;
        }

        if (sscanf(xmlstrnodes[net_node_gps_min_alt].c_str(), "%f", &in_net->min_alt) < 1) {
            fprintf(stderr, "WARNING:  Illegal min alt '%s', skipping rest of network.\n",
                    xmlstrnodes[net_node_gps_min_alt].c_str());
            return -1;
        }

        if (sscanf(xmlstrnodes[net_node_gps_max_alt].c_str(), "%f", &in_net->max_alt) < 1) {
            fprintf(stderr, "WARNING:  Illegal max alt '%s', skipping rest of network.\n",
                    xmlstrnodes[net_node_gps_max_alt].c_str());
            return -1;
        }

        if (sscanf(xmlstrnodes[net_node_gps_min_spd].c_str(), "%f", &in_net->min_spd) < 1) {
            fprintf(stderr, "WARNING:  Illegal min spd in '%s', skipping rest of network.\n",
                    xmlstrnodes[net_node_gps_min_spd].c_str());
            return -1;
        }

        if (sscanf(xmlstrnodes[net_node_gps_max_spd].c_str(), "%f", &in_net->max_spd) < 1) {
            fprintf(stderr, "WARNING:  Illegal max spd in '%s', skipping test of network.\n",
                    xmlstrnodes[net_node_gps_max_spd].c_str());
            return -1;
        }
    }

    if (XMLIsBlank(xmlstrnodes[net_node_ip_range])) {
        memset(&in_net->ipdata.range_ip, 0, sizeof(uint8_t) * 4);
    } else {
        short int ip[4];
        if (sscanf(xmlstrnodes[net_node_ip_range].c_str(), "%hd.%hd.%hd.%hd",
                   &ip[0], &ip[1], &ip[2], &ip[3]) < 4) {
            fprintf(stderr, "WARNING:  Illegal ip-range '%s', skipping rest of network.\n",
                    xmlstrnodes[net_node_ip_range].c_str());
            return -1;
        }

        in_net->ipdata.range_ip[0] = ip[0];
        in_net->ipdata.range_ip[1] = ip[1];
        in_net->ipdata.range_ip[2] = ip[2];
        in_net->ipdata.range_ip[3] = ip[3];

    }

    return 1;
}

// Convert a network from the string structs to an actually wireless network struct
int NetXmlCisco2Struct(wireless_network *in_net, cdp_packet *in_cdp) {

    if (XMLIsBlank(xmlstrnodes[net_node_cdp_device_id])) {
        fprintf(stderr, "WARNING:  Blank cdp device-id\n");
    }

    snprintf(in_cdp->dev_id, 128, "%s", xmlstrnodes[net_node_cdp_device_id].c_str());

    if (XMLIsBlank(xmlstrnodes[net_node_cdp_interface]))
        in_cdp->interface[0] = '\0';
    else
        snprintf(in_cdp->interface, 128, "%s", xmlstrnodes[net_node_cdp_interface].c_str());

    if (XMLIsBlank(xmlstrnodes[net_node_cdp_ip])) {
        memset(&in_cdp->ip, 0, sizeof(uint8_t) * 4);
    } else {
        if (sscanf(xmlstrnodes[net_node_cdp_ip].c_str(), "%d.%d.%d.%d",
                   (unsigned int *) &in_cdp->ip[0], (unsigned int *) &in_cdp->ip[1],
                   (unsigned int *) &in_cdp->ip[2], (unsigned int *) &in_cdp->ip[3]) < 4) {
            fprintf(stderr, "WARNING:  Illegal cdp-ip '%s', skipping rest of network.\n",
                    xmlstrnodes[net_node_cdp_ip].c_str());
            return -1;
        }
    }

    if (XMLIsBlank(xmlstrnodes[net_node_cdp_platform]))
        in_cdp->platform[0] = '\0';
    else
        snprintf(in_cdp->platform, 128, "%s", xmlstrnodes[net_node_cdp_platform].c_str());

    if (XMLIsBlank(xmlstrnodes[net_node_cdp_software]))
        in_cdp->software[0] = '\0';
    else
        snprintf(in_cdp->software, 512, "%s", xmlstrnodes[net_node_cdp_software].c_str());

    in_net->cisco_equip[in_cdp->dev_id] = *in_cdp;

    return 1;
}

static void xpat_net_start(void *data, const char *el, const char **attr) {
    if (netnode == net_node_none) {
        if (strcasecmp(el, "detection-run") == 0) {
            netnode = net_node_detection_run;

            for (int i = 0; attr[i]; i += 2) {
                if (strcasecmp(attr[i], "kismet-version") == 0) {
                    if (sscanf(attr[i+1], "%f", &net_kisversion) < 1) {
                        fprintf(stderr, "WARNING:  Illegal value '%s' for kismet version\n",
                                attr[i+1]);
                    }
                } else if (strcasecmp(attr[i], "start-time") == 0) {
                    net_run_start = XMLAsc2Time(attr[i+1]);
                } else if (strcasecmp(attr[i], "end-time") == 0) {
                    net_run_end = XMLAsc2Time(attr[i+1]);
                } else {
                    fprintf(stderr, "WARNING: Illegal attribute '%s' on detection-run\n",
                            attr[i]);
                }

            }

        } else {
            fprintf(stderr, "WARNING: Illegal tag '%s' at base level\n", el);
        }
    } else if (netnode == net_node_detection_run) {
        if (strcasecmp(el, "comment") == 0) {
            netnode = net_node_comment;
        } else if (strcasecmp(el, "wireless-network") == 0) {
            netnode = net_node_wireless_network;

            for (int i = 0; attr[i]; i += 2) {
                if (strcasecmp(attr[i], "type") == 0) {
                    if (strcasecmp(attr[i+1], "infrastructure") == 0)
                        building_net->type = network_ap;
                    else if (strcasecmp(attr[i+1], "ad-hoc") == 0)
                        building_net->type = network_adhoc;
                    else if (strcasecmp(attr[i+1], "probe") == 0)
                        building_net->type = network_probe;
                    else if (strcasecmp(attr[i+1], "data") == 0)
                        building_net->type = network_data;
                    else if (strcasecmp(attr[i+1], "lucent") == 0)
                        building_net->type = network_turbocell;
                    else if (strcasecmp(attr[i+1], "turbocell") == 0)
                        building_net->type = network_turbocell;
                    else if (strcasecmp(attr[i+1], "unknown") == 0)
                        building_net->type = network_data;
                    else {
                        fprintf(stderr, "WARNING:  Illegal type '%s' on wireless-network\n",
                                attr[i+1]);
                        building_net->type = network_data;
                    }
                } else if (strcasecmp(attr[i], "number") == 0)
                    ; // do nothing about the number
                else if (strcasecmp(attr[i], "wep") == 0) {
                    if (strcasecmp(attr[i+1], "true") == 0)
                        building_net->wep = 1;
                    else
                        building_net->wep = 0;
                } else if (strcasecmp(attr[i], "cloaked") == 0) {
                    if (strcasecmp(attr[i+1], "true") == 0)
                        building_net->cloaked = 1;
                    else
                        building_net->cloaked = 0;
                } else if (strcasecmp(attr[i], "first-time") == 0) {
                    building_net->first_time = XMLAsc2Time(attr[i+1]);
                } else if (strcasecmp(attr[i], "last-time") == 0) {
                    building_net->last_time = XMLAsc2Time(attr[i+1]);
                } else if (strcasecmp(attr[i], "carrier") == 0) {
                    // We need to do something smarter with this
                } else {
                    fprintf(stderr, "WARNING:  Illegal attribute '%s' on wireless-network\n",
                            attr[i]);
                }
            }
        } else {
            fprintf(stderr, "WARNING:  Illegal tag '%s' in detection-run\n", el);
        }
    } else if (netnode == net_node_wireless_network) {
        if (strcasecmp(el, "SSID") == 0) {
            netnode = net_node_wn_SSID;
        } else if (strcasecmp(el, "BSSID") == 0) {
            netnode = net_node_wn_BSSID;
        } else if (strcasecmp(el, "info") == 0) {
            netnode = net_node_wn_info;
        } else if (strcasecmp(el, "channel") == 0) {
            netnode = net_node_wn_channel;
        } else if (strcasecmp(el, "maxrate") == 0) {
            netnode = net_node_wn_maxrate;
        } else if (strcasecmp(el, "maxseenrate") == 0) {
            netnode = net_node_wn_maxseenrate;
        } else if (strcasecmp(el, "carrier") == 0) {
            netnode = net_node_wn_carrier;
        } else if (strcasecmp(el, "encoding") == 0) {
            netnode = net_node_wn_encoding;
        } else if (strcasecmp(el, "packets") == 0) {
            netnode = net_node_packdata;
        } else if (strcasecmp(el, "datasize") == 0) {
            netnode = net_node_wn_datasize;
        } else if (strcasecmp(el, "gps-info") == 0) {
            netnode = net_node_gpsdata;

            building_net->gps_fixed = 2;

            for (int i = 0; attr[i]; i += 2) {
                 if (strcasecmp(attr[i], "unit") == 0) {
                    if (strcasecmp(attr[i+1], "metric") == 0)
                        building_net->metric = 1;
                    else
                        building_net->metric = 0;
                } else {
                    fprintf(stderr, "WARNING:  Illegal attribute '%s' on gps-info\n",
                            attr[i]);
                }
            }

        } else if (strcasecmp(el, "ip-address") == 0) {
            netnode = net_node_ipdata;

            for (int i = 0; attr[i]; i += 2) {
                if (strcasecmp(attr[i], "type") == 0) {
                    if (strcasecmp(attr[i], "none") == 0)
                        building_net->ipdata.atype = address_none;
                    else if (strcasecmp(attr[i+1], "arp") == 0)
                        building_net->ipdata.atype = address_arp;
                    else if (strcasecmp(attr[i+1], "udp") == 0)
                        building_net->ipdata.atype = address_udp;
                    else if (strcasecmp(attr[i+1], "tcp") == 0)
                        building_net->ipdata.atype = address_tcp;
                    else if (strcasecmp(attr[i+1], "dhcp") == 0)
                        building_net->ipdata.atype = address_dhcp;
                    else {
                        building_net->ipdata.atype = address_none;
                        fprintf(stderr, "WARNING:  Illegal value '%s' on ip-address type\n",
                               attr[i+1]);
                    }
                } else {
                    fprintf(stderr, "WARNING:  Illegal attribute '%s' on ip-address\n",
                            attr[i]);
                }
            }

        } else if (strcasecmp(el, "wireless-client") == 0) {
            netnode = net_node_wireless_client;

            // We don't parse any other attributes of wireless clients right now

        } else if (strcasecmp(el, "cisco") == 0) {
            netnode = net_node_cisco;

            for (int i = 0; attr[i]; i += 2) {
                if (strcasecmp(attr[i], "number") == 0)
                    ; // Do nothing about the number
                else
                    fprintf(stderr, "WARNING:  Illegal attribute '%s' on cisco\n",
                            attr[i]);
            }

        } else {
            fprintf(stderr, "WARNING: Illegal tag '%s' in wireless-network\n", el);
        }
    } else if (netnode == net_node_packdata) {
        if (strcasecmp(el, "LLC") == 0) {
            netnode = net_node_pk_LLC;
        } else if (strcasecmp(el, "data") == 0) {
            netnode = net_node_pk_data;
        } else if (strcasecmp(el, "crypt") == 0) {
            netnode = net_node_pk_crypt;
        } else if (strcasecmp(el, "weak") == 0) {
            netnode = net_node_pk_weak;
        } else if (strcasecmp(el, "total") == 0) {
            netnode = net_node_pk_total;
        } else if (strcasecmp(el, "dupeiv") == 0) {
            netnode = net_node_pk_dupeiv;
        } else {
            fprintf(stderr, "WARNING: Illegal tag '%s' in packets\n", el);
        }
    } else if (netnode == net_node_gpsdata) {
        if (strcasecmp(el, "first-lat") == 0 || strcasecmp(el, "last-lat") == 0 ||
            strcasecmp(el, "first-lon") == 0 || strcasecmp(el, "last-lon") == 0 ||
            strcasecmp(el, "first-alt") == 0 || strcasecmp(el, "last-alt") == 0 ||
            strcasecmp(el, "first-spd") == 0 || strcasecmp(el, "last-spd") == 0 ||
            strcasecmp(el, "first-fix") == 0 || strcasecmp(el, "last-fix") == 0) {
            netnode = net_node_gps_expired;
        } else if (strcasecmp(el, "min-lat") == 0) {
            netnode = net_node_gps_min_lat;
        } else if (strcasecmp(el, "max-lat") == 0) {
            netnode = net_node_gps_max_lat;
        } else if (strcasecmp(el, "min-lon") == 0) {
            netnode = net_node_gps_min_lon;
        } else if (strcasecmp(el, "max-lon") == 0) {
            netnode = net_node_gps_max_lon;
        } else if (strcasecmp(el, "min-alt") == 0) {
            netnode = net_node_gps_min_alt;
        } else if (strcasecmp(el, "max-alt") == 0) {
            netnode = net_node_gps_max_alt;
        } else if (strcasecmp(el, "min-spd") == 0) {
            netnode = net_node_gps_min_spd;
        } else if (strcasecmp(el, "max-spd") == 0) {
            netnode = net_node_gps_max_spd;
        } else {
            fprintf(stderr, "WARNING:  Illegal tag '%s' in gps-info\n", el);
        }
    } else if (netnode == net_node_ipdata) {
        if (strcasecmp(el, "ip-range") == 0) {
            netnode = net_node_ip_range;
        } else if (strcasecmp(el, "ip-mask") == 0) {
            netnode = net_node_ip_mask;
        } else if (strcasecmp(el, "ip-gateway") == 0) {
            netnode = net_node_ip_gateway;
        } else {
            fprintf(stderr, "WARNING:  Illegal tag '%s' in ip-address\n", el);
        }
    } else if (netnode == net_node_cisco) {
        if (strcasecmp(el, "cdp-device-id") == 0) {
            netnode = net_node_cdp_device_id;
        } else if (strcasecmp(el, "cdp-capability") == 0) {
            netnode = net_node_cdp_cap;

            for (int i = 0; attr[i]; i += 2) {
                if (strcasecmp(attr[i], "level1") == 0) {
                    if (strcasecmp(attr[i+1], "true") == 0)
                        building_cdp->cap.level1 = 1;
                    else
                        building_cdp->cap.level1 = 0;
                } else if (strcasecmp(attr[i], "igmp-forward") == 0) {
                    if (strcasecmp(attr[i+1], "true") == 0)
                        building_cdp->cap.igmp_forward = 1;
                    else
                        building_cdp->cap.igmp_forward = 0;
                } else if (strcasecmp(attr[i], "netlayer") == 0) {
                    if (strcasecmp(attr[i+1], "true") == 0)
                        building_cdp->cap.nlp = 1;
                    else
                        building_cdp->cap.nlp = 0;
                } else if (strcasecmp(attr[i], "level2-switching") == 0) {
                    if (strcasecmp(attr[i+1], "true") == 0)
                        building_cdp->cap.level2_switching = 1;
                    else
                        building_cdp->cap.level2_switching = 0;
                } else if (strcasecmp(attr[i], "level2-sourceroute") == 0) {
                    if (strcasecmp(attr[i+1], "true") == 0)
                        building_cdp->cap.level2_sourceroute = 1;
                    else
                        building_cdp->cap.level2_sourceroute = 0;
                } else if (strcasecmp(attr[i], "level2-transparent") == 0) {
                    if (strcasecmp(attr[i+1], "true") == 0)
                        building_cdp->cap.level2_transparent = 1;
                    else
                        building_cdp->cap.level2_transparent = 0;
                } else if (strcasecmp(attr[i], "level3-routing") == 0) {
                    if (strcasecmp(attr[i+1], "true") == 0)
                        building_cdp->cap.level3 = 1;
                    else
                        building_cdp->cap.level3 = 0;
                } else {
                    fprintf(stderr, "WARNING:  Illegal attribute '%s' on cdp-capability\n",
                            attr[i]);
                }
            }
        } else if (strcasecmp(el, "cdp-interface") == 0) {
            netnode = net_node_cdp_interface;
        } else if (strcasecmp(el, "cdp-ip") == 0) {
            netnode = net_node_cdp_ip;
        } else if (strcasecmp(el, "cdp-platform") == 0) {
            netnode = net_node_cdp_platform;
        } else if (strcasecmp(el, "cdp-software") == 0) {
            netnode = net_node_cdp_software;
        } else {
            fprintf(stderr, "WARNING: Illegal tag '%s' in cisco\n", el);
        }
    } else if (netnode == net_node_wireless_client) {
        // We don't parse client data for now
        if (strcasecmp(el, "client-datasize") == 0)
            netnode = net_node_wc_datasize;
        else if (strcasecmp(el, "client-mac") == 0)
            netnode = net_node_wc_mac;
        else if (strcasecmp(el, "client-ip-address") == 0)
            netnode = net_node_wc_ip_address;
        else if (strcasecmp(el, "client-maxrate") == 0)
            netnode = net_node_wc_maxrate;
        else if (strcasecmp(el, "client-maxseenrate") == 0)
            netnode = net_node_wc_maxseenrate;
        else if (strcasecmp(el, "client-encoding") == 0)
            netnode = net_node_wc_encoding;
        else if (strcasecmp(el, "client-channel") == 0)
            netnode = net_node_wc_channel;
        else if (strcasecmp(el, "client-packets") == 0)
            netnode = net_node_wc_packdata;
        else if (strcasecmp(el, "client-gps-info") == 0)
            netnode = net_node_wc_gpsdata;
        else
            fprintf(stderr, "WARNING:  Illegal tag '%s' in wireless-client\n", el);
    } else if (netnode == net_node_wc_gpsdata) {
        if (strcasecmp(el, "client-min-lat") == 0) {
            netnode = net_node_wc_gps_min_lat;
        } else if (strcasecmp(el, "client-max-lat") == 0) {
            netnode = net_node_wc_gps_max_lat;
        } else if (strcasecmp(el, "client-min-lon") == 0) {
            netnode = net_node_wc_gps_min_lon;
        } else if (strcasecmp(el, "client-max-lon") == 0) {
            netnode = net_node_wc_gps_max_lon;
        } else if (strcasecmp(el, "client-min-alt") == 0) {
            netnode = net_node_wc_gps_min_alt;
        } else if (strcasecmp(el, "client-max-alt") == 0) {
            netnode = net_node_wc_gps_max_alt;
        } else if (strcasecmp(el, "client-min-spd") == 0) {
            netnode = net_node_wc_gps_min_spd;
        } else if (strcasecmp(el, "client-max-spd") == 0) {
            netnode = net_node_wc_gps_max_spd;
        } else {
            fprintf(stderr, "WARNING:  Illegal tag '%s' in client-gps-info\n", el);
        }
    } else if (netnode == net_node_wc_packdata) {
        if (strcasecmp(el, "client-data") == 0) {
            netnode = net_node_wc_pk_data;
        } else if (strcasecmp(el, "client-crypt") == 0) {
            netnode = net_node_wc_pk_crypt;
        } else if (strcasecmp(el, "client-weak") == 0) {
            netnode = net_node_wc_pk_weak;
        } else {
            fprintf(stderr, "WARNING: Illegal tag '%s' in client-packets\n", el);
        }
    } else {
        fprintf(stderr, "WARNING: Illegal tag '%s' in unknown state %d.\n", el, netnode);
    }
}

// Handle closing a tag
static void xpat_net_end(void *data, const char *el) {
    // I hate expat.
    if (netnode == net_node_detection_run)
        netnode = net_node_none;
    else if (netnode == net_node_comment)
        netnode = net_node_detection_run;
    else if (netnode == net_node_wireless_network) {
        // Push our data into the network
        NetXmlStr2Struct(building_net);
        netnode = net_node_detection_run;
        // Stash our network somewhere
        netvec.push_back(building_net);
        // Make a new network to build into
        building_net = new wireless_network;
        building_net->gps_fixed = 0;
        building_net->manuf_score = 0;
        // And clear the strings
        for (int i = 0; i < net_node_numnodes; i++)
            xmlstrnodes[i] = "";
    } else if (netnode > net_node_wireless_network && netnode < net_node_packdata)
        netnode = net_node_wireless_network;
    else if (netnode == net_node_packdata || netnode == net_node_gpsdata ||
             netnode == net_node_ipdata)
        netnode = net_node_wireless_network;
    else if (netnode == net_node_cisco) {
        // Insert our cisco info each time we close one off
        NetXmlCisco2Struct(building_net, building_cdp);
        netnode = net_node_wireless_network;
        // These get copied, not mem-pushed, so we can clear it instead of
        // making a new one
        memset(building_cdp, 0, sizeof(cdp_packet));
        // Clear the cisco blocks
        for (int i = net_node_cisco; i < net_node_numnodes; i++)
            xmlstrnodes[i] = "";
    } else if (netnode > net_node_packdata && netnode < net_node_gpsdata)
        netnode = net_node_packdata;
    else if (netnode > net_node_gpsdata && netnode < net_node_ipdata)
        netnode = net_node_gpsdata;
    else if (netnode > net_node_ipdata && netnode < net_node_cisco)
        netnode = net_node_ipdata;
    else if (netnode > net_node_cisco && netnode < net_node_wireless_client)
        netnode = net_node_cisco;
    else if (netnode == net_node_wireless_client) {
        // We'd insert our client if we parsed it, but we don't right now...
        netnode = net_node_wireless_network;
    } else if (netnode > net_node_wireless_client && netnode < net_node_wc_packdata)
        netnode = net_node_wireless_client;
    else if (netnode == net_node_wc_packdata)
        netnode = net_node_wireless_client;
    else if (netnode > net_node_wc_packdata && netnode < net_node_wc_gpsdata)
        netnode = net_node_wc_packdata;
    else if (netnode == net_node_wc_gpsdata)
        netnode = net_node_wireless_client;
    else if (netnode > net_node_wc_gpsdata)
        netnode = net_node_wc_gpsdata;

}

static void xpat_net_string(void *data, const XML_Char *s, int len) {
    for (int i = 0; i < len; i++) {
        xmlstrnodes[netnode] += s[i];
    }
}

#ifdef HAVE_LIBZ
vector<wireless_network *> XMLFetchNetworkList(gzFile in_file) {
#else
vector<wireless_network *> XMLFetchNetworkList(FILE *in_file) {
#endif
    // Clear out the network vector
    netvec.clear();

    XML_Parser p = XML_ParserCreate(NULL);
    if (! p) {
        fprintf(stderr, "Couldn't allocate memory for parser\n");
        return netvec;
    }

    XML_SetElementHandler(p, xpat_net_start, xpat_net_end);
    XML_SetCharacterDataHandler(p, xpat_net_string);

    building_net = new wireless_network;
    building_net->gps_fixed = 0;
    building_net->manuf_score = 0;
    building_cdp = new cdp_packet;

    for (;;) {
        int done;
        int len = 0;

#ifdef HAVE_LIBZ
        len = gzread(in_file, Buff, BUFFSIZE-2);
        if (len < 0 && errno < 0) {
            fprintf(stderr, "Read error\n");
            return netvec;
        }
        Buff[len+1] = '\0';
        done = gzeof(in_file);
#else
        len = fread(Buff, 1, BUFFSIZE, in_file);
        if (ferror(in_file)) {
            fprintf(stderr, "Read error\n");
            return netvec;
        }
        done = feof(in_file);
#endif

        if (! XML_Parse(p, Buff, len, done)) {
            fprintf(stderr, "Parse error at line %d:\n%s\n",
                    XML_GetCurrentLineNumber(p),
                    XML_ErrorString(XML_GetErrorCode(p)));
            return netvec;
        }

        if (done)
            break;
    }

    return netvec;
}

time_t XMLFetchNetworkStart() {
    return net_run_start;
}

time_t XMLFetchNetworkEnd() {
    return net_run_end;
}

double XMLFetchNetworkVersion() {
    return net_kisversion;
}

// point we're building
gps_point *building_point;
int building_point_valid = 1;
int point_id = 0;

// Vector of points
vector<gps_point *> ptvec;

float gps_version;
time_t gps_run_start;

// Every fricking possible XML node.
enum gps_xml_node {
    gps_node_none,
    gps_node_run,
    gps_node_comment,
    gps_node_netfile,
    gps_node_point
};

string netfile;

gps_xml_node gpsnode;

static void xpat_gps_start(void *data, const char *el, const char **attr) {
    if (gpsnode == gps_node_none) {
        if (strcasecmp(el, "gps-run") == 0) {
            gpsnode = gps_node_run;

            for (int i = 0; attr[i]; i += 2) {
                if (strcasecmp(attr[i], "gps-version") == 0) {
                    if (sscanf(attr[i+1], "%f", &gps_version) == 0) {
                        fprintf(stderr, "WARNING:  Illegal value '%s' for gps version\n",
                                attr[i+1]);
                    }
                } else if (strcasecmp(attr[i], "start-time") == 0) {
                    gps_run_start = XMLAsc2Time(attr[i+1]);
                } else {
                    fprintf(stderr, "WARNING: Illegal attribute '%s' on detection-run\n",
                            attr[i]);
                }
            }
        } else {
            fprintf(stderr, "WARNING: Illegal tag '%s' at base level\n", el);
        }
    } else if (gpsnode == gps_node_run) {
        if (strcasecmp(el, "network-file") == 0) {
            gpsnode = gps_node_netfile;
        } else if (strcasecmp(el, "comment") == 0) {
            gpsnode = gps_node_comment;
        } else if (strcasecmp(el, "gps-point") == 0) {
            gpsnode = gps_node_point;
            for (int i = 0; attr[i]; i += 2) {
                if (strcasecmp(attr[i], "bssid") == 0) {
                    if (sscanf(attr[i+1], "%s", building_point->bssid) < 1)
                        fprintf(stderr, "WARNING:  Illegal value '%s' on gps-point bssid\n",
                                attr[i+1]);
                } else if (strcasecmp(attr[i], "source") == 0) {
                    if (sscanf(attr[i+1], "%s", building_point->source) < 1)
                        fprintf(stderr, "WARNING:  Illegal value '%s' on gps-point source\n",
                                attr[i+1]);
                } else if (strcasecmp(attr[i], "time-sec") == 0) {
                    if (sscanf(attr[i+1], "%ld", &building_point->tv_sec) < 1)
                        fprintf(stderr, "WARNING:  Illegal value '%s' on gps-point time-sec\n",
                                attr[i+1]);
                } else if (strcasecmp(attr[i], "time-usec") == 0) {
                    if (sscanf(attr[i+1], "%ld", &building_point->tv_usec) < 1)
                        fprintf(stderr, "WARNING:  Illegal value '%s' on gps-point time-usec\n",
                                attr[i+1]);
                } else if (strcasecmp(attr[i], "lat") == 0) {
                    if (sscanf(attr[i+1], "%f", &building_point->lat) < 1)
                        fprintf(stderr, "WARNING:  Illegal value '%s' on gps-point lat\n",
                                attr[i+1]);
                    if (building_point->lat < -180 || building_point->lat > 180) {
                        fprintf(stderr, "WARNING:  Illegal numerical lat '%f' on gps-point, skipping.\n",
                                building_point->lat);
                        building_point_valid = 0;
                    }
                } else if (strcasecmp(attr[i], "lon") == 0) {
                    if (sscanf(attr[i+1], "%f", &building_point->lon) < 1)
                        fprintf(stderr, "WARNING:  Illegal value '%s' on gps-point lon\n",
                                attr[i+1]);
                    if (building_point->lon < -180 || building_point->lon > 180) {
                        fprintf(stderr, "WARNING:  Illegal numerical lon '%f' on gps-point, skipping.\n",
                                building_point->lon);
                        building_point_valid = 0;
                    }
                } else if (strcasecmp(attr[i], "alt") == 0) {
                    if (sscanf(attr[i+1], "%f", &building_point->alt) < 1)
                        fprintf(stderr, "WARNING:  Illegal value '%s' on gps-point alt\n",
                                attr[i+1]);
                } else if (strcasecmp(attr[i], "heading") == 0) {
                    if (sscanf(attr[i+1], "%f", &building_point->heading) < 1)
                        fprintf(stderr, "WARNING:  Illegal value '%s' on gps-point heading\n",
                                attr[i+1]);
                } else if (strcasecmp(attr[i], "spd") == 0) {
                    if (sscanf(attr[i+1], "%f", &building_point->spd) < 1)
                        fprintf(stderr, "WARNING:  Illegal value '%s' on gps-point spd\n",
                                attr[i+1]);
                } else if (strcasecmp(attr[i], "fix") == 0) {
                    if (sscanf(attr[i+1], "%d", &building_point->fix) < 1)
                        fprintf(stderr, "WARNING:  Illegal value '%s' on gps-point fix\n",
                                attr[i+1]);
                } else if (strcasecmp(attr[i], "signal") == 0) {
                    if (sscanf(attr[i+1], "%d", &building_point->signal) < 1)
                        fprintf(stderr, "WARNING:  Illegal value '%s' on gps-point signal\n",
                                attr[i+1]);
                } else if (strcasecmp(attr[i], "quality") == 0) {
                    if (sscanf(attr[i+1], "%d", &building_point->quality) < 1)
                        fprintf(stderr, "WARNING:  Illegal value '%s' on gps-point quality\n",
                                attr[i+1]);
                } else if (strcasecmp(attr[i], "noise") == 0) {
                    if (sscanf(attr[i+1], "%d", &building_point->noise) < 1)
                        fprintf(stderr, "WARNING:  Illegal value '%s' on gps-point noise\n",
                                attr[i+1]);
                } else {
                    fprintf(stderr, "WARNING:  Illegal attribute '%s' on gps-point\n",
                            attr[i]);
                }
            }
        } else {
            fprintf(stderr, "WARNING:  Illegal tag '%s' at gps-run level\n", el);
        }
    }
}


// Handle closing a tag
static void xpat_gps_end(void *data, const char *el) {
    if (gpsnode == gps_node_run) {
        gpsnode = gps_node_none;
    } else if (gpsnode == gps_node_netfile) {
        gpsnode = gps_node_run;
    } else if (gpsnode == gps_node_comment) {
        gpsnode = gps_node_run;
    } else if (gpsnode == gps_node_point) {
        gpsnode = gps_node_run;
        if (building_point_valid == 0) {
            // Skip this point, its corrupted
            delete building_point;
        } else {
            ptvec.push_back(building_point);
        }
        building_point = new gps_point;
        building_point_valid = 1;
        memset(building_point, 0, sizeof(gps_point));
        building_point->id = point_id++;
    }

}

static void xpat_gps_string(void *data, const XML_Char *s, int len) {
    if (gpsnode == gps_node_netfile)
        for (int i = 0; i < len; i++)
            netfile += s[i];
}

#ifdef HAVE_LIBZ
vector<gps_point *> XMLFetchGpsList(gzFile in_file) {
#else
vector<gps_point *> XMLFetchGpsList(FILE *in_file) {
#endif

    gpsnode = gps_node_none;

    // Clear out the network vector
    ptvec.clear();
    netfile = "";

    XML_Parser p = XML_ParserCreate(NULL);
    if (! p) {
        fprintf(stderr, "Couldn't allocate memory for parser\n");
        return ptvec;
    }

    XML_SetElementHandler(p, xpat_gps_start, xpat_gps_end);
    XML_SetCharacterDataHandler(p, xpat_gps_string);

    building_point = new gps_point;
    building_point_valid = 1;
    memset(building_point, 0, sizeof(gps_point));

    for (;;) {
        int done;
        int len = 0;

#ifdef HAVE_LIBZ
        len = gzread(in_file, Buff, BUFFSIZE-2);
        if (len < 0 && errno < 0) {
            fprintf(stderr, "WARNING: Read error\n");
            return ptvec;
        }
        Buff[len+1] = '\0';
        done = gzeof(in_file);
#else
        len = fread(Buff, 1, BUFFSIZE, in_file);
        if (ferror(in_file)) {
            fprintf(stderr, "WARNING: Read error\n");
            return ptvec;
        }
        done = feof(in_file);
#endif

        if (! XML_Parse(p, Buff, len, done)) {
            fprintf(stderr, "WARNING: Parse error at line %d:\n%s\n",
                    XML_GetCurrentLineNumber(p),
                    XML_ErrorString(XML_GetErrorCode(p)));
            return ptvec;
        }

        if (done)
            break;
    }

    return ptvec;
}

double XMLFetchGpsVersion() {
    return gps_version;
}

string XMLFetchGpsNetfile() {
    return netfile;
}

time_t XMLFetchGpsStart() {
    return gps_run_start;
}

#else

vector<wireless_network *> XMLFetchNetworkList(FILE *in_file) {
    vector<wireless_network *> ret;

    return ret;
}

time_t XMLFetchNetworkStart() {
    return 0;
}

time_t XMLFetchNetworkEnd() {
    return 0;
}

double XMLFetchGpsVersion() {
    return 0;
}

string XMLFetchGpsNetfile() {
    return "";
}

time_t XMLFetchGpsStart() {
    return 0;
}

vector<gps_point *> XMLFetchGpsList(FILE *in_file) {
    vector<gps_point *> ret;

    return ret;
}


#endif
