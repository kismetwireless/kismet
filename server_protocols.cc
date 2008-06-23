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

#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include "packetsource.h"
#include "packetsourcetracker.h"
#include "server_protocols.h"
#include "server_globals.h"

char const * const INFO_fields_text[] = {
    "networks", "packets", "crypt", "weak",
    "noise", "dropped", "rate", "signal", 
    NULL
};

char const * const STATUS_fields_text[] = {
    "text",
    NULL
};

char const * const ALERT_fields_text[] = {
    "sec", "usec", "header", "bssid", "source", "dest", "other", "channel", "text",
    NULL
};

char const * const PACKET_fields_text[] = {
    "type", "subtype", "timesec", "encrypted",
    "weak", "beaconrate", "sourcemac", "destmac",
    "bssid", "ssid", "prototype", "sourceip",
    "destip", "sourceport", "destport", "nbtype",
    "nbsource", "sourcename", "signal", "noise",
    NULL
};

char const * const STRING_fields_text[] = {
    "bssid", "sourcemac", "text",
    NULL
};

char const * const CISCO_fields_text[] = {
    "placeholder",
    NULL
};

char const * const KISMET_fields_text[] = {
    "version", "starttime", "servername", "timestamp", "channelhop", "newversion",
    NULL
};

char const * const PROTOCOLS_fields_text[] = {
    "protocols",
    NULL
};

char const * const CAPABILITY_fields_text[] = {
    "capabilities",
    NULL
};

char const * const TIME_fields_text[] = {
    "timesec",
    NULL
};

char const * const TERMINATE_fields_text[] = {
    "text",
    NULL
};

char const * const GPS_fields_text[] = {
    "lat", "lon", "alt", "spd", "heading", "fix",
    NULL
};

char const * const REMOVE_fields_text[] = {
    "bssid",
    NULL
};

char const * const NETWORK_fields_text[] = {
    "bssid", "type", "ssid", "beaconinfo",
    "llcpackets", "datapackets", "cryptpackets",
    "weakpackets", "channel", "wep", "firsttime",
    "lasttime", "atype", "rangeip", "gpsfixed",
    "minlat", "minlon", "minalt", "minspd",
    "maxlat", "maxlon", "maxalt", "maxspd",
    "octets", "cloaked", "beaconrate", "maxrate",
    "manufkey", "manufscore",
    "quality", "signal", "noise",
    "rssi", "rssi_max",
    "bestquality", "bestsignal", "bestnoise",
    "bestlat", "bestlon", "bestalt",
    "agglat", "agglon", "aggalt", "aggpoints",
    "datasize",
    "turbocellnid", "turbocellmode", "turbocellsat",
    "carrierset", "maxseenrate", "encodingset",
    "decrypted", "dupeivpackets", "bsstimestamp",
    NULL
};

char const * const CLIENT_fields_text[] = {
    "bssid", "mac", "type", "firsttime", "lasttime",
    "manufkey", "manufscore",
    "datapackets", "cryptpackets", "weakpackets",
    "gpsfixed",
    "minlat", "minlon", "minalt", "minspd",
    "maxlat", "maxlon", "maxalt", "maxspd",
    "agglat", "agglon", "aggalt", "aggpoints",
    "maxrate",
    "quality", "signal", "noise",
    "bestquality", "bestsignal", "bestnoise",
    "bestlat", "bestlon", "bestalt",
    "atype", "ip", "datasize", "maxseenrate", "encodingset",
    "decrypted", "wep", 
    NULL
};

char const * const ERROR_fields_text[] = {
    "text",
    NULL
};

char const * const ACK_fields_text[] = {
    "cmdnum",
    NULL
};

char const * const WEPKEY_fields_text[] = {
    "origin", "bssid", "key", "encrypted", "failed",
    NULL
};

char const * const CARD_fields_text[] = {
    "interface", "type", "username", "channel", "id", "packets", "hopping",
    NULL
};

// Kismet welcome printer.  Data should be KISMET_data
int Protocol_KISMET(PROTO_PARMS) {
    KISMET_data *kdata = (KISMET_data *) data;

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        switch ((KISMET_fields) (*field_vec)[x]) {
        case KISMET_version:
            out_string += kdata->version;
            break;
        case KISMET_starttime:
            out_string += kdata->starttime;
            break;
        case KISMET_servername:
            out_string += kdata->servername;
            break;
        case KISMET_timestamp:
            out_string += kdata->timestamp;
            break;
        case KISMET_chanhop:
            if (channel_hop == 0)
                out_string += "0";
            else
                out_string += "1";
            break;
        case KISMET_newversion:
            out_string += kdata->newversion;
            break;
        default:
            out_string = "Unknown field requested.";
            return -1;
            break;
        }

        out_string += " ";
    }

    return 1;
}

// Our own internal capabilities printer - we completely ignore the field vec because
// theres only one field that we can print out.  This expects the data pointer to be a
// pointer to the server protocol map
// *PROTOCOLS:123: ALERT,KISMET,NETWORK,CLIENT,...
int Protocol_PROTOCOLS(PROTO_PARMS) {
    map<int, server_protocol *> *srvmap = (map<int, server_protocol *> *) data;

    for (map<int, server_protocol *>::iterator x = srvmap->begin(); x != srvmap->end(); ++x) {
        out_string += x->second->header + ",";
    }

    out_string = out_string.substr(0, out_string.length() - 1);

    return 1;
}

// Our second internal capabilities printer - generate a line of valid fields for a
// protocol.  This expects the data pointer to be a pointer to a server_protocol record.
// *CAPABILITY:123: NETWORK bssid,packets,crypt,weak,...
int Protocol_CAPABILITY(PROTO_PARMS) {
    server_protocol *proto = (server_protocol *) data;

    out_string = proto->header + " ";

    for (unsigned int x = 0; x < proto->field_vec.size(); x++) {
        out_string += proto->field_vec[x] + ",";
    }

    out_string = out_string.substr(0, out_string.length() - 1);

    return 1;
}

// Time printer.  We don't care about the fields since we only have one thing to
// print out.  Data = int
int Protocol_TIME(PROTO_PARMS) {
    char tmpstr[32];
    int *tim = (int *) data;
    snprintf(tmpstr, 32, "%d", *tim);
    out_string += tmpstr;
    return 1;
}

// We don't care about fields.  Data = string
int Protocol_TERMINATE(PROTO_PARMS) {
    string *str = (string *) data;
    out_string += *str;
    return 1;
}

// We don't care about fields.  Data = string
int Protocol_ERROR(PROTO_PARMS) {
    string *str = (string *) data;
    out_string += *str;
    return 1;
}

// We don't care about fields.  Data = int
int Protocol_ACK(PROTO_PARMS) {
    char tmpstr[32];
    int *tim = (int *) data;
    snprintf(tmpstr, 32, "%d", *tim);
    out_string += tmpstr;
    return 1;
}


int Protocol_GPS(PROTO_PARMS) {
    GPS_data *gdata = (GPS_data *) data;

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        switch ((GPS_fields) (*field_vec)[x]) {
        case GPS_lat:
            out_string += gdata->lat;
            break;
        case GPS_lon:
            out_string += gdata->lon;
            break;
        case GPS_alt:
            out_string += gdata->alt;
            break;
        case GPS_spd:
            out_string += gdata->spd;
            break;
        case GPS_heading:
            out_string += gdata->heading;
            break;
        case GPS_fix:
            out_string += gdata->mode;
            break;
        default:
            out_string = "Unknown field requested.";
            return -1;
            break;
        }

        out_string += " ";
    }

    return 1;
}

// General info.  data = INFO_data
int Protocol_INFO(PROTO_PARMS) {
    INFO_data *idata = (INFO_data *) data;

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        switch ((INFO_fields) (*field_vec)[x]) {
        case INFO_networks:
            out_string += idata->networks;
            break;
        case INFO_packets:
            out_string += idata->packets;
            break;
        case INFO_crypt:
            out_string += idata->crypt;
            break;
        case INFO_weak:
            out_string += idata->weak;
            break;
        case INFO_noise:
            out_string += idata->noise;
            break;
        case INFO_dropped:
            out_string += idata->dropped;
            break;
        case INFO_rate:
            out_string += idata->rate;
            break;
        case INFO_signal:
            out_string += idata->signal;
            break;
        default:
            out_string = "Unknown field requested.";
            return -1;
            break;
        }

        out_string += " ";
    }

    return 1;
}

// We don't care about fields.  Data = string
int Protocol_REMOVE(PROTO_PARMS) {
    string *str = (string *) data;
    out_string += *str;
    return 1;
}

// We don't care about fields.  Data = string
int Protocol_STATUS(PROTO_PARMS) {
    string *str = (string *) data;
    out_string += *str;
    return 1;
}


// Convert a network to a NETWORK_data record for fast transmission
// The order of this is VERY IMPORTANT.  It HAS TO MATCH the order of the
// char *[] array of fields.
void Protocol_Network2Data(const wireless_network *net, NETWORK_data *data) {
    char tmpstr[256];

    // Reserve fields
    data->ndvec.reserve(50);

    data->ndvec.push_back(net->bssid.Mac2String());

    snprintf(tmpstr, 128, "%d", (int) net->type);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 255, "\001%s\001", net->ssid.length() > 0 ? net->ssid.c_str() : " ");
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 255, "\001%s\001", net->beacon_info.length() > 0 ? net->beacon_info.c_str() : " ");
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->llc_packets);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->data_packets);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->crypt_packets);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->interesting_packets);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->channel);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->crypt_set);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", (int) net->first_time);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", (int) net->last_time);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", (int) net->ipdata.atype);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%hu.%hu.%hu.%hu",
             net->ipdata.range_ip[0], net->ipdata.range_ip[1],
             net->ipdata.range_ip[2], net->ipdata.range_ip[3]);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->gps_fixed);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->min_lat);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->min_lon);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->min_alt);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->min_spd);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->max_lat);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->max_lon);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->max_alt);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->max_spd);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->ipdata.octets);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->cloaked);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->beacon);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%2.1f", net->maxrate);
    data->ndvec.push_back(tmpstr);

    // Deprecated
    // data->ndvec.push_back(net->manuf_key.Mac2String());
    data->ndvec.push_back("00:00:00:00:00:00");

    // Deprecated
    /*
    snprintf(tmpstr, 128, "%d", net->manuf_score);
    data->ndvec.push_back(tmpstr);
    */
    data->ndvec.push_back("0");

    snprintf(tmpstr, 128, "%d", net->quality);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->signal);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->noise);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->rssi);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->rssi_max);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->best_quality);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->best_signal);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->best_noise);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->best_lat);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->best_lon);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->best_alt);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->aggregate_lat);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->aggregate_lon);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", net->aggregate_alt);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%ld", net->aggregate_points);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%ld", net->datasize);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->turbocell_nid);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", (int) net->turbocell_mode);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->turbocell_sat);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->carrier_set);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->maxseenrate);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->encoding_set);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->decrypted);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", net->dupeiv_packets);
    data->ndvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%"PRId64"", net->bss_timestamp);
    data->ndvec.push_back(tmpstr);

}

// Network records.  data = NETWORK_data
int Protocol_NETWORK(PROTO_PARMS) {
    NETWORK_data *ndata = (NETWORK_data *) data;

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        unsigned int fnum = (*field_vec)[x];
        if (fnum >= ndata->ndvec.size()) {
            out_string = "Unknown field requested.";
            return -1;
        } else {
            out_string += ndata->ndvec[fnum] + " ";
        }
    }

    return 1;
}

void Protocol_Client2Data(const wireless_network *net, const wireless_client *cli, CLIENT_data *data) {
    char tmpstr[128];

    // Reserve fields
    data->cdvec.reserve(50);

    data->cdvec.push_back(net->bssid.Mac2String());

    data->cdvec.push_back(cli->mac.Mac2String());

    snprintf(tmpstr, 128, "%d", (int) cli->type);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", (int) cli->first_time);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", (int) cli->last_time);
    data->cdvec.push_back(tmpstr);

    // Deprecated
    // data->cdvec.push_back(cli->manuf_key.Mac2String());
    data->cdvec.push_back("00:00:00:00:00:00");

    // deprecated
    /*
    snprintf(tmpstr, 128, "%d", cli->manuf_score);
    data->cdvec.push_back(tmpstr);
    */
    data->cdvec.push_back("0");

    snprintf(tmpstr, 128, "%d", cli->data_packets);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", cli->crypt_packets);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", cli->interesting_packets);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", cli->gps_fixed);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->min_lat);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->min_lon);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->min_alt);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->min_spd);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->max_lat);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->max_lon);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->max_alt);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->max_spd);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->aggregate_lat);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->aggregate_lon);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->aggregate_alt);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%ld", cli->aggregate_points);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%2.1f", cli->maxrate);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", cli->quality);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", cli->signal);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", cli->noise);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", cli->best_quality);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", cli->best_signal);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", cli->best_noise);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->best_lat);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->best_lon);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%f", cli->best_alt);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", (int) cli->ipdata.atype);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%hu.%hu.%hu.%hu",
             cli->ipdata.ip[0], cli->ipdata.ip[1],
             cli->ipdata.ip[2], cli->ipdata.ip[3]);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%ld", cli->datasize);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", cli->maxseenrate);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", cli->encoding_set);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", cli->decrypted);
    data->cdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", cli->crypt_set);
    data->cdvec.push_back(tmpstr);

}

// client records.  data = CLIENT_data
int Protocol_CLIENT(PROTO_PARMS) {
    CLIENT_data *cdata = (CLIENT_data *) data;

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        unsigned int fnum = (*field_vec)[x];
        if (fnum >= cdata->cdvec.size()) {
            out_string = "Unknown field requested.";
            return -1;
        } else {
            out_string += cdata->cdvec[fnum] + " ";
        }
    }

    return 1;
}

// alert.  data = ALERT_data
int Protocol_ALERT(PROTO_PARMS) {
    ALERT_data *adata = (ALERT_data *) data;

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        switch ((ALERT_fields) (*field_vec)[x]) {
        case ALERT_header:
            out_string += adata->header;
            break;
        case ALERT_sec:
            out_string += adata->sec;
            break;
        case ALERT_usec:
            out_string += adata->usec;
            break;
        case ALERT_bssid:
            out_string += adata->bssid;
            break;
        case ALERT_source:
            out_string += adata->source;
            break;
        case ALERT_dest:
            out_string += adata->dest;
            break;
        case ALERT_other:
            out_string += adata->other;
            break;
        case ALERT_channel:
            out_string += adata->channel;
            break;
        case ALERT_text:
            out_string += string("\001") + adata->text + string("\001");
            break;
        default:
            out_string = "Unknown field requested.";
            return -1;
            break;
        }

        out_string += " ";
    }

    return 1;
}

void Protocol_Packet2Data(const packet_info *info, PACKET_data *data) {
    char tmpstr[128];

    // Reserve
    data->pdvec.reserve(10);

    snprintf(tmpstr, 128, "%d", (int) info->type);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", (int) info->subtype);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", (int) info->ts.tv_sec);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", info->encrypted);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", info->interesting);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", info->beacon);
    data->pdvec.push_back(tmpstr);

    data->pdvec.push_back(info->source_mac.Mac2String());

    data->pdvec.push_back(info->dest_mac.Mac2String());

    data->pdvec.push_back(info->bssid_mac.Mac2String());

    snprintf(tmpstr, 128, "\001%s\001", strlen(info->ssid) == 0 ? " " : info->ssid);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", (int) info->proto.type);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%hu.%hu.%hu.%hu",
             info->proto.source_ip[0], info->proto.source_ip[1],
             info->proto.source_ip[2], info->proto.source_ip[3]);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%hu.%hu.%hu.%hu",
             info->proto.dest_ip[0], info->proto.dest_ip[1],
             info->proto.dest_ip[2], info->proto.dest_ip[3]);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", info->proto.sport);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", info->proto.dport);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%d", (int) info->proto.nbtype);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "\001%s\001", strlen(info->proto.netbios_source) == 0 ? " " : info->proto.netbios_source);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "\001%s\001", strlen(info->sourcename) == 0 ? " " :
             info->sourcename);
    data->pdvec.push_back(tmpstr);

	snprintf(tmpstr, 128, "%d", info->signal);
    data->pdvec.push_back(tmpstr);

	snprintf(tmpstr, 128, "%d", info->noise);
    data->pdvec.push_back(tmpstr);

}

// packet records.  data = PACKET_data
int Protocol_PACKET(PROTO_PARMS) {
    PACKET_data *pdata = (PACKET_data *) data;

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        unsigned int fnum = (*field_vec)[x];
        if (fnum >= pdata->pdvec.size()) {
            out_string = "Unknown field requested.";
            return -1;
        } else {
            out_string += pdata->pdvec[fnum] + " ";
        }
    }

    return 1;
}

// string.  data = STRING_data
int Protocol_STRING(PROTO_PARMS) {
    STRING_data *sdata = (STRING_data *) data;

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        switch ((STRING_fields) (*field_vec)[x]) {
        case STRING_bssid:
            out_string += sdata->bssid;
            break;
        case STRING_sourcemac:
            out_string += sdata->sourcemac;
            break;
        case STRING_text:
            out_string += sdata->text;
            break;
        default:
            out_string = "Unknown field requested.";
            return -1;
            break;
        }

        out_string += " ";
    }

    return 1;
}

// wep keys.  data = wep_key_info
int Protocol_WEPKEY(PROTO_PARMS) {
    wep_key_info *winfo = (wep_key_info *) data;
    char wdstr[10];

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        switch ((WEPKEY_fields) (*field_vec)[x]) {
        case WEPKEY_origin:
            if (winfo->fragile == 0)
                out_string += "0";
            else
                out_string += "1";
            break;
        case WEPKEY_bssid:
            out_string += winfo->bssid.Mac2String();
            break;
        case WEPKEY_key:
            for (unsigned int kpos = 0; kpos < WEPKEY_MAX && kpos < winfo->len; kpos++) {
                snprintf(wdstr, 3, "%02X", (uint8_t) winfo->key[kpos]);
                out_string += wdstr;
                if (kpos < (WEPKEY_MAX - 1) && kpos < (winfo->len - 1))
                    out_string += ":";
            }
            break;
        case WEPKEY_decrypted:
            snprintf(wdstr, 10, "%d", winfo->decrypted);
            out_string += wdstr;
            break;
        case WEPKEY_failed:
            snprintf(wdstr, 10, "%d", winfo->failed);
            out_string += wdstr;
            break;
        default:
            out_string = "Unknown field requested.";
            return -1;
            break;
        }

        out_string += " ";
    }

    return 1;
}

int Protocol_CARD(PROTO_PARMS) {
    meta_packsource *csrc = (meta_packsource *) data;
    char tmp[32];

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        switch ((CARD_fields) (*field_vec)[x]) {
        case CARD_interface:
            out_string += csrc->device.c_str();
            break;
        case CARD_type:
            // Fix this in the future...
            out_string += csrc->prototype->cardtype.c_str();
            break;
        case CARD_username:
            snprintf(tmp, 32, "\001%s\001", csrc->name.c_str());
            out_string += tmp;
            break;
        case CARD_channel:
            snprintf(tmp, 32, "%d", csrc->capsource->FetchChannel());
            out_string += tmp;
            break;
        case CARD_id:
            snprintf(tmp, 32, "%d", csrc->id);
            out_string += tmp;
            break;
        case CARD_packets:
            snprintf(tmp, 32, "%d", csrc->capsource->FetchNumPackets());
            out_string += tmp;
            break;
        case CARD_hopping:
            snprintf(tmp, 32, "%d", csrc->ch_hop);
            out_string += tmp;
            break;
        }

        out_string += " ";
    }
    return 1;
}
