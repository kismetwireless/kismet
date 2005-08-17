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
#include "util.h"
#include "configfile.h"
#include "packet.h"
#include "packetsourcetracker.h"
#include "alertracker.h"
#include "packetchain.h"
#include "kis_netframe.h"
#include "getopt.h"

char *KISMET_fields_text[] = {
    "version", "starttime", "servername", "timestamp", "channelhop", "newversion",
    NULL
};

char *ERROR_fields_text[] = {
    "cmdid", "text",
    NULL
};

char *ACK_fields_text[] = {
    "cmdid", "text",
    NULL
};

char *PROTOCOLS_fields_text[] = {
    "protocols",
    NULL
};

char *TERMINATE_fields_text[] = {
    "text",
    NULL
};

char *CAPABILITY_fields_text[] = {
    "capabilities",
    NULL
};

char *TIME_fields_text[] = {
    "timesec",
    NULL
};

char *INFO_fields_text[] = {
    "networks", "packets", "crypt", "weak",
    "noise", "dropped", "rate", "signal",
    NULL
};

char *STATUS_fields_text[] = {
    "text",
    NULL
};

char *PACKET_fields_text[] = {
    "type", "subtype", "timesec", "encrypted",
    "weak", "beaconrate", "sourcemac", "destmac",
    "bssid", "ssid", "prototype", "sourceip",
    "destip", "sourceport", "destport", "nbtype",
    "nbsource", "sourcename",
    NULL
};

char *STRING_fields_text[] = {
    "bssid", "sourcemac", "text",
    NULL
};

char *CISCO_fields_text[] = {
    "placeholder",
    NULL
};

char *WEPKEY_fields_text[] = {
    "origin", "bssid", "key", "encrypted", "failed",
    NULL
};

char *CARD_fields_text[] = {
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
            out_string += "\001" + kdata->servername + "\001";
            break;
        case KISMET_timestamp:
            out_string += kdata->timestamp;
            break;
        case KISMET_chanhop:
            if (globalreg->sourcetracker->FetchChannelHop() == 0)
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
    map<int, KisNetFramework::server_protocol *> *srvmap = 
        (map<int, KisNetFramework::server_protocol *> *) data;

    for (map<int, KisNetFramework::server_protocol *>::iterator x = 
         srvmap->begin(); x != srvmap->end(); ++x) {
        out_string += x->second->header + ",";
    }

    out_string = out_string.substr(0, out_string.length() - 1);

    return 1;
}

// Our second internal capabilities printer - generate a line of valid fields for a
// protocol.  This expects the data pointer to be a pointer to a server_protocol record.
// *CAPABILITY:123: NETWORK bssid,packets,crypt,weak,...
int Protocol_CAPABILITY(PROTO_PARMS) {
    KisNetFramework::server_protocol *proto = 
        (KisNetFramework::server_protocol *) data;

    out_string = proto->header + " ";

    for (unsigned int x = 0; x < proto->field_vec.size(); x++) {
        out_string += proto->field_vec[x] + ",";
    }

    out_string = out_string.substr(0, out_string.length() - 1);

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
    CLIRESP_data *rdata = (CLIRESP_data *) data;
    char dig[10];

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        switch ((ERROR_fields) (*field_vec)[x]) {
            case ERROR_cmdid:
                snprintf(dig, 10, "%d", rdata->cmdid);
                out_string += dig;
                break;
            case ERROR_cmdtext:
                out_string += "\001" + rdata->resptext + "\001";
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

// We don't care about fields.  Data = int
int Protocol_ACK(PROTO_PARMS) {
    CLIRESP_data *rdata = (CLIRESP_data *) data;
    char dig[10];

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        switch ((ACK_fields) (*field_vec)[x]) {
            case ACK_cmdid:
                snprintf(dig, 10, "%d", rdata->cmdid);
                out_string += dig;
                break;
            case ACK_cmdtext:
                out_string += "\001" + rdata->resptext + "\001";
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

// Time printer.  We don't care about the fields since we only have one thing to
// print out.  Data = int
int Protocol_TIME(PROTO_PARMS) {
    char tmpstr[32];
    int *tim = (int *) data;
    snprintf(tmpstr, 32, "%d", *tim);
    out_string += tmpstr;
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
int Protocol_STATUS(PROTO_PARMS) {
    string *str = (string *) data;
    out_string += *str;
    return 1;
}

void Protocol_Packet2Data(const kis_packet *info, PACKET_data *data) {
	// Broken for now
#if 0
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

    snprintf(tmpstr, 128, "%hd.%hd.%hd.%hd",
             info->proto.source_ip[0], info->proto.source_ip[1],
             info->proto.source_ip[2], info->proto.source_ip[3]);
    data->pdvec.push_back(tmpstr);

    snprintf(tmpstr, 128, "%hd.%hd.%hd.%hd",
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
#endif
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

// Client commands
int Clicmd_CAPABILITY(CLIENT_PARMS) {
    // We don't have to do any funny parsing so we can take advantage of being
    // given the preparsed stuff
    int cmdref;

    if (parsedcmdline->size() != 1) {
        snprintf(errstr, 1024, "Illegal capability request");
        return -1;
    }

    if ((cmdref = 
         globalreg->kisnetserver->FetchProtocolRef(((*parsedcmdline)[0]).word)) < 0) {
        snprintf(errstr, 1024, "Unknown protocol: '%s'", 
				 ((*parsedcmdline)[0]).word.c_str());
        return -1;
    }

    KisNetFramework::server_protocol *prot;

    if ((prot = globalreg->kisnetserver->FetchProtocol(cmdref)) == NULL) {
        snprintf(errstr, 1024, "Unable to fetch protocol info");
        return -1;
    }

    globalreg->kisnetserver->SendToClient(in_clid, 
										  globalreg->netproto_map[PROTO_REF_CLIENT],
										  (void *) prot, NULL);
    
    return 1;
}

int Clicmd_ENABLE(CLIENT_PARMS) {
    // We don't have to do any funny parsing so we can take advantage of being
    // given the preparsed stuff
    int cmdref;

    if (parsedcmdline->size() < 2) {
        snprintf(errstr, 1024, "Illegal enable request");
        return -1;
    }

    if ((cmdref = 
         globalreg->kisnetserver->FetchProtocolRef(((*parsedcmdline)[0]).word)) < 0) {
        snprintf(errstr, 1024, "Unknown protocol: '%s'", 
				 ((*parsedcmdline)[0]).word.c_str());
        return -1;
    }

    KisNetFramework::server_protocol *prot;

    if ((prot = globalreg->kisnetserver->FetchProtocol(cmdref)) == NULL) {
        snprintf(errstr, 1024, "Unable to fetch protocol info");
        return -1;
    }

    vector<int> numericf;

    // Match * - Rough match, good enough for me to just do the first character, 
	// if this becomes a problem sometime come back to it and do it a better way
    if (((*parsedcmdline)[1]).word[0] == '*') {
        for (unsigned int x = 0; x < prot->field_vec.size(); x++) {
            numericf.push_back(x);
        }
    } else {
        vector<string> field_vec = StrTokenize(((*parsedcmdline)[1]).word, ",");
        for (unsigned int x = 0; x < field_vec.size(); x++) {
            map<string, int>::iterator fitr = 
                prot->field_map.find(StrLower(field_vec[x]));

            if (fitr == prot->field_map.end()) {
                snprintf(errstr, 1024, "Unknown field %s", field_vec[x].c_str());
                return -1;
            }

            numericf.push_back(fitr->second);
        }
    }

    globalreg->kisnetserver->AddProtocolClient(in_clid, cmdref, numericf);

	if (prot->enable != NULL)
		(*prot->enable)(in_clid, globalreg);

    return 1;
}

int Clicmd_REMOVE(CLIENT_PARMS) {
    // We don't have to do any funny parsing so we can take advantage of being
    // given the preparsed stuff
    int cmdref;

    if (parsedcmdline->size() != 1) {
        snprintf(errstr, 1024, "Illegal remove request");
        return -1;
    }

    if ((cmdref = 
         globalreg->kisnetserver->FetchProtocolRef(((*parsedcmdline)[0]).word)) < 0) {
        snprintf(errstr, 1024, "Unknown protocol: '%s'", 
				 ((*parsedcmdline)[0]).word.c_str());
        return -1;
    }

    // Just nuke it from us entirely
    globalreg->kisnetserver->DelProtocolClient(in_clid, cmdref);
    
    return 1;
}

int Clicmd_CHANLOCK(CLIENT_PARMS) {
    if (parsedcmdline->size() != 2) {
        snprintf(errstr, 1024, "Illegal chanlock request");
        return -1;
    }

    int metanum;
    if (sscanf(((*parsedcmdline)[0]).word.c_str(), "%d", &metanum) != 1) {
        snprintf(errstr, 1024, "Illegal chanlock request");
        return -1;
    }

    int chnum;
    if (sscanf(((*parsedcmdline)[1]).word.c_str(), "%d", &chnum) != 1) {
        snprintf(errstr, 1024, "Illegal chanlock request");
        return -1;
    }

    // See if this meta number even exists...
    meta_packsource *meta;
    if ((meta = globalreg->sourcetracker->FetchMetaID(metanum)) == NULL) {
        snprintf(errstr, 1024, "Illegal chanlock request, unknown meta id");
        return -1;
    }

    // See if the meta can control channel
    if (meta->prototype->channelcon == NULL) {
        snprintf(errstr, 1024, "Illegal chanlock request, source cannot change channel");
        return -1;
    }

    // See if the requested channel is in the list of valid channels for this
    // source...
    int chvalid = 0;
    for (unsigned int chi = 0; chi < meta->channels.size(); chi++) {
        if (meta->channels[chi] == chnum) {
            chvalid = 1;
            break;
        }
    }

    if (chvalid == 0) {
        snprintf(errstr, 1024, "Illegal chanlock request - illegal channel for this source");
        return -1;
    }

    // Finally if we're valid, stop the source from hopping and lock it to this
    // channel
    globalreg->sourcetracker->SetHopping(0, meta);
    globalreg->sourcetracker->SetChannel(chnum, meta);

    snprintf(errstr, 1024, "Locking source '%s' to channel %d", meta->name.c_str(), chnum);
    globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    
    return 1;
}

int Clicmd_CHANHOP(CLIENT_PARMS) {
    if (parsedcmdline->size() != 2) {
        snprintf(errstr, 1024, "Illegal chanhop request");
        return -1;
    }

    int metanum;
    if (sscanf(((*parsedcmdline)[0]).word.c_str(), "%d", &metanum) != 1) {
        snprintf(errstr, 1024, "Illegal chanhop request");
        return -1;
    }

    int chnum;
    if (sscanf(((*parsedcmdline)[1]).word.c_str(), "%d", &chnum) != 1) {
        snprintf(errstr, 1024, "Illegal chanhop request");
        return -1;
    }

    // See if this meta number even exists...
    meta_packsource *meta;
    if ((meta = globalreg->sourcetracker->FetchMetaID(metanum)) == NULL) {
        snprintf(errstr, 1024, "Illegal chanhop request, unknown meta id");
        return -1;
    }

    // See if the meta can control channel
    if (meta->prototype->channelcon == NULL) {
        snprintf(errstr, 1024, "Illegal chanhop request, source cannot change channel");
        return -1;
    }

    globalreg->sourcetracker->SetHopping(1, meta);

    snprintf(errstr, 1024, "Setting source '%s' to channelhopping", meta->name.c_str());
    globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    
    return 1;
}

int Clicmd_PAUSE(CLIENT_PARMS) {
    globalreg->sourcetracker->PauseSources();

    globalreg->messagebus->InjectMessage("Pausing capture on all packet sources", MSGFLAG_INFO);
    
    return 1;
}

int Clicmd_RESUME(CLIENT_PARMS) {
    globalreg->sourcetracker->ResumeSources();

    globalreg->messagebus->InjectMessage("Resuming capture on all packet sources", MSGFLAG_INFO);

    return 1;
}

int Clicmd_LISTWEPKEYS(CLIENT_PARMS) {
    if (globalreg->client_wepkey_allowed == 0) {
        snprintf(errstr, 1024, "Server does not allow clients to fetch keys");
        return -1;
    }

    if (globalreg->bssid_wep_map.size() == 0) {
        snprintf(errstr, 1024, "Server has no WEP keys");
        return -1;
    }

    int wepkey_ref = globalreg->kisnetserver->FetchProtocolRef("WEPKEY");

    if (wepkey_ref < 0) {
        snprintf(errstr, 1024, "Unable to find WEPKEY protocol");
        return -1;
    }
    
    for (macmap<wep_key_info *>::iterator wkitr = globalreg->bssid_wep_map.begin();
         wkitr != globalreg->bssid_wep_map.end(); wkitr++) {
        globalreg->kisnetserver->SendToClient(in_clid, wepkey_ref, 
											  (void *) wkitr->second, NULL);
    }

    return 1;
}

int Clicmd_ADDWEPKEY(CLIENT_PARMS) {
    if (parsedcmdline->size() != 1) {
        snprintf(errstr, 1024, "Illegal addwepkey request");
        return -1;
    }

    vector<string> keyvec = StrTokenize((*parsedcmdline)[1].word, ",");
    if (keyvec.size() != 2) {
        snprintf(errstr, 1024, "Illegal addwepkey request");
        return -1;
    }

    wep_key_info *winfo = new wep_key_info;
    winfo->fragile = 1;
    winfo->bssid = keyvec[0].c_str();

    if (winfo->bssid.error) {
        snprintf(errstr, 1024, "Illegal addwepkey bssid");
        return -1;
    }

    unsigned char key[WEPKEY_MAX];
    int len = Hex2UChar((unsigned char *) keyvec[1].c_str(), key);

    winfo->len = len;
    memcpy(winfo->key, key, sizeof(unsigned char) * WEPKEY_MAX);

    // Replace exiting ones
    if (globalreg->bssid_wep_map.find(winfo->bssid) != globalreg->bssid_wep_map.end())
        delete globalreg->bssid_wep_map[winfo->bssid];

    globalreg->bssid_wep_map.insert(winfo->bssid, winfo);

    snprintf(errstr, 1024, "Added key %s length %d for BSSID %s",
             (*parsedcmdline)[0].word.c_str(), len, winfo->bssid.Mac2String().c_str());

    globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);

    return 1;
}

int Clicmd_DELWEPKEY(CLIENT_PARMS) {
    if (globalreg->client_wepkey_allowed == 0) {
        snprintf(errstr, 1024, "Server does not allow clients to modify keys");
        return -1;
    }

    if (parsedcmdline->size() != 1) {
        snprintf(errstr, 1024, "Illegal delwepkey command");
        return -1;
    }

    mac_addr bssid_mac = (*parsedcmdline)[0].word.c_str();

    if (bssid_mac.error) {
        snprintf(errstr, 1024, "Illegal delwepkey bssid");
        return -1;
    }

    if (globalreg->bssid_wep_map.find(bssid_mac) == globalreg->bssid_wep_map.end()) {
        snprintf(errstr, 1024, "Unknown delwepkey bssid");
        return -1;
    }

    delete globalreg->bssid_wep_map[bssid_mac];
    globalreg->bssid_wep_map.erase(bssid_mac);

    snprintf(errstr, 1024, "Deleted key for BSSID %s", 
             bssid_mac.Mac2String().c_str());
    globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);

    return 1;
}

void KisNetframe_MessageClient::ProcessMessage(string in_msg, int in_flags) {
    char msg[1024];

    if (in_flags & MSGFLAG_LOCAL)
        return;

    if (in_flags & MSGFLAG_DEBUG)
        snprintf(msg, 1024, "DEBUG - %s", in_msg.c_str());
    if (in_flags & MSGFLAG_INFO)
        snprintf(msg, 1024, "NOTICE - %s", in_msg.c_str());
    if (in_flags & MSGFLAG_ERROR)
        snprintf(msg, 1024, "ERROR - %s", in_msg.c_str());
    if (in_flags & MSGFLAG_FATAL)
        snprintf(msg, 1024, "FATAL - %s", in_msg.c_str());

    // Dispatch it out to the clients
    string tmp = msg;
    globalreg->kisnetserver->SendToAll(globalreg->netproto_map[PROTO_REF_STATUS], 
									   (void *) &tmp);

}

int KisNetFrame_TimeEvent(Timetracker::timer_event *evt, void *parm, GlobalRegistry *globalreg) {
    // We'll just assume we'll never fail here and that the TIME protocol
    // always exists.  If this isn't the case, we'll fail horribly.
    time_t curtime = time(0);

    globalreg->kisnetserver->SendToAll(globalreg->netproto_map[PROTO_REF_TIME], 
									   (void *) &curtime);
    
    return 1;
}

KisNetFramework::KisNetFramework() {
    fprintf(stderr, "*** KisNetFramework() This constructor should never be called!!\n");
}

KisNetFramework::KisNetFramework(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;
    netserver = NULL;
	int port = 0, maxcli = 0;
	char srv_proto[10], srv_bindhost[128];
	TcpServer *tcpsrv;
	char errstr[1024];
	string listenline;

	// Commandline stuff
	static struct option netframe_long_options[] = {
		{ "server-listen", required_argument, 0, 's' },
		{ 0, 0, 0, 0 }
	};
	int option_idx = 0;

	// Hack the extern getopt index
	optind = 0;

	while (1) {
		int r = getopt_long(globalreg->argc, globalreg->argv,
							"-s:",
							netframe_long_options, &option_idx);
		if (r < 0) break;

		switch (r) {
			case 's':
				listenline = string(optarg);
				printf("debug: '%s'\n", listenline.c_str());
				break;
		}
	}
	
	// Parse the config file and get the protocol and port info...  ah, abusing
	// evaluation shortcuts
	if (listenline.length() == 0 && 
		(listenline = globalreg->kismet_config->FetchOpt("listen")) == "") {
		_MSG("No 'listen' config line defined for the Kismet UI server", 
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	if (sscanf(listenline.c_str(), 
			   "%10[^:]://%128[^:]:%d", srv_proto, srv_bindhost, &port) != 3) {
		_MSG("Malformed 'listen' config line defined for the Kismet UI server",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	if (globalreg->kismet_config->FetchOpt("maxclients") == "") {
		_MSG("No 'maxclients' config line defined for the Kismet UI server, "
			 "defaulting to 5 clients.", MSGFLAG_INFO);
		maxcli = 5;
	} else if (sscanf(globalreg->kismet_config->FetchOpt("maxclients").c_str(), 
					  "%d", &maxcli) != 1) {
		_MSG("Malformed 'maxclients' config line defined for the Kismet UI server",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
	}

	if (globalreg->kismet_config->FetchOpt("allowedhosts") == "") {
		_MSG("No 'allowedhosts' config line defined for the Kismet UI server",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	// We only know how to set up a tcp server right now
	if (strncasecmp(srv_proto, "tcp", 10) == 0) {
		tcpsrv = new TcpServer(globalreg);
		tcpsrv->SetupServer(port, maxcli, srv_bindhost, 
							globalreg->kismet_config->FetchOpt("allowedhosts"));
		if (tcpsrv->EnableServer() < 0 || globalreg->fatal_condition) {
			_MSG("Failed to enable TCP listener for the Kismet UI server",
				 MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return;
		}
		tcpsrv->RegisterServerFramework(this);
		netserver = tcpsrv;
		snprintf(errstr, 1024, "Created Kismet UI TCP server on port %d",
				 port);
		_MSG(errstr, MSGFLAG_INFO);
	} else {
		_MSG("Invalid protocol in 'listen' config line for the Kismet UI server",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

    kisnet_msgcli = new KisNetframe_MessageClient(globalreg);

    // Register our network message handler to feed clients
    globalreg->messagebus->RegisterClient(kisnet_msgcli, MSGFLAG_ALL);
    
    // Register the core Kismet protocols

    // Protocols we REQUIRE all clients to support
	globalreg->netproto_map[PROTO_REF_KISMET] =
		RegisterProtocol("KISMET", 1, 0, KISMET_fields_text, &Protocol_KISMET, NULL);
	globalreg->netproto_map[PROTO_REF_ERROR] =
		RegisterProtocol("ERROR", 1, 0, ERROR_fields_text, &Protocol_ERROR, NULL);
	globalreg->netproto_map[PROTO_REF_ACK] =
		RegisterProtocol("ACK", 1, 0, ACK_fields_text, &Protocol_ACK, NULL);
	globalreg->netproto_map[PROTO_REF_PROTOCOL] =
		RegisterProtocol("PROTOCOLS", 1, 0, PROTOCOLS_fields_text,
						 &Protocol_PROTOCOLS, NULL);
	globalreg->netproto_map[PROTO_REF_CAPABILITY] =
		RegisterProtocol("CAPABILITY", 1, 0, CAPABILITY_fields_text,
						 &Protocol_CAPABILITY, NULL);
	globalreg->netproto_map[PROTO_REF_TERMINATE] =
		RegisterProtocol("TERMINATE", 1, 0, TERMINATE_fields_text,
						 &Protocol_TERMINATE, NULL);
	globalreg->netproto_map[PROTO_REF_TIME] =
		RegisterProtocol("TIME", 1, 0, TIME_fields_text, &Protocol_TIME, NULL);

    // Other protocols
    
    // Alert ref done in alertracker

	globalreg->netproto_map[PROTO_REF_CARD] =
		RegisterProtocol("CARD", 0, 0, CARD_fields_text, 
						 &Protocol_CARD, NULL);
    // This has been broken for a long time now
    // RegisterProtocol("CISCO", 0, CISCO_fields_text, &Protocol_CISCO, NULL);
	globalreg->netproto_map[PROTO_REF_INFO] =
		RegisterProtocol("INFO", 0, 0, INFO_fields_text, 
						 &Protocol_INFO, NULL);
	globalreg->netproto_map[PROTO_REF_PACKET] =
		RegisterProtocol("PACKET", 0, 0, PACKET_fields_text, &Protocol_PACKET, NULL);
	globalreg->netproto_map[PROTO_REF_STATUS] =
		RegisterProtocol("STATUS", 0, 0, STATUS_fields_text, &Protocol_STATUS, NULL);
	globalreg->netproto_map[PROTO_REF_STRING] =
		RegisterProtocol("STRING", 0, 0, STRING_fields_text, 
						 &Protocol_STRING, NULL);
	globalreg->netproto_map[PROTO_REF_WEPKEY] =
		RegisterProtocol("WEPKEY", 0, 0, WEPKEY_fields_text, &Protocol_WEPKEY, NULL);

    // Kismet builtin client commands
    RegisterClientCommand("CAPABILITY", &Clicmd_CAPABILITY);
    RegisterClientCommand("ENABLE", &Clicmd_ENABLE);
    RegisterClientCommand("REMOVE", &Clicmd_REMOVE);
    RegisterClientCommand("CHANLOCK", &Clicmd_CHANLOCK);
    RegisterClientCommand("CHANHOP", &Clicmd_CHANHOP);
    RegisterClientCommand("PAUSE", &Clicmd_PAUSE);
    RegisterClientCommand("RESUME", &Clicmd_RESUME);

    // Sanity check for timetracker
    if (globalreg->timetracker == NULL) {
        fprintf(stderr, "*** KisNetFramework globalreg->timetracker not "
                "initialized.  We're going to crash and burn!  Report this error.\n");
        exit(1);
    }

    // Register timer events
    globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, 
                                          &KisNetFrame_TimeEvent, NULL);

}

KisNetFramework::~KisNetFramework() {
    // Remove our message handler
    globalreg->messagebus->RemoveClient(kisnet_msgcli);
}

int KisNetFramework::Accept(int in_fd) {
    // Create their options
    client_opt *opt = new client_opt;
    client_optmap[in_fd] = opt;

    // Set the mandatory sentences.  We don't have to do error checking here because
    // it can't exist in the required vector if it isn't registered.
    for (unsigned int reqprot = 0; reqprot < required_protocols.size(); reqprot++) {
        int tref = required_protocols[reqprot];
        vector<int> reqfields;
        map<int, server_protocol *>::iterator spitr = protocol_map.find(tref);
        for (unsigned int fnum = 0; fnum < spitr->second->field_vec.size(); fnum++) {
            reqfields.push_back(fnum);
        }

        AddProtocolClient(in_fd, tref, reqfields);
    }

    // Send the mandatory stuff like the Kismet info
    KISMET_data kdat;
    char temp[512];

    kdat.version = "0.0.0";
    snprintf(temp, 512, "%u", (unsigned int) globalreg->start_time);
    kdat.starttime = string(temp);
    kdat.servername = globalreg->servername;
    kdat.timestamp = string(TIMESTAMP);
    snprintf(temp, 512, "%s.%s.%s", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY);
    kdat.newversion = string(temp);
   
    SendToClient(in_fd, globalreg->netproto_map[PROTO_REF_KISMET], 
				 (void *) &kdat, NULL);
  
    // Protocols
    SendToClient(in_fd, globalreg->netproto_map[PROTO_REF_PROTOCOL], 
				 (void *) &protocol_map, NULL);
    
    return 1;
}

int KisNetFramework::ParseData(int in_fd) {
    int len, rlen;
    char *buf;
    string strbuf;

    len = netserver->FetchReadLen(in_fd);
    buf = new char[len + 1];
    
    if (netserver->ReadData(in_fd, buf, len, &rlen) < 0) {
        globalreg->messagebus->InjectMessage("KisNetFramework::ParseData failed to "
											 "fetch data from the client.", 
											 MSGFLAG_ERROR);
        return -1;
    }
    buf[len] = '\0';

    // Parse without including partials, so we don't get a fragmented command 
    // out of the buffer
    vector<string> inptok = StrTokenize(buf, "\n", 0);
    delete[] buf;

    // Bail on no useful data
    if (inptok.size() < 1) {
        return 0;
    }


    for (unsigned int it = 0; it < inptok.size(); it++) {
        // No matter what we've dealt with this data block
        netserver->MarkRead(in_fd, inptok[it].length() + 1);

        // Handle funny trailing stuff from telnet and some other clients
        if (inptok[it][inptok[it].length() - 1] == '\r') {
            inptok[it] = inptok[it].substr(0, inptok[it].length() - 1);
        }
        
        vector<smart_word_token> cmdtoks = SmartStrTokenize(inptok[it], " ");

        if (cmdtoks.size() < 2) {
            // Silently fail since there wasn't enough to deal with it
            continue;
        }

        int cmdid;
        if (sscanf(cmdtoks[0].word.c_str(), "!%d", &cmdid) != 1) {
            // Silently fail if we can't figure out how to generate the error, again
            continue;
        }

        // Nuke the first element of the command tokens (we just pulled it off to 
		// get the cmdid)
        cmdtoks.erase(cmdtoks.begin());

        // Find a command function to deal with this protocol
        CLIRESP_data rdat;
        rdat.cmdid = cmdid;

        map<string, ClientCommand>::iterator ccitr = 
			client_cmd_map.find(StrLower(cmdtoks[0].word));
        if (ccitr != client_cmd_map.end()) {
            // Nuke the first word again - we just pulled it off to get the command
            cmdtoks.erase(cmdtoks.begin());

            string fullcmd = 
				inptok[it].substr(cmdtoks[0].end, (inptok[it].length() - 
												   cmdtoks[0].end));
            // Call the processor and return error conditions and ack
            if ((*ccitr->second)
				(in_fd, this, globalreg, errstr, fullcmd, &cmdtoks) < 0) {
                rdat.resptext = string(errstr);
                SendToClient(in_fd, globalreg->netproto_map[PROTO_REF_ERROR], 
							 (void *) &rdat, NULL);
				_MSG("Failed Kismet client command: " + rdat.resptext, MSGFLAG_ERROR);
            } else {
                rdat.resptext = string("OK");
                SendToClient(in_fd, globalreg->netproto_map[PROTO_REF_ACK], 
							 (void *) &rdat, NULL);
            }
        } else {
            rdat.resptext = string("NO SUCH COMMAND");
            SendToClient(in_fd, globalreg->netproto_map[PROTO_REF_ERROR], 
						 (void *) &rdat, NULL);
        }

    }
    
    return 1;
}

int KisNetFramework::KillConnection(int in_fd) {
    // Do a little testing here since we might not have an opt record
    map<int, client_opt *>::iterator citr = client_optmap.find(in_fd);
    if (citr != client_optmap.end()) {
        // Remove all our protocols
        for (map<int, vector<int> >::iterator clpitr = citr->second->protocols.begin();
             clpitr != citr->second->protocols.end(); ++clpitr)
            DelProtocolClient(in_fd, clpitr->first);

        delete citr->second;
        client_optmap.erase(citr);
    }

    return 1;
}

int KisNetFramework::RegisterClientCommand(string in_cmdword, ClientCommand in_cmd) {
    string lcmd = StrLower(in_cmdword);

    if (in_cmdword.length() > 16) {
        snprintf(errstr, 1024, "KisNetFramework::RegisterClientCommand refusing to "
                 "register '%s' as it is greater than 16 characters.",
                 in_cmdword.c_str());
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    if (client_cmd_map.find(lcmd) != client_cmd_map.end()) {
        snprintf(errstr, 1024, "KisNetFramework::RegisterClientCommand refusing to "
                 "register command '%s', command already exists.", lcmd.c_str());
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    client_cmd_map[lcmd] = in_cmd;

    return 1;
}

// Create an output string based on the clients
// This looks very complex - and it is - but almost all of the "big" ops like
// find are done with integer references.  They're cheap.
// This takes the struct to be sent and pumps it through the dynamic protocol/field
// system.
int KisNetFramework::SendToClient(int in_fd, int in_refnum, const void *in_data,
								  kis_protocol_cache *in_cache) {
    // Make sure this is a valid client
    map<int, client_opt *>::iterator opitr = client_optmap.find(in_fd);
    if (opitr == client_optmap.end()) {
        snprintf(errstr, 1024, "KisNetFramework::SendToClient illegal client %d.", 
				 in_fd);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }
    client_opt *opt = opitr->second;

    // See if this client even handles this protocol...
    map<int, vector<int> >::iterator clprotitr = opt->protocols.find(in_refnum);
    if (clprotitr == opt->protocols.end())
        return 0;

    const vector<int> *fieldlist = &clprotitr->second;

    // Find this protocol now - we only do this after we're sure we want to print to
    // it.
    map<int, server_protocol *>::iterator spitr = protocol_map.find(in_refnum);
    if (spitr == protocol_map.end()) {
        snprintf(errstr, 1024, "KisNetFramework::SendToClient Protocol %d not "
				 "registered.", in_refnum);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }
    server_protocol *prot = spitr->second;

	if (prot->cacheable && in_cache == NULL) {
        snprintf(errstr, 1024, "KisNetFramework::SendToClient protocol %s "
				 "requires caching but got a NULL cache ref, fix me",
				 prot->header.c_str());
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    // Bounce through the printer function
    string fieldtext;
    if ((*prot->printer)(fieldtext, fieldlist, in_data, in_cache, globalreg) == -1) {
        snprintf(errstr, 1024, "%s", fieldtext.c_str());
        return -1;
    }

    // Assemble a line for them:
    // *HEADER: DATA\n
    //  16      x   1
    int nlen = prot->header.length() + fieldtext.length() + 5; // *..: \n\0
    char *outtext = new char[nlen];
    snprintf(outtext, nlen, "*%s: %s\n", prot->header.c_str(), fieldtext.c_str());
    netserver->WriteData(in_fd, (uint8_t *) outtext, strlen(outtext));
    delete[] outtext;

    return nlen;
}

int KisNetFramework::SendToAll(int in_refnum, const void *in_data) {
    vector<int> clvec;
    int nsent = 0;

	if (netserver == NULL)
		return 0;

	kis_protocol_cache cache;

    netserver->FetchClientVector(&clvec);

    for (unsigned int x = 0; x < clvec.size(); x++) {
        if (SendToClient(clvec[x], in_refnum, in_data, &cache) > 0)
            nsent++;
    }

    return nsent;
}

int KisNetFramework::RegisterProtocol(string in_header, int in_required, int in_cache,
									  char **in_fields,
                                      int (*in_printer)(PROTO_PARMS),
                                      void (*in_enable)(PROTO_ENABLE_PARMS)) {
    // First, see if we're already registered and return a -1 if we are.  You can't
    // register a protocol twice.
    if (FetchProtocolRef(in_header) != -1) {
        snprintf(errstr, 1024, "KisNetFramework::RegisterProtocol refusing to "
                 "register '%s' as it is already a registered protocol.",
                 in_header.c_str());
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    if (in_header.length() > 16) {
        snprintf(errstr, 1024, "KisNetFramework::RegisterProtocol refusing to "
                 "register '%s' as it is greater than 16 characters.",
                 in_header.c_str());
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    int refnum = protocol_map.size() + 1;

    server_protocol *sen = new server_protocol;
    sen->ref_index = refnum;
    sen->header = in_header;

    int x = 0;
    while (in_fields[x] != NULL) {
        sen->field_map[in_fields[x]] = x;
        sen->field_vec.push_back(in_fields[x]);
        x++;
    }
    sen->printer = in_printer;
    sen->enable = in_enable;
    sen->required = in_required;
	sen->cacheable = in_cache;

    // Put us in the map
    protocol_map[refnum] = sen;
    ref_map[in_header] = refnum;

    if (in_required)
        required_protocols.push_back(refnum);

    return refnum;
}

int KisNetFramework::FetchProtocolRef(string in_header) {
    map<string, int>::iterator rmitr = ref_map.find(in_header);
    if (rmitr == ref_map.end())
        return -1;

    return rmitr->second;
}

KisNetFramework::server_protocol *KisNetFramework::FetchProtocol(int in_ref) {
    KisNetFramework::server_protocol *ret = NULL;

    map<int, KisNetFramework::server_protocol *>::iterator spi =
        protocol_map.find(in_ref);

    if (spi != protocol_map.end())
        ret = spi->second;
    
    return ret;
}

int KisNetFramework::FetchNumClientRefs(int in_refnum) {
    map<int, int>::iterator cmpitr = client_mapped_protocols.find(in_refnum);
    if (cmpitr != client_mapped_protocols.end())
        return cmpitr->second;

    return 0;
}

int KisNetFramework::FetchNumClients() {
    return netserver->FetchNumClients();
}

void KisNetFramework::AddProtocolClient(int in_fd, int in_refnum, vector<int> in_fields) {
    map<int, client_opt *>::iterator citr = client_optmap.find(in_fd);
    if (citr == client_optmap.end()) {
        return;
    }

    // Find out if it already exists and increment the use count if it does
    map<int, vector<int> >::iterator clpitr = citr->second->protocols.find(in_refnum);
    if (clpitr == citr->second->protocols.end())
        client_mapped_protocols[in_refnum]++;

    citr->second->protocols[in_refnum] = in_fields;
}

void KisNetFramework::DelProtocolClient(int in_fd, int in_refnum) {
    map<int, client_opt *>::iterator citr = client_optmap.find(in_fd);
    if (citr == client_optmap.end())
        return;

    map<int, vector<int> >::iterator clpitr = citr->second->protocols.find(in_refnum);
    if (clpitr != citr->second->protocols.end()) {
        citr->second->protocols.erase(clpitr);
        client_mapped_protocols[in_refnum]--;
    }
}
