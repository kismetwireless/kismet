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

#include "finitestate.h"
#include "util.h"

Finitetracker::Finitetracker() {
    atracker = NULL;
}

Finitetracker::~Finitetracker() {
    // Nothing smart to do here
}

int Finitetracker::ProcessPacket(const kis_packet *in_packet, const packet_info *in_info) {

    int ret = 0;

    for (unsigned int x = 0; x < fsa_vec.size(); x++) {
        if ((ret = fsa_vec[x]->ProcessPacket(in_packet, in_info)) < 0)
            return ret;
    }

    return 1;
}

void Finitetracker::AddAlertracker(Alertracker *in_tracker) {
    atracker = in_tracker;
}

int Finitetracker::EnableAlert(string in_alname, alert_time_unit in_unit,
                               int in_rate, int in_burstrate) {

    if (atracker == NULL)
        return -1;

    string lname = StrLower(in_alname);
    if (lname == "probenojoin") {
        ProbeNoJoinAutomata *pnja = new ProbeNoJoinAutomata(atracker, in_unit, in_rate, in_burstrate);
        fsa_vec.push_back(pnja);
        return 1;
    }

    return 0;
}

ProbeNoJoinAutomata::ProbeNoJoinAutomata(Alertracker *in_tracker, alert_time_unit in_unit, int in_rate, int in_burstrate) {
    atracker = in_tracker;
    alertid = atracker->RegisterAlert("PROBENOJOIN", in_unit, in_rate, in_burstrate);
}

ProbeNoJoinAutomata::~ProbeNoJoinAutomata() {
    for (map<mac_addr, _fsa_element *>::iterator iter = bssid_map.begin();
         iter != bssid_map.end(); ++iter) {
        delete iter->second;
    }
}

int ProbeNoJoinAutomata::ProcessPacket(const kis_packet *in_packet, const packet_info *in_info) {
    _fsa_element *elem;
    map<mac_addr, _fsa_element *>::iterator iter;

    if (in_info->type == packet_management && in_info->subtype == packet_sub_probe_req) {
        // For probe reqs we look at the source MAC and see what we have.  We'll let someone
        // probe as much as they want, they'd just better answer if a network starts talking to
        // them.  Just make a tracking record that they've been probing
        if ((iter = bssid_map.find(in_info->source_mac)) == bssid_map.end()) {
            elem = new _fsa_element;
            bssid_map[in_info->source_mac] = elem;
            return 1;
        } else {
            return 1;
        }
    } else if (in_info->type == packet_management && in_info->subtype == packet_sub_probe_resp) {
        // Responses create an element if none exists for the destination, and we set anyone getting a
        // response to state 1
        if ((iter = bssid_map.find(in_info->dest_mac)) == bssid_map.end()) {
            elem = new _fsa_element;
            bssid_map[in_info->dest_mac] = elem;
        } else {
            elem = iter->second;
        }

        if (elem->state <= 1) {
            elem->state = 1;
            elem->counter++;

            // Trigger on threshold
            if (elem->counter > 10) {
                char atext[STATUS_MAX];
                snprintf(atext, STATUS_MAX, "Suspicious client %s - probing networks but never participating.",
                         iter->first.Mac2String().c_str());
                atracker->RaiseAlert(alertid, atext);
            }

        }

        return 1;
    } else if (in_info->type == packet_data) {
        // If they look like a netstumbler packet, we don't let them go
        if (in_info->proto.type == proto_netstumbler || in_info->proto.type == proto_lucenttest ||
            in_info->proto.type == proto_wellenreiter)
            return 1;

        // If the source is our person, they're exonerated - they're doing normal traffic
        if ((iter = bssid_map.find(in_info->source_mac)) == bssid_map.end()) {
            elem = new _fsa_element;
            bssid_map[in_info->source_mac] = elem;
        } else {
            elem = iter->second;
        }

        elem->state = 2;

        return 1;
    }


    return 0;
}


