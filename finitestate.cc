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
#include "packetracker.h"
#include "util.h"

ProbeNoJoinAutomata::ProbeNoJoinAutomata(Packetracker *in_ptracker, Alertracker *in_atracker,
                                         alert_time_unit in_unit, int in_rate, int in_burstrate) {
    atracker = in_atracker;
    ptracker = in_ptracker;
    alertid = atracker->RegisterAlert("PROBENOJOIN", in_unit, in_rate, in_burstrate);
}

ProbeNoJoinAutomata::~ProbeNoJoinAutomata() {
    for (map<mac_addr, _fsa_element *>::iterator iter = bssid_map.begin();
         iter != bssid_map.end(); ++iter) {
        delete iter->second;
    }
}

int ProbeNoJoinAutomata::ProcessPacket(const packet_info *in_info) {
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

SequenceSpoofAutomata::SequenceSpoofAutomata(Packetracker *in_ptracker, Alertracker *in_atracker,
                                             alert_time_unit in_unit, int in_rate, int in_burstrate) {
    atracker = in_atracker;
    ptracker = in_ptracker;
    alertid = atracker->RegisterAlert("SEQUENCESPOOF", in_unit, in_rate, in_burstrate);
}

SequenceSpoofAutomata::~SequenceSpoofAutomata() {
}


int SequenceSpoofAutomata::ProcessPacket(const packet_info *in_info) {
    // Only sequence-track beacons (for now)
    int ret = 0;
    /*
    if (in_info->type != packet_management && in_info->subtype != packet_sub_beacon)
        return 0;

    // Try to match the mac addr to an existing network
    map<mac_adder, _fsa_element *>::iterator iter;


    // If we have more than 2 suspicious MAC changes in the records, raise an alert.
    if (count > 2) {
        char atext[STATUS_MAX];
        snprintf(atext, STATUS_MAX, "Suspicious sequence order - %s looks like %s (%d to %d).  Possible FakeAP.",
                 in_info->source_mac.Mac2String().c_str(), seq->source_mac.Mac2String().c_str(),
                 in_info->sequence_number, seq->seq_num);
        atracker->RaiseAlert(alertid, atext);
        fprintf(stderr, "**FORCED** %s\n", atext);
        ret = 1;
    }

    // Put it on the stack
    seq = new _seq_elem;
    seq->seq_num = in_info->sequence_number;
    seq->source_mac = in_info->source_mac;
    seq_stack.push_back(seq);
    if (seq_stack.size() > 150) {
        delete seq_stack[0];
        seq_stack.erase(seq_stack.begin());
    }
    */

    return ret;
}

