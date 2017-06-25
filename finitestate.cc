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

ProbeNoJoinAutomata::ProbeNoJoinAutomata(GlobalRegistry *in_globalreg,
                                         alert_time_unit in_unit, int in_rate, int in_burstrate) {
    globalreg = in_globalreg;
    alertid = globalreg->alertracker->RegisterAlert("PROBENOJOIN", in_unit, in_rate, in_burstrate);
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
            if (elem->counter > 25) {
                char atext[STATUS_MAX];
                snprintf(atext, STATUS_MAX, "Suspicious client %s - probing networks but never participating.",
                         iter->first.Mac2String().c_str());
                globalreg->alertracker->RaiseAlert(alertid, 0, iter->first, 0, 0, in_info->channel, atext);
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

DisassocTrafficAutomata::DisassocTrafficAutomata(GlobalRegistry *in_globalreg,
                        alert_time_unit in_unit, int in_rate, int in_burstrate) {
    globalreg = in_globalreg;
    alertid = globalreg->alertracker->RegisterAlert("DISASSOCTRAFFIC", in_unit, in_rate, in_burstrate);
}

DisassocTrafficAutomata::~DisassocTrafficAutomata() {

}

int DisassocTrafficAutomata::ProcessPacket(const packet_info *in_info) {
    _fsa_element *elem;
    map<mac_addr, _fsa_element *>::iterator iter;
    char atext[STATUS_MAX];

    if (in_info->type == packet_management && in_info->subtype == packet_sub_disassociation) {
        iter = source_map.find(in_info->source_mac);

        if (iter == source_map.end()) {
            elem = new _fsa_element;
            source_map[in_info->source_mac] = elem;
            elem->counter = 0;
        } else {
            elem = iter->second;
        }

        elem->state = 0;
        gettimeofday(&elem->last_time, NULL);
    } else if (in_info->type == packet_management && in_info->subtype == packet_sub_deauthentication) {
        iter = source_map.find(in_info->source_mac);

        if (iter == source_map.end()) {
            elem = new _fsa_element;
            source_map[in_info->source_mac] = elem;
            elem->counter = 0;
        } else {
            elem = iter->second;
        }

        elem->state = 1;
        gettimeofday(&elem->last_time, NULL);
    } else if (in_info->type == packet_data) {
        iter = source_map.find(in_info->source_mac);

        if (iter == source_map.end())
            return 0;

        elem = iter->second;

        struct timeval tv;
        gettimeofday(&tv, NULL);

        // Raise an alert if someone is exchanging data w/in 10 seconds of disassociating or deauthenticating
        if (tv.tv_sec - elem->last_time.tv_sec < 10) {
            elem->counter++;

            snprintf(atext, STATUS_MAX, "Suspicious traffic on %s.  Data traffic within 10 seconds of disassociate.",
                     in_info->source_mac.Mac2String().c_str());
            globalreg->alertracker->RaiseAlert(alertid, in_info->bssid_mac, in_info->source_mac, 
                                               0, 0, in_info->channel, atext);

            return 1;
        } else {
            delete[] iter->second;
            source_map.erase(iter);
        }

    }

    return 0;
}

BssTimestampAutomata::BssTimestampAutomata(GlobalRegistry *in_globalreg,
                        alert_time_unit in_unit, int in_rate, int in_burstrate) {
    globalreg = in_globalreg;
    alertid = globalreg->alertracker->RegisterAlert("BSSTIMESTAMP", in_unit, in_rate, in_burstrate);
}

BssTimestampAutomata::~BssTimestampAutomata() {
    for (macmap<BssTimestampAutomata::_bs_fsa_element *>::iterator iter = bss_map.begin();
         iter != bss_map.end(); ++iter) {
        delete iter->second;
    }
}

int BssTimestampAutomata::ProcessPacket(const packet_info *in_info) {
    _bs_fsa_element *elem;
    char atext[1024];

    // Don't track BSS timestamp for non-beacon frames or for adhoc networks
    if (in_info->timestamp == 0 || in_info->type != packet_management || 
        in_info->subtype != packet_sub_beacon || in_info->distrib == adhoc_distribution)
        return 0;

    macmap<BssTimestampAutomata::_bs_fsa_element *>::iterator iter = bss_map.find(in_info->bssid_mac);
    if (iter == bss_map.end()) {
        elem = new _bs_fsa_element;
        elem->bss_timestamp = in_info->timestamp;
        bss_map.insert(in_info->bssid_mac, elem);
        return 0;
    } else {
        elem = *(iter->second);
    }

    if (in_info->timestamp < elem->bss_timestamp) {
        if (elem->counter > 0) {
            // Generate an alert, we're getting a bunch of invalid timestamps

            snprintf(atext, STATUS_MAX, "Out-of-sequence BSS timestamp on %s "
                     "- got %llx, expected %llx - this could indicate AP spoofing",
                     in_info->bssid_mac.Mac2String().c_str(), in_info->timestamp,
                     elem->bss_timestamp);
            globalreg->alertracker->RaiseAlert(alertid, in_info->bssid_mac, 0, 0, 0, in_info->channel, atext);

            // Reset so we don't keep thrashing here
            elem->counter = 0;
            elem->bss_timestamp = in_info->timestamp;

            return 1;
        } else {
            // Increase our invalid stock
            elem->counter += 10;
        }
    } else if (elem->counter > 0) {
        elem->counter--;
    }

    elem->bss_timestamp = in_info->timestamp;

    return 0;
}

WepRebroadcastAutomata::WepRebroadcastAutomata(GlobalRegistry *in_globalreg,
                                               alert_time_unit in_unit, int in_rate, int in_burstrate) {
    globalreg = in_globalreg;
    alertid = globalreg->alertracker->RegisterAlert("WEPREBROADCAST", in_unit, in_rate, in_burstrate);
}

WepRebroadcastAutomata::~WepRebroadcastAutomata() {
}

int WepRebroadcastAutomata::ProcessPacket(const packet_info *in_info) {
    return 0;
}

#if 0
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
    char atext[STATUS_MAX];

    if (in_info->type != packet_management || in_info->subtype != packet_sub_beacon)
        return 0;

    // See if we know about this network
    wireless_network *net = ptracker->MatchNetwork(in_info);

    if (net != NULL) {
        // If we found a network for this packet, see if it's got a sequence mismatch.
        // remember we modulo the sequence by 4096, so we won't worry about a sequence drop
        // if the network used to be near the wraparound
        if (net->last_sequence < 4000 && net->last_sequence != 0 &&
            (in_info->sequence_number < net->last_sequence)) {
            snprintf(atext, STATUS_MAX, "Suspicious sequence change - %s %d to %d.  Possible spoof attempt.",
                     net->bssid.Mac2String().c_str(), net->last_sequence, in_info->sequence_number);
            atracker->RaiseAlert(alertid, atext);
        }

    }

    /*
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
#endif
