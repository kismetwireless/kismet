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

#ifndef __FINITESTATE_H__
#define __FINITESTATE_H__

#include "config.h"

#include <time.h>
#include <sys/time.h>

#include "kismet_server.h"
#include "alertracker.h"

// Forward definition for packetracker
class Packetracker;

// Finite state automata superclass which handles a category of tracking conditions.
// It's possible that there can be multiple state machines of a single category
// (ie, tracking multiple potential quesitionable MACs); the FiniteAutomata is
// responsible for handling these in whatever sane manner is necessary and for
// timing out old conections.
class FiniteAutomata {
public:
    // An individual state element
    class _fsa_element {
    public:
        _fsa_element() {
            last_time.tv_sec = start_time.tv_sec = death_time.tv_sec = 0;
            last_time.tv_usec = start_time.tv_usec = death_time.tv_usec = 0;
            state = 0;
            counter = 0;
        }

        struct timeval last_time;
        struct timeval start_time;
        struct timeval death_time;
        int state;
        int counter;
    };

    virtual ~FiniteAutomata() { }

    // Handle a packet
    virtual int ProcessPacket(const packet_info *in_info) = 0;

    int FetchAlertRef() { return alertid; }

protected:
    Alertracker *atracker;
    Packetracker *ptracker;
    int alertid;
};

// Finite state automata to watch people who probe and never exchange data after an association
class ProbeNoJoinAutomata : public FiniteAutomata {
public:
    ProbeNoJoinAutomata(Packetracker *in_ptracker, Alertracker *in_atracker,
                        alert_time_unit in_unit, int in_rate, int in_burstrate);
    ~ProbeNoJoinAutomata();

    // States:
    // State 0: Probe only
    // State 1: Probe and response seen
    // State 2: Normal user, probe response and data seen

    // Threshold if state == 2 && counter is over threshold

    int ProcessPacket(const packet_info *in_info);

protected:
    // Map of probing clients to responding people.  If the client sends any "normal" data
    // destined to that network, we reset them.
    map<mac_addr, _fsa_element *> bssid_map;
};

// Finite state automata to watch sequence numbers
class SequenceSpoofAutomata : public FiniteAutomata {
public:
    SequenceSpoofAutomata(Packetracker *in_ptracker, Alertracker *in_atracker,
                          alert_time_unit in_unit, int in_rate, int in_burstrate);
    ~SequenceSpoofAutomata();

    int ProcessPacket(const packet_info *in_info);

protected:
    // State 0 - Undefined source
    // State 1 - Source with beacons only
    // State 2 - Source with real traffic

    map<mac_addr, _fsa_element *> seq_map;
};

#endif
