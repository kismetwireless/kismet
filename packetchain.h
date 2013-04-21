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

#ifndef __PACKETCHAIN_H__
#define __PACKETCHAIN_H__

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <algorithm>
#include <string>
#include <vector>
#include <map>

#include <pthread.h>

#include "globalregistry.h"
#include "packet.h"

// Packet chain progression
// GENESIS
//   --> genesis_chain
//
// (arbitrary fill-in by whomever generated the packet before injection)
//
// POST-CAPTURE
//
// DISSECT
//
// DECRYPT
//
// DATA-DISSECT
//
// CLASSIFIER
//
// TRACKER
//
// LOGGING
//
// DESTROY
//   --> destroy_chain

#define CHAINPOS_GENESIS        1
#define CHAINPOS_POSTCAP        2
#define CHAINPOS_LLCDISSECT     3
#define CHAINPOS_DECRYPT        4
#define CHAINPOS_DATADISSECT    5
#define CHAINPOS_CLASSIFIER     6
#define CHAINPOS_TRACKER		7
#define CHAINPOS_LOGGING        8
#define CHAINPOS_DESTROY        9

#define CHAINCALL_PARMS GlobalRegistry *globalreg, void *auxdata, kis_packet *in_pack

class kis_packet;

class Packetchain {
public:
    Packetchain();
    Packetchain(GlobalRegistry *in_globalreg);

    int RegisterPacketComponent(string in_component);
    int RemovePacketComponent(int in_id);
	string FetchPacketComponentName(int in_id);

    // Generate a packet and hand it back
    kis_packet *GeneratePacket();
    // Inject a packet into the chain
    int ProcessPacket(kis_packet *in_pack);
    // Destroy a packet at the end of its life
    void DestroyPacket(kis_packet *in_pack);
 
    // Callback and information 
    typedef int (*pc_callback)(CHAINCALL_PARMS);
    typedef struct {
        int priority;
		Packetchain::pc_callback callback;
        void *auxdata;
		int id;
    } pc_link;

    // Register a callback, aux data, a chain to put it in, and the priority 
    int RegisterHandler(pc_callback in_cb, void *in_aux, int in_chain, int in_prio);
    int RemoveHandler(pc_callback in_cb, int in_chain);
	int RemoveHandler(int in_id, int in_chain);

protected:
    GlobalRegistry *globalreg;

    int next_componentid, next_handlerid;

    map<string, int> component_str_map;
    map<int, string> component_id_map;

    // These two chains get called after a packet is generated and
    // before the final destruction, respectively
    vector<Packetchain::pc_link *> genesis_chain;
    vector<Packetchain::pc_link *> destruction_chain;

    // Core chain components
    vector<Packetchain::pc_link *> postcap_chain;
    vector<Packetchain::pc_link *> llcdissect_chain;
    vector<Packetchain::pc_link *> decrypt_chain;
    vector<Packetchain::pc_link *> datadissect_chain;
    vector<Packetchain::pc_link *> classifier_chain;
	vector<Packetchain::pc_link *> tracker_chain;
    vector<Packetchain::pc_link *> logging_chain;

	pthread_mutex_t packetchain_mutex;
};

#endif

