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
#include <functional>
#include <queue>
#include <thread>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "packet.h"


/* Packets are added to the packet queue from any thread (including the main 
 * thread).
 *
 * They are then processed by the packet consumption thread(s) via the registered
 * chain handlers.
 *
 * Once being inserted into the packet chain, the packet pointer may no longer be
 * considered valid by the generating thread.
 *
 * Packet chain progression
 * GENESIS
 *   --> genesis_chain
 * 
 * (arbitrary fill-in by whomever generated the packet before injection)
 * 
 * POST-CAPTURE
 * 
 * DISSECT
 * 
 * DECRYPT
 * 
 * DATA-DISSECT
 * 
 * CLASSIFIER
 * 
 * TRACKER
 * 
 * LOGGING
 * 
 * DESTROY
 *   --> destroy_chain
 */

#define CHAINPOS_GENESIS        1
#define CHAINPOS_POSTCAP        2
#define CHAINPOS_LLCDISSECT     3
#define CHAINPOS_DECRYPT        4
#define CHAINPOS_DATADISSECT    5
#define CHAINPOS_CLASSIFIER     6
#define CHAINPOS_TRACKER		7
#define CHAINPOS_LOGGING        8
#define CHAINPOS_DESTROY        9

#define CHAINCALL_PARMS GlobalRegistry *globalreg __attribute__ ((unused)), \
    void *auxdata __attribute__ ((unused)), \
    kis_packet *in_pack

class kis_packet;

class Packetchain : public LifetimeGlobal {
public:
    static std::string global_name() { return "PACKETCHAIN"; }

    static std::shared_ptr<Packetchain> create_packetchain() {
        std::shared_ptr<Packetchain> mon(new Packetchain());
        Globalreg::globalreg->packetchain = mon.get();
        Globalreg::globalreg->RegisterLifetimeGlobal(mon);
        Globalreg::globalreg->InsertGlobal(global_name(), mon);
        return mon;
    }

private:
    Packetchain();

public:
    virtual ~Packetchain();

    int RegisterPacketComponent(std::string in_component);
    int RemovePacketComponent(int in_id);
    std::string FetchPacketComponentName(int in_id);

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
        std::function<int (kis_packet *)> l_callback;
        void *auxdata;
		int id;
    } pc_link;

    // Register a callback, aux data, a chain to put it in, and the priority 
    int RegisterHandler(pc_callback in_cb, void *in_aux, int in_chain, int in_prio);
    int RegisterHandler(std::function<int (kis_packet *)> in_cb, int in_chain, int in_prio);
    int RemoveHandler(pc_callback in_cb, int in_chain);
	int RemoveHandler(int in_id, int in_chain);

protected:
    void packet_queue_processor();

    // Common function for both insertion methods
    int RegisterIntHandler(pc_callback in_cb, void *in_aux, 
            std::function<int (kis_packet *)> in_l_cb, 
            int in_chain, int in_prio);

    int next_componentid, next_handlerid;

    std::map<std::string, int> component_str_map;
    std::map<int, std::string> component_id_map;

    // These two chains get called after a packet is generated and
    // before the final destruction, respectively
    std::vector<Packetchain::pc_link *> genesis_chain;
    std::vector<Packetchain::pc_link *> destruction_chain;

    // Core chain components
    std::vector<Packetchain::pc_link *> postcap_chain;
    std::vector<Packetchain::pc_link *> llcdissect_chain;
    std::vector<Packetchain::pc_link *> decrypt_chain;
    std::vector<Packetchain::pc_link *> datadissect_chain;
    std::vector<Packetchain::pc_link *> classifier_chain;
	std::vector<Packetchain::pc_link *> tracker_chain;
    std::vector<Packetchain::pc_link *> logging_chain;

    // Whole packet-chain mutex
    kis_recursive_timed_mutex packetchain_mutex;

    std::vector<std::thread> packet_threads;

    kis_recursive_timed_mutex packetqueue_mutex;
    conditional_locker<int> packet_condition;
    std::queue<kis_packet *> packet_queue;
    bool packetchain_shutdown;

    // Warning and discard levels for packet queue being full
    unsigned int packet_queue_warning, packet_queue_drop;
    time_t last_packet_queue_user_warning, last_packet_drop_user_warning;
};

#endif

