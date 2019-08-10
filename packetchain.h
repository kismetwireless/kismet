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
 */

#define CHAINPOS_POSTCAP        2
#define CHAINPOS_LLCDISSECT     3
#define CHAINPOS_DECRYPT        4
#define CHAINPOS_DATADISSECT    5
#define CHAINPOS_CLASSIFIER     6
#define CHAINPOS_TRACKER		7
#define CHAINPOS_LOGGING        8

#define CHAINCALL_PARMS global_registry *globalreg __attribute__ ((unused)), \
    void *auxdata __attribute__ ((unused)), \
    kis_packet *in_pack

class kis_packet;

class packet_chain : public lifetime_global {
public:
    static std::string global_name() { return "PACKETCHAIN"; }

    static std::shared_ptr<packet_chain> create_packetchain() {
        std::shared_ptr<packet_chain> mon(new packet_chain());
        Globalreg::globalreg->packetchain = mon.get();
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    packet_chain();

public:
    virtual ~packet_chain();

    int RegisterPacketComponent(std::string in_component);
    int RemovePacketComponent(int in_id);
    std::string FetchPacketComponentName(int in_id);

    // Generate a packet and hand it back
    kis_packet *GeneratePacket();
    // Inject a packet into the chain
    int process_packet(kis_packet *in_pack);
    // Destroy a packet at the end of its life
    void DestroyPacket(kis_packet *in_pack);
 
    // Callback and information 
    typedef int (*pc_callback)(CHAINCALL_PARMS);
    typedef struct {
        int priority;
		packet_chain::pc_callback callback;
        std::function<int (kis_packet *)> l_callback;
        void *auxdata;
		int id;
    } pc_link;

    // Register a callback, aux data, a chain to put it in, and the priority 
    int register_handler(pc_callback in_cb, void *in_aux, int in_chain, int in_prio);
    int register_handler(std::function<int (kis_packet *)> in_cb, int in_chain, int in_prio);
    int RemoveHandler(pc_callback in_cb, int in_chain);
	int RemoveHandler(int in_id, int in_chain);

protected:
    void packet_queue_processor(int slot_number);

    // Common function for both insertion methods
    int RegisterIntHandler(pc_callback in_cb, void *in_aux, 
            std::function<int (kis_packet *)> in_l_cb, 
            int in_chain, int in_prio);

    int next_componentid, next_handlerid;

    std::map<std::string, int> component_str_map;
    std::map<int, std::string> component_id_map;

    // Core chain components
    std::vector<packet_chain::pc_link *> postcap_chain;
    std::vector<packet_chain::pc_link *> llcdissect_chain;
    std::vector<packet_chain::pc_link *> decrypt_chain;
    std::vector<packet_chain::pc_link *> datadissect_chain;
    std::vector<packet_chain::pc_link *> classifier_chain;
	std::vector<packet_chain::pc_link *> tracker_chain;
    std::vector<packet_chain::pc_link *> logging_chain;

    // Packet component mutex
    kis_recursive_timed_mutex packetcomp_mutex;

    std::vector<std::thread> packet_threads;

    std::mutex packetqueue_cv_mutex;
    std::condition_variable packetqueue_cv;

    std::queue<kis_packet *> packet_queue;
    bool packetchain_shutdown;

    // Synchronization lock between threads and packet chain so we can make sure
    // we've locked every thread down before changing the packetchain handlers
    kis_recursive_timed_mutex packet_chain_sync_mutex;

    std::atomic<bool> packet_chain_pause;

    // Vector of conditional locks to force sync of all the threads when necessary
    std::vector<conditional_locker<int> *> packet_thread_cls;

    // Locker for the handler threads to wait on to resume them all
    conditional_locker<unsigned int> packet_chain_pause_cl;

    // Synchronize and lock the service threads, returns when done
    int sync_service_threads(std::function<int (void)> fn);

    // Warning and discard levels for packet queue being full
    unsigned int packet_queue_warning, packet_queue_drop;
    time_t last_packet_queue_user_warning, last_packet_drop_user_warning;
};

#endif

