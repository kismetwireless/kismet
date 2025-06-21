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

#include "eventbus.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "kis_net_beast_httpd.h"
#include "objectpool.h"
#include "unordered_dense.h"
#include "timetracker.h"
#include "trackedelement.h"
#include "trackedrrd.h"

#include "moodycamel/blockingconcurrentqueue.h"

/*
 * Packets are captured (typically from an IO thread, either for ASIO IPC and TCP or
 * boost-beast websocket io).
 *
 * Within the capturing thread, the POSTCAP chain is executed; this is responsible
 * for doing the initial decapsulation of the packet and creation of an assignment
 * hash which is used to assign the packet to a demod thread.
 *
 * Assignment hashes should attempt to be consistent for the devices contained in
 * the packet.  This necessitates dissecting the basic mac-layer information from
 * the packet, but allows kismet to assign packets modifying the same devices to
 * the same threads, minimizing device locking requirements when updating the device
 * content.
 *
 * Packet chain progression
 * GENESIS
 *
 * (arbitrary fill-in by whomever generated the packet before injection)
 *
 * POST-CAPTURE (executed in capture io thread)
 *
 * (assignment to mapped packet chain based on post-capture packet identifier
 * hash mapped to number of packet processing chains we have)
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

#define CHAINCALL_PARMS \
    void *auxdata __attribute__ ((unused)), \
    const std::shared_ptr<kis_packet>& in_pack

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

    void start_processing();

    int register_packet_component(std::string in_component);
    int remove_packet_component(int in_id);
    std::string fetch_packet_component_name(int in_id);

    // Generate a packet and hand it back
    std::shared_ptr<kis_packet> generate_packet();

    // Inject a packet into the chain
    int process_packet(std::shared_ptr<kis_packet> in_pack);

    // Callback and information
    typedef int (*pc_callback)(CHAINCALL_PARMS);
    typedef struct {
        int priority;

		packet_chain::pc_callback callback;

        void *auxdata;
		int id;
    } pc_link;

    // Register a callback, aux data, a chain to put it in, and the priority
    int register_handler(pc_callback in_cb, void *in_aux, int in_chain, int in_prio);
    int remove_handler(pc_callback in_cb, int in_chain);
	int remove_handler(int in_id, int in_chain);

    static std::string event_packetstats() { return "PACKETCHAIN_STATS"; }

    template<typename T>
    std::shared_ptr<T> new_packet_component() {
        kis_lock_guard<kis_mutex> lk(packetcomp_mutex);

        auto p = component_pool_map.find(typeid(T).hash_code());

        if (p != component_pool_map.end()) {
            return std::static_pointer_cast<shared_object_pool<T>>(p->second)->acquire();
        } else {
            auto pool = std::make_shared<shared_object_pool<T>>();
            pool->set_max(1024);
            pool->set_reset([](T *c) { c->reset(); });
            component_pool_map.insert({typeid(T).hash_code(), pool});
            return pool->acquire();
        }
    }

protected:
    void packet_queue_processor(moodycamel::BlockingConcurrentQueue<std::shared_ptr<kis_packet>> *packet_queue);

    // Common function for both insertion methods
    int register_int_handler(pc_callback in_cb, void *in_aux, int in_chain, int in_prio);

    int next_componentid, next_handlerid;

    std::map<std::string, int> component_str_map;
    std::map<int, std::string> component_id_map;

    // Core chain components
    std::vector<std::shared_ptr<packet_chain::pc_link>> postcap_chain;
    std::vector<std::shared_ptr<packet_chain::pc_link>> llcdissect_chain;
    std::vector<std::shared_ptr<packet_chain::pc_link>> decrypt_chain;
    std::vector<std::shared_ptr<packet_chain::pc_link>> datadissect_chain;
    std::vector<std::shared_ptr<packet_chain::pc_link>> classifier_chain;
	std::vector<std::shared_ptr<packet_chain::pc_link>> tracker_chain;
    std::vector<std::shared_ptr<packet_chain::pc_link>> logging_chain;

    // Updated chain components
    std::vector<std::shared_ptr<packet_chain::pc_link>> postcap_chain_new;
    std::vector<std::shared_ptr<packet_chain::pc_link>> llcdissect_chain_new;
    std::vector<std::shared_ptr<packet_chain::pc_link>> decrypt_chain_new;
    std::vector<std::shared_ptr<packet_chain::pc_link>> datadissect_chain_new;
    std::vector<std::shared_ptr<packet_chain::pc_link>> classifier_chain_new;
	std::vector<std::shared_ptr<packet_chain::pc_link>> tracker_chain_new;
    std::vector<std::shared_ptr<packet_chain::pc_link>> logging_chain_new;

    bool postcap_chain_update;
    bool llcdissect_chain_update;
    bool decrypt_chain_update;
    bool datadissect_chain_update;
    bool classifier_chain_update;
    bool tracker_chain_update;
    bool logging_chain_update;

    // Packet component mutex
    kis_mutex packetcomp_mutex;

    // Packet chain mutex
    kis_shared_mutex packetchain_mutex;

    struct packet_thread {
        std::thread packet_thread;
        moodycamel::BlockingConcurrentQueue<std::shared_ptr<kis_packet>> packet_queue;
    };

    packet_thread **packet_threads;
    size_t n_packet_threads;

    bool packetchain_shutdown;

    // Warning and discard levels for packet queue being full
    unsigned int packet_queue_warning, packet_queue_drop;
    time_t last_packet_queue_user_warning, last_packet_drop_user_warning;

    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_default_aggregator,
        kis_tracked_rrd_prev_pos_extreme_aggregator,
        kis_tracked_rrd_prev_pos_extreme_aggregator>> packet_peak_rrd;
    int packet_peak_rrd_id;

    std::shared_ptr<kis_tracked_rrd<>> packet_rate_rrd;
    int packet_rate_rrd_id;

    std::shared_ptr<kis_tracked_rrd<>> packet_error_rrd;
    int packet_error_rrd_id;

    std::shared_ptr<kis_tracked_rrd<>> packet_dupe_rrd;
    int packet_dupe_rrd_id;

    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>> packet_queue_rrd;
    int packet_queue_rrd_id;

    std::shared_ptr<kis_tracked_rrd<>> packet_drop_rrd;
    int packet_drop_rrd_id;

    std::shared_ptr<kis_tracked_rrd<>> packet_processed_rrd;
    int packet_processed_rrd_id;

    std::shared_ptr<tracker_element_map> packet_stats_map;

    std::shared_ptr<time_tracker> timetracker;
    int event_timer_id;
    std::shared_ptr<event_bus> eventbus;

    // Packet & data component pools
    shared_object_pool<kis_packet> packet_pool;

    ankerl::unordered_dense::map<size_t, std::shared_ptr<void>> component_pool_map;

    // Unique lock for packet number and dedupe
    kis_shared_mutex pack_no_mutex;

    // Next unique packet number
    std::atomic<uint64_t> unique_packet_no;

    // A simple array of hash to packet ID for the past 1024 unique packets
    typedef struct packno_map {
        packno_map() {
            hash = 0;
            packno = 0;
        }

        uint32_t hash;
        uint64_t packno;
        std::shared_ptr<kis_packet> original_pkt;
    } packno_map_t;

    packno_map_t dedupe_list[1024];

    // Current position in the dedupe list
    std::atomic<unsigned int> dedupe_list_pos;

	int pack_comp_linkframe, pack_comp_decap, pack_comp_l1_agg, pack_comp_l1, pack_comp_datasource;

};

#endif

