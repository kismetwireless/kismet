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
#include <mutex>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <algorithm>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <functional>
#include <queue>
#include <thread>
#include <unordered_set>

#include "eventbus.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "kis_net_beast_httpd.h"
#include "objectpool.h"
#include "unordered_dense.h"
#include "timetracker.h"
#include "trackedelement.h"
#include "trackedrrd.h"

#include <condition_variable>
#include <deque>

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
class kis_datachunk;

// Handoff queue to one packet thread.  Packets come out in the order they were queued,
// whichever threads queued them, so a source's packets are processed in capture order.
class packet_fifo {
public:
    void enqueue(std::shared_ptr<kis_packet> in_pack) {
        bool wake;

        pending.fetch_add(1, std::memory_order_relaxed);

        {
            std::lock_guard<std::mutex> lk(mutex);
            queue.push_back(std::move(in_pack));
            wake = waiting;
        }

        if (wake)
            cv.notify_one();
    }

    // Move everything queued into an empty out, in order; false if nothing was queued
    bool try_dequeue_all(std::deque<std::shared_ptr<kis_packet>>& out) {
        std::lock_guard<std::mutex> lk(mutex);

        if (queue.empty())
            return false;

        std::swap(out, queue);
        return true;
    }

    void wait_dequeue_all(std::deque<std::shared_ptr<kis_packet>>& out) {
        std::unique_lock<std::mutex> lk(mutex);

        waiting = true;
        cv.wait(lk, [this]() { return !queue.empty(); });
        waiting = false;

        std::swap(out, queue);
    }

    // The consumer finished a dequeued packet
    void packet_done() {
        pending.fetch_sub(1, std::memory_order_relaxed);
    }

    // Packets queued or dequeued and not yet finished
    size_t size_approx() const {
        return pending.load(std::memory_order_relaxed);
    }

protected:
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<std::shared_ptr<kis_packet>> queue;
    bool waiting = false;
    std::atomic<size_t> pending{0};
};

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
        // pools protect their internal state; we only have to protect creating the pool
        // or changing how packet IDs are mapped

        auto lk = std::shared_lock(packetcomp_mutex);

        auto p = component_pool_map.find(typeid(T).hash_code());

        if (p != component_pool_map.end()) {
            return std::static_pointer_cast<shared_object_pool<T>>(p->second)->acquire();
        } else {
            lk.unlock();

            auto ulk = std::unique_lock(packetcomp_mutex);

            auto pool = std::make_shared<shared_object_pool<T>>();
            pool->set_max(1024);
            pool->set_reset([](T *c) { c->reset(); });
            component_pool_map.insert({typeid(T).hash_code(), pool});

            return pool->acquire();
        }
    }

protected:
    void packet_queue_processor(packet_fifo *packet_queue);

    // Common function for both insertion methods
    int register_int_handler(pc_callback in_cb, void *in_aux, int in_chain, int in_prio);

    int next_componentid, next_handlerid;

    std::unordered_map<std::string, int> component_str_map;
    std::map<int, std::string> component_id_map;

    // All handler chains.  A snapshot is never modified once it is published; registering or
    // removing a handler publishes a new one.  Threads running packets keep a reference to the
    // snapshot they are using, so a removed link stays valid until they are done with it.
    struct pc_chains {
        uint64_t generation = 0;

        std::vector<pc_link> postcap;
        std::vector<pc_link> llcdissect;
        std::vector<pc_link> decrypt;
        std::vector<pc_link> datadissect;
        std::vector<pc_link> classifier;
        std::vector<pc_link> tracker;
        std::vector<pc_link> logging;
    };

    using pc_chains_ptr = std::shared_ptr<const pc_chains>;

    // Reference to a chain snapshot held by the current thread; remove_handler() does not
    // wait for snapshots held by the calling thread itself
    class pc_chains_ref {
    public:
        pc_chains_ref() = default;
        pc_chains_ref(const pc_chains_ref&) = delete;
        pc_chains_ref& operator=(const pc_chains_ref&) = delete;
        ~pc_chains_ref() { reset(); }

        void set(pc_chains_ptr in_chains);
        void reset();

        const pc_chains *get() const { return chains.get(); }
        const pc_chains *operator->() const { return chains.get(); }

    private:
        pc_chains_ptr chains;
    };

    // Current snapshot, protected by packetchain_mutex
    pc_chains_ptr chains;
    // Generation of the current snapshot, so packet threads can check it without locking
    std::atomic<uint64_t> chains_generation;

    pc_chains_ptr fetch_chains();
    static std::vector<pc_link> *select_chain(pc_chains *in_chains, int in_chain);

    // Publish a new snapshot; must hold packetchain_mutex
    void publish_chains(std::shared_ptr<pc_chains> in_chains);

    int remove_int_handler(const std::function<bool (const pc_link&)>& in_match, int in_chain);

    // Wait until no other thread is still running a replaced snapshot
    void wait_for_retired_chains();

    std::mutex retired_mutex;
    // Replaced snapshots which may still be in use
    std::vector<std::weak_ptr<const pc_chains>> retired_chains;
    // Snapshots held by threads currently waiting in remove_handler()
    std::unordered_multiset<const void *> waiting_chains;

    // Packet component mutex
    mutable kis_shared_mutex packetcomp_mutex;

    // Packet chain mutex
    mutable kis_shared_mutex packetchain_mutex;

    struct packet_thread {
        std::thread packet_thread;
        packet_fifo packet_queue;
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

    // Recent unique packets for duplicate detection, protected by pack_no_mutex.  Hashes
    // are kept apart from the packets so the scan reads contiguous memory; a null packet
    // marks an empty slot.
    static constexpr size_t dedupe_list_sz = 1024;

    // A packet goes to its assigned thread unless that thread is this far behind, then to
    // the least busy thread, so one busy device can't overflow a single queue
    static constexpr size_t assignment_spill_backlog = 1024;

public:
    // A packet thread is far enough behind that capture readers should pause, so a source
    // faster than processing (such as a pcap replay) is slowed down instead of dropped
    bool backlog_high() const;

    // Readers pause above this backlog per thread, or half the drop limit if lower
    static constexpr size_t reader_pause_backlog = 4096;

protected:
    std::array<uint32_t, dedupe_list_sz> dedupe_hash;
    std::array<std::shared_ptr<kis_packet>, dedupe_list_sz> dedupe_pkt;

    // Next slot to fill in the dedupe list
    size_t dedupe_list_pos;

    // Packets which matched a hash and are still being compared; they're visible to the
    // dedupe scan but don't occupy the window until confirmed as originals
    std::vector<std::shared_ptr<kis_packet>> dedupe_pending;

    // Number the packet or alias it to an identical earlier packet
    void dedupe_packet(const std::shared_ptr<kis_packet>& packet,
            const std::shared_ptr<kis_datachunk>& chunk);

    // Add an original to the window; caller holds pack_no_mutex.  Returns the evicted packet
    // so it can be released after the lock is dropped.
    std::shared_ptr<kis_packet> dedupe_insert(const std::shared_ptr<kis_packet>& packet);

	int pack_comp_linkframe, pack_comp_decap, pack_comp_l1_agg, pack_comp_datasource;

};

#endif

