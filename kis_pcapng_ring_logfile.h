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

#ifndef __KIS_PCAPNG_RING_LOGFILE_H__
#define __KIS_PCAPNG_RING_LOGFILE_H__

#include "config.h"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "kis_pcapnglogfile.h"
#include "logtracker.h"
#include "pcapng_stream_futurebuf.h"

// Continuous wifi capture written to a multi-slot file ring on tmpfs. Steady
// state writes zero bytes to permanent storage. On demand (HTTP POST to
// /logging/pcapng_ring/snapshot/<label>) the current ring is copied to a
// persistent directory and capture continues for a configurable post-trigger
// window. Intended pairing: an external monitoring tool watches Kismet's
// alert stream and calls snapshot when something interesting happens, so
// the pcap evidence around the trigger is preserved without any
// continuous on-disk capture.
class kis_pcapng_ring_logfile : public kis_logfile {
public:
    kis_pcapng_ring_logfile(shared_log_builder in_builder);
    virtual ~kis_pcapng_ring_logfile();

    // in_template is unused — ring slots have fixed names inside ring_dir —
    // but the signature is fixed by kis_logfile.
    virtual bool open_log(const std::string& in_template,
            const std::string& in_path) override;
    virtual void close_log() override;

    // Atomically copy the current ring contents to
    //   <persist_dir>/<label>/pre.pcapng
    // then continue capturing for post_seconds into
    //   <persist_dir>/<label>/post.pcapng
    // Returns the final on-disk path of pre.pcapng (post.pcapng is in the
    // same directory). Throws std::runtime_error on validation or IO error.
    std::string snapshot(const std::string& label, unsigned int post_seconds);

protected:
    // Rotate the active ring file: close current, advance index, truncate
    // and open next. Called from inside the writer thread loop only.
    void rotate_ring();

    // Absolute path to ring slot `idx`.
    std::string ring_slot_path(unsigned int idx) const;

    // Background prune thread body. Enforces persist_max_total_mb and
    // persist_max_age_days every persist_prune_interval seconds.
    void prune_loop();
    void prune_once();

    // Concatenate the given source files into dest. Each ring file is a
    // self-contained pcapng section (its own SHB), so concatenation produces
    // a valid multi-section pcapng that Wireshark/tshark read natively.
    void concat_files(const std::vector<std::string>& sources,
            const std::string& dest, uint64_t *out_bytes);

    // Returns the list of ring slot paths sorted by modification time
    // (oldest first), excluding the slot currently being written.
    std::vector<std::string> list_complete_ring_slots() const;

    // Free space in bytes on the filesystem hosting persist_dir, or 0 on
    // error (errno is logged).
    uint64_t persist_dir_free_bytes() const;

    pcapng_stream_packetchain<pcapng_logfile_accept_ftor,
        pcapng_logfile_select_ftor> *pcapng;

    // `buffer` is read by the writer thread (each loop iteration) and the
    // snapshot thread (to wake the writer via sync()). Using shared_ptr +
    // a small mutex around the swap is what makes force_rotate_now() safe
    // against concurrent rotate_ring(): the snapshot thread captures a
    // shared_ptr copy, keeping the old buffer alive across sync() even if
    // the writer has already swapped to a new one and released its own
    // reference. Without this the snapshot's `buffer->sync()` raced with
    // `delete old_buffer` in rotate_ring (use-after-free).
    std::shared_ptr<future_chainbuf> buffer;
    std::mutex buffer_mutex;

    FILE *ring_file;
    std::thread stream_t;
    std::thread prune_t;

    // Atomic stop signal for the prune thread; checked between sleeps.
    std::atomic<bool> shutting_down;

    // Active ring slot index (writer thread only).
    unsigned int active_slot;

    // Bytes written into the active ring slot since it was last opened.
    uint64_t active_slot_bytes;

    // Cross-thread rotation request. The snapshot HTTP handler sets this
    // and calls buffer->sync() to wake the writer; the writer thread checks
    // it after each buffer drain and performs the rotation, then notifies
    // rotation_cv so the snapshot can proceed. This indirection keeps all
    // rotate_ring() calls on the writer thread (avoids races with the
    // writer's fwrite + buffer access).
    std::atomic<bool> force_rotate_pending;
    std::mutex rotation_mutex;
    std::condition_variable rotation_cv;
    uint64_t rotation_count;  // monotonic; protected by rotation_mutex

    // Block until the writer thread performs at least one rotation cycle
    // (force-triggered or natural). Used by snapshot() to freeze the
    // active slot's bytes into a complete ring file before copying.
    // Returns true on success, false on timeout / shutdown.
    bool force_rotate_now(std::chrono::seconds timeout);

    // Config (read once in the constructor).
    std::string ring_dir;
    std::string persist_dir;
    uint64_t ring_file_size_bytes;
    unsigned int ring_file_count;
    unsigned int default_post_seconds;
    uint64_t persist_max_total_bytes;
    unsigned int persist_max_age_days;
    uint64_t persist_min_free_bytes;
    unsigned int persist_prune_interval;

    // Filter knobs — same semantics as kis_pcapng_logfile.
    bool log_duplicate_packets;
    bool truncate_duplicate_packets;
    bool log_data_packets;
    int pack_comp_l1data, pack_comp_linkframe;

    // Serializes /snapshot calls. Concurrent snapshots are simpler to reason
    // about when serialized; the post-trigger window means a single snapshot
    // already takes O(post_seconds), and operators rarely fire alerts close
    // enough together to matter.
    kis_mutex snapshot_mutex;
};

class pcapng_ring_logfile_builder : public kis_logfile_builder {
public:
    pcapng_ring_logfile_builder() :
        kis_logfile_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    pcapng_ring_logfile_builder(int in_id) :
        kis_logfile_builder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    pcapng_ring_logfile_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_logfile_builder(in_id, e) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~pcapng_ring_logfile_builder() { }

    virtual shared_logfile build_logfile(shared_log_builder builder) override {
        return shared_logfile(new kis_pcapng_ring_logfile(builder));
    }

    virtual void initialize() override {
        set_log_class("pcapng_ring");
        set_log_name("PcapNG memory ring");
        set_stream(true);
        // Singleton because the snapshot HTTP route is class-scoped, not
        // instance-scoped; running two ring logs would race on the same path.
        set_singleton(true);
        set_log_description("PcapNG multi-interface capture written to an "
                "in-memory (tmpfs) ring buffer, with on-demand snapshot to "
                "persistent storage for incident forensics");
    }
};

#endif
