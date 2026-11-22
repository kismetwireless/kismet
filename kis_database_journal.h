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

#ifndef __KIS_DATABASE_JOURNAL_H__
#define __KIS_DATABASE_JOURNAL_H__

#include "config.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <sqlite3.h>

// The kismetdb log's journal: the commit cycle, WAL checkpoints, and finishing a file as a
// single .kismet.  Needs only sqlite, so it's tested without the server.
namespace kismetdb_journal {

enum class journal_mode : uint8_t { wal, persist };

// kis_log_journal_mode values, any case
std::optional<journal_mode> parse_mode(std::string_view s);
const char *mode_name(journal_mode m);

// The -wal file sqlite keeps next to a WAL log, and its size when it exists
std::string wal_path(const std::string& db_path);
std::optional<uint64_t> wal_file_size(const std::string& db_path);

// The WAL is cut back to this size each time it starts over, and a persist journal to this
// size after each commit
constexpr int64_t journal_size_limit_bytes = 64 * 1024 * 1024;

// sqlite waits for a busy lock only on a thread inside a busy_wait, up to its budget.  Other
// threads on the connection (the packet writer spilling its cache) are never held up.
class busy_wait {
public:
    explicit busy_wait(std::chrono::milliseconds budget);
    ~busy_wait();

    busy_wait(const busy_wait&) = delete;
    busy_wait& operator=(const busy_wait&) = delete;

private:
    std::chrono::steady_clock::time_point prev;
};

int busy_handler(void *aux, int count);

// Holds the connection's own mutex, so the statements in its scope run with no other
// thread's statement between them; the connection is opened with SQLITE_OPEN_FULLMUTEX
class connection_lock {
public:
    explicit connection_lock(sqlite3 *db);
    ~connection_lock();

    connection_lock(const connection_lock&) = delete;
    connection_lock& operator=(const connection_lock&) = delete;

private:
    sqlite3_mutex *mutex;
};

struct mode_result {
    journal_mode mode = journal_mode::persist;
    // Why a WAL that was asked for isn't used, "" when it is (or wasn't asked for)
    std::string wal_unavailable;
    // The sqlite error, extended, that kept the WAL from opening; SQLITE_OK when sqlite didn't
    // switch to it at all, SQLITE_PROTOCOL when a new log already had a -shm
    int wal_rc = SQLITE_OK;
};

// How long setting up a WAL waits for another program that has the new file locked.  Opening
// a WAL, building its index or a short read holds the lock for milliseconds; this covers that
// many times over on slow storage.  Rotation sets up the new file with the log's writers held,
// so they pause about this long while something else holds that file.  sqlite's own retries
// on a WAL index another program keeps locked aren't bounded by it, and can take seconds.
constexpr std::chrono::milliseconds mode_busy_budget{250};

// Whether Kismet made the log file it's setting up
enum class log_file : uint8_t { created, existing };

// Set up the journal of a newly opened log and install the busy handler.  WAL falls back to
// persist when sqlite doesn't switch to it, or can't open or write it (the filesystem can't
// hold its shared memory index, or a -shm opens only read-only, say); not when another
// program still has the log locked after mode_busy_budget, once it's in WAL mode (err says
// so).  A log Kismet created that already has a -shm is another program's, which can hold
// sqlite in its index retries, so it isn't tried as WAL; the -shm is left alone.  mode is the
// journal the log has, WAL too when leaving it failed.  err says what else went wrong, if
// anything.
mode_result apply_mode(sqlite3 *db, journal_mode want, log_file file, std::string& err);

// Why a WAL fell back to persist, for the log message, from mode_result::wal_rc
const char *fallback_cause(int wal_rc);

enum class commit_state : uint8_t {
    committed,      // saved, or there was no transaction to save
    held,           // not saved and still open with its data, such as busy; try again later
    lost,           // failed, and sqlite rolled the transaction back
};

commit_state classify_commit(int rc, bool in_transaction_after);

struct commit_result {
    commit_state state = commit_state::committed;
    int rc = SQLITE_OK;
    std::string err;
};

// COMMIT the open transaction, if there is one, waiting up to busy_budget for readers
commit_result commit(sqlite3 *db, std::chrono::milliseconds busy_budget);

// BEGIN a transaction unless one is still open (a held commit), so a failed commit never
// leaves a nested BEGIN behind
int begin(sqlite3 *db, std::string& err);

// ROLLBACK the open transaction, if there is one
int rollback(sqlite3 *db, std::string& err);

struct checkpoint_result {
    int rc = SQLITE_OK;
    // Frames in the WAL and how many of them are in the database file; -1 when it isn't WAL
    int log_frames = -1;
    int checkpointed_frames = -1;

    bool complete() const {
        return rc == SQLITE_OK && checkpointed_frames == log_frames;
    }
};

checkpoint_result checkpoint(sqlite3 *db, int mode, std::chrono::milliseconds busy_budget);

// The WAL after a tick, from the writer's catch-up checkpoint and the second connection's
// bulk one.  A read on the writer's own connection (a pcapng download) fails the catch-up
// with SQLITE_LOCKED and no frame counts; the bulk checkpoint still counts the frames that
// read holds back, and the result stays SQLITE_LOCKED, so it never counts as complete.
checkpoint_result wal_state(const checkpoint_result& catchup,
        const std::optional<checkpoint_result>& bulk);

// sqlite3_step, and once more within a short busy wait if another connection had the log
// locked for a moment (one opening its WAL, say); writers off the commit tick otherwise
// fail at once, and a failed insert closes the log
int step(sqlite3_stmt *stmt, std::chrono::milliseconds retry_budget);

struct finish_result {
    // The log is one .kismet file
    bool single_file = false;
    // A -wal file is left, and is part of the log
    bool wal_left = false;
    std::string err;
};

// End a file as a single .kismet: a final checkpoint and journal_mode=DELETE, both within
// busy_budget.  The caller commits first and is the only user of the handle.
finish_result finish(sqlite3 *db, std::chrono::milliseconds busy_budget);

// A second connection to a WAL log, for checkpoints that run without the writer's
// connection mutex; nullptr with err set when it can't open
sqlite3 *open_checkpointer(const std::string& path, std::string& err);

// The first of a run of failures is reported at once and the rest at most once per interval,
// with how many there were
class repeat_report {
public:
    explicit repeat_report(std::chrono::seconds in_interval) :
        interval{in_interval} { }

    // How many failures to report now, this one included; 0 to stay quiet
    unsigned int failed(std::chrono::steady_clock::time_point now);
    // A success: how many failures the run it ends had, 0 if there was none
    unsigned int succeeded();
    // When the current run of failures started
    std::chrono::steady_clock::time_point since() const { return first; }

private:
    std::chrono::seconds interval;
    std::chrono::steady_clock::time_point first{}, last{};
    unsigned int pending = 0, total = 0;
};

// Bytes of WAL file the frames take
uint64_t wal_bytes(int frames, int64_t page_size);

// The database's page size, 0 if it can't be read
int64_t page_size(sqlite3 *db);

// Watches the WAL after each tick's checkpoint: something reading the log (another program,
// or a pcapng download) keeps the checkpoint from finishing, and the WAL can't start over
class wal_watch {
public:
    enum class verdict : uint8_t { quiet, warn, cleared };

    static constexpr uint64_t default_warn_bytes = 64 * 1024 * 1024;
    static constexpr std::chrono::seconds rewarn{60};

    explicit wal_watch(uint64_t in_warn_bytes = default_warn_bytes) :
        warn_bytes{in_warn_bytes} { }

    verdict update(const checkpoint_result& c, int64_t page_size,
            std::chrono::steady_clock::time_point now);

    // A read on the writer's connection held the checkpoint back and nothing counted the
    // frames (no second connection); judged by the -wal file's size instead
    verdict held_back(uint64_t wal_file_bytes, std::chrono::steady_clock::time_point now);

    uint64_t bytes() const { return last_bytes; }

private:
    verdict incomplete(std::chrono::steady_clock::time_point now);

    uint64_t warn_bytes;
    bool warned = false;
    std::chrono::steady_clock::time_point last_warn{};
    uint64_t last_bytes = 0;
};

}

#endif
