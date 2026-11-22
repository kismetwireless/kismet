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

// How long setting up a WAL waits for another program that has the new file locked.  Rotation
// does this with the writers held, so it's short; sqlite's own WAL index retries aren't
// bounded by it.
constexpr std::chrono::milliseconds mode_busy_budget{250};

// Whether Kismet made the log file it's setting up
enum class log_file : uint8_t { created, existing };

// Set up a newly opened log's journal and install the busy handler.  WAL falls back to persist
// where sqlite can't open or write it, but not when the log is only locked by another program
// (err says so).  A -shm next to a log Kismet created is another program's, and is left alone.
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

// A held commit keeps its data in memory (a persist log can't spill it to the file while it's
// read), so it's rolled back once it has been held this long or uses this much cache.  Both
// are checked only when the commit is tried, every 10 s, so the cache can pass the limit
// by what's logged in between.
constexpr std::chrono::seconds max_hold{120};
constexpr int64_t max_hold_bytes = 64 * 1024 * 1024;

bool hold_exhausted(std::chrono::steady_clock::duration held, int64_t cache_bytes);

// How long a rotation counts its old file's commit as held.  A tick that drops a hold starts
// the next one from zero while the reader stays, so the rotation would never reach the limit
// itself; once a tick has dropped, the time the file has been due counts too.
std::chrono::steady_clock::duration rotation_hold(std::chrono::steady_clock::duration held,
        std::chrono::steady_clock::duration due_for, bool tick_dropped);

// Heap memory the connection's page cache uses
int64_t cache_bytes(sqlite3 *db);

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
// bulk one.  A read on the writer's connection fails the catch-up with SQLITE_LOCKED and no
// frame counts; those come from the bulk checkpoint, and the result is never complete.
checkpoint_result wal_state(const checkpoint_result& catchup,
        const std::optional<checkpoint_result>& bulk);

// sqlite3_step, retried within retry_budget while another connection has the log locked for a
// moment; a failed insert closes the log.  sqlite skips the busy handler when the connection
// already has a read open (a pcapng download), so this sleeps between tries itself.  Each
// try reads its error code and message (err, "" on success) under the connection mutex,
// before another thread can replace them.
int step(sqlite3_stmt *stmt, std::chrono::milliseconds retry_budget, std::string& err);

struct finish_result {
    // The log is one .kismet file
    bool single_file = false;
    // A -wal file holding frames is left, and is part of the log
    bool wal_left = false;
    std::string err;
};

// End a file as a single .kismet: a final checkpoint, journal_mode=DELETE and, for a log that
// was in WAL, remove_unused_wal_files(), all within busy_budget.  The caller commits first and
// is the only user of the handle.
finish_result finish(sqlite3 *db, std::chrono::milliseconds busy_budget);

// The -shm, and an empty -wal, that some sqlite builds (Apple's, or a persistent WAL) leave
// next to a log once it has left WAL mode; nothing uses them in DELETE mode.  They're removed
// while the log is locked exclusively, so no other program can take it back to WAL meanwhile,
// and only as regular files.  Returns why one stays, "" when none does.
std::string remove_unused_wal_files(sqlite3 *db, std::chrono::milliseconds busy_budget);

// Why the log tools mustn't VACUUM this log, "" when they may.  A log in WAL mode, or a
// persist log with its -journal, may be one Kismet is still writing; a vacuum holds the write
// lock while it runs, and Kismet's next insert then fails and closes the log.
std::string vacuum_hazard(sqlite3 *db);

// The log tools' clean: VACUUM, unless vacuum_hazard() says not to, when skipped says why.
// Returns the vacuum's sqlite result, SQLITE_OK when it's skipped; err has its message.
int vacuum_if_finished(sqlite3 *db, std::string& skipped, std::string& err);

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

// The commit failures since the log was last saved, reported as a repeat_report.  A held
// commit's data is saved by the next one that goes through; a lost one's isn't.
class commit_failures {
public:
    explicit commit_failures(std::chrono::seconds in_interval) :
        report{in_interval} { }

    // How many failures to report now, as repeat_report::failed
    unsigned int held(std::chrono::steady_clock::time_point now) { return report.failed(now); }
    unsigned int lost(std::chrono::steady_clock::time_point now) {
        any_lost = true;
        return report.failed(now);
    }

    struct saved_result {
        unsigned int failures = 0;
        // Some of them lost their data, which this save doesn't hold
        bool lost = false;
    };

    // A commit went through, ending the run
    saved_result saved() {
        saved_result r{report.succeeded(), any_lost};
        any_lost = false;
        return r;
    }

    // The run ended without a save: what it held is gone, or was on another file
    void reset() {
        report.succeeded();
        any_lost = false;
    }

private:
    repeat_report report;
    bool any_lost = false;
};

// Bytes of WAL file the frames take
uint64_t wal_bytes(int frames, int64_t page_size);

// An integer pragma's value, such as page_size; 0 if it can't be read
int64_t pragma_int(sqlite3 *db, const char *sql);

// The page size cached when the file opened, or read again when that read failed (0)
int64_t known_page_size(sqlite3 *db, int64_t cached);

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
