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

#include <algorithm>
#include <cctype>
#include <charconv>
#include <thread>

#include <sys/stat.h>
#include <unistd.h>

#include "kis_database_journal.h"

namespace kismetdb_journal {

namespace {

// Deadline for busy waits on this thread; the default lets nothing wait
thread_local std::chrono::steady_clock::time_point busy_deadline{};

constexpr auto busy_sleep = std::chrono::milliseconds(5);

// Run a statement; on failure err gets this statement's own message, which another thread
// on the connection can't replace
int exec(sqlite3 *db, const char *sql, std::string& err) {
    char *msg = nullptr;
    auto rc = sqlite3_exec(db, sql, nullptr, nullptr, &msg);

    if (rc != SQLITE_OK)
        err = msg != nullptr ? msg : sqlite3_errstr(rc);

    sqlite3_free(msg);
    return rc;
}

// The text of a pragma's single result row, such as the journal mode it set.  On failure
// extended_rc, if given, gets sqlite's extended error code.
int pragma_text(sqlite3 *db, const char *sql, std::string& out, std::string& err,
        int *extended_rc = nullptr) {
    sqlite3_stmt *stmt = nullptr;
    auto rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmt);

        if (rc == SQLITE_ROW) {
            auto t = sqlite3_column_text(stmt, 0);
            out = t != nullptr ? reinterpret_cast<const char *>(t) : "";
            rc = SQLITE_OK;
        } else if (rc == SQLITE_DONE) {
            out.clear();
            rc = SQLITE_OK;
        }
    }

    if (rc != SQLITE_OK) {
        err = sqlite3_errstr(rc);
        if (extended_rc != nullptr)
            *extended_rc = sqlite3_extended_errcode(db);
    }

    sqlite3_finalize(stmt);
    return rc;
}

void append_err(std::string& err, const std::string& what) {
    if (!err.empty())
        err += "; ";
    err += what;
}

// The size of a regular file (not a link) at p
std::optional<off_t> regular_size(const std::string& p) {
    struct stat st;

    if (p.empty() || lstat(p.c_str(), &st) != 0 || !S_ISREG(st.st_mode))
        return std::nullopt;

    return st.st_size;
}

// journal_mode=PERSIST, also from a WAL sqlite couldn't open.  Leaving WAL checkpoints it,
// which needs the shared memory index; the first try fails, and closes the WAL.  In exclusive
// locking mode sqlite opens it again with the index in heap memory, and can leave it.  The
// exclusive lock is given up at the next read after locking_mode=NORMAL.  lock_err says when
// the log stays locked instead, or when that read failed and the lock may still be held.
int set_persist(sqlite3 *db, std::string& m, std::string& e, std::string& lock_err) {
    auto rc = pragma_text(db, "PRAGMA journal_mode=PERSIST", m, e);
    if (rc == SQLITE_OK)
        return rc;

    std::string v, le;
    if (pragma_text(db, "PRAGMA locking_mode=EXCLUSIVE", v, le) != SQLITE_OK)
        return rc;

    m.clear();
    e.clear();
    rc = pragma_text(db, "PRAGMA journal_mode=PERSIST", m, e);

    // sqlite answers with the mode it kept; it stays exclusive while it has a WAL index in
    // heap memory, for one
    const auto normal_rc = pragma_text(db, "PRAGMA locking_mode=NORMAL", v, le);
    if (normal_rc == SQLITE_OK && v != "normal")
        lock_err = "the log stays locked to other programs while Kismet has it open, as "
            "sqlite couldn't leave exclusive locking (locking mode " + v + ")";
    else if (normal_rc != SQLITE_OK || pragma_text(db, "PRAGMA schema_version", v, le) != SQLITE_OK)
        lock_err = "sqlite couldn't confirm it gave up its exclusive lock on the log (" + le +
            "); other programs may not be able to open it while Kismet has it open";

    return rc;
}

// Reads work with a -shm sqlite could only open read-only (another user's, or a directory),
// and every write then fails; take the write lock and give it back
int write_probe(sqlite3 *db, std::string& err, int& extended_rc) {
    auto rc = exec(db, "BEGIN IMMEDIATE", err);
    if (rc == SQLITE_OK)
        rc = rollback(db, err);

    if (rc != SQLITE_OK)
        extended_rc = sqlite3_extended_errcode(db);

    return rc;
}

// Another connection had the log locked; anything else is the WAL itself failing
bool is_busy(int rc) {
    const auto primary = rc & 0xff;
    return primary == SQLITE_BUSY || primary == SQLITE_LOCKED;
}

void set_wal_options(sqlite3 *db, std::string& err) {
    std::string e;

    // A commit doesn't sync, only checkpoints do; after a power loss the log keeps
    // everything up to a recent commit and isn't corrupted
    if (exec(db, "PRAGMA synchronous=NORMAL", e) != SQLITE_OK)
        append_err(err, "couldn't set synchronous=NORMAL: " + e);

    // Checkpoints run from the commit timer instead of inside a commit
    if (exec(db, "PRAGMA wal_autocheckpoint=0", e) != SQLITE_OK)
        append_err(err, "couldn't turn off wal_autocheckpoint: " + e);
}

// The -wal and -shm a WAL that couldn't be used leaves behind, once the log is out of WAL
// mode; only files this connection made, and never a -wal holding anything
void remove_unused_wal(const std::string& path, bool had_wal, bool had_shm) {
    if (path.empty())
        return;

    if (!had_wal && regular_size(wal_path(path)) == 0)
        unlink(wal_path(path).c_str());

    const auto shm = path + "-shm";
    if (!had_shm && regular_size(shm).has_value())
        unlink(shm.c_str());
}

}

std::optional<journal_mode> parse_mode(std::string_view s) {
    std::string l;
    l.reserve(s.size());
    for (auto c : s)
        l.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));

    if (l == "wal")
        return journal_mode::wal;
    if (l == "persist")
        return journal_mode::persist;

    return std::nullopt;
}

const char *mode_name(journal_mode m) {
    return m == journal_mode::wal ? "wal" : "persist";
}

std::string wal_path(const std::string& db_path) {
    return db_path + "-wal";
}

std::optional<uint64_t> wal_file_size(const std::string& db_path) {
    if (db_path.empty())
        return std::nullopt;

    const auto sz = regular_size(wal_path(db_path));
    if (!sz.has_value())
        return std::nullopt;

    return static_cast<uint64_t>(*sz);
}

busy_wait::busy_wait(std::chrono::milliseconds budget) :
    prev{busy_deadline} {
    busy_deadline = std::chrono::steady_clock::now() + budget;
}

busy_wait::~busy_wait() {
    busy_deadline = prev;
}

int busy_handler(void *, int) {
    const auto now = std::chrono::steady_clock::now();

    if (now >= busy_deadline)
        return 0;

    std::this_thread::sleep_for(std::min<std::chrono::steady_clock::duration>(busy_sleep,
                busy_deadline - now));
    return 1;
}

connection_lock::connection_lock(sqlite3 *db) :
    mutex{sqlite3_db_mutex(db)} {
    // nullptr when the connection isn't serialized; entering it is then a no-op
    sqlite3_mutex_enter(mutex);
}

connection_lock::~connection_lock() {
    sqlite3_mutex_leave(mutex);
}

mode_result apply_mode(sqlite3 *db, journal_mode want, log_file file, std::string& err) {
    mode_result r;
    sqlite3_busy_handler(db, busy_handler, nullptr);

    std::string e;
    const auto limit = "PRAGMA journal_size_limit=" + std::to_string(journal_size_limit_bytes);
    if (exec(db, limit.c_str(), e) != SQLITE_OK)
        append_err(err, "couldn't set journal_size_limit: " + e);

    const auto fn = sqlite3_db_filename(db, "main");
    const std::string path = fn != nullptr ? fn : "";
    bool had_wal = false, had_shm = false;

    if (want == journal_mode::wal) {
        had_wal = !path.empty() && regular_size(wal_path(path)).has_value();
        had_shm = !path.empty() && regular_size(path + "-shm").has_value();
    }

    // Another program's -shm, which sqlite would recover as the WAL index; a lock held on it
    // keeps sqlite retrying for seconds, with no busy wait, before it fails
    if (want == journal_mode::wal && had_shm && file == log_file::created) {
        r.wal_rc = SQLITE_PROTOCOL;
        r.wal_unavailable = "Kismet didn't make '" + path + "-shm' and leaves it there";
    } else if (want == journal_mode::wal) {
        std::string m;
        e.clear();
        int rc;
        bool switched = false;

        {
            // One wait for the three steps, for another program that has the new file
            // open (one reading it, or opening its WAL)
            busy_wait w(mode_busy_budget);

            rc = pragma_text(db, "PRAGMA journal_mode=WAL", m, e, &r.wal_rc);
            switched = rc == SQLITE_OK && m == "wal";

            if (switched) {
                // sqlite opens the WAL, and builds its index, on the next read.  Done now, the
                // first insert can't race another connection opening the new file; it's also
                // where a filesystem that can't hold the index fails.
                std::string v;
                rc = pragma_text(db, "PRAGMA schema_version", v, e, &r.wal_rc);

                if (rc == SQLITE_OK)
                    rc = write_probe(db, e, r.wal_rc);
            }
        }

        // Still locked after the wait says nothing against the WAL, and the log is already
        // in WAL mode; leaving it would need that lock too
        if (switched && (rc == SQLITE_OK || is_busy(rc))) {
            if (rc != SQLITE_OK)
                append_err(err, "another program had the new log locked while its WAL was set "
                        "up (" + e + "); logging may fail until it lets go");

            set_wal_options(db, err);
            r.mode = journal_mode::wal;
            r.wal_rc = SQLITE_OK;
            return r;
        }

        if (rc != SQLITE_OK)
            r.wal_unavailable = e + ", sqlite code " + std::to_string(r.wal_rc);
        else
            r.wal_unavailable = "sqlite kept the " + (m.empty() ? std::string{"old"} : m) + " journal";
    }

    std::string m, lock_err;
    e.clear();
    const auto persist_rc = set_persist(db, m, e, lock_err);

    if (!lock_err.empty())
        append_err(err, lock_err);

    if (persist_rc != SQLITE_OK || m != "persist") {
        append_err(err, "couldn't set the persist journal (" + (e.empty() ? "mode " + m : e) + ")");

        // The mode the log is in, so a WAL keeps its checkpoints and the watch.  Still locked,
        // a -wal says it's WAL, as finish() takes it.
        std::string actual;
        e.clear();
        const auto read_rc = pragma_text(db, "PRAGMA journal_mode", actual, e);
        const bool locked_wal = is_busy(read_rc) && wal_file_size(path).has_value();

        if ((read_rc == SQLITE_OK && actual == "wal") || locked_wal) {
            const auto stays = locked_wal ? "the log's journal mode couldn't be read (" + e +
                "); it has a -wal, so it's taken as WAL" : std::string{"the log stays in WAL mode"};
            append_err(err, stays + (r.wal_unavailable.empty() ? "" : ", which failed: " +
                        r.wal_unavailable));
            set_wal_options(db, err);
            r.mode = journal_mode::wal;
            r.wal_unavailable.clear();
            r.wal_rc = SQLITE_OK;
        }

        return r;
    }

    if (want != journal_mode::wal)
        return r;

    // The file stays marked WAL when sqlite couldn't open the -wal at all, and every read
    // then tries to open it again
    std::string v;
    if (pragma_text(db, "PRAGMA schema_version", v, e) != SQLITE_OK) {
        append_err(err, "the log can't be used after leaving WAL: " + e);
        return r;
    }

    remove_unused_wal(path, had_wal, had_shm);
    return r;
}

const char *fallback_cause(int wal_rc) {
    switch (wal_rc & 0xff) {
        case SQLITE_BUSY:
        case SQLITE_LOCKED:
            return "another program had the new log open";
        case SQLITE_READONLY:
            return "its -shm file can't be written";
        case SQLITE_PROTOCOL:
            return "a -shm file from another program is next to it";
        default:
            return "WAL isn't available on this filesystem";
    }
}

commit_state classify_commit(int rc, bool in_transaction_after) {
    if (rc == SQLITE_OK)
        return commit_state::committed;

    // sqlite keeps the transaction open after a busy commit, and after some I/O errors
    return in_transaction_after ? commit_state::held : commit_state::lost;
}

commit_result commit(sqlite3 *db, std::chrono::milliseconds busy_budget) {
    commit_result r;

    if (sqlite3_get_autocommit(db))
        return r;

    {
        busy_wait w(busy_budget);
        r.rc = exec(db, "COMMIT", r.err);
    }

    r.state = classify_commit(r.rc, sqlite3_get_autocommit(db) == 0);
    return r;
}

bool hold_exhausted(std::chrono::steady_clock::duration held, int64_t cache_bytes) {
    return held >= max_hold || cache_bytes >= max_hold_bytes;
}

std::chrono::steady_clock::duration rotation_hold(std::chrono::steady_clock::duration held,
        std::chrono::steady_clock::duration due_for, bool tick_dropped) {
    return tick_dropped ? std::max(held, due_for) : held;
}

int64_t cache_bytes(sqlite3 *db) {
    int cur = 0, high = 0;

    if (sqlite3_db_status(db, SQLITE_DBSTATUS_CACHE_USED, &cur, &high, 0) != SQLITE_OK)
        return 0;

    return cur;
}

int begin(sqlite3 *db, std::string& err) {
    if (!sqlite3_get_autocommit(db))
        return SQLITE_OK;

    return exec(db, "BEGIN TRANSACTION", err);
}

int rollback(sqlite3 *db, std::string& err) {
    if (sqlite3_get_autocommit(db))
        return SQLITE_OK;

    return exec(db, "ROLLBACK", err);
}

checkpoint_result checkpoint(sqlite3 *db, int mode, std::chrono::milliseconds busy_budget) {
    checkpoint_result r;
    busy_wait w(busy_budget);

    r.rc = sqlite3_wal_checkpoint_v2(db, nullptr, mode, &r.log_frames, &r.checkpointed_frames);
    return r;
}

checkpoint_result wal_state(const checkpoint_result& catchup,
        const std::optional<checkpoint_result>& bulk) {
    if (catchup.rc != SQLITE_LOCKED || !bulk.has_value() || bulk->rc != SQLITE_OK)
        return catchup;

    auto r = *bulk;
    r.rc = SQLITE_LOCKED;
    return r;
}

int step(sqlite3_stmt *stmt, std::chrono::milliseconds retry_budget, std::string& err) {
    auto db = sqlite3_db_handle(stmt);
    int extended_rc = SQLITE_OK;

    // The connection mutex is recursive, and sqlite3_step holds it too
    auto step_once = [stmt, db, &extended_rc, &err]() {
        connection_lock clk(db);
        const auto r = sqlite3_step(stmt);
        extended_rc = sqlite3_extended_errcode(db);
        if (r == SQLITE_DONE || r == SQLITE_ROW)
            err.clear();
        else
            err = sqlite3_errmsg(db);
        return r;
    };

    auto rc = step_once();
    if (rc != SQLITE_BUSY)
        return rc;

    const auto deadline = std::chrono::steady_clock::now() + retry_budget;

    while (true) {
        // The connection's read is older than another writer's commit; it can't write until
        // that read ends, so waiting won't help
        if (extended_rc == SQLITE_BUSY_SNAPSHOT)
            return rc;

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return rc;

        // A busy write hasn't changed anything; the statement runs again from the start
        sqlite3_reset(stmt);

        {
            busy_wait w(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now));
            rc = step_once();
        }

        if (rc != SQLITE_BUSY)
            return rc;

        std::this_thread::sleep_for(std::min<std::chrono::steady_clock::duration>(busy_sleep,
                    deadline - std::chrono::steady_clock::now()));
    }
}

finish_result finish(sqlite3 *db, std::chrono::milliseconds busy_budget) {
    finish_result f;
    std::string m, e;

    const auto deadline = std::chrono::steady_clock::now() + busy_budget;
    auto remaining = [deadline]() {
        return std::max(std::chrono::milliseconds(0),
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline -
                    std::chrono::steady_clock::now()));
    };

    const auto fn = sqlite3_db_filename(db, "main");
    const std::string path = fn != nullptr ? fn : "";

    // A mode that can't be read is taken as WAL when the log has a -wal.  sqlite's state is
    // unknown then, so there's no final checkpoint; journal_mode=DELETE still checkpoints the
    // WAL when it succeeds.
    bool was_wal, mode_read;
    if (pragma_text(db, "PRAGMA journal_mode", m, e) == SQLITE_OK) {
        mode_read = true;
        was_wal = m == "wal";
    } else {
        append_err(f.err, "couldn't read the journal mode: " + e);
        mode_read = false;
        was_wal = wal_file_size(path).has_value();
    }

    // Waits for readers to finish with the WAL; switching to DELETE then copies nothing more
    if (was_wal && mode_read) {
        auto c = checkpoint(db, SQLITE_CHECKPOINT_TRUNCATE, remaining());
        if (c.rc != SQLITE_OK)
            append_err(f.err, std::string{"final checkpoint: "} + sqlite3_errstr(c.rc));
    }

    // Removes the -wal and -shm, or the persist -journal.  Leaving WAL needs the log to
    // itself, and sqlite doesn't wait for that, so try again until the budget runs out.
    std::string delete_err;
    while (true) {
        m.clear();
        e.clear();
        const auto rc = pragma_text(db, "PRAGMA journal_mode=DELETE", m, e);

        if (rc == SQLITE_OK && m == "delete")
            break;

        delete_err = rc != SQLITE_OK ? "journal_mode=DELETE: " + e : "";

        if ((rc != SQLITE_OK && rc != SQLITE_BUSY && rc != SQLITE_LOCKED) ||
                std::chrono::steady_clock::now() >= deadline)
            break;

        std::this_thread::sleep_for(std::min<std::chrono::steady_clock::duration>(busy_sleep,
                    deadline - std::chrono::steady_clock::now()));
    }

    if (!delete_err.empty())
        append_err(f.err, delete_err);

    // An empty -wal, as the final checkpoint leaves it, holds nothing of the log
    f.single_file = m == "delete";
    f.wal_left = !f.single_file && wal_file_size(path).value_or(0) > 0;

    if (!f.single_file && f.err.empty())
        f.err = "the journal mode stayed " + m;

    return f;
}

sqlite3 *open_checkpointer(const std::string& path, std::string& err) {
    sqlite3 *h = nullptr;

    // Never creates the file; it's the open log or nothing
    auto rc = sqlite3_open_v2(path.c_str(), &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr);

    if (rc != SQLITE_OK) {
        err = h != nullptr ? sqlite3_errmsg(h) : sqlite3_errstr(rc);
        sqlite3_close_v2(h);
        return nullptr;
    }

    sqlite3_busy_handler(h, busy_handler, nullptr);

    std::string m, e;
    if (pragma_text(h, "PRAGMA journal_mode", m, e) != SQLITE_OK || m != "wal") {
        err = e.empty() ? "the log isn't in WAL mode (" + m + ")" : e;
        sqlite3_close_v2(h);
        return nullptr;
    }

    return h;
}

unsigned int repeat_report::failed(std::chrono::steady_clock::time_point now) {
    if (total == 0)
        first = now;

    ++pending;
    ++total;

    if (last != std::chrono::steady_clock::time_point{} && now - last < interval)
        return 0;

    last = now;

    const auto n = pending;
    pending = 0;
    return n;
}

unsigned int repeat_report::succeeded() {
    const auto n = total;

    total = 0;
    pending = 0;
    last = std::chrono::steady_clock::time_point{};
    first = std::chrono::steady_clock::time_point{};

    return n;
}

uint64_t wal_bytes(int frames, int64_t page_size) {
    // A 32 byte file header, and a 24 byte header per frame
    constexpr uint64_t wal_header = 32;
    constexpr uint64_t frame_header = 24;

    if (frames <= 0 || page_size <= 0)
        return 0;

    return wal_header + static_cast<uint64_t>(frames) * (static_cast<uint64_t>(page_size) + frame_header);
}

int64_t pragma_int(sqlite3 *db, const char *sql) {
    std::string v, e;
    int64_t n = 0;

    if (pragma_text(db, sql, v, e) != SQLITE_OK)
        return 0;

    const auto [end, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
    if (ec != std::errc{} || end != v.data() + v.size())
        return 0;

    return n;
}

int64_t known_page_size(sqlite3 *db, int64_t cached) {
    if (cached > 0)
        return cached;

    return pragma_int(db, "PRAGMA page_size");
}

std::string vacuum_hazard(sqlite3 *db) {
    const auto fn = sqlite3_db_filename(db, "main");
    const std::string path = fn != nullptr ? fn : "";

    std::string m, e;
    if (pragma_text(db, "PRAGMA journal_mode", m, e) != SQLITE_OK)
        return "its journal mode can't be read (" + e + ")";

    if (m == "wal")
        return "it's in WAL mode, so a running Kismet may still be logging to it";

    if (regular_size(path + "-journal").has_value())
        return "it has a -journal file, so a running Kismet may still be logging to it";

    return "";
}

int vacuum_if_finished(sqlite3 *db, std::string& skipped, std::string& err) {
    skipped = vacuum_hazard(db);
    if (!skipped.empty())
        return SQLITE_OK;

    return exec(db, "VACUUM", err);
}

wal_watch::verdict wal_watch::update(const checkpoint_result& c, int64_t page_size,
        std::chrono::steady_clock::time_point now) {
    // Not WAL, or the checkpoint itself failed; nothing to judge.  SQLITE_LOCKED with frame
    // counts is a read on the writer's connection holding the WAL back (wal_state()).
    if ((c.rc != SQLITE_OK && c.rc != SQLITE_LOCKED) || c.log_frames < 0)
        return verdict::quiet;

    last_bytes = wal_bytes(c.log_frames, page_size);

    if (c.complete()) {
        if (!warned)
            return verdict::quiet;

        warned = false;
        last_warn = std::chrono::steady_clock::time_point{};
        return verdict::cleared;
    }

    return incomplete(now);
}

wal_watch::verdict wal_watch::held_back(uint64_t wal_file_bytes,
        std::chrono::steady_clock::time_point now) {
    last_bytes = wal_file_bytes;
    return incomplete(now);
}

wal_watch::verdict wal_watch::incomplete(std::chrono::steady_clock::time_point now) {
    // Over the limit, not at it: a -wal that started over keeps its size, cut back to
    // journal_size_limit, which is the default limit
    if (last_bytes <= warn_bytes)
        return verdict::quiet;

    if (warned && now - last_warn < rewarn)
        return verdict::quiet;

    warned = true;
    last_warn = now;
    return verdict::warn;
}

}
