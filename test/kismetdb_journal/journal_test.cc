/* Tests for kismetdb_journal (kis_database_journal.h): the kismetdb log's commit cycle while
 * another program reads the log, in persist and WAL mode; WAL checkpoints and restarts;
 * falling back to persist where sqlite can't use a WAL; finishing a log as one file; and the
 * busy wait and report helpers.
 *
 * --legacy runs the same reader checks through the statements the log used before (unchecked
 * END/BEGIN, no busy handling), which lose the data.
 *
 *   make test/kismetdb_journal/journal_test && test/kismetdb_journal/journal_test [--legacy]
 */

#include "config.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include <fcntl.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "kis_database_journal.h"

using namespace kismetdb_journal;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::steady_clock;

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

static std::string dir;
static bool legacy = false;

static bool exists(const std::string& p) {
    struct stat st;
    return stat(p.c_str(), &st) == 0;
}

static off_t file_size(const std::string& p) {
    struct stat st;
    return stat(p.c_str(), &st) == 0 ? st.st_size : -1;
}

static std::string fresh(const char *name) {
    auto p = dir + "/" + name;
    for (auto s : {"", "-journal", "-wal", "-shm"})
        unlink((p + s).c_str());
    return p;
}

static sqlite3 *open_rw(const std::string& p) {
    sqlite3 *h = nullptr;
    if (sqlite3_open_v2(p.c_str(), &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
        fprintf(stderr, "can't open %s\n", p.c_str());
        exit(1);
    }
    return h;
}

static void exec_ok(sqlite3 *h, const char *sql) {
    char *e = nullptr;
    if (sqlite3_exec(h, sql, nullptr, nullptr, &e) != SQLITE_OK) {
        fprintf(stderr, "%s: %s\n", sql, e ? e : "?");
        exit(1);
    }
}

// A pragma's first result
static std::string pragma(sqlite3 *h, const char *sql) {
    sqlite3_stmt *s = nullptr;
    std::string v = "(failed)";
    if (sqlite3_prepare_v2(h, sql, -1, &s, nullptr) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW) {
        auto t = sqlite3_column_text(s, 0);
        v = t != nullptr ? reinterpret_cast<const char *>(t) : "";
    }
    sqlite3_finalize(s);
    return v;
}

// A log like kismetdb's: the table, the journal, and an open transaction
static sqlite3 *make_log(const std::string& p, journal_mode m, journal_mode *active = nullptr) {
    auto h = open_rw(p);
    exec_ok(h, "CREATE TABLE packets (n INT, packet BLOB)");

    if (legacy) {
        sqlite3_exec(h, "PRAGMA journal_mode=PERSIST", nullptr, nullptr, nullptr);
        sqlite3_exec(h, "BEGIN TRANSACTION", nullptr, nullptr, nullptr);
        return h;
    }

    std::string err;
    auto a = apply_mode(h, m, log_file::created, err).mode;
    CHECK(err.empty());
    CHECK(a == m);
    if (active != nullptr)
        *active = a;
    CHECK(begin(h, err) == SQLITE_OK);
    return h;
}

static int inserted = 0;

static void insert(sqlite3 *h, int n) {
    sqlite3_stmt *s = nullptr;
    CHECK(sqlite3_prepare_v2(h, "INSERT INTO packets VALUES (?, ?)", -1, &s, nullptr) == SQLITE_OK);
    std::string blob(300, 'x');
    for (int i = 0; i < n; i++) {
        sqlite3_bind_int(s, 1, inserted++);
        sqlite3_bind_blob(s, 2, blob.data(), blob.size(), SQLITE_STATIC);
        CHECK(sqlite3_step(s) == SQLITE_DONE);
        sqlite3_reset(s);
    }
    sqlite3_finalize(s);
}

// Rows another program sees in the log
static int count_rows(const std::string& p) {
    sqlite3 *h = nullptr;
    int n = -1;
    if (sqlite3_open_v2(p.c_str(), &h, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK) {
        sqlite3_stmt *s = nullptr;
        if (sqlite3_prepare_v2(h, "SELECT count(*) FROM packets", -1, &s, nullptr) == SQLITE_OK &&
                sqlite3_step(s) == SQLITE_ROW)
            n = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
    }
    sqlite3_close_v2(h);
    return n;
}

// Another program part way through reading the log, like kismetdb_to_pcap
struct reader {
    sqlite3 *h = nullptr;
    sqlite3_stmt *s = nullptr;

    explicit reader(const std::string& p) {
        CHECK(sqlite3_open_v2(p.c_str(), &h, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
        CHECK(sqlite3_prepare_v2(h, "SELECT packet FROM packets", -1, &s, nullptr) == SQLITE_OK);
        CHECK(sqlite3_step(s) == SQLITE_ROW);
    }

    void done() {
        sqlite3_finalize(s);
        s = nullptr;
        sqlite3_close_v2(h);
        h = nullptr;
    }

    ~reader() { done(); }
};

// One commit timer tick, as the log does it
static commit_result tick(sqlite3 *h, sqlite3 *ckpt = nullptr, checkpoint_result *cr = nullptr,
        checkpoint_result *bulk = nullptr) {
    if (legacy) {
        sqlite3_exec(h, "END TRANSACTION", nullptr, nullptr, nullptr);
        sqlite3_exec(h, "BEGIN TRANSACTION", nullptr, nullptr, nullptr);
        return commit_result{};
    }

    std::string err;
    commit_result r;
    checkpoint_result c;
    const bool wal = ckpt != nullptr || cr != nullptr;

    {
        connection_lock lk(h);
        r = commit(h, milliseconds(50));
        if (wal && ckpt == nullptr && r.state != commit_state::held)
            c = checkpoint(h, SQLITE_CHECKPOINT_PASSIVE, milliseconds(0));
        CHECK(begin(h, err) == SQLITE_OK);
    }

    if (ckpt != nullptr && r.state != commit_state::held) {
        auto b = checkpoint(ckpt, SQLITE_CHECKPOINT_PASSIVE, milliseconds(0));
        if (bulk != nullptr)
            *bulk = b;

        connection_lock lk(h);
        auto r2 = commit(h, milliseconds(50));
        CHECK(r2.state == commit_state::committed);
        c = checkpoint(h, SQLITE_CHECKPOINT_PASSIVE, milliseconds(0));
        CHECK(begin(h, err) == SQLITE_OK);
    }

    if (cr != nullptr)
        *cr = c;
    return r;
}

// Closing the log, as the log does it; true when everything committed
static bool close_log(sqlite3 *h, finish_result *fin = nullptr) {
    if (legacy) {
        sqlite3_exec(h, "END TRANSACTION", nullptr, nullptr, nullptr);
        sqlite3_exec(h, "PRAGMA journal_mode=DELETE", nullptr, nullptr, nullptr);
        sqlite3_exec(h, "BEGIN_EXCLUSIVE", nullptr, nullptr, nullptr);
        sqlite3_exec(h, "COMMIT", nullptr, nullptr, nullptr);
        sqlite3_close_v2(h);
        return true;
    }

    auto r = commit(h, milliseconds(100));
    auto f = finish(h, milliseconds(100));
    if (fin != nullptr)
        *fin = f;
    sqlite3_close_v2(h);
    return r.state == commit_state::committed;
}

// Another program reads the log from before the first tick until after Kismet exits, like a
// long kismetdb_to_pcap.  Everything logged meanwhile should be in the file.  The legacy
// statements lose all of it; WAL keeps all of it; persist can't save it either, but every
// tick and the close say so.
static void test_reader_until_exit(journal_mode m) {
    auto p = fresh(m == journal_mode::wal ? "exit-wal.kismet" : "exit-persist.kismet");
    inserted = 0;
    auto h = make_log(p, m);
    insert(h, 100);
    tick(h);

    std::string e;
    auto c = !legacy && m == journal_mode::wal ? open_checkpointer(p, e) : nullptr;
    checkpoint_result cr;
    bool saved;

    {
        reader rd(p);

        for (int t = 0; t < 3; t++) {
            insert(h, 500);
            auto r = tick(h, c, c != nullptr ? &cr : nullptr);
            if (!legacy && m == journal_mode::persist) {
                CHECK(r.state == commit_state::held);
                CHECK(r.rc == SQLITE_BUSY);
                CHECK(!r.err.empty());
                // Still the one transaction, no nested BEGIN
                CHECK(sqlite3_get_autocommit(h) == 0);
            } else if (!legacy) {
                CHECK(r.state == commit_state::committed);
            }
        }

        insert(h, 50);
        sqlite3_close_v2(c);
        saved = close_log(h);
    }

    if (!legacy && m == journal_mode::persist) {
        CHECK(!saved);
        const auto n = count_rows(p);
        CHECK(n == 100);
        if (n != 100)
            fprintf(stderr, "  %d rows in the log, then %d, -journal %lld bytes\n", n,
                    count_rows(p), (long long) file_size(p + "-journal"));
        return;
    }

    if (!legacy)
        CHECK(saved);
    CHECK(count_rows(p) == inserted);
    if (count_rows(p) != inserted)
        fprintf(stderr, "  %d of %d rows in the log\n", count_rows(p), inserted);
}

// Persist: the data stays in the open transaction while a reader blocks the commit, and the
// first tick after the reader finishes saves it all; the log ends as one file
static void test_persist_retry() {
    if (legacy)
        return;

    auto p = fresh("persist.kismet");
    inserted = 0;
    auto h = make_log(p, journal_mode::persist);
    insert(h, 100);
    tick(h);

    {
        reader rd(p);
        for (int t = 0; t < 3; t++) {
            insert(h, 500);
            CHECK(tick(h).state == commit_state::held);
        }

        // The waiting commit keeps sqlite's pending lock, so no new reader can start until
        // this one is done
        CHECK(count_rows(p) == -1);
    }

    insert(h, 100);
    CHECK(tick(h).state == commit_state::committed);
    CHECK(count_rows(p) == 1700);

    insert(h, 10);
    finish_result f;
    CHECK(close_log(h, &f));
    CHECK(count_rows(p) == 1710);
    CHECK(f.single_file && !f.wal_left);
    CHECK(!exists(p + "-journal"));
}

// WAL: commits succeed while a reader holds the log; the checkpoint can't finish, the WAL grows
// and the watch warns; it clears once the reader is done
static void test_wal_reader() {
    if (legacy)
        return;

    auto p = fresh("wal.kismet");
    inserted = 0;
    auto h = make_log(p, journal_mode::wal);
    auto ck = std::string{};
    auto c = open_checkpointer(p, ck);
    CHECK(c != nullptr);

    wal_watch watch(256 * 1024);
    const auto t0 = steady_clock::now();
    checkpoint_result cr;

    insert(h, 100);
    tick(h, c, &cr);
    CHECK(cr.complete());
    CHECK(watch.update(cr, 4096, t0) == wal_watch::verdict::quiet);

    {
        reader rd(p);
        int warns = 0;

        for (int t = 0; t < 4; t++) {
            insert(h, 500);
            auto r = tick(h, c, &cr);
            CHECK(r.state == commit_state::committed);
            CHECK(!cr.complete());
            if (watch.update(cr, 4096, t0 + seconds(t)) == wal_watch::verdict::warn)
                warns++;
            // Another program sees each tick's data right away
            CHECK(count_rows(p) == inserted);
        }

        // Warned once the WAL passed the limit, not again within the minute
        CHECK(warns == 1);
        CHECK(watch.bytes() >= 256 * 1024);
    }

    insert(h, 10);
    tick(h, c, &cr);
    CHECK(cr.complete());
    CHECK(watch.update(cr, 4096, t0 + seconds(10)) == wal_watch::verdict::cleared);
    CHECK(watch.update(cr, 4096, t0 + seconds(20)) == wal_watch::verdict::quiet);

    sqlite3_close_v2(c);
    finish_result f;
    CHECK(close_log(h, &f));
    CHECK(f.single_file && !f.wal_left && f.err.empty());
    CHECK(!exists(p + "-wal") && !exists(p + "-shm") && !exists(p + "-journal"));
    CHECK(count_rows(p) == inserted);
}

// A pcapng download reads on the writer's own connection.  It holds the WAL back like another
// program's read, but the writer's catch-up checkpoint then fails with SQLITE_LOCKED and no
// frame counts, so the watch has to go by the second connection's checkpoint.
static void test_wal_download() {
    if (legacy)
        return;

    auto p = fresh("download.kismet");
    inserted = 0;
    auto h = make_log(p, journal_mode::wal);
    std::string e;
    auto c = open_checkpointer(p, e);
    CHECK(c != nullptr);

    checkpoint_result cr, bulk;
    insert(h, 100);
    tick(h, c, &cr, &bulk);
    CHECK(cr.complete());

    sqlite3_stmt *dl = nullptr;
    CHECK(sqlite3_prepare_v2(h, "SELECT packet FROM packets", -1, &dl, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(dl) == SQLITE_ROW);

    wal_watch watch(256 * 1024);
    const auto t0 = steady_clock::now();
    int warns = 0;

    for (int t = 0; t < 4; t++) {
        insert(h, 500);
        CHECK(tick(h, c, &cr, &bulk).state == commit_state::committed);
        CHECK(cr.rc == SQLITE_LOCKED);
        CHECK(bulk.rc == SQLITE_OK && bulk.log_frames > 0);

        auto s = wal_state(cr, bulk);
        CHECK(!s.complete());
        if (watch.update(s, page_size(h), t0 + seconds(t)) == wal_watch::verdict::warn)
            warns++;
        CHECK(sqlite3_step(dl) == SQLITE_ROW);
    }

    CHECK(warns == 1);
    CHECK(watch.bytes() >= 256 * 1024);

    sqlite3_finalize(dl);
    insert(h, 10);
    tick(h, c, &cr, &bulk);
    CHECK(cr.complete());
    CHECK(watch.update(wal_state(cr, bulk), page_size(h), t0 + seconds(10)) ==
            wal_watch::verdict::cleared);

    sqlite3_close_v2(c);
    CHECK(close_log(h));
    CHECK(count_rows(p) == inserted);
}

// Setting up WAL opens the writer's WAL and its index at once, while the log is still the
// writer's alone.  Left to the first insert, it raced the second connection (or another
// program) opening the new file, which then held the log locked while it built the index,
// and the insert failed.
static void test_wal_opened() {
    if (legacy)
        return;

    auto p = fresh("opened.kismet");
    auto h = open_rw(p);
    exec_ok(h, "CREATE TABLE packets (n INT, packet BLOB)");
    std::string err;
    auto r = apply_mode(h, journal_mode::wal, log_file::created, err);
    CHECK(r.mode == journal_mode::wal && r.wal_unavailable.empty() && r.wal_rc == SQLITE_OK);
    CHECK(err.empty());
    CHECK(exists(p + "-wal") && exists(p + "-shm"));
    CHECK(pragma(h, "PRAGMA synchronous") == "1");
    CHECK(close_log(h));
}

// A writer off the commit tick (a snapshot, an alert) waits a moment for another connection's
// brief lock, within its budget only; with none it's busy at once
static void test_step_retry() {
    if (legacy)
        return;

    auto p = fresh("retry.kismet");
    inserted = 0;
    auto h = make_log(p, journal_mode::wal);
    auto o = open_rw(p);
    exec_ok(o, "BEGIN IMMEDIATE");

    sqlite3_stmt *s = nullptr;
    CHECK(sqlite3_prepare_v2(h, "INSERT INTO packets VALUES (1, x'00')", -1, &s, nullptr) == SQLITE_OK);

    auto t0 = steady_clock::now();
    CHECK(step(s, milliseconds(0)) == SQLITE_BUSY);
    CHECK(steady_clock::now() - t0 < milliseconds(100));
    sqlite3_reset(s);

    // Released part way through the budget
    std::thread th([o]() {
        std::this_thread::sleep_for(milliseconds(20));
        exec_ok(o, "COMMIT");
    });
    CHECK(step(s, milliseconds(1000)) == SQLITE_DONE);
    th.join();
    sqlite3_reset(s);

    {
        std::string err;
        connection_lock lk(h);
        CHECK(commit(h, milliseconds(0)).state == commit_state::committed);
        CHECK(begin(h, err) == SQLITE_OK);
    }

    // Held past the budget: busy, after about the budget
    exec_ok(o, "BEGIN IMMEDIATE");
    t0 = steady_clock::now();
    CHECK(step(s, milliseconds(50)) == SQLITE_BUSY);
    auto waited = steady_clock::now() - t0;
    CHECK(waited >= milliseconds(45) && waited < milliseconds(1000));
    sqlite3_reset(s);
    exec_ok(o, "COMMIT");

    CHECK(step(s, milliseconds(0)) == SQLITE_DONE);
    sqlite3_finalize(s);
    sqlite3_close_v2(o);
    CHECK(close_log(h));
    CHECK(count_rows(p) == 2);
}

// The tick's two step checkpoint lets the WAL start over every tick, so it stays about one
// tick's data; so does the writer-only fallback.  A checkpoint during the transaction alone
// never lets it start over.
static void test_wal_restart() {
    if (legacy)
        return;

    for (int variant = 0; variant < 2; variant++) {
        auto p = fresh(variant == 0 ? "restart.kismet" : "restart1.kismet");
        inserted = 0;
        auto h = make_log(p, journal_mode::wal);
        std::string e;
        auto c = variant == 0 ? open_checkpointer(p, e) : nullptr;
        checkpoint_result cr;

        insert(h, 2000);
        tick(h, c, &cr);
        const auto one = file_size(p + "-wal");

        for (int t = 0; t < 10; t++) {
            insert(h, 2000);
            tick(h, c, &cr);
            CHECK(cr.complete());
        }

        // Started over each tick: one tick's data plus the catch-up
        CHECK(file_size(p + "-wal") < one * 2);

        sqlite3_close_v2(c);
        CHECK(close_log(h));
        CHECK(count_rows(p) == inserted);
        CHECK(!exists(p + "-wal"));
    }

    auto p = fresh("restart2.kismet");
    inserted = 0;
    auto h = make_log(p, journal_mode::wal);
    std::string e;
    auto c = open_checkpointer(p, e);
    off_t one = 0;
    for (int t = 0; t < 6; t++) {
        insert(h, 2000);
        checkpoint(c, SQLITE_CHECKPOINT_PASSIVE, milliseconds(0));
        insert(h, 2000);
        connection_lock lk(h);
        commit(h, milliseconds(0));
        begin(h, e);
        if (t == 0)
            one = file_size(p + "-wal");
    }
    CHECK(file_size(p + "-wal") > one * 4);
    sqlite3_close_v2(c);
    CHECK(close_log(h));
}

// An idle program holding the log open keeps it from leaving WAL mode; the -wal is reported
// and still holds the data
static void test_finish_held() {
    if (legacy)
        return;

    auto p = fresh("held.kismet");
    inserted = 0;
    auto h = make_log(p, journal_mode::wal);
    insert(h, 200);

    sqlite3 *idle = nullptr;
    CHECK(sqlite3_open_v2(p.c_str(), &idle, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
    sqlite3_stmt *s = nullptr;
    CHECK(sqlite3_prepare_v2(idle, "SELECT count(*) FROM packets", -1, &s, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(s) == SQLITE_ROW);
    sqlite3_finalize(s);

    finish_result f;
    CHECK(close_log(h, &f));
    CHECK(!f.single_file && f.wal_left && !f.err.empty());
    CHECK(exists(p + "-wal"));
    sqlite3_close_v2(idle);
    CHECK(count_rows(p) == 200);
}

// Another program that lets go of the log part way through the budget: the checkpoint has
// nothing to wait for, but leaving WAL mode does, and it waits within the same budget
static void test_finish_retry() {
    if (legacy)
        return;

    auto p = fresh("finretry.kismet");
    inserted = 0;
    auto h = make_log(p, journal_mode::wal);
    insert(h, 200);
    CHECK(tick(h, nullptr, nullptr).state == commit_state::committed);
    {
        connection_lock lk(h);
        CHECK(commit(h, milliseconds(0)).state == commit_state::committed);
    }

    sqlite3 *idle = nullptr;
    CHECK(sqlite3_open_v2(p.c_str(), &idle, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
    CHECK(count_rows(p) == 200);
    sqlite3_stmt *s = nullptr;
    CHECK(sqlite3_prepare_v2(idle, "SELECT count(*) FROM packets", -1, &s, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(s) == SQLITE_ROW);
    sqlite3_finalize(s);

    std::thread th([idle]() {
        std::this_thread::sleep_for(milliseconds(150));
        sqlite3_close_v2(idle);
    });

    const auto t0 = steady_clock::now();
    auto f = finish(h, milliseconds(2000));
    const auto waited = steady_clock::now() - t0;
    th.join();

    CHECK(f.single_file && !f.wal_left);
    if (!f.single_file)
        fprintf(stderr, "  finish: %s\n", f.err.c_str());
    CHECK(waited < milliseconds(2000));
    CHECK(!exists(p + "-wal"));
    sqlite3_close_v2(h);
    CHECK(count_rows(p) == 200);
}

// The journal mode can't be read or changed: a -wal next to the log still counts as part of it
static int deny_journal_pragma(void *, int action, const char *a1, const char *, const char *,
        const char *) {
    return action == SQLITE_PRAGMA && a1 != nullptr && strcmp(a1, "journal_mode") == 0 ?
        SQLITE_DENY : SQLITE_OK;
}

static void test_finish_unreadable() {
    if (legacy)
        return;

    auto p = fresh("unreadable.kismet");
    inserted = 0;
    auto h = make_log(p, journal_mode::wal);
    insert(h, 50);
    {
        connection_lock lk(h);
        CHECK(commit(h, milliseconds(0)).state == commit_state::committed);
    }

    // With the mode unknown nothing is checkpointed: the -wal keeps its frames
    const auto wal_before = file_size(p + "-wal");
    CHECK(wal_before > 0);

    sqlite3_set_authorizer(h, deny_journal_pragma, nullptr);
    auto f = finish(h, milliseconds(100));
    CHECK(!f.single_file && f.wal_left && !f.err.empty());
    CHECK(exists(p + "-wal"));
    CHECK(file_size(p + "-wal") == wal_before);
    sqlite3_set_authorizer(h, nullptr, nullptr);
    sqlite3_close_v2(h);
    CHECK(count_rows(p) == 50);
}

// A filesystem sqlite's WAL can't use, as a VFS over the default one.  The log's xShmMap
// fails with shm_rc (a share that can't create or map the index); or its -wal can't be
// opened; or it has no shared memory methods, so sqlite never switches to WAL.  Everything
// else goes straight to the default VFS.
enum class wal_fault : uint8_t { shm_map, wal_open, no_shm };

static constexpr const char *fault_vfs_name = "kismet-test-walfault";
static sqlite3_vfs *base_vfs = nullptr;
static sqlite3_vfs fault_vfs;
static sqlite3_io_methods fault_methods;
static wal_fault fault = wal_fault::shm_map;
static int shm_rc = SQLITE_IOERR_SHMMAP;
static int shm_maps = 0;

static int fault_shm_map(sqlite3_file *, int, int, int, void volatile **pp) {
    shm_maps++;
    *pp = nullptr;
    return shm_rc;
}

static int fault_open(sqlite3_vfs *, const char *name, sqlite3_file *f, int flags, int *out) {
    if (fault == wal_fault::wal_open && (flags & SQLITE_OPEN_WAL) != 0) {
        f->pMethods = nullptr;
        return SQLITE_CANTOPEN;
    }

    auto rc = base_vfs->xOpen(base_vfs, name, f, flags, out);
    if (rc != SQLITE_OK || f->pMethods == nullptr || (flags & SQLITE_OPEN_MAIN_DB) == 0)
        return rc;

    fault_methods = *f->pMethods;
    if (fault == wal_fault::shm_map) {
        fault_methods.xShmMap = fault_shm_map;
    } else if (fault == wal_fault::no_shm) {
        fault_methods.iVersion = 1;
        fault_methods.xShmMap = nullptr;
        fault_methods.xShmLock = nullptr;
        fault_methods.xShmBarrier = nullptr;
        fault_methods.xShmUnmap = nullptr;
        fault_methods.xFetch = nullptr;
        fault_methods.xUnfetch = nullptr;
    }
    f->pMethods = &fault_methods;
    return rc;
}

static void register_fault_vfs() {
    if (base_vfs != nullptr)
        return;

    base_vfs = sqlite3_vfs_find(nullptr);
    fault_vfs = *base_vfs;
    fault_vfs.zName = fault_vfs_name;
    fault_vfs.xOpen = fault_open;
    CHECK(sqlite3_vfs_register(&fault_vfs, 0) == SQLITE_OK);
}

// Rows a program on the same filesystem sees; it can't use a WAL either
static int count_rows_fault(const std::string& p) {
    sqlite3 *h = nullptr;
    int n = -1;
    if (sqlite3_open_v2(p.c_str(), &h, SQLITE_OPEN_READONLY, fault_vfs_name) == SQLITE_OK) {
        sqlite3_stmt *s = nullptr;
        if (sqlite3_prepare_v2(h, "SELECT count(*) FROM packets", -1, &s, nullptr) == SQLITE_OK &&
                sqlite3_step(s) == SQLITE_ROW)
            n = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
    }
    sqlite3_close_v2(h);
    return n;
}

// A WAL sqlite can't use falls back to persist: the log takes and saves data, leaves no
// -wal or -shm behind, keeps the default sync, and holds no lock between transactions
static void fallback_case(const char *name, wal_fault f, int rc, int want_rc, bool stray_shm = false) {
    const auto failed_before = failures;
    fault = f;
    shm_rc = rc;
    shm_maps = 0;

    auto p = fresh(name);
    if (stray_shm) {
        auto fd = fopen((p + "-shm").c_str(), "w");
        CHECK(fd != nullptr);
        if (fd != nullptr)
            fclose(fd);
    }

    sqlite3 *h = nullptr;
    CHECK(sqlite3_open_v2(p.c_str(), &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                SQLITE_OPEN_FULLMUTEX, fault_vfs_name) == SQLITE_OK);
    exec_ok(h, "CREATE TABLE packets (n INT, packet BLOB)");

    // A stray -shm next to a log that was already there; one next to a new log isn't tried
    std::string err;
    auto r = apply_mode(h, journal_mode::wal, stray_shm ? log_file::existing : log_file::created, err);
    CHECK(r.mode == journal_mode::persist);
    CHECK(err.empty());
    CHECK(!r.wal_unavailable.empty());
    CHECK(r.wal_rc == want_rc);
    if (f == wal_fault::shm_map)
        CHECK(shm_maps > 0);
    if (f == wal_fault::no_shm)
        CHECK(r.wal_unavailable == "sqlite kept the delete journal");
    else
        CHECK(r.wal_unavailable.find("sqlite code " + std::to_string(want_rc)) != std::string::npos);

    CHECK(pragma(h, "PRAGMA journal_mode") == "persist");
    // Without a schema the query answers the connection's default, not the log's mode
    CHECK(pragma(h, "PRAGMA main.locking_mode") == "normal");
    CHECK(pragma(h, "PRAGMA synchronous") == "2");
    CHECK(!exists(p + "-wal"));
    CHECK(exists(p + "-shm") == stray_shm);

    // Another program can take the write lock: the fallback left none held
    {
        auto o = open_rw(p);
        CHECK(sqlite3_exec(o, "BEGIN IMMEDIATE; COMMIT", nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close_v2(o);
    }

    inserted = 0;
    CHECK(begin(h, err) == SQLITE_OK);
    insert(h, 20);
    CHECK(tick(h).state == commit_state::committed);
    CHECK(count_rows_fault(p) == 20);
    insert(h, 20);

    finish_result fin;
    CHECK(close_log(h, &fin));
    CHECK(fin.single_file && !fin.wal_left);
    CHECK(count_rows_fault(p) == 40);
    CHECK(count_rows(p) == 40);
    CHECK(!exists(p + "-wal") && !exists(p + "-journal"));

    if (failures != failed_before)
        fprintf(stderr, "  in the %s fallback\n", name);
}

static void test_wal_fallback() {
    register_fault_vfs();

    fallback_case("fb_shmmap.kismet", wal_fault::shm_map, SQLITE_IOERR_SHMMAP, SQLITE_IOERR_SHMMAP);
    fallback_case("fb_shmopen.kismet", wal_fault::shm_map, SQLITE_IOERR_SHMOPEN, SQLITE_IOERR_SHMOPEN);
    fallback_case("fb_shmsize.kismet", wal_fault::shm_map, SQLITE_IOERR_SHMSIZE, SQLITE_IOERR_SHMSIZE);
    fallback_case("fb_ioerr.kismet", wal_fault::shm_map, SQLITE_IOERR, SQLITE_IOERR);
    fallback_case("fb_stray.kismet", wal_fault::shm_map, SQLITE_IOERR_SHMMAP, SQLITE_IOERR_SHMMAP, true);
    fallback_case("fb_cantopen.kismet", wal_fault::shm_map, SQLITE_CANTOPEN, SQLITE_CANTOPEN);
    fallback_case("fb_noshm.kismet", wal_fault::no_shm, SQLITE_OK, SQLITE_OK);

    // persist is never tried as WAL
    fault = wal_fault::shm_map;
    shm_maps = 0;
    auto p = fresh("fb_persist.kismet");
    sqlite3 *h = nullptr;
    CHECK(sqlite3_open_v2(p.c_str(), &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                SQLITE_OPEN_FULLMUTEX, fault_vfs_name) == SQLITE_OK);
    exec_ok(h, "CREATE TABLE packets (n INT, packet BLOB)");
    std::string err;
    auto r = apply_mode(h, journal_mode::persist, log_file::created, err);
    CHECK(r.mode == journal_mode::persist && r.wal_unavailable.empty() && err.empty());
    CHECK(shm_maps == 0);
    CHECK(close_log(h));

    // A -wal that can't be created at all leaves the file marked WAL, which sqlite can't
    // undo without opening it; that's an error, not a quiet fallback
    fault = wal_fault::wal_open;
    p = fresh("fb_walopen.kismet");
    CHECK(sqlite3_open_v2(p.c_str(), &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                SQLITE_OPEN_FULLMUTEX, fault_vfs_name) == SQLITE_OK);
    exec_ok(h, "CREATE TABLE packets (n INT, packet BLOB)");
    err.clear();
    r = apply_mode(h, journal_mode::wal, log_file::created, err);
    CHECK(r.mode == journal_mode::persist);
    CHECK((r.wal_rc & 0xff) == SQLITE_CANTOPEN);
    CHECK(!r.wal_unavailable.empty());
    CHECK(err.find("can't be used after leaving WAL") != std::string::npos);
    sqlite3_close_v2(h);
}

// A -shm left where the new log goes that sqlite can open only read-only: another user's
// (mode 0444 here), or a directory.  Reads work in WAL and every write fails, so the log
// falls back to persist and takes data.
enum class shm_block : uint8_t { read_only, directory };

static void shm_blocked_case(const char *name, shm_block kind) {
    const auto failed_before = failures;
    auto p = fresh(name);
    const auto shm = p + "-shm";

    if (kind == shm_block::directory) {
        rmdir(shm.c_str());
        CHECK(mkdir(shm.c_str(), 0755) == 0);
    } else {
        auto fd = fopen(shm.c_str(), "w");
        CHECK(fd != nullptr);
        if (fd != nullptr)
            fclose(fd);
        CHECK(chmod(shm.c_str(), 0444) == 0);

        // Root writes it anyway
        if (access(shm.c_str(), W_OK) == 0) {
            printf("  skipping the read-only -shm case: this user can write a 0444 file\n");
            unlink(shm.c_str());
            return;
        }
    }

    auto h = open_rw(p);
    exec_ok(h, "CREATE TABLE packets (n INT, packet BLOB)");

    // Another user's -shm next to a log that was already there
    std::string err;
    auto r = apply_mode(h, journal_mode::wal, log_file::existing, err);
    CHECK(r.mode == journal_mode::persist);
    CHECK(err.empty());
    CHECK((r.wal_rc & 0xff) == SQLITE_READONLY);
    CHECK(r.wal_unavailable.find("sqlite code " + std::to_string(r.wal_rc)) != std::string::npos);
    CHECK(std::string{fallback_cause(r.wal_rc)} == "its -shm file can't be written");
    CHECK(pragma(h, "PRAGMA journal_mode") == "persist");
    CHECK(pragma(h, "PRAGMA main.locking_mode") == "normal");
    CHECK(!exists(p + "-wal"));
    CHECK(exists(shm));
    if (!err.empty())
        fprintf(stderr, "  apply_mode: %s\n", err.c_str());

    inserted = 0;
    CHECK(begin(h, err) == SQLITE_OK);
    insert(h, 20);
    CHECK(tick(h).state == commit_state::committed);
    CHECK(count_rows(p) == 20);

    // Another program can still write: no lock is held between transactions
    {
        auto o = open_rw(p);
        CHECK(sqlite3_exec(o, "BEGIN IMMEDIATE; COMMIT", nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close_v2(o);
    }

    insert(h, 20);
    finish_result fin;
    CHECK(close_log(h, &fin));
    CHECK(fin.single_file && !fin.wal_left);
    CHECK(count_rows(p) == 40);
    CHECK(!exists(p + "-wal") && !exists(p + "-journal"));

    // Not this log's to remove
    CHECK(exists(shm));
    if (kind == shm_block::directory)
        rmdir(shm.c_str());
    else
        unlink(shm.c_str());

    if (failures != failed_before)
        fprintf(stderr, "  in the %s blocked -shm case\n", name);
}

static void test_shm_blocked() {
    shm_blocked_case("shm_ro.kismet", shm_block::read_only);
    shm_blocked_case("shm_dir.kismet", shm_block::directory);
}

// The first journal_mode pragma is refused, so set_persist takes its exclusive locking path
static int deny_first_journal_pragma(void *aux, int action, const char *a1, const char *,
        const char *, const char *) {
    auto n = static_cast<int *>(aux);
    if (action != SQLITE_PRAGMA || a1 == nullptr || strcmp(a1, "journal_mode") != 0)
        return SQLITE_OK;
    return (*n)++ == 0 ? SQLITE_DENY : SQLITE_OK;
}

// sqlite keeps exclusive locking on a temporary database, as it does while it has a WAL index
// in heap memory; the fallback has to say the log stays locked
static void test_persist_stays_locked() {
    sqlite3 *h = nullptr;
    CHECK(sqlite3_open_v2("", &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
    exec_ok(h, "CREATE TABLE packets (n INT, packet BLOB)");

    int pragmas = 0;
    sqlite3_set_authorizer(h, deny_first_journal_pragma, &pragmas);
    std::string err;
    auto r = apply_mode(h, journal_mode::persist, log_file::created, err);
    sqlite3_set_authorizer(h, nullptr, nullptr);

    CHECK(pragmas >= 2);
    CHECK(r.mode == journal_mode::persist);
    CHECK(pragma(h, "PRAGMA main.locking_mode") == "exclusive");
    CHECK(err.find("stays locked to other programs") != std::string::npos);
    CHECK(err.find("locking mode exclusive") != std::string::npos);
    if (err.find("stays locked") == std::string::npos)
        fprintf(stderr, "  apply_mode on a database left exclusive: '%s'\n", err.c_str());
    sqlite3_close_v2(h);
}

// set_persist leaves exclusive locking (the answer is "normal") but the read that gives the
// lock back is refused; that's unconfirmed, not "stays locked"
static int deny_persist_unlock(void *aux, int action, const char *a1, const char *,
        const char *, const char *) {
    auto n = static_cast<int *>(aux);
    if (action != SQLITE_PRAGMA || a1 == nullptr)
        return SQLITE_OK;
    if (strcmp(a1, "schema_version") == 0)
        return SQLITE_DENY;
    if (strcmp(a1, "journal_mode") == 0)
        return (*n)++ == 0 ? SQLITE_DENY : SQLITE_OK;
    return SQLITE_OK;
}

static void test_persist_unlock_unconfirmed() {
    auto p = fresh("unlock.kismet");
    auto h = open_rw(p);
    exec_ok(h, "CREATE TABLE packets (n INT, packet BLOB)");

    int pragmas = 0;
    sqlite3_set_authorizer(h, deny_persist_unlock, &pragmas);
    std::string err;
    auto r = apply_mode(h, journal_mode::persist, log_file::created, err);
    sqlite3_set_authorizer(h, nullptr, nullptr);

    CHECK(pragmas >= 2);
    CHECK(r.mode == journal_mode::persist);
    CHECK(pragma(h, "PRAGMA main.locking_mode") == "normal");
    CHECK(err.find("stays locked") == std::string::npos);
    CHECK(err.find("couldn't confirm it gave up its exclusive lock") != std::string::npos);
    if (err.find("couldn't confirm") == std::string::npos)
        fprintf(stderr, "  apply_mode with the unlock read refused: '%s'\n", err.c_str());
    CHECK(close_log(h));
}

// Another program uses the new log while apply_mode sets it up: its SQL runs on a second
// connection from the authorizer, when apply_mode prepares the trigger statement, or before
// apply_mode starts.  hold > 0 lets go that long after, from a thread; 0 holds until done().
struct interloper {
    std::string path;
    const char *trigger = nullptr;  // "BEGIN" (the write probe), a pragma name, or nullptr: at once
    const char *sql = nullptr;
    milliseconds hold{0};
    sqlite3 *h = nullptr;
    bool fired = false;
    std::thread release;

    void take() {
        fired = true;
        h = open_rw(path);
        CHECK(sqlite3_exec(h, sql, nullptr, nullptr, nullptr) == SQLITE_OK);

        if (hold > milliseconds(0))
            release = std::thread([this]() {
                std::this_thread::sleep_for(hold);
                let_go();
            });
    }

    void let_go() {
        sqlite3_exec(h, "ROLLBACK", nullptr, nullptr, nullptr);
        sqlite3_close_v2(h);
        h = nullptr;
    }

    void done() {
        if (release.joinable())
            release.join();
        else if (h != nullptr)
            let_go();
    }

    static int authorize(void *aux, int action, const char *a1, const char *, const char *,
            const char *) {
        auto self = static_cast<interloper *>(aux);
        if (self->fired || a1 == nullptr)
            return SQLITE_OK;

        const bool hit = strcmp(self->trigger, "BEGIN") == 0 ?
            action == SQLITE_TRANSACTION && strcmp(a1, "BEGIN") == 0 :
            action == SQLITE_PRAGMA && strcmp(a1, self->trigger) == 0;

        if (hit)
            self->take();
        return SQLITE_OK;
    }
};

// The mode apply_mode reports is the log's, and the log takes data once the other program
// lets go.  blocks: the other program's lock makes apply_mode wait.
static void interloper_case(const char *name, const char *trigger, const char *sql,
        milliseconds hold, bool blocks, journal_mode expect) {
    const auto failed_before = failures;
    auto p = fresh(name);
    auto h = open_rw(p);
    exec_ok(h, "CREATE TABLE packets (n INT, packet BLOB)");

    interloper o;
    o.path = p;
    o.trigger = trigger;
    o.sql = sql;
    o.hold = hold;

    if (trigger == nullptr)
        o.take();
    else
        sqlite3_set_authorizer(h, interloper::authorize, &o);

    std::string err;
    const auto t0 = steady_clock::now();
    auto r = apply_mode(h, journal_mode::wal, log_file::created, err);
    const auto waited = steady_clock::now() - t0;
    sqlite3_set_authorizer(h, nullptr, nullptr);

    const auto log_mode = pragma(h, "PRAGMA journal_mode");
    CHECK(o.fired);
    CHECK(r.mode == expect);
    CHECK(log_mode == mode_name(r.mode));
    CHECK(waited < mode_busy_budget * 4);

    if (r.mode == journal_mode::wal)
        CHECK(r.wal_unavailable.empty() && r.wal_rc == SQLITE_OK);
    else
        CHECK(std::string{fallback_cause(r.wal_rc)} == "another program had the new log open");

    // Let go within the wait, or never in the way: nothing to say.  Held past it: the whole
    // wait, and a WAL says it was locked.
    if (!blocks || hold > milliseconds(0)) {
        CHECK(err.empty());
        if (!blocks)
            CHECK(waited < mode_busy_budget);
    } else {
        CHECK(waited >= mode_busy_budget - milliseconds(10));
        if (r.mode == journal_mode::wal)
            CHECK(err.find("had the new log locked") != std::string::npos);
    }

    o.done();

    inserted = 0;
    CHECK(begin(h, err) == SQLITE_OK);
    insert(h, 20);
    CHECK(tick(h).state == commit_state::committed);
    insert(h, 20);
    finish_result fin;
    CHECK(close_log(h, &fin));
    CHECK(fin.single_file && !fin.wal_left);
    CHECK(count_rows(p) == 40);
    CHECK(!exists(p + "-wal") && !exists(p + "-shm") && !exists(p + "-journal"));

    if (failures != failed_before)
        fprintf(stderr, "  in the %s case: mode %s, log %s, waited %lld ms, err '%s', unavailable '%s'\n",
                name, mode_name(r.mode), log_mode.c_str(),
                static_cast<long long>(std::chrono::duration_cast<milliseconds>(waited).count()),
                err.c_str(), r.wal_unavailable.c_str());
}

static void test_interlopers() {
    constexpr auto brief = milliseconds(30);
    constexpr auto held = milliseconds(0);
    const auto writer = "BEGIN IMMEDIATE";
    const auto reader = "BEGIN; SELECT count(*) FROM packets";
    const auto exclusive = "PRAGMA locking_mode=EXCLUSIVE; BEGIN; SELECT count(*) FROM packets";

    // The WAL write lock taken between the switch and the write probe
    interloper_case("il_writer.kismet", "BEGIN", writer, brief, true, journal_mode::wal);
    interloper_case("il_writer_held.kismet", "BEGIN", writer, held, true, journal_mode::wal);

    // An exclusive lock taken at the read that opens the WAL
    interloper_case("il_excl.kismet", "schema_version", exclusive, brief, true, journal_mode::wal);
    interloper_case("il_excl_held.kismet", "schema_version", exclusive, held, true, journal_mode::wal);

    // A reader in WAL is no obstacle
    interloper_case("il_wal_reader.kismet", "schema_version", reader, held, false, journal_mode::wal);

    // A reader already in the file blocks the switch to WAL; held past the wait, the log
    // stays out of WAL and uses persist
    interloper_case("il_reader.kismet", nullptr, reader, brief, true, journal_mode::wal);
    interloper_case("il_reader_held.kismet", nullptr, reader, held, true, journal_mode::persist);
}

// Another process holds the log until let_go(); posix locks are per process, so a second
// connection in this one can't take some of them.  sql runs on its own connection; nullptr
// takes a read lock on the -shm's WAL write lock byte instead, as a program recovering the
// WAL index holds it.
struct other_process {
    pid_t pid = -1;
    int release = -1;

    static constexpr off_t wal_write_lock_offset = 120;

    bool take(const std::string& p, const char *sql) {
        int ready[2], rel[2];
        if (pipe(ready) != 0)
            return false;
        if (pipe(rel) != 0) {
            close(ready[0]);
            close(ready[1]);
            return false;
        }

        pid = fork();
        if (pid == 0) {
            close(ready[0]);
            close(rel[1]);
            bool ok;
            sqlite3 *h = nullptr;
            int fd = -1;

            if (sql != nullptr) {
                ok = sqlite3_open_v2(p.c_str(), &h, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK &&
                    sqlite3_exec(h, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
            } else {
                fd = open((p + "-shm").c_str(), O_RDWR | O_CREAT, 0644);
                struct flock fl{};
                fl.l_type = F_RDLCK;
                fl.l_whence = SEEK_SET;
                fl.l_start = wal_write_lock_offset;
                fl.l_len = 1;
                ok = fd >= 0 && fcntl(fd, F_SETLK, &fl) == 0;
            }

            const char c = ok ? 'y' : 'n';
            char r;
            if (write(ready[1], &c, 1) != 1 || read(rel[0], &r, 1) < 0)
                _exit(2);
            if (h != nullptr) {
                sqlite3_exec(h, "ROLLBACK", nullptr, nullptr, nullptr);
                sqlite3_close_v2(h);
            }
            if (fd >= 0)
                close(fd);
            _exit(0);
        }

        close(ready[1]);
        close(rel[0]);
        release = rel[1];

        char c = 'n';
        const bool ok = pid > 0 && read(ready[0], &c, 1) == 1 && c == 'y';
        close(ready[0]);
        return ok;
    }

    // Returns once the other process is gone, and its locks with it
    void let_go() {
        if (release >= 0)
            close(release);
        release = -1;
        if (pid > 0) {
            int st = 0;
            CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
        }
        pid = -1;
    }
};

// A new log with a -shm another program holds: sqlite's index recovery waited seconds on it,
// outside any busy wait, then failed.  The log isn't tried as WAL, and leaves the -shm.
static void test_other_process_shm() {
    const auto failed_before = failures;
    auto p = fresh("xp_shm.kismet");
    const auto shm = p + "-shm";
    {
        auto h0 = open_rw(p);
        exec_ok(h0, "CREATE TABLE packets (n INT, packet BLOB)");
        sqlite3_close_v2(h0);
    }

    other_process o;
    CHECK(o.take(p, nullptr));

    auto h = open_rw(p);
    std::string err;
    const auto t0 = steady_clock::now();
    auto r = apply_mode(h, journal_mode::wal, log_file::created, err);
    const auto waited = steady_clock::now() - t0;

    CHECK(r.mode == journal_mode::persist);
    CHECK(pragma(h, "PRAGMA journal_mode") == "persist");
    CHECK(waited < mode_busy_budget);
    CHECK(err.empty());
    CHECK(r.wal_rc == SQLITE_PROTOCOL);
    CHECK(std::string{fallback_cause(r.wal_rc)} == "a -shm file from another program is next to it");
    CHECK(r.wal_unavailable.find(shm) != std::string::npos);

    // Logs while the other program still holds its -shm
    inserted = 0;
    CHECK(begin(h, err) == SQLITE_OK);
    insert(h, 20);
    CHECK(tick(h).state == commit_state::committed);
    CHECK(count_rows(p) == 20);

    o.let_go();

    insert(h, 20);
    finish_result fin;
    CHECK(close_log(h, &fin));
    CHECK(fin.single_file && !fin.wal_left);
    CHECK(count_rows(p) == 40);
    CHECK(!exists(p + "-wal") && !exists(p + "-journal"));
    CHECK(exists(shm));
    unlink(shm.c_str());

    if (failures != failed_before)
        fprintf(stderr, "  in the other process -shm case: mode %s, waited %lld ms, rc %d, err '%s', unavailable '%s'\n",
                mode_name(r.mode),
                static_cast<long long>(std::chrono::duration_cast<milliseconds>(waited).count()),
                r.wal_rc, err.c_str(), r.wal_unavailable.c_str());
}

// A log in WAL that another process holds in exclusive locking mode: the WAL switch, the
// persist switch and reading the mode back are all busy.  It has a -wal, so it's WAL.
static void test_other_process_exclusive() {
    const auto failed_before = failures;
    auto p = fresh("xp_excl.kismet");
    {
        auto h0 = open_rw(p);
        exec_ok(h0, "CREATE TABLE packets (n INT, packet BLOB)");
        exec_ok(h0, "PRAGMA journal_mode=WAL");
        sqlite3_close_v2(h0);
    }

    other_process o;
    CHECK(o.take(p, "PRAGMA locking_mode=EXCLUSIVE; BEGIN; SELECT count(*) FROM packets"));
    CHECK(exists(p + "-wal"));

    auto h = open_rw(p);
    std::string err;
    const auto t0 = steady_clock::now();
    auto r = apply_mode(h, journal_mode::wal, log_file::existing, err);
    const auto waited = steady_clock::now() - t0;

    o.let_go();

    CHECK(r.mode == journal_mode::wal);
    CHECK(pragma(h, "PRAGMA journal_mode") == "wal");
    CHECK(waited < mode_busy_budget * 4);
    CHECK(r.wal_unavailable.empty() && r.wal_rc == SQLITE_OK);
    CHECK(err.find("couldn't set the persist journal") != std::string::npos);
    CHECK(err.find("taken as WAL") != std::string::npos);

    inserted = 0;
    CHECK(begin(h, err) == SQLITE_OK);
    insert(h, 20);
    CHECK(tick(h).state == commit_state::committed);
    insert(h, 20);
    finish_result fin;
    CHECK(close_log(h, &fin));
    CHECK(fin.single_file && !fin.wal_left);
    CHECK(count_rows(p) == 40);
    CHECK(!exists(p + "-wal") && !exists(p + "-shm") && !exists(p + "-journal"));

    if (failures != failed_before)
        fprintf(stderr, "  in the other process exclusive case: mode %s, waited %lld ms, err '%s', unavailable '%s'\n",
                mode_name(r.mode),
                static_cast<long long>(std::chrono::duration_cast<milliseconds>(waited).count()),
                err.c_str(), r.wal_unavailable.c_str());
}

// The write probe fails on a read-only -shm and the persist switch is refused: the log is
// still WAL, and says so
static int deny_persist_pragma(void *, int action, const char *a1, const char *a2,
        const char *, const char *) {
    if (action == SQLITE_PRAGMA && a1 != nullptr && strcmp(a1, "journal_mode") == 0 &&
            a2 != nullptr && strcasecmp(a2, "persist") == 0)
        return SQLITE_DENY;
    return SQLITE_OK;
}

static void test_persist_refused_reports_wal() {
    auto p = fresh("refused.kismet");
    const auto shm = p + "-shm";
    auto fd = fopen(shm.c_str(), "w");
    CHECK(fd != nullptr);
    if (fd != nullptr)
        fclose(fd);
    CHECK(chmod(shm.c_str(), 0444) == 0);

    if (access(shm.c_str(), W_OK) == 0) {
        printf("  skipping the refused persist case: this user can write a 0444 file\n");
        unlink(shm.c_str());
        return;
    }

    auto h = open_rw(p);
    exec_ok(h, "CREATE TABLE packets (n INT, packet BLOB)");

    // A -shm next to a log that was already there, so WAL is tried
    sqlite3_set_authorizer(h, deny_persist_pragma, nullptr);
    std::string err;
    auto r = apply_mode(h, journal_mode::wal, log_file::existing, err);
    sqlite3_set_authorizer(h, nullptr, nullptr);

    CHECK(pragma(h, "PRAGMA journal_mode") == "wal");
    CHECK(r.mode == journal_mode::wal);
    CHECK(r.wal_unavailable.empty() && r.wal_rc == SQLITE_OK);
    CHECK(err.find("couldn't set the persist journal") != std::string::npos);
    CHECK(err.find("stays in WAL mode, which failed") != std::string::npos);
    if (r.mode != journal_mode::wal)
        fprintf(stderr, "  refused persist: mode %s, err '%s'\n", mode_name(r.mode), err.c_str());

    sqlite3_close_v2(h);
    unlink(shm.c_str());
}

// The -wal file and its size, which the watch falls back on when no checkpoint counted the
// frames; and rolling back a commit that couldn't be saved
static void test_wal_file() {
    auto p = fresh("walfile.kismet");
    CHECK(wal_path(p) == p + "-wal");
    CHECK(!wal_file_size(p).has_value());
    CHECK(!wal_file_size("").has_value());

    inserted = 0;
    auto h = make_log(p, journal_mode::wal);
    insert(h, 500);
    {
        connection_lock lk(h);
        CHECK(commit(h, milliseconds(0)).state == commit_state::committed);
    }
    auto sz = wal_file_size(p);
    CHECK(sz.has_value() && *sz == static_cast<uint64_t>(file_size(p + "-wal")) && *sz > 0);

    wal_watch w(256 * 1024);
    const auto t0 = steady_clock::now();
    CHECK(w.held_back(256 * 1024, t0) == wal_watch::verdict::quiet);
    CHECK(w.held_back(256 * 1024 + 1, t0) == wal_watch::verdict::warn);
    CHECK(w.bytes() == 256 * 1024 + 1);
    CHECK(w.held_back(1024 * 1024, t0 + seconds(30)) == wal_watch::verdict::quiet);
    CHECK(w.held_back(1024 * 1024, t0 + seconds(61)) == wal_watch::verdict::warn);
    checkpoint_result ok;
    ok.log_frames = 2;
    ok.checkpointed_frames = 2;
    CHECK(w.update(ok, 4096, t0 + seconds(70)) == wal_watch::verdict::cleared);

    std::string err;
    CHECK(rollback(h, err) == SQLITE_OK && err.empty());
    CHECK(begin(h, err) == SQLITE_OK);
    insert(h, 10);
    CHECK(rollback(h, err) == SQLITE_OK && err.empty());
    CHECK(sqlite3_get_autocommit(h) != 0);
    sqlite3_close_v2(h);
    CHECK(count_rows(p) == 500);
}

// Only the thread inside a busy_wait waits; another thread on the same connection (the
// packet writer) gets busy at once
static void test_busy_scope() {
    if (legacy)
        return;

    auto p = fresh("busy.kismet");
    inserted = 0;
    auto h = make_log(p, journal_mode::persist);
    insert(h, 10);
    CHECK(tick(h).state == commit_state::committed);
    insert(h, 10);
    reader rd(p);

    auto t0 = steady_clock::now();
    auto r = commit(h, milliseconds(200));
    auto waited = steady_clock::now() - t0;
    CHECK(r.state == commit_state::held);
    CHECK(waited >= milliseconds(190) && waited < milliseconds(1500));

    t0 = steady_clock::now();
    r = commit(h, milliseconds(0));
    CHECK(r.state == commit_state::held);
    CHECK(steady_clock::now() - t0 < milliseconds(100));

    steady_clock::duration other{};
    {
        busy_wait outer(milliseconds(1000));
        std::thread th([&]() {
            auto t1 = steady_clock::now();
            char *e = nullptr;
            sqlite3_exec(h, "COMMIT", nullptr, nullptr, &e);
            sqlite3_free(e);
            other = steady_clock::now() - t1;
        });
        th.join();
    }
    CHECK(other < milliseconds(100));

    rd.done();
    CHECK(commit(h, milliseconds(0)).state == commit_state::committed);
    sqlite3_close_v2(h);
}

static void test_helpers() {
    CHECK(parse_mode("wal") == journal_mode::wal);
    CHECK(parse_mode("WAL") == journal_mode::wal);
    CHECK(parse_mode("Persist") == journal_mode::persist);
    CHECK(!parse_mode(""));
    CHECK(!parse_mode("delete"));
    CHECK(!parse_mode("wal "));
    CHECK(!parse_mode(std::string_view("wal\0x", 5)));
    CHECK(std::string{mode_name(journal_mode::wal)} == "wal");
    CHECK(std::string{mode_name(journal_mode::persist)} == "persist");

    const std::string busy_cause = "another program had the new log open";
    const std::string fs_cause = "WAL isn't available on this filesystem";
    CHECK(fallback_cause(SQLITE_BUSY) == busy_cause);
    CHECK(fallback_cause(SQLITE_BUSY_SNAPSHOT) == busy_cause);
    CHECK(fallback_cause(SQLITE_LOCKED) == busy_cause);
    CHECK(fallback_cause(SQLITE_LOCKED_SHAREDCACHE) == busy_cause);
    CHECK(std::string{fallback_cause(SQLITE_READONLY)} == "its -shm file can't be written");
    CHECK(fallback_cause(SQLITE_IOERR_SHMMAP) == fs_cause);
    CHECK(fallback_cause(SQLITE_CANTOPEN) == fs_cause);
    CHECK(fallback_cause(SQLITE_OK) == fs_cause);

    CHECK(classify_commit(SQLITE_OK, false) == commit_state::committed);
    CHECK(classify_commit(SQLITE_BUSY, true) == commit_state::held);
    CHECK(classify_commit(SQLITE_IOERR, false) == commit_state::lost);
    CHECK(classify_commit(SQLITE_FULL, true) == commit_state::held);

    CHECK(wal_bytes(0, 4096) == 0);
    CHECK(wal_bytes(-1, 4096) == 0);
    CHECK(wal_bytes(1, 0) == 0);
    CHECK(wal_bytes(1, 4096) == 32 + 4120);
    CHECK(wal_bytes(1000000, 65536) == 32 + 1000000ULL * 65560);

    repeat_report rr(seconds(60));
    const auto t0 = steady_clock::now();
    CHECK(rr.failed(t0) == 1);
    CHECK(rr.since() == t0);
    CHECK(rr.failed(t0 + seconds(10)) == 0);
    CHECK(rr.failed(t0 + seconds(30)) == 0);
    CHECK(rr.failed(t0 + seconds(61)) == 3);
    CHECK(rr.since() == t0);
    CHECK(rr.succeeded() == 4);
    CHECK(rr.succeeded() == 0);
    CHECK(rr.failed(t0 + seconds(62)) == 1);
    CHECK(rr.since() == t0 + seconds(62));

    // Not WAL, or a failed checkpoint, says nothing
    wal_watch w(1);
    CHECK(w.update(checkpoint_result{}, 4096, t0) == wal_watch::verdict::quiet);
    checkpoint_result busy;
    busy.rc = SQLITE_BUSY;
    busy.log_frames = 100;
    busy.checkpointed_frames = 0;
    CHECK(w.update(busy, 4096, t0) == wal_watch::verdict::quiet);

    // The catch-up is used when it ran; when a read on the writer's connection locked it,
    // the bulk checkpoint's frame counts, still incomplete
    checkpoint_result ok;
    ok.rc = SQLITE_OK;
    ok.log_frames = 10;
    ok.checkpointed_frames = 10;
    checkpoint_result locked;
    locked.rc = SQLITE_LOCKED;
    CHECK(wal_state(ok, std::nullopt).complete());
    CHECK(wal_state(ok, busy).log_frames == 10);
    auto ws = wal_state(locked, ok);
    CHECK(ws.rc == SQLITE_LOCKED && ws.log_frames == 10 && ws.checkpointed_frames == 10);
    CHECK(!ws.complete());
    CHECK(wal_state(locked, std::nullopt).log_frames == -1);
    CHECK(wal_state(locked, busy).log_frames == -1);
    CHECK(w.update(ws, 4096, t0) == wal_watch::verdict::warn);
    CHECK(w.update(wal_state(locked, std::nullopt), 4096, t0) == wal_watch::verdict::quiet);
    CHECK(w.update(ok, 4096, t0) == wal_watch::verdict::cleared);

    // No WAL on a database sqlite can't give one
    sqlite3 *m = nullptr;
    CHECK(sqlite3_open(":memory:", &m) == SQLITE_OK);
    std::string err;
    auto mr = apply_mode(m, journal_mode::wal, log_file::created, err);
    CHECK(mr.mode == journal_mode::persist);
    CHECK(mr.wal_unavailable == "sqlite kept the memory journal");
    CHECK(!err.empty());
    sqlite3_close(m);

    // A checkpointer is only for an existing WAL log
    err.clear();
    CHECK(open_checkpointer(dir + "/missing.kismet", err) == nullptr && !err.empty());
    auto p = fresh("notwal.kismet");
    auto h = make_log(p, journal_mode::persist);
    err.clear();
    CHECK(open_checkpointer(p, err) == nullptr && !err.empty());
    CHECK(close_log(h));
    CHECK(!exists(p + "-journal"));
}

int main(int argc, char **argv) {
    legacy = argc > 1 && strcmp(argv[1], "--legacy") == 0;

    const char *tmp = getenv("TMPDIR");
    std::string tmpl = std::string{tmp != nullptr && tmp[0] != '\0' ? tmp : "/tmp"} + "/kismetdb_journal.XXXXXX";
    if (mkdtemp(tmpl.data()) == nullptr) {
        perror("mkdtemp");
        return 1;
    }
    dir = tmpl;

    if (!legacy) {
        test_helpers();
        test_wal_fallback();
        test_shm_blocked();
        test_persist_stays_locked();
        test_persist_unlock_unconfirmed();
        test_interlopers();
        test_other_process_shm();
        test_other_process_exclusive();
        test_persist_refused_reports_wal();
        test_wal_file();
        test_busy_scope();
        test_wal_reader();
        test_wal_download();
        test_wal_opened();
        test_step_retry();
        test_wal_restart();
        test_finish_held();
        test_finish_retry();
        test_finish_unreadable();
        test_persist_retry();
        test_reader_until_exit(journal_mode::persist);
    }
    test_reader_until_exit(journal_mode::wal);

    if (failures != 0) {
        fprintf(stderr, "%d check(s) failed%s, sqlite %s; files in %s\n", failures,
                legacy ? " (legacy statements)" : "", sqlite3_libversion(), dir.c_str());
        return 1;
    }

    printf("kismetdb journal: all checks passed%s, sqlite %s\n", legacy ? " (legacy statements)" : "",
            sqlite3_libversion());
    return 0;
}
