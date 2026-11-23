/* Tests for devicetracker_view_walk: a walk over a view's device list a batch at a time,
 * against devices leaving (empty slots), squeezes of the empty slots, new devices, records
 * made again under the same key, and records leaving and joining again.  Every device in the
 * list throughout the walk must be emitted.
 *
 *   make test/entity/view_walk_test && test/entity/view_walk_test
 */

#include "config.h"

#include <cstdio>
#include <memory>
#include <random>
#include <set>
#include <unordered_map>
#include <vector>

#include "devicetracker_view_walk.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

struct fake_device {
    uint64_t key;
    uint64_t iid;
};

using dev_ptr = std::shared_ptr<fake_device>;

// The view's list, presence map and squeeze, as devicetracker_view keeps them
struct fake_view {
    std::vector<dev_ptr> list;
    std::unordered_map<uint64_t, view_walk::place> presence;
    size_t holes = 0;
    uint64_t squeezed = 0;
    uint64_t next_iid = 1;
    uint32_t next_serial = 1;
    size_t min_holes = 256;

    void join(const dev_ptr& d) {
        presence[d->key] = view_walk::place{static_cast<uint32_t>(list.size()), next_serial++};
        list.push_back(d);
    }

    dev_ptr add(uint64_t key) {
        auto d = std::make_shared<fake_device>(fake_device{key, next_iid++});
        join(d);
        return d;
    }

    void remove(uint64_t key) {
        const auto pi = presence.find(key);
        if (pi == presence.end())
            return;
        list[pi->second.slot] = nullptr;
        presence.erase(pi);
        if (++holes >= min_holes && holes * 4 >= list.size())
            squeeze();
    }

    // The same record leaves and joins again at the end, as a rule view or a filtered view's
    // update callback can do
    void rejoin(dev_ptr d) {
        remove(d->key);
        join(d);
    }

    void squeeze() {
        size_t w = 0;
        for (size_t r = 0; r < list.size(); r++) {
            if (list[r] == nullptr)
                continue;
            if (w != r)
                list[w] = std::move(list[r]);
            presence[list[w]->key].slot = static_cast<uint32_t>(w);
            w++;
        }
        squeezed += list.size() - w;
        list.resize(w);
        holes = 0;
    }

    bool batch(view_walk::cursor<uint64_t>& c, size_t n, std::vector<dev_ptr>& out) {
        return view_walk::batch(c, list, squeezed, n,
                [this](uint64_t k) -> std::optional<view_walk::place> {
                    const auto pi = presence.find(k);
                    if (pi == presence.end())
                        return std::nullopt;
                    return pi->second;
                },
                [](const dev_ptr& d) { return d->key; },
                [&out](const dev_ptr& d) { out.push_back(d); });
    }
};

static std::set<uint64_t> iids_of(const std::vector<dev_ptr>& v) {
    std::set<uint64_t> s;
    for (const auto& d : v)
        s.insert(d->iid);
    return s;
}

static void test_plain() {
    fake_view v;
    for (uint64_t k = 0; k < 10; k++)
        v.add(k);

    view_walk::cursor<uint64_t> c;
    std::vector<dev_ptr> out;
    CHECK(v.batch(c, 4, out));
    CHECK(out.size() == 4 && out[0]->key == 0 && out[3]->key == 3);
    out.clear();
    CHECK(v.batch(c, 4, out));
    CHECK(v.batch(c, 4, out) == false);
    CHECK(out.size() == 6 && out.back()->key == 9);

    // At the end it stays at the end, and a new device is still reached
    out.clear();
    CHECK(!v.batch(c, 4, out) && out.empty());
    v.add(10);
    CHECK(!v.batch(c, 4, out));
    CHECK(out.size() == 1 && out[0]->key == 10);

    // An empty list
    fake_view e;
    view_walk::cursor<uint64_t> ec;
    CHECK(!e.batch(ec, 4, out));
    CHECK(ec.slot == 0);
}

// A run of empty slots longer than a batch doesn't stall the walk
static void test_empty_run() {
    fake_view v;
    v.min_holes = 1u << 30;
    for (uint64_t k = 0; k < 20; k++)
        v.add(k);

    view_walk::cursor<uint64_t> c;
    std::vector<dev_ptr> out;
    v.batch(c, 2, out);
    for (uint64_t k = 2; k < 18; k++)
        v.remove(k);

    size_t batches = 0;
    while (v.batch(c, 3, out))
        batches++;
    CHECK(batches < 10);
    CHECK(out.size() == 4 && out[2]->key == 18 && out[3]->key == 19);
}

// A squeeze between batches moves devices to lower slots: none are skipped
static void test_squeeze() {
    fake_view v;
    v.min_holes = 1u << 30;
    for (uint64_t k = 0; k < 100; k++)
        v.add(k);

    view_walk::cursor<uint64_t> c;
    std::vector<dev_ptr> out;
    v.batch(c, 50, out);

    // The last device copied is gone, and everything before it: the walk steps back
    for (uint64_t k = 0; k < 50; k++)
        v.remove(k);
    v.squeeze();
    while (v.batch(c, 7, out))
        ;
    auto s = iids_of(out);
    CHECK(s.size() == 100);

    // The last device copied stays: the walk goes on right after it
    fake_view w;
    w.min_holes = 1u << 30;
    for (uint64_t k = 0; k < 100; k++)
        w.add(k);
    view_walk::cursor<uint64_t> d;
    out.clear();
    w.batch(d, 50, out);
    for (uint64_t k = 0; k < 40; k++)
        w.remove(k);
    w.squeeze();
    std::vector<dev_ptr> rest;
    w.batch(d, 5, rest);
    CHECK(rest.size() == 5 && rest[0]->key == 50);
}

// The last device copied is made again under its key, at the end of the list: the walk doesn't
// jump there and skip the devices between
static void test_recreated_last() {
    fake_view v;
    v.min_holes = 1u << 30;
    for (uint64_t k = 0; k < 30; k++)
        v.add(k);

    view_walk::cursor<uint64_t> c;
    std::vector<dev_ptr> out;
    v.batch(c, 10, out);
    CHECK(out.back()->key == 9);

    v.remove(9);
    v.add(9);
    for (uint64_t k = 0; k < 9; k++)
        v.remove(k);
    v.squeeze();

    std::vector<dev_ptr> rest;
    while (v.batch(c, 4, rest))
        ;
    std::set<uint64_t> keys;
    for (const auto& d : rest)
        keys.insert(d->key);
    for (uint64_t k = 10; k < 30; k++)
        CHECK(keys.count(k) == 1);
    CHECK(keys.count(9) == 1);
}

// The last device copied leaves and the same record joins again at the end: the walk doesn't
// jump there and skip the devices between, with or without a squeeze after
static void test_rejoined_last() {
    // And with the join serials wrapping through 0 between the batches
    for (const auto& [squeeze, first_serial] : {std::pair{false, 1u}, std::pair{true, 1u},
            std::pair{false, 0xfffffff0u}, std::pair{true, 0xfffffff0u}}) {
        fake_view v;
        v.min_holes = 1u << 30;
        v.next_serial = first_serial;
        for (uint64_t k = 0; k < 30; k++)
            v.add(k);

        view_walk::cursor<uint64_t> c;
        std::vector<dev_ptr> out;
        v.batch(c, 10, out);
        CHECK(out.back()->key == 9);

        v.rejoin(out.back());
        if (squeeze) {
            for (uint64_t k = 0; k < 9; k++)
                v.remove(k);
            v.squeeze();
        }

        std::vector<dev_ptr> rest;
        while (v.batch(c, 4, rest))
            ;
        std::set<uint64_t> keys;
        for (const auto& d : rest)
            keys.insert(d->key);
        size_t skipped = 0;
        for (uint64_t k = 10; k < 30; k++)
            skipped += keys.count(k) == 0;
        if (skipped != 0)
            fprintf(stderr, "rejoin%s: %zu of 20 devices in the list throughout skipped\n",
                    squeeze ? " + squeeze" : "", skipped);
        CHECK(skipped == 0);
    }
}

// Random churn: removals (with the view's own squeeze rule), new devices, re-made records and
// records leaving and joining again (the last one copied, often) between batches.  Devices
// present from the start to the end are all emitted; the walk ends, and repeats stay bounded.
static void test_churn() {
    std::mt19937_64 rng(7);

    for (int round = 0; round < 300; round++) {
        fake_view v;
        v.min_holes = 1 + rng() % 64;
        // Half the rounds wrap the join serials during the walk
        if (round % 2)
            v.next_serial = 0xffffffffu - static_cast<uint32_t>(rng() % 4000);
        const size_t n0 = rng() % 3000;
        uint64_t next_key = 0;
        for (size_t i = 0; i < n0; i++)
            v.add(next_key++);

        std::set<uint64_t> start;
        for (const auto& d : v.list)
            start.insert(d->iid);
        std::set<uint64_t> gone;

        view_walk::cursor<uint64_t> c;
        std::vector<dev_ptr> out;
        const size_t batch_n = 1 + rng() % 200;
        size_t batches = 0;
        bool more = true;

        while (more && batches < 100000) {
            more = v.batch(c, batch_n, out);
            batches++;

            if (!out.empty() && rng() % 3 == 0 && v.presence.count(out.back()->key) &&
                    v.list[v.presence[out.back()->key].slot] == out.back()) {
                gone.insert(out.back()->iid);
                v.rejoin(out.back());
            }

            const size_t ops = rng() % 40;
            for (size_t o = 0; o < ops; o++) {
                const auto r = rng() % 11;
                if (r == 10 && !v.presence.empty()) {
                    const auto idx = rng() % v.list.size();
                    if (v.list[idx] != nullptr) {
                        gone.insert(v.list[idx]->iid);
                        v.rejoin(v.list[idx]);
                    }
                } else if (r < 6 && !v.presence.empty()) {
                    // Remove a random present device
                    const auto idx = rng() % v.list.size();
                    if (v.list[idx] != nullptr) {
                        gone.insert(v.list[idx]->iid);
                        v.remove(v.list[idx]->key);
                    }
                } else if (r < 8) {
                    v.add(next_key++);
                } else if (!v.presence.empty()) {
                    // Made again under the same key
                    const auto idx = rng() % v.list.size();
                    if (v.list[idx] != nullptr) {
                        const auto k = v.list[idx]->key;
                        gone.insert(v.list[idx]->iid);
                        v.remove(k);
                        v.add(k);
                    }
                }
            }
            if (rng() % 50 == 0 && v.holes > 0)
                v.squeeze();
        }

        CHECK(batches < 100000);

        const auto seen = iids_of(out);
        for (const auto i : start)
            if (!gone.count(i) && !seen.count(i)) {
                fprintf(stderr, "round %d: device %lu in the list throughout was skipped\n", round,
                        static_cast<unsigned long>(i));
                failures++;
                break;
            }
    }
}

int main() {
    test_plain();
    test_empty_run();
    test_squeeze();
    test_recreated_last();
    test_rejoined_last();
    test_churn();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("all view walk tests passed\n");
    return 0;
}
