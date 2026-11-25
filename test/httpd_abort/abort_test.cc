/* Tests for stopping http responses whose client went away, and for the limit on large
 * lists built at once (issue 774): socket_peer_closed, future_chainbuf wait_for and
 * cancel, concurrency_limit, and the connection's once-only close callback.
 *
 *   make test/httpd_abort/abort_test && test/httpd_abort/abort_test
 */

#include "config.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <functional>
#include <ostream>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "concurrency_limit.h"
#include "future_chainbuf.h"
#include "util.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

using namespace std::chrono_literals;

// A connected loopback TCP pair: server and client ends
struct tcp_pair {
    int srv = -1;
    int cli = -1;

    tcp_pair() {
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        if (lfd < 0)
            return;

        struct sockaddr_in sa = {};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = 0;
        socklen_t sl = sizeof(sa);

        if (bind(lfd, (struct sockaddr *) &sa, sizeof(sa)) < 0 ||
                listen(lfd, 1) < 0 ||
                getsockname(lfd, (struct sockaddr *) &sa, &sl) < 0) {
            close(lfd);
            return;
        }

        cli = socket(AF_INET, SOCK_STREAM, 0);
        if (cli < 0 || connect(cli, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
            close(lfd);
            return;
        }

        srv = accept(lfd, nullptr, nullptr);
        close(lfd);
    }

    ~tcp_pair() {
        if (srv >= 0)
            close(srv);
        if (cli >= 0)
            close(cli);
    }

    bool ok() const { return srv >= 0 && cli >= 0; }

    void close_cli() {
        close(cli);
        cli = -1;
    }
};

// Loopback delivers at once, but give the stack a moment anyway
static void settle() {
    std::this_thread::sleep_for(20ms);
}

static void test_peer_closed() {
    CHECK(socket_peer_closed(-1));

    {
        tcp_pair p;
        CHECK(p.ok());
        CHECK(!socket_peer_closed(p.srv));
        CHECK(!socket_peer_closed(p.cli));
    }

    {
        // A pipelined request waiting to be read is a live client
        tcp_pair p;
        CHECK(p.ok());
        CHECK(write(p.cli, "GET / HTTP/1.1\r\n\r\n", 18) == 18);
        settle();
        CHECK(!socket_peer_closed(p.srv));

        // and the check reads none of it
        char buf[32];
        CHECK(recv(p.srv, buf, sizeof(buf), MSG_DONTWAIT) == 18);
    }

    {
        // curl -m: the client closes the socket
        tcp_pair p;
        CHECK(p.ok());
        p.close_cli();
        settle();
        CHECK(socket_peer_closed(p.srv));
    }

    {
        tcp_pair p;
        CHECK(p.ok());
        CHECK(shutdown(p.cli, SHUT_WR) == 0);
        settle();
        CHECK(socket_peer_closed(p.srv));
    }

    {
        // Reset by the client
        tcp_pair p;
        CHECK(p.ok());
        struct linger lg = {1, 0};
        CHECK(setsockopt(p.cli, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)) == 0);
        p.close_cli();
        settle();
        CHECK(socket_peer_closed(p.srv));
    }

#ifdef POLLRDHUP
    {
        // Unread data in front of the close, such as a TLS close_notify
        tcp_pair p;
        CHECK(p.ok());
        CHECK(write(p.cli, "\x15\x03\x03\x00\x02\x01\x00", 7) == 7);
        p.close_cli();
        settle();
        CHECK(socket_peer_closed(p.srv));
    }
#endif
}

static void test_wait_for() {
    {
        // Nothing comes: times out, and can wait again
        future_chainbuf cb;
        auto start = std::chrono::steady_clock::now();
        CHECK(cb.wait_for(50ms) == 0);
        CHECK(std::chrono::steady_clock::now() - start >= 45ms);
        CHECK(cb.running());

        bool threw = false;
        try {
            CHECK(cb.wait_for(10ms) == 0);
            CHECK(cb.wait_for(10ms) == 0);
        } catch (const std::exception&) {
            threw = true;
        }
        CHECK(!threw);
    }

    {
        // Data already waiting returns at once
        future_chainbuf cb;
        cb.put_data("abc", 3);
        auto start = std::chrono::steady_clock::now();
        CHECK(cb.wait_for(5s) == 3);
        CHECK(std::chrono::steady_clock::now() - start < 1s);
    }

    {
        // A producer completing wakes it
        future_chainbuf cb;
        std::thread t([&cb]() {
            std::this_thread::sleep_for(30ms);
            std::ostream os(&cb);
            os << "data";
            cb.complete();
        });

        auto start = std::chrono::steady_clock::now();
        size_t sz = 0;
        while ((sz = cb.wait_for(5s)) == 0 && cb.running())
            ;
        CHECK(sz == 4);
        CHECK(std::chrono::steady_clock::now() - start < 4s);
        t.join();
    }

    {
        // A cancel from another thread wakes it, and it stays woken
        future_chainbuf cb;
        std::thread t([&cb]() {
            std::this_thread::sleep_for(30ms);
            cb.cancel();
        });

        auto start = std::chrono::steady_clock::now();
        CHECK(cb.wait_for(5s) == 0);
        CHECK(std::chrono::steady_clock::now() - start < 4s);
        CHECK(!cb.running());
        CHECK(cb.cancelled());
        CHECK(cb.wait_for(5s) == 0);
        t.join();
    }

    {
        // Producer and a consumer polling with short waits, racing notify against timeout
        future_chainbuf cb;
        constexpr size_t n_writes = 20000;

        std::thread t([&cb]() {
            std::ostream os(&cb);
            for (size_t i = 0; i < n_writes; i++) {
                os << 'x';
                if (i % 512 == 0)
                    os.flush();
            }
            cb.complete();
        });

        size_t got = 0;
        bool threw = false;

        try {
            while (cb.size() || cb.running()) {
                char *d;
                auto sz = cb.get(&d);
                if (sz) {
                    got += sz;
                    cb.consume(sz);
                }
                cb.wait_for(1ms);
            }
        } catch (const std::exception&) {
            threw = true;
        }

        t.join();
        CHECK(!threw);
        CHECK(got == n_writes);
    }
}

static void test_cancel_stream() {
    {
        // A plain ostream drops writes after a cancel, as before
        future_chainbuf cb;
        std::ostream os(&cb);
        os << "before";
        CHECK(cb.size() == 6);
        cb.cancel();

        bool threw = false;
        try {
            os << "after";
            os.put('x');
        } catch (...) {
            threw = true;
        }

        CHECK(!threw);
        CHECK(os.bad());
        CHECK(cb.size() == 6);
    }

    {
        // One asking for badbit exceptions gets cancelled_error, from strings and chars
        future_chainbuf cb;
        std::ostream os(&cb);
        os.exceptions(std::ios::badbit);
        os << "before";
        cb.cancel();

        bool cancelled = false;
        try {
            os << "after";
        } catch (const future_chainbuf::cancelled_error&) {
            cancelled = true;
        }
        CHECK(cancelled);

        std::ostream os2(&cb);
        os2.exceptions(std::ios::badbit);
        cancelled = false;
        try {
            os2 << 'x';
        } catch (const future_chainbuf::cancelled_error&) {
            cancelled = true;
        }
        CHECK(cancelled);
        CHECK(cb.size() == 6);
    }

    {
        // Completing isn't cancelling: late writes are dropped quietly
        future_chainbuf cb;
        std::ostream os(&cb);
        os.exceptions(std::ios::badbit);
        os << "done";
        cb.complete();

        bool threw = false;
        try {
            os << "late";
        } catch (...) {
            threw = true;
        }
        CHECK(!threw);
        CHECK(!cb.cancelled());
        CHECK(cb.size() == 4);
    }

    {
        // put_data, used by the packet streams, still drops quietly
        future_chainbuf cb;
        cb.cancel();
        bool threw = false;
        try {
            cb.put_data("abc", 3);
        } catch (...) {
            threw = true;
        }
        CHECK(!threw);
        CHECK(cb.size() == 0);
    }
}

static void test_limit() {
    {
        concurrency_limit lim(2);

        auto a = lim.try_acquire();
        auto b = lim.try_acquire();
        auto c = lim.try_acquire();
        CHECK(a.held());
        CHECK(b.held());
        CHECK(!c.held());
        CHECK(lim.active() == 2);

        a.release();
        CHECK(!a.held());
        CHECK(lim.active() == 1);
        a.release();
        CHECK(lim.active() == 1);

        c = lim.try_acquire();
        CHECK(c.held());
        CHECK(!lim.try_acquire().held());
        CHECK(lim.active() == 2);

        // Moving hands the slot over without counting it twice
        concurrency_limit::slot d(std::move(c));
        CHECK(d.held());
        CHECK(!c.held());
        CHECK(lim.active() == 2);

        b = std::move(d);
        CHECK(lim.active() == 1);
        CHECK(b.held());

        b = concurrency_limit::slot{};
        CHECK(lim.active() == 0);
    }

    {
        concurrency_limit lim(1);
        {
            auto a = lim.try_acquire();
            CHECK(a.held());
            CHECK(!lim.try_acquire().held());
        }
        CHECK(lim.active() == 0);
        CHECK(lim.try_acquire().held());

        lim.set_max(3);
        auto a = lim.try_acquire();
        auto b = lim.try_acquire();
        auto c = lim.try_acquire();
        CHECK(a.held() && b.held() && c.held());
        CHECK(!lim.try_acquire().held());
    }

    {
        // No limit
        concurrency_limit lim(0);
        std::vector<concurrency_limit::slot> v;
        for (int i = 0; i < 100; i++)
            v.push_back(lim.try_acquire());
        bool all = true;
        for (const auto& s : v)
            all = all && s.held();
        CHECK(all);
        CHECK(lim.active() == 100);
        v.clear();
        CHECK(lim.active() == 0);
    }

    {
        // Many threads at once never hold more than the limit
        constexpr unsigned int max = 4;
        concurrency_limit lim(max);
        std::atomic<unsigned int> holding{0};
        std::atomic<unsigned int> peak{0};
        std::atomic<unsigned int> granted{0};
        std::vector<std::thread> threads;

        for (int t = 0; t < 16; t++) {
            threads.emplace_back([&]() {
                for (int i = 0; i < 5000; i++) {
                    auto s = lim.try_acquire();
                    if (!s.held())
                        continue;

                    granted++;
                    auto h = ++holding;
                    auto p = peak.load();
                    while (h > p && !peak.compare_exchange_weak(p, h))
                        ;
                    holding--;
                }
            });
        }

        for (auto& t : threads)
            t.join();

        CHECK(peak <= max);
        CHECK(granted > 0);
        CHECK(lim.active() == 0);
    }
}

// The connection close callback runs exactly once whichever of set and close comes first
static void test_closure_once() {
    {
        closure_once c;
        int n = 0;
        c.set([&]() { n++; });
        CHECK(n == 0);
        c.fire();
        CHECK(n == 1);
        c.fire();
        CHECK(n == 1);
    }

    {
        // Closed before the generator sets it
        closure_once c;
        int n = 0;
        c.fire();
        c.set([&]() { n++; });
        CHECK(n == 1);
        c.fire();
        CHECK(n == 1);
    }

    {
        // The stream was already cancelled
        closure_once c;
        int n = 0;
        c.set([&]() { n++; }, true);
        CHECK(n == 1);
        c.fire();
        CHECK(n == 1);
    }

    {
        // A later set replaces one not yet run
        closure_once c;
        int a = 0, b = 0;
        c.set([&]() { a++; });
        c.set([&]() { b++; });
        c.fire();
        CHECK(a == 0);
        CHECK(b == 1);
    }

    {
        // Nothing set, or an empty callback
        closure_once c;
        c.fire();
        c.set(nullptr);
        c.set(std::function<void ()>{}, true);
        CHECK(true);
    }

    {
        // The callback runs outside the lock, so it may set another
        closure_once c;
        int n = 0;
        c.set([&]() { c.set([&]() { n++; }); });
        c.fire();
        CHECK(n == 1);
    }

    {
        // Set on one thread and fire on another, started together
        constexpr int rounds = 2000;
        int wrong = 0;

        for (int r = 0; r < rounds; r++) {
            closure_once c;
            std::atomic<int> n{0};
            std::atomic<bool> go{false};

            std::thread setter([&]() {
                while (!go)
                    ;
                c.set([&]() { n++; });
            });

            std::thread closer([&]() {
                while (!go)
                    ;
                c.fire();
            });

            go = true;
            setter.join();
            closer.join();

            if (n != 1)
                wrong++;
        }

        CHECK(wrong == 0);
    }
}

int main() {
    test_peer_closed();
    test_wait_for();
    test_cancel_stream();
    test_limit();
    test_closure_once();

    if (failures) {
        fprintf(stderr, "abort_test: %d failure(s)\n", failures);
        return 1;
    }

    printf("abort_test: all tests passed\n");
    return 0;
}
