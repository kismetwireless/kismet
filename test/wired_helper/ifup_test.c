/* Live test of kismet_cap_wired's bring-up child (wired_ifupd.c) on a veth pair
 * in a user, network and mount namespace of its own, so no host interface is
 * touched; make -C capture_wired test runs it as
 *
 *   unshare -r -n -m sh -c 'mount -t sysfs sysfs /sys && \
 *       ip link add wtest0 type veth peer name wtest1 && \
 *       test/wired_helper/ifup_test wtest0 wtest1'
 *
 * Both interfaces start down.  The child holds CAP_NET_ADMIN alone, one
 * descriptor and no_new_privs; this process, with CAP_NET_ADMIN dropped, can't
 * bring an interface up itself, but the child brings up the first and changes
 * only IFF_UP, says "already up" the second time, refuses loopback, missing
 * interfaces and malformed requests, still answers after them, and exits when
 * its socket closes or its parent dies.  A link renamed between the check and
 * the set is the one set up, and the request fails.  With --host-sysfs <if>, run
 * under unshare -r -n without the sysfs mount, nothing is classified by the
 * host's /sys.  Exits 0 when every check passes, 1 on a failure, 77 outside a
 * network namespace of its own.
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sched.h>

#include <sys/socket.h>
#include <sys/wait.h>

#include <net/if.h>

#include <linux/capability.h>

#include "../../capture_wired/wired_ifupd.h"
#include "../../capture_wired/wired_sysfs.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { \
        failures++; \
        printf("FAIL %s:%d: ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } \
} while (0)

static long if_flags(const char *ifname) {
    char path[256], buf[32];
    FILE *f;
    long v = -1;

    snprintf(path, sizeof(path), "/sys/class/net/%s/flags", ifname);

    if ((f = fopen(path, "r")) == NULL)
        return -1;

    if (fgets(buf, sizeof(buf), f) != NULL)
        v = strtol(buf, NULL, 16);

    fclose(f);
    return v;
}

/* A hex field ("CapEff:") of /proc/<pid>/status, or a decimal one with base 10 */
static long long status_field(pid_t pid, const char *key, int base) {
    char path[64], line[256];
    size_t kl = strlen(key);
    long long v = -1;
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/status", (int) pid);

    if ((f = fopen(path, "r")) == NULL)
        return -1;

    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, key, kl) == 0) {
            v = strtoll(line + kl, NULL, base);
            break;
        }
    }

    fclose(f);
    return v;
}

static int fd_count(pid_t pid) {
    char path[64];
    struct dirent *e;
    DIR *d;
    int n = 0;

    snprintf(path, sizeof(path), "/proc/%d/fd", (int) pid);

    if ((d = opendir(path)) == NULL)
        return -1;

    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] != '.')
            n++;
    }

    closedir(d);
    return n;
}

/* Exited: reaped here, or gone or a zombie elsewhere */
static int gone_within(pid_t pid, int ms) {
    char path[64], line[256];
    FILE *f;
    int i, st, gone;

    snprintf(path, sizeof(path), "/proc/%d/status", (int) pid);

    for (i = 0; i < ms / 10; i++) {
        if (waitpid(pid, &st, WNOHANG) == pid)
            return 1;

        if ((f = fopen(path, "r")) == NULL)
            return 1;

        gone = 0;

        while (fgets(line, sizeof(line), f) != NULL) {
            if (strncmp(line, "State:", 6) == 0) {
                gone = strchr(line, 'Z') != NULL;
                break;
            }
        }

        fclose(f);

        if (gone)
            return 1;

        usleep(10000);
    }

    return 0;
}

static int answer_with(const wired_ifupd_ops_t *ops, const char *ifname, int *err) {
    wired_ifup_req_t req;
    wired_ifup_reply_t rep;
    wired_ifup_status_t st;

    wired_ifup_req_build(ifname, 5, &req);
    wired_ifupd_answer((uint8_t *) &req, sizeof(req), ops, &rep);

    return wired_ifup_reply_parse((uint8_t *) &rep, sizeof(rep), 5, &st, err) == 1 ? (int) st : -1;
}

static const char *rename_a = NULL, *rename_b = NULL;
static int set_up_calls = 0;

/* Between the check and the set, a is renamed away and b takes its name */
static int renaming_set_up(int ifindex) {
    char cmd[256];

    set_up_calls++;
    snprintf(cmd, sizeof(cmd), "ip link set %s name wtestr && ip link set %s name %s",
            rename_a, rename_b, rename_a);

    if (system(cmd) != 0) {
        errno = EIO;
        return -1;
    }

    return wired_set_up(ifindex);
}

static int counting_set_up(int ifindex) {
    (void) ifindex;
    set_up_calls++;
    errno = EPERM;
    return -1;
}

/* The index checked is the one set up, whatever holds the name by then */
static void test_rename(const char *a, const char *b) {
    const wired_ifupd_ops_t ops = { WIRED_SYSFS_NET, wired_nl_getlink, renaming_set_up };
    char cmd[256];
    int err = 0, st;

    rename_a = a;
    rename_b = b;
    set_up_calls = 0;
    st = answer_with(&ops, a, &err);
    CHECK(st == WIRED_IFUP_FAILED && err == ESTALE && set_up_calls == 1,
            "renamed between check and set: %d %d", st, err);
    CHECK(wired_nl_read_up("wtestr") == 1, "the checked link came up");
    CHECK(wired_nl_read_up(a) == 0, "the link now named %s stayed down", a);

    snprintf(cmd, sizeof(cmd), "ip link set wtestr down && ip link set %s name %s && "
            "ip link set wtestr name %s", a, b, a);
    CHECK(system(cmd) == 0, "names put back");
    CHECK(wired_nl_read_up(a) == 0 && wired_nl_read_up(b) == 0, "both down again");
}

/* Foreign only when the namespace's owner is outside this user namespace: here
 * it's this one's, and from a new user namespace it's the parent's */
static void test_foreign(void) {
    pid_t pid;
    int st = 0;

    CHECK(wired_netns_foreign() == 0, "the network namespace is this user namespace's");

    if ((pid = fork()) == 0) {
        if (unshare(CLONE_NEWUSER) < 0)
            _exit(77);

        _exit(wired_netns_foreign() == 1 ? 0 : 1);
    }

    CHECK(pid > 0 && waitpid(pid, &st, 0) == pid && WIFEXITED(st), "foreign child");

    if (WEXITSTATUS(st) == 77)
        printf("foreign check skipped: no nested user namespace\n");
    else
        CHECK(WEXITSTATUS(st) == 0, "foreign from a new user namespace");
}

/* Run with this network namespace's links but the host's /sys: nothing is
 * classified by a /sys which isn't this namespace's */
static int host_sysfs_main(const char *a) {
    const wired_ifupd_ops_t ops = { WIRED_SYSFS_NET, wired_nl_getlink, counting_set_up };
    wired_nl_link_t link;
    char path[128];
    int err = 0, st;

    if (if_flags(a) >= 0 || wired_nl_getlink(a, 0, &link) < 0) {
        printf("skip: run it in a network namespace of its own holding %s, with the host's "
                "/sys\n", a);
        return 77;
    }

    set_up_calls = 0;
    st = answer_with(&ops, a, &err);
    CHECK(st == WIRED_IFUP_FAILED && err == EXDEV && set_up_calls == 0,
            "another namespace's /sys refused: %d %d", st, err);
    st = answer_with(&ops, "lo", &err);
    CHECK(st == WIRED_IFUP_FAILED && err == EOPNOTSUPP && set_up_calls == 0, "lo by netlink");
    st = answer_with(&ops, "nosuch0", &err);
    CHECK(st == WIRED_IFUP_FAILED && err == ENODEV && set_up_calls == 0, "missing by netlink");
    snprintf(path, sizeof(path), "/sys/class/net/%s", a);
    CHECK(access(path, F_OK) < 0 && wired_nl_read_up(a) == 0,
            "netlink sees %s down where /sys doesn't see it", a);

    printf("%s: %d checks, %d failed\n", failures ? "FAIL" : "ok", checks, failures);
    return failures != 0;
}

/* A raw request, answered with the reply's status, or -1 */
static int raw_request(int fd, const void *req, size_t len, uint32_t seq, int *err) {
    uint8_t buf[sizeof(wired_ifup_reply_t) + 8];
    wired_ifup_status_t st;
    ssize_t r;

    if (send(fd, req, len, MSG_NOSIGNAL) != (ssize_t) len)
        return -1;

    if ((r = recv(fd, buf, sizeof(buf), 0)) < 0)
        return -1;

    return wired_ifup_reply_parse(buf, (size_t) r, seq, &st, err) == 1 ? (int) st : -1;
}

static void test_hostile(wired_ifupd_t *d) {
    wired_ifup_req_t req;
    uint8_t big[sizeof(req) * 4];
    int err = 0;

    wired_ifup_req_build("wtest0", 900, &req);
    CHECK(raw_request(d->fd, &req, sizeof(req) - 1, 0, &err) == WIRED_IFUP_FAILED &&
            err == EINVAL, "short request: %d", err);

    memset(big, 0, sizeof(big));
    memcpy(big, &req, sizeof(req));
    CHECK(raw_request(d->fd, big, sizeof(big), 0, &err) == WIRED_IFUP_FAILED && err == EINVAL,
            "long request: %d", err);

    memset(req.ifname, 'a', sizeof(req.ifname));
    CHECK(raw_request(d->fd, &req, sizeof(req), 900, &err) == WIRED_IFUP_FAILED &&
            err == EINVAL, "name without NUL: %d", err);

    wired_ifup_req_build("wtest0", 901, &req);
    req.ifname[sizeof(req.ifname) - 1] = 'x';
    CHECK(raw_request(d->fd, &req, sizeof(req), 901, &err) == WIRED_IFUP_FAILED &&
            err == EINVAL, "bytes after the NUL: %d", err);

    wired_ifup_req_build("wtest0", 902, &req);
    req.magic ^= 1;
    CHECK(raw_request(d->fd, &req, sizeof(req), 0, &err) == WIRED_IFUP_FAILED && err == EINVAL,
            "bad magic: %d", err);

    wired_ifup_req_build("wtest0", 903, &req);
    memcpy(req.ifname, "../wtest0", 10);
    CHECK(raw_request(d->fd, &req, sizeof(req), 903, &err) == WIRED_IFUP_FAILED &&
            err == EINVAL, "path name: %d", err);

    /* A stale answer queued ahead of the next request's */
    wired_ifup_req_build("lo", 904, &req);
    CHECK(send(d->fd, &req, sizeof(req), MSG_NOSIGNAL) == (ssize_t) sizeof(req), "stale send");
}

static void test_parent_death(void) {
    wired_ifupd_t d;
    int p[2], st;
    pid_t mid, child = -1;

    CHECK(pipe(p) == 0, "pipe");

    if ((mid = fork()) == 0) {
        memset(&d, 0, sizeof(d));
        d.fd = -1;

        if (wired_ifupd_spawn(&d) < 0)
            _exit(1);

        if (write(p[1], &d.pid, sizeof(d.pid)) != (ssize_t) sizeof(d.pid))
            _exit(1);

        /* The socket stays open: only the parent's death can end the child */
        pause();
        _exit(0);
    }

    close(p[1]);
    CHECK(mid > 0 && read(p[0], &child, sizeof(child)) == (ssize_t) sizeof(child),
            "middle process");
    close(p[0]);

    if (mid <= 0 || child <= 0)
        return;

    /* Running, with its sets cut */
    for (st = 0; st < 100 && status_field(child, "CapPrm:", 16) != 1LL << CAP_NET_ADMIN; st++)
        usleep(10000);

    CHECK(status_field(child, "CapPrm:", 16) == 1LL << CAP_NET_ADMIN, "child running");
    kill(mid, SIGKILL);
    waitpid(mid, &st, 0);
    CHECK(gone_within(child, 2000), "child gone with its parent");
}

/* A stopped child: the request times out with the socket kept, nothing more is
 * sent while it's busy, and once it runs again its late answer comes in and the
 * next request goes through.  a is up by now */
static void test_stopped_child(wired_ifupd_t *d, const char *a) {
    int err = 0, st, i;

    d->timeout_ms = 300;
    CHECK(kill(d->pid, SIGSTOP) == 0, "stop the child");
    st = wired_ifupd_request(d, "nosuch1", &err);
    CHECK(st < 0 && err == ETIMEDOUT && d->busy && d->fd >= 0 && d->state == WIRED_IFUPD_RUNNING,
            "stopped child times out: %d %d", st, err);
    st = wired_ifupd_request(d, a, &err);
    CHECK(st < 0 && err == EBUSY, "busy while stopped: %d %d", st, err);
    CHECK(kill(d->pid, SIGCONT) == 0, "continue the child");

    for (i = 0; i < 300 && d->busy; i++) {
        usleep(10 * 1000);
        wired_ifupd_collect(d);
    }

    CHECK(!d->busy && d->fd >= 0, "late answer collected");
    d->timeout_ms = WIRED_IFUPD_TIMEOUT_MS;
    st = wired_ifupd_request(d, a, &err);
    CHECK(st == WIRED_IFUP_ALREADY, "recovered: %d %d", st, err);
}

int main(int argc, char *argv[]) {
    const char *a, *b;
    const long long admin = 1LL << CAP_NET_ADMIN;
    wired_ifupd_t d;
    long before, after;
    int err = 0, st;

    if (argc == 3 && strcmp(argv[1], "--host-sysfs") == 0)
        return host_sysfs_main(argv[2]);

    if (argc < 3) {
        printf("usage: ifup_test <down if> <down if> | --host-sysfs <down if>\n");
        return 2;
    }

    a = argv[1];
    b = argv[2];

    if (if_flags("eth0") >= 0 || if_flags(a) < 0 || if_flags(b) < 0) {
        printf("skip: run it in a network namespace of its own holding %s and %s\n", a, b);
        return 77;
    }

    test_foreign();
    CHECK(wired_nl_read_up(a) == 0, "%s starts down", a);
    CHECK(wired_nl_read_up(b) == 0, "%s starts down", b);

    memset(&d, 0, sizeof(d));
    d.fd = -1;
    CHECK(wired_ifupd_spawn(&d) == 1 && d.fd >= 0 && d.pid > 0, "spawn: %s", strerror(errno));

    if (d.fd < 0)
        goto out;

    /* Let it reach its loop before its sets are read */
    st = wired_ifupd_request(&d, "nosuch0", &err);
    CHECK(st == WIRED_IFUP_FAILED && err == ENODEV, "missing interface: %d %d", st, err);

    CHECK(status_field(d.pid, "CapEff:", 16) == admin, "child CapEff %llx",
            status_field(d.pid, "CapEff:", 16));
    CHECK(status_field(d.pid, "CapPrm:", 16) == admin, "child CapPrm %llx",
            status_field(d.pid, "CapPrm:", 16));
    CHECK(status_field(d.pid, "CapInh:", 16) == 0, "child CapInh");
    CHECK(status_field(d.pid, "CapAmb:", 16) == 0, "child CapAmb");
    CHECK(status_field(d.pid, "NoNewPrivs:", 10) == 1, "child no_new_privs");
    CHECK(fd_count(d.pid) == 4, "child has its socket and stdio on /dev/null: %d", fd_count(d.pid));

    /* While this process still holds CAP_NET_ADMIN to hand on, and to rename */
    test_parent_death();
    test_rename(a, b);

    CHECK(wired_ifupd_drop_admin() == 1, "drop CAP_NET_ADMIN here");
    CHECK((status_field(getpid(), "CapEff:", 16) & admin) == 0 &&
            (status_field(getpid(), "CapPrm:", 16) & admin) == 0 &&
            (status_field(getpid(), "CapAmb:", 16) & admin) == 0, "no CAP_NET_ADMIN here");
    errno = 0;
    CHECK(wired_set_up((int) if_nametoindex(b)) < 0 && errno == EPERM, "%s refused here: %s", b,
            strerror(errno));
    CHECK(wired_nl_read_up(b) == 0, "%s still down", b);

    before = if_flags(a);
    st = wired_ifupd_request(&d, a, &err);
    after = if_flags(a);
    CHECK(st == WIRED_IFUP_DONE, "bring %s up: %d %s", a, st, strerror(err));
    CHECK(wired_nl_read_up(a) == 1, "%s up", a);
    CHECK((after & ~0x1L) == (before & ~0x1L) && !(after & 0x100), "only IFF_UP changed: %lx -> %lx",
            before, after);
    CHECK(wired_ifupd_request(&d, a, &err) == WIRED_IFUP_ALREADY && if_flags(a) == after,
            "up again changes nothing");

    st = wired_ifupd_request(&d, "lo", &err);
    CHECK(st == WIRED_IFUP_FAILED && err == EOPNOTSUPP, "loopback refused: %d %d", st, err);
    CHECK(wired_ifupd_request(&d, "../x", &err) < 0 && err == EINVAL, "bad name never sent");

    test_stopped_child(&d, a);
    test_hostile(&d);

    /* After every failure above, a retry still works */
    st = wired_ifupd_request(&d, b, &err);
    CHECK(st == WIRED_IFUP_DONE && wired_nl_read_up(b) == 1, "bring %s up: %d %s",
            b, st, strerror(err));

    close(d.fd);
    CHECK(gone_within(d.pid, 2000), "child exits at EOF");

out:
    printf("%s: %d checks, %d failed\n", failures ? "FAIL" : "ok", checks, failures);
    return failures != 0;
}
