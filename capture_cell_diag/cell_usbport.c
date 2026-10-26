/* cell_usbport.c - a modem's serial interface over libusb, as a plain fd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * See cell_usbport.h. Parsing is always built; the bridge only with
 * HAVE_CELL_USBSERIAL.
 */
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "cell_usbport.h"

int cell_usbport_mode_parse(const char *v) {
    if (v == NULL)
        return -1;
    if (strcasecmp(v, "auto") == 0)
        return CELL_USB_AUTO;
    if (strcasecmp(v, "force") == 0 || strcasecmp(v, "yes") == 0 ||
        strcasecmp(v, "true") == 0)
        return CELL_USB_FORCE;
    if (strcasecmp(v, "off") == 0 || strcasecmp(v, "no") == 0 ||
        strcasecmp(v, "false") == 0)
        return CELL_USB_OFF;
    return -1;
}

/* One decimal field, digits only, in [lo, hi]; *pp is left past it */
static int parse_field(const char **pp, long lo, long hi, long *out) {
    const char *p = *pp;
    long v = 0;
    int n = 0;

    while (isdigit((unsigned char)*p) && n < 4) {
        v = v * 10 + (*p - '0');
        p++;
        n++;
    }

    if (n == 0 || isdigit((unsigned char)*p) || v < lo || v > hi)
        return -1;

    *out = v;
    *pp = p;
    return 0;
}

int cell_usbport_parse(const char *spec, int *bus, int *addr, int *ifnum) {
    const char *p;
    long b, a, i;

    if (!cell_usbport_is_spec(spec))
        return -1;

    p = spec + strlen(CELL_USBPORT_PREFIX);

    if (parse_field(&p, 1, 255, &b) != 0 || *p++ != '-')
        return -1;
    if (parse_field(&p, 1, 127, &a) != 0 || *p++ != ':')
        return -1;
    if (parse_field(&p, 0, 31, &i) != 0 || *p != '\0')
        return -1;

    if (bus) *bus = (int)b;
    if (addr) *addr = (int)a;
    if (ifnum) *ifnum = (int)i;
    return 0;
}

#ifdef HAVE_CELL_USBSERIAL

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../usbserial/usbserial.h"

/* Modem data waiting for the helper to read it. A reader this far behind loses
 * the newest data, counted and reported. */
#define USBPORT_RING      (1024 * 1024)
#define USBPORT_IO        16384
#define USBPORT_SOCKBUF   (256 * 1024)
/* How long a close waits for the last write (a DIAG log-mask stop) to reach
 * the modem, and how long an open waits for this process's previous holder of
 * the interface to let go */
#define USBPORT_FLUSH_MS  1000
#define USBPORT_REOPEN_MS 3000

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

typedef struct usbport_bridge {
    struct usbport_bridge *next;

    char spec[CELL_USBPORT_SPEC_MAX];
    int bus, addr, ifnum;
    int closing;

    int bfd;
    int wake[2];

    usbserial_dev_t *dev;
    usbserial_port_t *port;

    pthread_mutex_t lock;
    uint8_t *ring;
    size_t head;
    size_t len;
    unsigned long long dropped;
    unsigned long long reported;
    int failed;
    char reason[128];
} usbport_bridge_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
static usbport_bridge_t *g_bridges;
static cell_usb_mode_t g_mode = CELL_USB_AUTO;

static cell_usbport_info_t g_cache[CELL_USBPORT_MAX];
static int g_ncache;
static int g_cached;

void cell_usbport_set_mode(cell_usb_mode_t mode) {
    pthread_mutex_lock(&g_lock);
    g_mode = mode;
    pthread_mutex_unlock(&g_lock);
}

cell_usb_mode_t cell_usbport_mode(void) {
    cell_usb_mode_t m;
    pthread_mutex_lock(&g_lock);
    m = g_mode;
    pthread_mutex_unlock(&g_lock);
    return m;
}

static void enum_cb(const usbserial_portinfo_t *pi, void *aux) {
    cell_usbport_info_t *c;
    (void)aux;

    if (g_ncache >= CELL_USBPORT_MAX || pi->ifnum > 31)
        return;

    c = &g_cache[g_ncache++];
    memset(c, 0, sizeof(*c));
    snprintf(c->spec, sizeof(c->spec), "usb:%u-%u:%u", pi->bus, pi->addr, pi->ifnum);
    snprintf(c->dev, sizeof(c->dev), "usb:%u-%u", pi->bus, pi->addr);
    snprintf(c->model, sizeof(c->model), "%s", pi->model ? pi->model : "");
    snprintf(c->role, sizeof(c->role), "%s", pi->role ? pi->role : "");
    c->ifnum = pi->ifnum;
    c->cls = pi->cls;
    c->sub = pi->sub;
    c->prot = pi->prot;
    c->driver = pi->driver;
}

/* g_lock held */
static void enumerate_locked(void) {
    g_ncache = 0;
    if (usbserial_enum(enum_cb, NULL) < 0)
        g_ncache = 0;
    g_cached = 1;
}

/* g_lock held; an interface the helper may claim in this mode */
static int admitted_locked(const cell_usbport_info_t *c) {
    if (g_mode == CELL_USB_OFF)
        return 0;
    if (g_mode == CELL_USB_FORCE)
        return 1;
    return c->driver == 0;
}

int cell_usbport_scan(cell_usbport_info_t *out, int max) {
    int n = 0;

    pthread_mutex_lock(&g_lock);
    if (g_mode == CELL_USB_OFF) {
        pthread_mutex_unlock(&g_lock);
        return 0;
    }
    enumerate_locked();
    for (int i = 0; i < g_ncache && n < max; i++) {
        if (admitted_locked(&g_cache[i]))
            out[n++] = g_cache[i];
    }
    pthread_mutex_unlock(&g_lock);

    return n;
}

int cell_usbport_info(const char *spec, cell_usbport_info_t *out) {
    int found = 0;

    pthread_mutex_lock(&g_lock);
    for (int pass = 0; pass < 2 && !found; pass++) {
        if (pass == 1 || !g_cached)
            enumerate_locked();
        for (int i = 0; i < g_ncache; i++) {
            if (strcmp(g_cache[i].spec, spec) == 0) {
                if (out)
                    *out = g_cache[i];
                found = 1;
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_lock);

    return found;
}

int cell_usbport_siblings(const char *dev, cell_usbport_info_t *out, int max) {
    int n = 0;

    pthread_mutex_lock(&g_lock);
    if (!g_cached)
        enumerate_locked();
    for (int i = 0; i < g_ncache && n < max; i++) {
        if (strcmp(g_cache[i].dev, dev) == 0)
            out[n++] = g_cache[i];
    }
    pthread_mutex_unlock(&g_lock);

    return n;
}

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void bridge_wake(usbport_bridge_t *b) {
    char c = 0;
    if (write(b->wake[1], &c, 1) < 0) {
        /* full: a wakeup is already pending */
    }
}

/* usbserial's event thread */
static void bridge_rx(usbserial_port_t *port, const uint8_t *data, size_t len,
                      void *aux) {
    usbport_bridge_t *b = (usbport_bridge_t *)aux;
    size_t space, tail, first;
    (void)port;

    pthread_mutex_lock(&b->lock);
    space = USBPORT_RING - b->len;
    if (len > space) {
        b->dropped += len - space;
        len = space;
    }
    tail = (b->head + b->len) % USBPORT_RING;
    first = USBPORT_RING - tail;
    if (first > len)
        first = len;
    memcpy(b->ring + tail, data, first);
    memcpy(b->ring, data + first, len - first);
    b->len += len;
    pthread_mutex_unlock(&b->lock);

    bridge_wake(b);
}

/* usbserial's event thread, once */
static void bridge_err(usbserial_dev_t *dev, const char *reason, void *aux) {
    usbport_bridge_t *b = (usbport_bridge_t *)aux;
    (void)dev;

    pthread_mutex_lock(&b->lock);
    b->failed = 1;
    snprintf(b->reason, sizeof(b->reason), "%s", reason ? reason : "stopped");
    pthread_mutex_unlock(&b->lock);

    bridge_wake(b);
}

/* Modem data to the helper's socket; 1 if some is still waiting */
static int bridge_flush(usbport_bridge_t *b) {
    int pending;

    pthread_mutex_lock(&b->lock);
    while (b->len > 0) {
        size_t chunk = USBPORT_RING - b->head;
        ssize_t w;

        if (chunk > b->len)
            chunk = b->len;
        w = send(b->bfd, b->ring + b->head, chunk, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w <= 0)
            break;
        b->head = (b->head + (size_t)w) % USBPORT_RING;
        b->len -= (size_t)w;
    }
    pending = b->len > 0;

    if (b->dropped != b->reported) {
        fprintf(stderr, "cell usb port %s: reader is behind, dropped %llu bytes "
                "so far\n", b->spec, b->dropped);
        b->reported = b->dropped;
    }
    pthread_mutex_unlock(&b->lock);

    return pending;
}

static void bridge_free(usbport_bridge_t *b) {
    if (b->bfd >= 0)
        close(b->bfd);
    if (b->wake[0] >= 0)
        close(b->wake[0]);
    if (b->wake[1] >= 0)
        close(b->wake[1]);
    free(b->ring);
    pthread_mutex_destroy(&b->lock);
    free(b);
}

/* g_lock held */
static void registry_remove_locked(usbport_bridge_t *b) {
    usbport_bridge_t **pp;

    for (pp = &g_bridges; *pp != NULL; pp = &(*pp)->next) {
        if (*pp == b) {
            *pp = b->next;
            break;
        }
    }
    pthread_cond_broadcast(&g_cond);
}

static void *bridge_thread(void *arg) {
    usbport_bridge_t *b = (usbport_bridge_t *)arg;
    uint8_t buf[USBPORT_IO];
    int user_closed = 0;
    sigset_t ss;

    sigemptyset(&ss);
    sigaddset(&ss, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &ss, NULL);

    while (1) {
        struct pollfd pfd[2];
        int failed;

        pthread_mutex_lock(&b->lock);
        failed = b->failed;
        pthread_mutex_unlock(&b->lock);
        if (failed)
            break;

        pfd[0].fd = b->bfd;
        pfd[0].events = 0;
        pfd[0].revents = 0;
        /* Read from the helper only when the modem side can take a whole read,
         * so nothing read is ever dropped */
        if (usbserial_tx_space(b->port) >= sizeof(buf))
            pfd[0].events |= POLLIN;
        if (bridge_flush(b))
            pfd[0].events |= POLLOUT;
        pfd[1].fd = b->wake[0];
        pfd[1].events = POLLIN;
        pfd[1].revents = 0;

        if (poll(pfd, 2, 1000) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (pfd[1].revents & POLLIN) {
            while (read(b->wake[0], buf, sizeof(buf)) > 0)
                ;
        }

        if (pfd[0].revents & POLLIN) {
            ssize_t r = recv(b->bfd, buf, sizeof(buf), MSG_DONTWAIT);
            if (r == 0) {
                user_closed = 1;
                break;
            }
            if (r > 0 && usbserial_write(b->port, buf, (size_t)r) < 0)
                continue;   /* failed; the top of the loop sees it */
        } else if (pfd[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
            user_closed = 1;
            break;
        }
    }

    pthread_mutex_lock(&g_lock);
    b->closing = 1;
    pthread_mutex_unlock(&g_lock);

    if (user_closed) {
        /* The helper's last write may still be queued: let it reach the modem */
        uint64_t t0 = mono_ms();
        while (mono_ms() - t0 < USBPORT_FLUSH_MS) {
            int failed;
            pthread_mutex_lock(&b->lock);
            failed = b->failed;
            pthread_mutex_unlock(&b->lock);
            if (failed || usbserial_tx_space(b->port) == USBSERIAL_TXQ_SIZE)
                break;
            usleep(10 * 1000);
        }
        usbserial_close(b->dev);
    } else {
        usbserial_close(b->dev);

        pthread_mutex_lock(&b->lock);
        fprintf(stderr, "cell usb port %s: %s\n", b->spec,
                b->reason[0] ? b->reason : "stopped");
        pthread_mutex_unlock(&b->lock);

        /* The helper sees EOF, and its writes still land (and are discarded)
         * until it closes, so nothing it does raises SIGPIPE */
        shutdown(b->bfd, SHUT_WR);
        while (1) {
            struct pollfd pfd = { b->bfd, POLLIN, 0 };
            ssize_t r;
            if (poll(&pfd, 1, 1000) < 0 && errno != EINTR)
                break;
            if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)))
                continue;
            r = recv(b->bfd, buf, sizeof(buf), MSG_DONTWAIT);
            if (r == 0 || (r < 0 && errno != EAGAIN && errno != EINTR))
                break;
        }
    }

    pthread_mutex_lock(&g_lock);
    registry_remove_locked(b);
    pthread_mutex_unlock(&g_lock);

    bridge_free(b);
    return NULL;
}

/* g_lock held. Whether this process's holder of the interface has closed its
 * fd: its bridge sees the hangup at once, its thread may not have yet. */
static int holder_gone_locked(const usbport_bridge_t *b) {
    struct pollfd pfd = { b->bfd, 0, 0 };

    if (b->closing)
        return 1;
    if (poll(&pfd, 1, 0) > 0 && (pfd.revents & (POLLHUP | POLLERR)))
        return 1;
    return 0;
}

static usbport_bridge_t *find_locked(int bus, int addr, int ifnum) {
    for (usbport_bridge_t *b = g_bridges; b != NULL; b = b->next) {
        if (b->bus == bus && b->addr == addr && b->ifnum == ifnum)
            return b;
    }
    return NULL;
}

static void set_cloexec(int fd) {
    int fl = fcntl(fd, F_GETFD);
    if (fl >= 0)
        fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
}

int cell_usbport_open(const char *spec) {
    int bus, addr, ifnum;
    int sv[2] = { -1, -1 };
    usbport_bridge_t *b, *held;
    cell_usb_mode_t mode;
    char err[256];
    pthread_attr_t attr;
    pthread_t th;
    int sz = USBPORT_SOCKBUF;
    int e;

    err[0] = '\0';

    if (cell_usbport_parse(spec, &bus, &addr, &ifnum) != 0) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&g_lock);
    mode = g_mode;
    if (mode == CELL_USB_OFF) {
        pthread_mutex_unlock(&g_lock);
        errno = EPERM;
        return -1;
    }

    /* One holder per interface per process, as one flock per port */
    held = find_locked(bus, addr, ifnum);
    if (held != NULL && holder_gone_locked(held)) {
        struct timespec until;
        struct timeval now;
        gettimeofday(&now, NULL);
        until.tv_sec = now.tv_sec + USBPORT_REOPEN_MS / 1000;
        until.tv_nsec = (long)now.tv_usec * 1000 + (USBPORT_REOPEN_MS % 1000) * 1000000L;
        if (until.tv_nsec >= 1000000000L) {
            until.tv_sec++;
            until.tv_nsec -= 1000000000L;
        }
        while ((held = find_locked(bus, addr, ifnum)) != NULL) {
            if (pthread_cond_timedwait(&g_cond, &g_lock, &until) == ETIMEDOUT)
                break;
        }
    }
    if (find_locked(bus, addr, ifnum) != NULL) {
        pthread_mutex_unlock(&g_lock);
        errno = EWOULDBLOCK;
        return -1;
    }

    if ((b = (usbport_bridge_t *)calloc(1, sizeof(*b))) == NULL) {
        pthread_mutex_unlock(&g_lock);
        errno = ENOMEM;
        return -1;
    }
    snprintf(b->spec, sizeof(b->spec), "%s", spec);
    b->bus = bus;
    b->addr = addr;
    b->ifnum = ifnum;
    b->bfd = b->wake[0] = b->wake[1] = -1;
    pthread_mutex_init(&b->lock, NULL);

    /* Listed before the claim, so a second open in this process waits for this
     * one rather than racing it to the interface */
    b->next = g_bridges;
    g_bridges = b;
    pthread_mutex_unlock(&g_lock);

    b->dev = usbserial_open_ports(0, 0, bus, addr, 1u << ifnum,
                                  mode == CELL_USB_FORCE ? USBSERIAL_DETACH : 0,
                                  err, sizeof(err));
    if (b->dev == NULL) {
        e = errno;
        if (e == EAGAIN)
            e = EWOULDBLOCK;
        goto fail;
    }
    if (usbserial_num_ports(b->dev) != 1 ||
        (b->port = usbserial_get_port(b->dev, 0)) == NULL) {
        e = ENODEV;
        goto fail;
    }

    if ((b->ring = (uint8_t *)malloc(USBPORT_RING)) == NULL) {
        e = ENOMEM;
        goto fail;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        sv[0] = sv[1] = -1;
        e = errno;
        goto fail;
    }
    b->bfd = sv[1];
    if (pipe(b->wake) != 0) {
        b->wake[0] = b->wake[1] = -1;
        e = errno;
        goto fail;
    }
    set_cloexec(sv[0]);
    set_cloexec(sv[1]);
    set_cloexec(b->wake[0]);
    set_cloexec(b->wake[1]);
    fcntl(b->wake[0], F_SETFL, fcntl(b->wake[0], F_GETFL, 0) | O_NONBLOCK);
    fcntl(b->wake[1], F_SETFL, fcntl(b->wake[1], F_GETFL, 0) | O_NONBLOCK);
    setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
#ifdef SO_NOSIGPIPE
    {
        int one = 1;
        setsockopt(sv[0], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        setsockopt(sv[1], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    }
#endif

    if (usbserial_start(b->dev, bridge_rx, bridge_err, b, err, sizeof(err)) != 0) {
        e = EIO;
        goto fail;
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    e = pthread_create(&th, &attr, bridge_thread, b);
    pthread_attr_destroy(&attr);
    if (e != 0)
        goto fail;

    return sv[0];

fail:
    if (b->dev != NULL)
        usbserial_close(b->dev);
    if (sv[0] >= 0)
        close(sv[0]);
    /* A claim another process holds is the scan's ordinary "busy" */
    if (err[0] && e != EWOULDBLOCK)
        fprintf(stderr, "cell usb port %s: %s\n", spec, err);
    pthread_mutex_lock(&g_lock);
    registry_remove_locked(b);
    pthread_mutex_unlock(&g_lock);
    bridge_free(b);
    errno = e;
    return -1;
}

#endif
