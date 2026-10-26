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

/* Serves the serial ports of a USB modem that has no host driver (such as a
 * Quectel modem on macOS) as pseudo-terminals, so ordinary serial tools and the
 * Kismet capture tools can open them like any tty. */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#ifdef __APPLE__
#include <util.h>
#elif defined(__linux__)
#include <pty.h>
#else
#include <libutil.h>
#endif

#include "usbserial.h"

/* Data from the device waiting for the tty reader; when the reader falls this far
 * behind, newer data is dropped and counted */
#define PTY_BUF_SIZE    (1024 * 1024)

typedef struct {
    usbserial_port_t *port;

    int master;
    int slave;
    char tty[PATH_MAX];
    char link[PATH_MAX];

    pthread_mutex_t lock;
    uint8_t *buf;
    size_t head;
    size_t len;
    unsigned long long dropped;
    unsigned long long reported_dropped;
} bridge_port_t;

static bridge_port_t bports[USBSERIAL_MAX_PORTS];
static size_t num_bports;

static int wake_pipe[2] = { -1, -1 };
static volatile sig_atomic_t quit;
static volatile sig_atomic_t device_failed;
static char fail_reason[256];
static int verbose;

static void handle_signal(int sig) {
    (void) sig;
    quit = 1;
}

static void wake(void) {
    char c = 0;

    if (write(wake_pipe[1], &c, 1) < 0) {
        /* Full means a wakeup is already pending */
    }
}

static void rx_cb(usbserial_port_t *port, const uint8_t *data, size_t len, void *aux) {
    bridge_port_t *bp = NULL;
    size_t i, space, tail, first;

    (void) aux;

    for (i = 0; i < num_bports; i++) {
        if (bports[i].port == port) {
            bp = &bports[i];
            break;
        }
    }

    if (bp == NULL)
        return;

    pthread_mutex_lock(&bp->lock);

    space = PTY_BUF_SIZE - bp->len;
    if (len > space) {
        bp->dropped += len - space;
        len = space;
    }

    tail = (bp->head + bp->len) % PTY_BUF_SIZE;
    first = PTY_BUF_SIZE - tail;
    if (first > len)
        first = len;

    memcpy(bp->buf + tail, data, first);
    memcpy(bp->buf, data + first, len - first);
    bp->len += len;

    pthread_mutex_unlock(&bp->lock);

    wake();
}

static void err_cb(usbserial_dev_t *dev, const char *reason, void *aux) {
    (void) dev;
    (void) aux;

    snprintf(fail_reason, sizeof(fail_reason), "%s", reason);
    device_failed = 1;
    wake();
}

/* Send buffered device data to the tty; returns 1 if some is still waiting */
static int flush_to_pty(bridge_port_t *bp) {
    int pending;

    pthread_mutex_lock(&bp->lock);

    while (bp->len > 0) {
        size_t chunk = PTY_BUF_SIZE - bp->head;
        ssize_t w;

        if (chunk > bp->len)
            chunk = bp->len;

        w = write(bp->master, bp->buf + bp->head, chunk);

        if (w <= 0)
            break;

        bp->head = (bp->head + (size_t) w) % PTY_BUF_SIZE;
        bp->len -= (size_t) w;
    }

    pending = bp->len > 0;

    if (bp->dropped != bp->reported_dropped) {
        fprintf(stderr, "%s: reader is behind, dropped %llu bytes so far\n",
                usbserial_port_role(bp->port), bp->dropped);
        bp->reported_dropped = bp->dropped;
    }

    pthread_mutex_unlock(&bp->lock);

    return pending;
}

static int open_pty(bridge_port_t *bp) {
    struct termios tio;

    if (openpty(&bp->master, &bp->slave, bp->tty, NULL, NULL) < 0)
        return -1;

    /* Raw, so the line discipline doesn't echo, translate line endings or eat
     * DIAG's binary framing before a client sets its own mode */
    if (tcgetattr(bp->slave, &tio) == 0) {
        cfmakeraw(&tio);
        tcsetattr(bp->slave, TCSANOW, &tio);
    }

    fchmod(bp->slave, 0600);

    fcntl(bp->master, F_SETFL, fcntl(bp->master, F_GETFL, 0) | O_NONBLOCK);
    fcntl(bp->master, F_SETFD, FD_CLOEXEC);
    fcntl(bp->slave, F_SETFD, FD_CLOEXEC);

    /* The bridge keeps the slave open too, so the master doesn't see a hangup each
     * time a client closes the port */
    return 0;
}

/* Replace only a symlink that's already there; never a file */
static int make_link(bridge_port_t *bp, const char *dir, const char *prefix) {
    struct stat st;
    int n;

    n = snprintf(bp->link, sizeof(bp->link), "%s/%s-%s", dir, prefix,
            usbserial_port_role(bp->port));

    if (n < 0 || (size_t) n >= sizeof(bp->link)) {
        bp->link[0] = 0;
        fprintf(stderr, "link path for %s is too long\n", usbserial_port_role(bp->port));
        return -1;
    }

    if (lstat(bp->link, &st) == 0) {
        if (!S_ISLNK(st.st_mode)) {
            fprintf(stderr, "not replacing %s, which isn't a symlink\n", bp->link);
            bp->link[0] = 0;
            return -1;
        }

        unlink(bp->link);
    }

    if (symlink(bp->tty, bp->link) < 0) {
        fprintf(stderr, "could not link %s: %s\n", bp->link, strerror(errno));
        bp->link[0] = 0;
        return -1;
    }

    return 0;
}

/* Remove our link, if it still points at our tty */
static void remove_link(bridge_port_t *bp) {
    char target[PATH_MAX];
    ssize_t n;

    if (bp->link[0] == 0)
        return;

    n = readlink(bp->link, target, sizeof(target) - 1);

    if (n > 0) {
        target[n] = 0;
        if (strcmp(target, bp->tty) == 0)
            unlink(bp->link);
    }
}

static int parse_hex16(const char *s, uint16_t *out) {
    char *end;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 16);

    if (errno != 0 || end == s || *end != 0 || v > 0xffff)
        return -1;

    *out = (uint16_t) v;
    return 0;
}

static int parse_u8(const char *s, int *out) {
    char *end;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 10);

    if (errno != 0 || end == s || *end != 0 || v > 255)
        return -1;

    *out = (int) v;
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "Serve a USB modem's serial ports as pseudo-terminals.\n\n"
            " --list                 list supported devices that are attached\n"
            " --device VID:PID       the device to open (default: first supported one)\n"
            " --usb BUS:ADDR         pick a device by USB bus and address\n"
            " --link-dir DIR         make links DIR/PREFIX-ROLE to each port's tty\n"
            " --link-prefix PREFIX   link name prefix (default: modem)\n"
            " --verbose              report traffic counts\n",
            argv0);
}

int main(int argc, char *argv[]) {
    static const struct option longopts[] = {
        { "list", no_argument, NULL, 'l' },
        { "device", required_argument, NULL, 'd' },
        { "usb", required_argument, NULL, 'u' },
        { "link-dir", required_argument, NULL, 'L' },
        { "link-prefix", required_argument, NULL, 'p' },
        { "verbose", no_argument, NULL, 'v' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };

    uint16_t vid = 0, pid = 0;
    int bus = -1, addr = -1;
    const char *link_dir = NULL;
    const char *link_prefix = "modem";
    usbserial_dev_t *dev;
    char err[512];
    struct sigaction sa;
    size_t i;
    int o, ret = 0;

    while ((o = getopt_long(argc, argv, "ld:u:L:p:vh", longopts, NULL)) != -1) {
        char *sep;

        switch (o) {
            case 'l':
                if (usbserial_list(stdout) == 0)
                    printf("no supported devices found\n");
                return 0;
            case 'd':
                if ((sep = strchr(optarg, ':')) == NULL) {
                    fprintf(stderr, "--device takes VID:PID in hex\n");
                    return 1;
                }
                *sep = 0;
                if (parse_hex16(optarg, &vid) < 0 || parse_hex16(sep + 1, &pid) < 0 ||
                        vid == 0) {
                    fprintf(stderr, "--device takes VID:PID in hex\n");
                    return 1;
                }
                if (usbserial_find_model(vid, pid) == NULL) {
                    fprintf(stderr, "%04x:%04x isn't a supported device\n", vid, pid);
                    return 1;
                }
                break;
            case 'u':
                if ((sep = strchr(optarg, ':')) == NULL) {
                    fprintf(stderr, "--usb takes BUS:ADDR\n");
                    return 1;
                }
                *sep = 0;
                if (parse_u8(optarg, &bus) < 0 || parse_u8(sep + 1, &addr) < 0) {
                    fprintf(stderr, "--usb takes BUS:ADDR\n");
                    return 1;
                }
                break;
            case 'L':
                link_dir = optarg;
                break;
            case 'p':
                if (strchr(optarg, '/') != NULL || optarg[0] == 0 || optarg[0] == '.') {
                    fprintf(stderr, "--link-prefix must be a plain name\n");
                    return 1;
                }
                link_prefix = optarg;
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                usage(argv[0]);
                return o == 'h' ? 0 : 1;
        }
    }

    if (pipe(wake_pipe) < 0) {
        fprintf(stderr, "could not create a pipe: %s\n", strerror(errno));
        return 1;
    }

    for (o = 0; o < 2; o++) {
        fcntl(wake_pipe[o], F_SETFL, fcntl(wake_pipe[o], F_GETFL, 0) | O_NONBLOCK);
        fcntl(wake_pipe[o], F_SETFD, FD_CLOEXEC);
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if ((dev = usbserial_open(vid, pid, bus, addr, err, sizeof(err))) == NULL) {
        fprintf(stderr, "%s\n", err);
        return 1;
    }

    for (i = 0; i < usbserial_num_ports(dev); i++) {
        bridge_port_t *bp = &bports[i];

        memset(bp, 0, sizeof(*bp));
        bp->port = usbserial_get_port(dev, i);
        bp->master = bp->slave = -1;
        pthread_mutex_init(&bp->lock, NULL);
        num_bports = i + 1;

        if ((bp->buf = (uint8_t *) malloc(PTY_BUF_SIZE)) == NULL || open_pty(bp) < 0) {
            fprintf(stderr, "could not create a pseudo-terminal: %s\n", strerror(errno));
            ret = 1;
            goto done;
        }
    }

    if (usbserial_start(dev, rx_cb, err_cb, NULL, err, sizeof(err)) < 0) {
        fprintf(stderr, "%s\n", err);
        ret = 1;
        goto done;
    }

    printf("%s\n", usbserial_model_name(dev));

    for (i = 0; i < num_bports; i++) {
        bridge_port_t *bp = &bports[i];

        if (link_dir != NULL)
            make_link(bp, link_dir, link_prefix);

        printf("  %-6s interface %u  %s%s%s\n", usbserial_port_role(bp->port),
                usbserial_port_ifnum(bp->port), bp->tty,
                bp->link[0] ? "  " : "", bp->link);
    }

    fflush(stdout);

    while (!quit && !device_failed) {
        struct pollfd pfd[USBSERIAL_MAX_PORTS + 1];
        uint8_t data[USBSERIAL_TX_XFER_SIZE];

        pfd[0].fd = wake_pipe[0];
        pfd[0].events = POLLIN;

        for (i = 0; i < num_bports; i++) {
            bridge_port_t *bp = &bports[i];

            pfd[i + 1].fd = bp->master;
            pfd[i + 1].events = 0;

            /* Only read from the tty when the device side can take a full read, so
             * nothing read is ever dropped */
            if (usbserial_tx_space(bp->port) >= sizeof(data))
                pfd[i + 1].events |= POLLIN;

            if (flush_to_pty(bp))
                pfd[i + 1].events |= POLLOUT;
        }

        if (poll(pfd, num_bports + 1, 1000) < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "poll failed: %s\n", strerror(errno));
            ret = 1;
            break;
        }

        if (pfd[0].revents & POLLIN) {
            while (read(wake_pipe[0], data, sizeof(data)) > 0)
                ;
        }

        for (i = 0; i < num_bports; i++) {
            bridge_port_t *bp = &bports[i];
            ssize_t r;

            if (!(pfd[i + 1].revents & POLLIN))
                continue;

            r = read(bp->master, data, sizeof(data));

            if (r > 0) {
                if (usbserial_write(bp->port, data, (size_t) r) < 0)
                    break;
                if (verbose)
                    fprintf(stderr, "%s: %zd bytes to the device\n",
                            usbserial_port_role(bp->port), r);
            }
        }
    }

    if (device_failed) {
        fprintf(stderr, "%s stopped: %s\n", usbserial_model_name(dev), fail_reason);
        ret = 1;
    }

done:
    usbserial_close(dev);

    for (i = 0; i < num_bports; i++) {
        bridge_port_t *bp = &bports[i];

        remove_link(bp);

        if (bp->master >= 0)
            close(bp->master);
        if (bp->slave >= 0)
            close(bp->slave);

        free(bp->buf);
        pthread_mutex_destroy(&bp->lock);
    }

    return ret;
}
