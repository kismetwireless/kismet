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

    Cell modem DIAG capture source for Kismet (Phase 1: diaggrok bridge).

    Passively taps a Qualcomm modem's DIAG port, applies a narrow DIAG log
    mask (LTE ML1 serving 0xB193 for M1), and pumps the raw HDLC byte stream to
    a Python bridge helper (tools/kismet_diag_decode.py from the decode-helper
    checkout, running under its .venv). The helper decodes each DIAG LOG_F
    record with diaggrok and emits cell_observation JSON lines, which this binary relays to Kismet via
    cf_send_json() exactly as capture_cell_at does. Every observation carries a
    prov block {"src":"diag","origin":"0xB193",...} so phy_cell can merge DIAG
    signal with AT identity on one tower without duplicates.

    The pipe boundary (raw HDLC bytes out, JSON lines in) is the Phase 2 seam:
    a pure-C decoder will replace the helper subprocess behind the same
    interface, one log code at a time.

    Addressing mirrors capture_cell_at: the source is celldiag-<15-digit IMEI>.
    The IMEI is resolved to a modem via an AT probe on a sibling serial port,
    then the DIAG interface (conventionally if00, the lowest USB interface on
    that modem's USB device) is opened for the tap.

    Source options:
      helper=<dir>       path to the checkout providing .venv + the helper
                         (default: $CELLDIAG_HELPER, else compiled-in default)
      diagport=<path>    explicit DIAG /dev/tty node (overrides auto-detect)
      replay=<file>      decode a raw-HDLC capture file instead of a live modem
                         (offline test hook; no modem opened, no mask sent)
      nomask=true        skip the LOG_CONFIG handshake (passive tap of whatever
                         a prior tool already enabled)
      debug=true|false   verbose message-bus logging
*/

#include "../config.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "../capture_framework.h"

#include "diag_capture.h"
#include "diag_config.h"

/* Compiled-in default helper checkout, overridable via helper= or $CELLDIAG_HELPER.
 * The helper needs <dir>/.venv/bin/python and <dir>/tools/kismet_diag_decode.py.
 * Empty default: set helper=/$CELLDIAG_HELPER at run time, or bake a local path
 * in with -DCELLDIAG_HELPER_DEFAULT='"/path/to/checkout"'. */
#ifndef CELLDIAG_HELPER_DEFAULT
#define CELLDIAG_HELPER_DEFAULT ""
#endif

/* One JSON cell_observation line from the helper. diaggrok observations are
 * small; 8 KiB is generous headroom. */
#define JSON_LINE_MAX       8192
#define ERRBUF_MAX          STATUS_MAX

/* -----------------------------------------------------------------------
 * Local state for the capture source
 * ----------------------------------------------------------------------- */

typedef struct {
    char *diag_path;        /* DIAG /dev/tty node (NULL in replay mode) */
    char *replay_path;      /* replay= file, or NULL for a live modem */
    char *helper_dir;       /* helper checkout root (venv + helper script) */
    char *modem_imei;       /* 15-digit IMEI, stamped into prov.imei */
    char *modem_firmware;
    char *modem_model;
    char *name;             /* human label for message-bus lines */

    int   diag_fd;          /* open DIAG port, or -1 (replay) */
    int   no_mask;          /* skip LOG_CONFIG (passive tap) */
    int   debug;

    /* Bridge helper subprocess */
    pid_t helper_pid;
    int   helper_in;        /* write end -> helper stdin (raw HDLC bytes) */
    int   helper_out;       /* read end  <- helper stdout (JSON lines) */

    /* Shared reader threaded through the LOG_CONFIG handshake and the capture
     * loop so bytes buffered during the handshake are not lost at the seam. */
    diag_reader_t reader;
} local_diag_t;

/* -----------------------------------------------------------------------
 * Serial helpers (AT identify only) - ported from capture_cell_at.c
 * ----------------------------------------------------------------------- */

static int serial_open(const char *path, int baudrate) {
    int fd;
    struct termios tty;
    speed_t speed;

    fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0)
        return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    memset(&tty, 0, sizeof(tty));
    if (tcgetattr(fd, &tty) != 0) {
        close(fd);
        return -1;
    }

    switch (baudrate) {
        case 9600:   speed = B9600;   break;
        case 19200:  speed = B19200;  break;
        case 38400:  speed = B38400;  break;
        case 57600:  speed = B57600;  break;
        case 460800: speed = B460800; break;
        case 921600: speed = B921600; break;
        default:     speed = B115200; break;
    }

    cfsetispeed(&tty, speed);
    cfsetospeed(&tty, speed);

    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;
    tty.c_cflag &= ~CRTSCTS;
    tty.c_cflag |= CREAD | CLOCAL;

    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~(IXON | IXOFF | IXANY | IGNBRK | BRKINT | PARMRK |
                      ISTRIP | INLCR | IGNCR | ICRNL);
    tty.c_oflag &= ~OPOST;

    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 10;

    tcflush(fd, TCIOFLUSH);
    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static void serial_close_fd(int *fd) {
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

/* Send an AT command and collect the response until OK/ERROR/timeout.
 * Returns response length, or -1 on error. (Transcript-free variant; DIAG
 * capture only needs AT for one-shot IMEI/firmware identification.) */
static int at_command(int fd, const char *cmd, char *resp_buf,
                      size_t resp_max, int timeout_ms) {
    char line_buf[1024];
    ssize_t n;
    size_t resp_len = 0;
    size_t line_pos = 0;
    struct timeval deadline, now_tv;

    if (fd < 0)
        return -1;

    tcflush(fd, TCIFLUSH);

    size_t cmd_len = strlen(cmd);
    char *send_buf = malloc(cmd_len + 3);
    if (!send_buf)
        return -1;
    snprintf(send_buf, cmd_len + 3, "%s\r\n", cmd);
    ssize_t written = write(fd, send_buf, strlen(send_buf));
    free(send_buf);
    if (written < 0)
        return -1;

    gettimeofday(&deadline, NULL);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_usec += (timeout_ms % 1000) * 1000;
    if (deadline.tv_usec >= 1000000) {
        deadline.tv_sec++;
        deadline.tv_usec -= 1000000;
    }

    resp_buf[0] = '\0';

    while (1) {
        gettimeofday(&now_tv, NULL);
        if (now_tv.tv_sec > deadline.tv_sec ||
            (now_tv.tv_sec == deadline.tv_sec &&
             now_tv.tv_usec >= deadline.tv_usec))
            break;

        long remaining_ms = (deadline.tv_sec - now_tv.tv_sec) * 1000 +
                            (deadline.tv_usec - now_tv.tv_usec) / 1000;
        if (remaining_ms <= 0)
            break;

        struct termios tty;
        tcgetattr(fd, &tty);
        int vtime = (remaining_ms > 1000) ? 10 : (remaining_ms / 100);
        if (vtime < 1) vtime = 1;
        tty.c_cc[VTIME] = vtime;
        tcsetattr(fd, TCSANOW, &tty);

        char c;
        n = read(fd, &c, 1);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            continue;

        if (c == '\n' || c == '\r') {
            if (line_pos == 0)
                continue;
            line_buf[line_pos] = '\0';
            if (strncmp(line_buf, cmd, strlen(cmd)) == 0) {
                line_pos = 0;
                continue;
            }
            if (resp_len + line_pos + 2 < resp_max) {
                if (resp_len > 0)
                    resp_buf[resp_len++] = '\n';
                memcpy(resp_buf + resp_len, line_buf, line_pos);
                resp_len += line_pos;
                resp_buf[resp_len] = '\0';
            }
            if (strcmp(line_buf, "OK") == 0 ||
                strcmp(line_buf, "ERROR") == 0 ||
                strncmp(line_buf, "+CME ERROR", 10) == 0)
                break;
            line_pos = 0;
        } else {
            if (line_pos < sizeof(line_buf) - 1)
                line_buf[line_pos++] = c;
        }
    }

    return (int)resp_len;
}

/* AT identify: probe a serial port for a modem and read its firmware + IMEI.
 * Non-AT ports (DIAG, NMEA) time out on the 150ms AT check and return 0. */
static int identify_modem(const char *path, char *fw_buf, size_t fw_sz,
                          char *imei_buf, size_t imei_sz) {
    char resp[4096];

    int fd = serial_open(path, 115200);
    if (fd < 0)
        return 0;

    int n = at_command(fd, "AT", resp, sizeof(resp), 150);
    if (n < 0 || strstr(resp, "OK") == NULL) {
        close(fd);
        return 0;
    }

    n = at_command(fd, "AT+CGMR", resp, sizeof(resp), 3000);
    fw_buf[0] = '\0';
    if (n > 0) {
        char *saveptr = NULL;
        char *line = strtok_r(resp, "\n", &saveptr);
        while (line) {
            while (*line == ' ') line++;
            if (*line && strcmp(line, "OK") != 0 &&
                strncmp(line, "+CME", 4) != 0) {
                strncpy(fw_buf, line, fw_sz - 1);
                fw_buf[fw_sz - 1] = '\0';
                break;
            }
            line = strtok_r(NULL, "\n", &saveptr);
        }
    }

    if (!fw_buf[0]) {
        close(fd);
        return 0;
    }

    n = at_command(fd, "AT+CGSN", resp, sizeof(resp), 3000);
    imei_buf[0] = '\0';
    if (n > 0) {
        char *saveptr = NULL;
        char *line = strtok_r(resp, "\n", &saveptr);
        while (line) {
            while (*line == ' ') line++;
            if (*line && strcmp(line, "OK") != 0 &&
                strncmp(line, "+CME", 4) != 0) {
                strncpy(imei_buf, line, imei_sz - 1);
                imei_buf[imei_sz - 1] = '\0';
                break;
            }
            line = strtok_r(NULL, "\n", &saveptr);
        }
    }

    close(fd);
    return 1;
}

/* -----------------------------------------------------------------------
 * USB / sysfs port topology - ported from capture_cell_at.c
 * ----------------------------------------------------------------------- */

static int find_modem_ports(char ports[][256], int max_ports) {
    glob_t g;
    int count = 0;

    if (glob("/dev/ttyUSB*", 0, NULL, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc && count < max_ports; i++) {
            strncpy(ports[count], g.gl_pathv[i], 255);
            ports[count][255] = '\0';
            count++;
        }
    }
    globfree(&g);

    if (glob("/dev/ttyACM*", 0, NULL, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc && count < max_ports; i++) {
            strncpy(ports[count], g.gl_pathv[i], 255);
            ports[count][255] = '\0';
            count++;
        }
    }
    globfree(&g);

    return count;
}

/* Map a tty node to its parent USB device id ("2-1") via sysfs. 1 on success. */
static int get_usb_device_id(const char *port_path, char *usb_dev, size_t usb_dev_sz) {
    char sysfs_path[512];
    char resolved[512];
    const char *port_name;

    port_name = strrchr(port_path, '/');
    if (port_name)
        port_name++;
    else
        port_name = port_path;

    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/tty/%s/device", port_name);
    if (realpath(sysfs_path, resolved) == NULL)
        return 0;

    char *slash1 = strrchr(resolved, '/');
    if (!slash1) return 0;
    *slash1 = '\0';
    char *slash2 = strrchr(resolved, '/');
    if (!slash2) return 0;
    *slash2 = '\0';
    char *dev_name = strrchr(resolved, '/');
    if (!dev_name) return 0;
    dev_name++;

    strncpy(usb_dev, dev_name, usb_dev_sz - 1);
    usb_dev[usb_dev_sz - 1] = '\0';
    return 1;
}

/* USB interface number for a tty node ("2-1:1.4" -> 4). -1 on failure. */
static int get_usb_interface_num(const char *port_path) {
    char sysfs_path[512];
    char resolved[512];
    const char *port_name;

    port_name = strrchr(port_path, '/');
    if (port_name)
        port_name++;
    else
        port_name = port_path;

    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/tty/%s/device", port_name);
    if (realpath(sysfs_path, resolved) == NULL)
        return -1;

    char *slash = strrchr(resolved, '/');
    if (!slash) return -1;
    *slash = '\0';
    char *iface_dir = strrchr(resolved, '/');
    if (!iface_dir) return -1;
    iface_dir++;
    char *dot = strrchr(iface_dir, '.');
    if (!dot) return -1;
    return atoi(dot + 1);
}

/* Scan serial ports for AT-responding modems, one per physical USB device.
 * Sorted so higher (AT-likely) interfaces are tried first, minimizing timeouts
 * on DIAG/NMEA ports. Calls cb per modem; non-zero cb return stops the scan. */
typedef int (*modem_scan_cb)(const char *port, const char *fw,
                             const char *imei, void *ctx);

static int scan_modems(modem_scan_cb cb, void *ctx) {
    char all_ports[64][256];
    char usb_devs[64][64];
    int if_nums[64];
    int n_all = find_modem_ports(all_ports, 64);
    int found = 0;

    for (int i = 0; i < n_all; i++) {
        if (!get_usb_device_id(all_ports[i], usb_devs[i], sizeof(usb_devs[i])))
            usb_devs[i][0] = '\0';
        if_nums[i] = get_usb_interface_num(all_ports[i]);
    }

    for (int i = 0; i < n_all - 1; i++) {
        for (int j = i + 1; j < n_all; j++) {
            int swap = 0;
            int cmp = strcmp(usb_devs[i], usb_devs[j]);
            if (cmp > 0)
                swap = 1;
            else if (cmp == 0 && if_nums[i] < if_nums[j])
                swap = 1;
            if (swap) {
                char tmp_port[256], tmp_dev[64];
                int tmp_if;
                memcpy(tmp_port, all_ports[i], 256);
                memcpy(all_ports[i], all_ports[j], 256);
                memcpy(all_ports[j], tmp_port, 256);
                memcpy(tmp_dev, usb_devs[i], 64);
                memcpy(usb_devs[i], usb_devs[j], 64);
                memcpy(usb_devs[j], tmp_dev, 64);
                tmp_if = if_nums[i]; if_nums[i] = if_nums[j]; if_nums[j] = tmp_if;
            }
        }
    }

    char done_devs[64][64];
    int n_done = 0;

    for (int i = 0; i < n_all; i++) {
        if (usb_devs[i][0]) {
            int skip = 0;
            for (int j = 0; j < n_done; j++) {
                if (strcmp(done_devs[j], usb_devs[i]) == 0) { skip = 1; break; }
            }
            if (skip)
                continue;
        }

        char fw_buf[256], imei_buf[64];
        if (!identify_modem(all_ports[i], fw_buf, sizeof(fw_buf),
                            imei_buf, sizeof(imei_buf)))
            continue;

        if (usb_devs[i][0] && n_done < 64) {
            strncpy(done_devs[n_done], usb_devs[i], 63);
            done_devs[n_done][63] = '\0';
            n_done++;
        }

        found++;
        if (cb && cb(all_ports[i], fw_buf, imei_buf, ctx))
            return found;
    }

    return found;
}

/* --- find-by-IMEI --- */

typedef struct {
    const char *target_imei;
    char *path_out;
    size_t path_sz;
    char *fw_out;
    size_t fw_sz;
    char *imei_out;
    size_t imei_sz;
} find_imei_ctx_t;

static int find_imei_cb(const char *port, const char *fw,
                        const char *imei, void *ctx) {
    find_imei_ctx_t *c = (find_imei_ctx_t *)ctx;
    if (strcmp(imei, c->target_imei) != 0)
        return 0;

    strncpy(c->path_out, port, c->path_sz - 1);
    c->path_out[c->path_sz - 1] = '\0';
    if (c->fw_out) {
        strncpy(c->fw_out, fw, c->fw_sz - 1);
        c->fw_out[c->fw_sz - 1] = '\0';
    }
    if (c->imei_out) {
        strncpy(c->imei_out, imei, c->imei_sz - 1);
        c->imei_out[c->imei_sz - 1] = '\0';
    }
    return 1;
}

static int find_port_by_imei(const char *imei, char *path_out, size_t path_sz,
                             char *fw_out, size_t fw_sz,
                             char *imei_out, size_t imei_sz) {
    find_imei_ctx_t ctx = {
        .target_imei = imei,
        .path_out = path_out, .path_sz = path_sz,
        .fw_out = fw_out, .fw_sz = fw_sz,
        .imei_out = imei_out, .imei_sz = imei_sz,
    };
    path_out[0] = '\0';
    scan_modems(find_imei_cb, &ctx);
    return path_out[0] != '\0' ? 1 : 0;
}

/* Locate the DIAG interface on the same USB device as `sibling_port`. Qualcomm
 * modems expose DIAG (QCDM) as the lowest USB interface (if00), so we pick the
 * tty on that USB device with the smallest interface number. Returns 1 on
 * success (out filled), 0 if the USB device or a sibling tty cannot be found. */
static int find_diag_port(const char *sibling_port, char *out, size_t outsz) {
    char target_dev[64];
    if (!get_usb_device_id(sibling_port, target_dev, sizeof(target_dev)))
        return 0;

    glob_t g;
    int best_if = 1 << 30;
    char best[256] = "";

    if (glob("/dev/ttyUSB*", 0, NULL, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc; i++) {
            char dev[64];
            if (!get_usb_device_id(g.gl_pathv[i], dev, sizeof(dev)))
                continue;
            if (strcmp(dev, target_dev) != 0)
                continue;
            int ifn = get_usb_interface_num(g.gl_pathv[i]);
            if (ifn >= 0 && ifn < best_if) {
                best_if = ifn;
                strncpy(best, g.gl_pathv[i], sizeof(best) - 1);
                best[sizeof(best) - 1] = '\0';
            }
        }
    }
    globfree(&g);

    if (!best[0])
        return 0;
    strncpy(out, best, outsz - 1);
    out[outsz - 1] = '\0';
    return 1;
}

/* -----------------------------------------------------------------------
 * Bridge helper subprocess
 * ----------------------------------------------------------------------- */

/* fork/exec <helper_dir>/.venv/bin/python <helper_dir>/tools/kismet_diag_decode.py
 * --imei <imei>, wiring two pipes: our helper_in -> child stdin (raw HDLC bytes),
 * child stdout -> our helper_out (JSON lines). Returns 0 on success. */
static int spawn_helper(local_diag_t *local) {
    int in_pipe[2];   /* parent writes in_pipe[1] -> child reads in_pipe[0] */
    int out_pipe[2];  /* child writes out_pipe[1] -> parent reads out_pipe[0] */

    if (pipe(in_pipe) != 0)
        return -1;
    if (pipe(out_pipe) != 0) {
        close(in_pipe[0]); close(in_pipe[1]);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        return -1;
    }

    if (pid == 0) {
        /* Child */
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);

        if (chdir(local->helper_dir) != 0)
            _exit(127);

        char python[1024], script[1024];
        snprintf(python, sizeof(python), "%s/.venv/bin/python", local->helper_dir);
        snprintf(script, sizeof(script), "%s/tools/kismet_diag_decode.py",
                 local->helper_dir);

        execl(python, python, script, "--imei",
              local->modem_imei ? local->modem_imei : "000000000000000",
              (char *)NULL);
        _exit(127);  /* exec failed */
    }

    /* Parent */
    close(in_pipe[0]);
    close(out_pipe[1]);
    local->helper_in = in_pipe[1];
    local->helper_out = out_pipe[0];
    local->helper_pid = pid;
    return 0;
}

static void reap_helper(local_diag_t *local) {
    if (local->helper_in >= 0) { close(local->helper_in); local->helper_in = -1; }
    if (local->helper_pid > 0) {
        int status;
        /* Closing stdin makes the helper hit EOF and exit; give it a moment,
         * then reap. */
        for (int i = 0; i < 20; i++) {
            if (waitpid(local->helper_pid, &status, WNOHANG) == local->helper_pid) {
                local->helper_pid = -1;
                break;
            }
            usleep(50000);
        }
        if (local->helper_pid > 0) {
            kill(local->helper_pid, SIGTERM);
            waitpid(local->helper_pid, &status, 0);
            local->helper_pid = -1;
        }
    }
    if (local->helper_out >= 0) { close(local->helper_out); local->helper_out = -1; }
}

/* Write the whole buffer, retrying short writes. Returns 0 on success, -1 if
 * the pipe is gone (helper died). */
static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;  /* EPIPE etc. */
        }
        off += (size_t)w;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Capture framework callbacks
 * ----------------------------------------------------------------------- */

typedef struct {
    cf_params_list_interface_t **interfaces;
    int n_found;
} list_ctx_t;

static int list_modem_cb(const char *port, const char *fw,
                         const char *imei, void *ctx) {
    (void)port;
    list_ctx_t *c = (list_ctx_t *)ctx;

    if (!imei[0])
        return 0;

    c->interfaces[c->n_found] = (cf_params_list_interface_t *)
        malloc(sizeof(cf_params_list_interface_t));
    memset(c->interfaces[c->n_found], 0, sizeof(cf_params_list_interface_t));

    char iface_name[512];
    snprintf(iface_name, sizeof(iface_name), "celldiag-%s", imei);
    c->interfaces[c->n_found]->interface = strdup(iface_name);

    char hw_desc[512];
    snprintf(hw_desc, sizeof(hw_desc), "%s IMEI:%s DIAG", fw, imei);
    c->interfaces[c->n_found]->hardware = strdup(hw_desc);

    c->n_found++;
    return 0;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
                  cf_params_list_interface_t ***interfaces) {
    (void)caph; (void)seqno; (void)msg;
    *interfaces = (cf_params_list_interface_t **)
        malloc(sizeof(cf_params_list_interface_t *) * 32);

    list_ctx_t ctx = { .interfaces = *interfaces, .n_found = 0 };
    scan_modems(list_modem_cb, &ctx);

    return ctx.n_found;
}

/* Validate a celldiag-<IMEI> definition without scanning ports (scanning can
 * exceed Kismet's 10s probe timeout). replay= definitions validate trivially. */
int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
                   char *msg, char **uuid,
                   cf_params_interface_t **ret_interface,
                   cf_params_spectrum_t **ret_spectrum) {
    (void)caph; (void)seqno; (void)uuid;
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    if (strncmp(interface, "celldiag-", 9) != 0) {
        free(interface);
        return 0;
    }

    const char *imei = interface + 9;
    if (strlen(imei) != 15) {
        snprintf(msg, STATUS_MAX,
                 "Invalid celldiag definition '%s' - expected celldiag-<15-digit IMEI>",
                 interface);
        free(interface);
        return 0;
    }
    for (int i = 0; i < 15; i++) {
        if (!isdigit(imei[i])) {
            snprintf(msg, STATUS_MAX, "Invalid IMEI in '%s' - must be 15 digits",
                     interface);
            free(interface);
            return 0;
        }
    }

    free(interface);
    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
                  char *msg, uint32_t *dlt, char **uuid,
                  cf_params_interface_t **ret_interface,
                  cf_params_spectrum_t **ret_spectrum) {
    (void)seqno; (void)dlt;
    local_diag_t *local = (local_diag_t *)caph->userdata;
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char buf[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }
    interface = strndup(placeholder, placeholder_len);

    if (strncmp(interface, "celldiag-", 9) != 0) {
        snprintf(msg, STATUS_MAX,
                 "Invalid celldiag definition '%s' - expected celldiag-<IMEI>",
                 interface);
        free(interface);
        return -1;
    }
    const char *imei = interface + 9;
    if (strlen(imei) != 15) {
        snprintf(msg, STATUS_MAX,
                 "Invalid celldiag definition '%s' - expected celldiag-<15-digit IMEI>",
                 interface);
        free(interface);
        return -1;
    }
    for (int i = 0; i < 15; i++) {
        if (!isdigit(imei[i])) {
            snprintf(msg, STATUS_MAX, "Invalid IMEI in '%s' - must be 15 digits",
                     interface);
            free(interface);
            return -1;
        }
    }
    char imei_def[16];
    strncpy(imei_def, imei, 15);
    imei_def[15] = '\0';
    free(interface);

    /* --- source options --- */
    local->helper_dir = NULL;
    if ((placeholder_len = cf_find_flag(&placeholder, "helper", definition)) > 0) {
        local->helper_dir = strndup(placeholder, placeholder_len);
    } else {
        const char *env = getenv("CELLDIAG_HELPER");
        local->helper_dir = strdup(env && *env ? env : CELLDIAG_HELPER_DEFAULT);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "replay", definition)) > 0)
        local->replay_path = strndup(placeholder, placeholder_len);

    char diagport_override[512] = "";
    if ((placeholder_len = cf_find_flag(&placeholder, "diagport", definition)) > 0) {
        char *p = strndup(placeholder, placeholder_len);
        strncpy(diagport_override, p, sizeof(diagport_override) - 1);
        free(p);
    }

    local->no_mask = 0;
    if ((placeholder_len = cf_find_flag(&placeholder, "nomask", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        if (strcmp(v, "true") == 0 || strcmp(v, "1") == 0)
            local->no_mask = 1;
        free(v);
    }

    local->debug = 1;
    const char *debug_env = getenv("KISMET_CELLDIAG_DEBUG");
    if (debug_env && (strcmp(debug_env, "0") == 0 || strcmp(debug_env, "false") == 0))
        local->debug = 0;
    if ((placeholder_len = cf_find_flag(&placeholder, "debug", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        if (strcmp(v, "false") == 0 || strcmp(v, "0") == 0)
            local->debug = 0;
        else if (strcmp(v, "true") == 0 || strcmp(v, "1") == 0)
            local->debug = 1;
        free(v);
    }

    local->modem_imei = strdup(imei_def);

    /* --- resolve the DIAG source --- */
    if (local->replay_path) {
        /* Offline: no modem, no mask; the capture thread reads the file. */
        local->diag_fd = -1;
        local->modem_model = strdup("DIAG replay");
        local->modem_firmware = strdup(local->replay_path);
    } else {
        char at_port[512], fw_buf[256], imei_buf[64];
        if (!find_port_by_imei(imei_def, at_port, sizeof(at_port),
                               fw_buf, sizeof(fw_buf), imei_buf, sizeof(imei_buf))) {
            snprintf(msg, STATUS_MAX, "Modem IMEI %s not found on any serial port",
                     imei_def);
            return -1;
        }
        local->modem_firmware = strdup(fw_buf);
        local->modem_model = strdup(fw_buf);

        char diag_port[512];
        if (diagport_override[0]) {
            strncpy(diag_port, diagport_override, sizeof(diag_port) - 1);
            diag_port[sizeof(diag_port) - 1] = '\0';
        } else if (!find_diag_port(at_port, diag_port, sizeof(diag_port))) {
            snprintf(msg, STATUS_MAX,
                     "Could not locate DIAG interface for IMEI %s (AT port %s); "
                     "pass diagport=/dev/ttyUSBx", imei_def, at_port);
            return -1;
        }

        local->diag_fd = diag_capture_open(diag_port);
        if (local->diag_fd < 0) {
            snprintf(msg, STATUS_MAX, "Failed to open DIAG port %s: %s",
                     diag_port, strerror(errno));
            return -1;
        }
        local->diag_path = strdup(diag_port);

        memset(&local->reader, 0, sizeof(local->reader));
        if (!local->no_mask) {
            if (diag_config_apply_narrow_mask(local->diag_fd, &local->reader,
                                              DIAG_TARGET_CODES,
                                              DIAG_TARGET_CODES_COUNT) != 0) {
                snprintf(msg, STATUS_MAX,
                         "DIAG LOG_CONFIG handshake failed on %s "
                         "(wrong port, or SPC-gated?)", diag_port);
                serial_close_fd(&local->diag_fd);
                return -1;
            }
        }
    }

    /* --- spawn the bridge helper --- */
    if (spawn_helper(local) != 0) {
        snprintf(msg, STATUS_MAX, "Failed to spawn DIAG bridge helper from %s",
                 local->helper_dir);
        if (local->diag_fd >= 0) serial_close_fd(&local->diag_fd);
        return -1;
    }

    /* --- interface info --- */
    char hw_desc[512];
    snprintf(hw_desc, sizeof(hw_desc), "%s IMEI:%s DIAG",
             local->modem_model, imei_def);
    local->name = strdup(hw_desc);
    (*ret_interface)->capif =
        strdup(local->diag_path ? local->diag_path :
               (local->replay_path ? local->replay_path : "diag"));
    (*ret_interface)->hardware = strdup(hw_desc);

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(buf, STATUS_MAX, "celldiag%s", imei_def);
        uint32_t hash = adler32_csum((unsigned char *)buf, strlen(buf));
        snprintf(buf, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
                 adler32_csum((unsigned char *)"kismet_cap_cell_diag",
                              strlen("kismet_cap_cell_diag")) & 0xFFFFFFFF,
                 hash & 0xFFFFFFFF);
        *uuid = strdup(buf);
    }

    snprintf(buf, STATUS_MAX, "Cell DIAG source %s opened (%s%s)",
             local->name,
             local->replay_path ? "replay " : "live ",
             local->replay_path ? local->replay_path :
                (local->no_mask ? "passive/no-mask" : local->diag_path));
    cf_send_message(caph, buf, MSGFLAG_INFO);

    return 1;
}

/* Drain any complete JSON lines currently buffered from the helper and relay
 * each to Kismet via cf_send_json. `line`/`line_len` hold a partial line across
 * calls. Returns 0 on success, -1 if the helper closed / send failed. */
static int drain_helper_lines(kis_capture_handler_t *caph, local_diag_t *local,
                              char *line, size_t *line_len) {
    uint8_t rd[4096];
    struct timeval tv;
    char errstr[ERRBUF_MAX];

    ssize_t n = read(local->helper_out, rd, sizeof(rd));
    if (n == 0)
        return -1;  /* helper closed stdout */
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;
        return -1;
    }

    for (ssize_t i = 0; i < n; i++) {
        char c = (char)rd[i];
        if (c == '\n') {
            if (*line_len == 0)
                continue;
            line[*line_len] = '\0';
            gettimeofday(&tv, NULL);
            int r = cf_send_json(caph, NULL, 0, NULL, NULL, tv,
                                 "CellModem", line);
            *line_len = 0;
            if (r < 0) {
                snprintf(errstr, ERRBUF_MAX,
                         "%s failed to send DIAG JSON to Kismet", local->name);
                cf_send_error(caph, 0, errstr);
                return -1;
            }
            if (r == 0)
                cf_handler_wait_ringbuffer(caph);
        } else if (c != '\r') {
            if (*line_len < JSON_LINE_MAX - 1)
                line[(*line_len)++] = c;
            /* else: overlong line, drop until next newline */
        }
    }
    return 0;
}

void capture_thread(kis_capture_handler_t *caph) {
    local_diag_t *local = (local_diag_t *)caph->userdata;
    char errstr[ERRBUF_MAX];
    static char line[JSON_LINE_MAX];
    size_t line_len = 0;

    int src_fd = local->diag_fd;
    int replay_fd = -1;
    if (local->replay_path) {
        replay_fd = open(local->replay_path, O_RDONLY);
        if (replay_fd < 0) {
            snprintf(errstr, ERRBUF_MAX, "%s cannot open replay file %s: %s",
                     local->name, local->replay_path, strerror(errno));
            cf_send_error(caph, 0, errstr);
            goto done;
        }
        src_fd = replay_fd;
    }

    /* Flush bytes the LOG_CONFIG handshake already buffered into the shared
     * reader before draining the live port (live path only). */
    if (!local->replay_path && local->reader.pos < local->reader.len) {
        size_t rem = local->reader.len - local->reader.pos;
        if (write_all(local->helper_in, local->reader.buf + local->reader.pos,
                      rem) != 0)
            goto helper_gone;
    }

    while (!caph->shutdown) {
        struct pollfd fds[2];
        fds[0].fd = src_fd;          fds[0].events = POLLIN;  fds[0].revents = 0;
        fds[1].fd = local->helper_out; fds[1].events = POLLIN; fds[1].revents = 0;

        int pr = poll(fds, 2, 250);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        /* Always relay helper output first: keeps its stdout pipe drained so a
         * large stdin write below can never deadlock against it. */
        if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            if (drain_helper_lines(caph, local, line, &line_len) != 0)
                goto helper_gone;
        }

        if (fds[0].revents & POLLIN) {
            uint8_t rbuf[65536];
            ssize_t n = read(src_fd, rbuf, sizeof(rbuf));
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN)
                    continue;
                break;
            }
            if (n == 0) {
                /* Replay: EOF - close stdin so the helper flushes, then drain
                 * its remaining output and finish. Live: a 0-byte read is a
                 * VTIME idle tick, keep going. */
                if (local->replay_path)
                    break;
                continue;
            }
            if (write_all(local->helper_in, rbuf, (size_t)n) != 0)
                goto helper_gone;
        } else if (fds[0].revents & (POLLHUP | POLLERR)) {
            break;
        }
    }

    /* Replay flush: signal EOF to the helper and relay whatever it emits. */
    if (local->replay_path && local->helper_in >= 0) {
        close(local->helper_in);
        local->helper_in = -1;
        for (;;) {
            struct pollfd pf = { .fd = local->helper_out, .events = POLLIN };
            int pr = poll(&pf, 1, 2000);
            if (pr <= 0)
                break;
            if (drain_helper_lines(caph, local, line, &line_len) != 0)
                break;
        }
    }

    if (replay_fd >= 0)
        close(replay_fd);
    goto done;

helper_gone:
    snprintf(errstr, ERRBUF_MAX, "%s DIAG bridge helper exited unexpectedly",
             local->name);
    cf_send_error(caph, 0, errstr);
    if (replay_fd >= 0)
        close(replay_fd);

done:
    reap_helper(local);
    if (local->diag_fd >= 0)
        serial_close_fd(&local->diag_fd);
    cf_handler_spindown(caph);
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(int argc, char *argv[]) {
    local_diag_t local = {
        .diag_path = NULL,
        .replay_path = NULL,
        .helper_dir = NULL,
        .modem_imei = NULL,
        .modem_firmware = NULL,
        .modem_model = NULL,
        .name = NULL,
        .diag_fd = -1,
        .no_mask = 0,
        .debug = 0,
        .helper_pid = -1,
        .helper_in = -1,
        .helper_out = -1,
    };

    /* A dead helper must not kill us with SIGPIPE mid-write; we detect the
     * broken pipe via write()'s EPIPE return instead. */
    signal(SIGPIPE, SIG_IGN);

    kis_capture_handler_t *caph = cf_handler_init("celldiag");
    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    cf_handler_set_userdata(caph, &local);
    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
    cf_handler_set_listdevices_cb(caph, list_callback);
    cf_handler_set_capture_cb(caph, capture_thread);

    int r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    cf_handler_remote_capture(caph);
    cf_jail_filesystem(caph);
    cf_drop_most_caps(caph);

    cf_handler_loop(caph);

    cf_handler_shutdown(caph);

    reap_helper(&local);
    if (local.diag_fd >= 0)
        close(local.diag_fd);
    free(local.diag_path);
    free(local.replay_path);
    free(local.helper_dir);
    free(local.modem_imei);
    free(local.modem_firmware);
    free(local.modem_model);
    free(local.name);

    return 0;
}
