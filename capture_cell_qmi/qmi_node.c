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

#define _GNU_SOURCE

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../capture_cell_diag/cell_discover.h"
#include "qmi_node.h"

static char g_root[PATH_MAX] = "";

void qmi_node_set_root(const char *root) {
    snprintf(g_root, sizeof(g_root), "%s", root != NULL ? root : "");
    cell_discover_set_root(root != NULL ? root : "");
}

static int rooted(char *out, size_t outsz, const char *path) {
    return (size_t) snprintf(out, outsz, "%s%s", g_root, path) < outsz;
}

/* <prefix><digits>, or <prefix><digits><mid><digits> when mid is set */
static int name_form(const char *s, const char *prefix, const char *mid) {
    const size_t pl = strlen(prefix);

    if (strncmp(s, prefix, pl) != 0)
        return 0;
    s += pl;

    if (*s < '0' || *s > '9')
        return 0;
    while (*s >= '0' && *s <= '9')
        s++;

    if (mid != NULL) {
        const size_t ml = strlen(mid);
        if (strncmp(s, mid, ml) != 0)
            return 0;
        s += ml;
        if (*s < '0' || *s > '9')
            return 0;
        while (*s >= '0' && *s <= '9')
            s++;
    }

    return *s == '\0';
}

static qmi_framing_t name_framing(const char *name, const char **why) {
    if (name_form(name, "wwan", "qmi")) {
        *why = "wwan";
        return QMI_FRAMING_QMUX;
    }
    if (name_form(name, "wwan", "mbim")) {
        *why = "wwan";
        return QMI_FRAMING_MBIM;
    }
    if (name_form(name, "mhi_QMI", NULL)) {
        *why = "mhi";
        return QMI_FRAMING_QMUX;
    }
    if (name_form(name, "mhi_MBIM", NULL)) {
        *why = "mhi";
        return QMI_FRAMING_MBIM;
    }
    return QMI_FRAMING_NONE;
}

int qmi_node_name_ok(const char *name) {
    const char *why;

    if (name == NULL)
        return 0;
    return name_form(name, "cdc-wdm", NULL) ||
        name_framing(name, &why) != QMI_FRAMING_NONE;
}

static const char *node_name(const char *dev, char *buf, size_t bufsz) {
    char resolved[PATH_MAX];
    const char *path = dev;

    /* A by-id or by-path link names its node by the link's target */
    if (g_root[0] == '\0' && realpath(dev, resolved) != NULL)
        path = resolved;

    /* A name too long for `buf` is no node's: left empty, it matches none */
    const char *slash = strrchr(path, '/');
    const int n = snprintf(buf, bufsz, "%s", slash != NULL ? slash + 1 : path);
    if (n < 0 || (size_t) n >= bufsz)
        buf[0] = '\0';
    return buf;
}

int qmi_node_path_ok(const char *path) {
    static const char dev[] = "/dev/";

    if (path == NULL || strncmp(path, dev, sizeof(dev) - 1) != 0)
        return 0;
    path += sizeof(dev) - 1;
    return strchr(path, '/') == NULL && qmi_node_name_ok(path);
}

qmi_framing_t qmi_node_framing(const char *dev, char *driver, size_t driversz) {
    char name[NAME_MAX + 1], rel[PATH_MAX], link[PATH_MAX], target[PATH_MAX];
    const char *why = "";

    if (driver != NULL && driversz > 0)
        driver[0] = '\0';
    if (dev == NULL)
        return QMI_FRAMING_NONE;

    node_name(dev, name, sizeof(name));

    qmi_framing_t f = name_framing(name, &why);
    if (f != QMI_FRAMING_NONE) {
        if (driver != NULL)
            snprintf(driver, driversz, "%s", why);
        return f;
    }

    if (!name_form(name, "cdc-wdm", NULL))
        return QMI_FRAMING_NONE;

    snprintf(rel, sizeof(rel), "/sys/class/usbmisc/%s/device/driver", name);
    if (!rooted(link, sizeof(link), rel))
        return QMI_FRAMING_NONE;

    const ssize_t n = readlink(link, target, sizeof(target) - 1);
    if (n <= 0)
        return QMI_FRAMING_NONE;
    target[n] = '\0';

    const char *drv = strrchr(target, '/');
    drv = drv != NULL ? drv + 1 : target;
    if (driver != NULL)
        snprintf(driver, driversz, "%s", drv);

    /* qmi_wwan_q is the out-of-tree Quectel build of qmi_wwan */
    if (strcmp(drv, "qmi_wwan") == 0 || strcmp(drv, "qmi_wwan_q") == 0)
        return QMI_FRAMING_QMUX;
    if (strcmp(drv, "cdc_mbim") == 0)
        return QMI_FRAMING_MBIM;

    return QMI_FRAMING_NONE;
}

/* The listening flag in /proc/net/unix (__SO_ACCEPTCON) */
#define UNIX_FLAG_LISTENING 0x00010000UL

int qmi_abstract_listening(const char *name) {
    char path[PATH_MAX], line[512];
    int found = 0;

    if (name == NULL || !rooted(path, sizeof(path), "/proc/net/unix"))
        return 0;

    FILE *f = fopen(path, "r");
    if (f == NULL)
        return 0;

    /* Num RefCount Protocol Flags Type St Inode Path */
    while (fgets(line, sizeof(line), f) != NULL) {
        char sock_path[256];
        unsigned long flags;

        sock_path[0] = '\0';
        if (sscanf(line, "%*s %*s %*s %lx %*s %*s %*s %255s", &flags, sock_path) != 2)
            continue;
        if (sock_path[0] != '@' || strcmp(sock_path + 1, name) != 0)
            continue;
        if (flags & UNIX_FLAG_LISTENING) {
            found = 1;
            break;
        }
    }

    fclose(f);
    return found;
}

const char *qmi_proxy_name(qmi_framing_t framing) {
    return framing == QMI_FRAMING_MBIM ? "mbim-proxy" : "qmi-proxy";
}

static void plan(qmi_open_plan_t *out, qmi_plan_mode_t mode, const char *proxy,
                 const char *fmt, ...) __attribute__((format(printf, 4, 5)));

static void plan(qmi_open_plan_t *out, qmi_plan_mode_t mode, const char *proxy,
                 const char *fmt, ...) {
    va_list ap;

    out->mode = mode;
    out->proxy = proxy;
    va_start(ap, fmt);
    vsnprintf(out->reason, sizeof(out->reason), fmt, ap);
    va_end(ap);
}

void qmi_open_decide(const char *dev, qmi_framing_t framing, qmi_open_req_t req,
                     const qmi_open_facts_t *f, qmi_open_plan_t *out) {
    const char *proxy = qmi_proxy_name(framing);

    if (req == QMI_OPEN_DIRECT_ONLY) {
        if (f->held) {
            plan(out, QMI_PLAN_REFUSE, NULL,
                 "%s is already open in %s (pid %d); a second direct opener "
                 "would take its replies", dev, f->held_comm, (int) f->held_pid);
            return;
        }
        plan(out, QMI_PLAN_DIRECT, NULL, "opening %s directly", dev);
        return;
    }

    if (f->held_by_other) {
        plan(out, QMI_PLAN_REFUSE, NULL,
             "%s is open in %s (pid %d); stop it, or have it use @%s, so the "
             "node can be shared", dev, f->other_comm, (int) f->other_pid, proxy);
        return;
    }

    if (f->proxy_listening) {
        plan(out, QMI_PLAN_PROXY, proxy, "sharing %s through @%s", dev, proxy);
        return;
    }

    if (req == QMI_OPEN_PROXY_ONLY) {
        plan(out, QMI_PLAN_REFUSE, NULL,
             "@%s is not running, and this source does not start it", proxy);
        return;
    }

    if (f->held) {
        /* Only the proxy holds the node, yet it is not listening: on its way
         * out, or wedged.  Neither is safe to open beside. */
        plan(out, QMI_PLAN_REFUSE, NULL,
             "%s is held by %s (pid %d), which is not accepting clients", dev,
             f->held_comm, (int) f->held_pid);
        return;
    }

    plan(out, QMI_PLAN_DIRECT, NULL, "no @%s running and nothing holds %s; "
         "opening it directly", proxy, dev);
}

void qmi_open_plan(const char *dev, qmi_framing_t framing, qmi_open_req_t req,
                   qmi_open_plan_t *out) {
    qmi_open_facts_t f;
    cell_busy_t b;
    const char *proxy = qmi_proxy_name(framing);

    memset(&f, 0, sizeof(f));
    f.proxy_listening = qmi_abstract_listening(proxy);

    if (cell_node_held(dev, NULL, &b)) {
        f.held = 1;
        f.held_pid = b.pid;
        snprintf(f.held_comm, sizeof(f.held_comm), "%s", b.comm[0] ? b.comm : "?");
    }

    if (cell_node_held(dev, proxy, &b)) {
        f.held_by_other = 1;
        f.other_pid = b.pid;
        snprintf(f.other_comm, sizeof(f.other_comm), "%s", b.comm[0] ? b.comm : "?");
    }

    qmi_open_decide(dev, framing, req, &f, out);
}
