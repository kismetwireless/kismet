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

    kismet_cap_cell_qmi: a cellular modem's serving and neighbour cells, read
    over QMI.

    The source polls the modem's NAS service (system info, cell location,
    signal info) on its QMI control node and forwards each cell as a
    CellModem JSON record, the same record the AT and DIAG cell sources send.

    Source definitions:
      cdc-wdm0:type=cellqmi            the node, by name (also wwan0qmi0,
                                       wwan0mbim0, mhi_QMI0, mhi_MBIM0)
      cellqmi:device=/dev/cdc-wdm0     the same, by path
    Options:
      interval=<ms>        poll period, default 2000, at least 500
      open=auto|proxy|direct
                           auto (default): share the node through qmi-proxy /
                           mbim-proxy when one is running, else open it
                           directly; proxy: only through a proxy; direct: never
      framing=qmux|mbim    what the node speaks, when its driver cannot be read
      backend=auto|qmi|mbim
                           on an MBIM node: auto (default) reads QMI over MBIM
                           when the function offers the QMI service, else
                           MBIM's own services; qmi or mbim insists on one

    QMI reaches the modem as bare QMUX on a qmi_wwan / wwan / MHI QMI node,
    or inside MBIM on a cdc_mbim node.  A modem whose MBIM function carries
    no QMI service is read natively over MBIM: BASE_STATIONS_INFO (MBIM 1.0
    only, never MBIMEx 3.0), else the atds location, with REGISTER_STATE for
    the PLMN.  A function that offers none of them is refused.
*/

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>

#include "../capture_framework.h"
#include "../config.h"
#include "../capture_cell_diag/cell_discover.h"
#include "../capture_cell_diag/cell_safefile.h"

#include "mbim_obs.h"
#include "qmi_node.h"
#include "qmi_obs.h"
#include "qmi_transport.h"

#define CELLQMI_INTERVAL_MS 2000
#define CELLQMI_INTERVAL_MIN_MS 500
#define CELLQMI_TIMEOUT_MS 3000
/* A modem that misses this many polls in a row has stopped answering */
#define CELLQMI_MISSED_MAX 3
/* Covers the client id release on close, and an MBIM close after it */
#define CELLQMI_CLOSE_GRACE_MS 3000
#define CELLQMI_LIST_MAX 32
/* BASE_STATIONS_INFO: the most cells of each RAT asked for */
#define CELLQMI_MBIM_CELLS_MAX 15

typedef enum {
    CELLQMI_BACKEND_AUTO = 0,
    CELLQMI_BACKEND_QMI,
    CELLQMI_BACKEND_MBIM,
} cellqmi_backend_t;

typedef struct {
    kis_capture_handler_t *caph;

    /* What open_callback decided, for the capture thread it starts */
    char *name;
    char *device;               /* as the definition names it */
    char node[PATH_MAX];        /* the resolved node: what is opened */
    dev_t node_rdev;            /* its device number, checked again at open */
    qmi_framing_t framing;
    char driver[64];
    qmi_open_req_t open_req;
    int via_proxy;
    cellqmi_backend_t backend;
    char plan_reason[320];
    char state[1200];           /* the client id record, when state_path is set */
    const char *state_path;
    unsigned int interval_ms;

    /* Guards the session: the capture thread opens and polls it, main()
     * closes it if the loop ends first.  The capture thread fills it in
     * before setting session_open, and nothing else reads it until then. */
    pthread_mutex_t lock;
    qmi_session_t session;
    int session_open;
    /* The native MBIM backend: the session above is unused */
    int native;
    mbim_session_t msession;

    int no_service;           /* -1 until the first poll */
} local_qmi_t;

/* The signal handler's way to the session */
static local_qmi_t *g_local;

/* A client id the modem never gets back stays allocated until it resets, and
 * neither the proxies nor the modem reclaim a dead client's ids.  SIGTERM
 * (the server going away) would otherwise end the helper without a release;
 * the release is prebuilt, so sending it here is one write(). */
static void fatal_signal(int sig) {
    if (g_local != NULL && g_local->session_open) {
        if (g_local->native)
            mbim_session_close_now(&g_local->msession);
        else
            qmi_session_release_now(&g_local->session);
    }

    signal(sig, SIG_DFL);
    raise(sig);
}

static void install_signal_release(void) {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fatal_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long) ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int stopping(kis_capture_handler_t *caph) {
    return caph->spindown || caph->shutdown || cf_handler_close_requested(caph);
}

typedef struct {
    char iface[256];
    char device[256];
    qmi_open_req_t open_req;
    int open_req_set;
    unsigned int interval_ms;
    qmi_framing_t framing;    /* QMI_FRAMING_NONE: from the node */
    cellqmi_backend_t backend;
} cellqmi_def_t;

/* 1 if the definition names a cellqmi source; 0 if it is someone else's;
 * -1 if it is ours but malformed (`msg` says why). */
static int parse_definition(char *definition, cellqmi_def_t *d, char *msg) {
    char *v;
    int vl;

    memset(d, 0, sizeof(*d));
    d->interval_ms = CELLQMI_INTERVAL_MS;

    if ((vl = cf_parse_interface(&v, definition)) <= 0 ||
        (size_t) vl >= sizeof(d->iface))
        return 0;
    memcpy(d->iface, v, (size_t) vl);
    d->iface[vl] = '\0';

    if ((vl = cf_find_flag(&v, "device", definition)) > 0) {
        if ((size_t) vl >= sizeof(d->device)) {
            snprintf(msg, STATUS_MAX, "cellqmi: device= path is too long");
            return -1;
        }
        memcpy(d->device, v, (size_t) vl);
        d->device[vl] = '\0';
    }

    if (strcmp(d->iface, "cellqmi") == 0) {
        if (d->device[0] == '\0') {
            snprintf(msg, STATUS_MAX, "cellqmi needs device=<path of the QMI or "
                     "MBIM control node>, or the node's name as the source");
            return -1;
        }
    } else if (qmi_node_name_ok(d->iface)) {
        if (d->device[0] == '\0') {
            const int n = snprintf(d->device, sizeof(d->device), "/dev/%s", d->iface);
            if (n < 0 || (size_t) n >= sizeof(d->device)) {
                snprintf(msg, STATUS_MAX, "cellqmi: the node name is too long");
                return -1;
            }
        }
    } else {
        return 0;
    }

    if (d->device[0] != '/') {
        snprintf(msg, STATUS_MAX, "cellqmi: device= must be an absolute path");
        return -1;
    }

    if ((vl = cf_find_flag(&v, "open", definition)) > 0) {
        if (vl == 4 && strncmp(v, "auto", 4) == 0)
            d->open_req = QMI_OPEN_AUTO;
        else if (vl == 5 && strncmp(v, "proxy", 5) == 0)
            d->open_req = QMI_OPEN_PROXY_ONLY;
        else if (vl == 6 && strncmp(v, "direct", 6) == 0)
            d->open_req = QMI_OPEN_DIRECT_ONLY;
        else {
            snprintf(msg, STATUS_MAX, "cellqmi: open= is auto, proxy or direct");
            return -1;
        }
    }

    if ((vl = cf_find_flag(&v, "framing", definition)) > 0) {
        if (vl == 4 && strncmp(v, "qmux", 4) == 0)
            d->framing = QMI_FRAMING_QMUX;
        else if (vl == 4 && strncmp(v, "mbim", 4) == 0)
            d->framing = QMI_FRAMING_MBIM;
        else {
            snprintf(msg, STATUS_MAX, "cellqmi: framing= is qmux or mbim");
            return -1;
        }
    }

    if ((vl = cf_find_flag(&v, "backend", definition)) > 0) {
        if (vl == 4 && strncmp(v, "auto", 4) == 0)
            d->backend = CELLQMI_BACKEND_AUTO;
        else if (vl == 3 && strncmp(v, "qmi", 3) == 0)
            d->backend = CELLQMI_BACKEND_QMI;
        else if (vl == 4 && strncmp(v, "mbim", 4) == 0)
            d->backend = CELLQMI_BACKEND_MBIM;
        else {
            snprintf(msg, STATUS_MAX, "cellqmi: backend= is auto, qmi or mbim");
            return -1;
        }
    }

    if ((vl = cf_find_flag(&v, "interval", definition)) > 0) {
        char num[16];
        char *end;
        if ((size_t) vl >= sizeof(num)) {
            snprintf(msg, STATUS_MAX, "cellqmi: interval= is a number of milliseconds");
            return -1;
        }
        memcpy(num, v, (size_t) vl);
        num[vl] = '\0';
        errno = 0;
        const unsigned long ms = strtoul(num, &end, 10);
        if (errno != 0 || *end != '\0' || ms < CELLQMI_INTERVAL_MIN_MS || ms > 3600000UL) {
            snprintf(msg, STATUS_MAX, "cellqmi: interval= is %d to 3600000 ms",
                     CELLQMI_INTERVAL_MIN_MS);
            return -1;
        }
        d->interval_ms = (unsigned int) ms;
    }

    return 1;
}

/* A stable UUID from the node's path */
static char *cellqmi_uuid(char *definition, const char *device) {
    char *v;
    int vl;
    char buf[64];
    const char *tag = "kismet_cap_cell_qmi";

    if ((vl = cf_find_flag(&v, "uuid", definition)) > 0)
        return strndup(v, (size_t) vl);

    snprintf(buf, sizeof(buf), "%08X-0000-0000-0000-%012X",
             adler32_csum((uint8_t *) tag, strlen(tag)) & 0xFFFFFFFF,
             adler32_csum((uint8_t *) device, strlen(device)));
    return strdup(buf);
}

/* "RM500Q-AE (qmi_wwan)": the USB product above a cdc-wdm node, if any */
static void describe_node(const char *device, const char *driver, char *out,
                          size_t outsz) {
    char path[512], product[128] = "";
    const char *name = strrchr(device, '/');
    name = name != NULL ? name + 1 : device;

    snprintf(path, sizeof(path), "/sys/class/usbmisc/%s/device/../product", name);
    FILE *f = fopen(path, "r");
    if (f != NULL) {
        if (fgets(product, sizeof(product), f) == NULL)
            product[0] = '\0';
        product[strcspn(product, "\r\n")] = '\0';
        fclose(f);
    }

    if (product[0] != '\0')
        snprintf(out, outsz, "%s (%s)", product, driver[0] ? driver : "?");
    else
        snprintf(out, outsz, "%s", driver[0] ? driver : "?");
}

/* Where a direct session records its client id (qmi_session_open_tracked):
 * ~/.kismet/cellqmi-<node>.cid, the caller's own directory, as cellat keeps
 * its lock state.  NULL (track nothing) when there is no ~/.kismet. */
static const char *cid_state_path(const char *dev, char *out, size_t outsz) {
    char home[1024], dir[1100], name[128];
    struct stat st;
    const char *base = strrchr(dev, '/');
    size_t n = 0;

    base = base != NULL ? base + 1 : dev;
    for (; *base != '\0' && n + 1 < sizeof(name); base++)
        name[n++] = (isalnum((unsigned char) *base) || *base == '-' || *base == '_')
                        ? *base : '_';
    name[n] = '\0';

    if (n == 0 || cell_home_dir(home, sizeof(home)) != 0)
        return NULL;
    snprintf(dir, sizeof(dir), "%s/.kismet", home);
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
        return NULL;
    if (snprintf(out, outsz, "%s/cellqmi-%s.cid", dir, name) >= (int) outsz)
        return NULL;
    return out;
}

static int is_char_device(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISCHR(st.st_mode);
}

/* The node `device` names, resolved once into `out`: what is checked and
 * what is opened, so a link changed after the check cannot move the open.
 * It must be a control node in /dev whatever framing= says, or a definition
 * could have the helper, as root, open and write any character device.
 * `rdev` gets its device number, which the open checks again.  Every failure
 * reads the same, so a definition cannot probe which paths exist. */
static int resolve_node(const char *device, char *out, size_t outsz, dev_t *rdev,
                        char *msg) {
    char resolved[PATH_MAX];
    struct stat st;

    if (realpath(device, resolved) == NULL || !qmi_node_path_ok(resolved) ||
        stat(resolved, &st) != 0 || !S_ISCHR(st.st_mode) ||
        snprintf(out, outsz, "%s", resolved) >= (int) outsz) {
        snprintf(msg, STATUS_MAX, "cellqmi: %s is not a QMI or MBIM control node "
                 "(/dev/cdc-wdmN, wwanNqmiM, wwanNmbimM, mhi_QMIN or mhi_MBIMN)",
                 device);
        return 0;
    }

    if (rdev != NULL)
        *rdev = st.st_rdev;
    return 1;
}

/* How the node will be read, before the open finds out.  The hardware string
 * goes out with the open reply, before the capture thread opens the node, so
 * for MBIM with backend=auto it names both: whether the function carries QMI
 * is known only once it answers (the open message then names the one used). */
static const char *planned_kind(qmi_framing_t framing, int via_proxy,
                                cellqmi_backend_t backend) {
    if (framing == QMI_FRAMING_QMUX)
        return qmi_transport_kind_name(via_proxy ? QMI_T_PROXY_QMUX : QMI_T_DIRECT_QMUX);
    if (backend == CELLQMI_BACKEND_QMI)
        return qmi_transport_kind_name(via_proxy ? QMI_T_PROXY_MBIM : QMI_T_DIRECT_MBIM);
    if (backend == CELLQMI_BACKEND_MBIM)
        return via_proxy ? "MBIM via mbim-proxy" : "MBIM";
    return via_proxy ? "QMI over MBIM or MBIM via mbim-proxy" : "QMI over MBIM or MBIM";
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
                   char *msg, char **uuid, cf_params_interface_t **ret_interface,
                   cf_params_spectrum_t **ret_spectrum) {
    cellqmi_def_t d;
    char node[PATH_MAX], driver[64], hw[256];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if (parse_definition(definition, &d, msg) != 1)
        return 0;

    /* Probing only looks: the node is opened by open, never here */
    if (!resolve_node(d.device, node, sizeof(node), NULL, msg))
        return 0;

    qmi_framing_t f = qmi_node_framing(node, driver, sizeof(driver));
    if (d.framing != QMI_FRAMING_NONE)
        f = d.framing;
    if (f == QMI_FRAMING_NONE)
        return 0;

    describe_node(node, driver, hw, sizeof(hw));
    (*ret_interface)->hardware = strdup(hw);
    *uuid = cellqmi_uuid(definition, d.device);

    return 1;
}

static void list_add(cf_params_list_interface_t **list, int *n, const char *name,
                     const char *device) {
    char driver[64], hw[256];

    if (*n >= CELLQMI_LIST_MAX || !is_char_device(device) ||
        qmi_node_framing(device, driver, sizeof(driver)) == QMI_FRAMING_NONE)
        return;

    cf_params_list_interface_t *li = calloc(1, sizeof(*li));
    if (li == NULL)
        return;

    describe_node(device, driver, hw, sizeof(hw));
    li->interface = strdup(name);
    li->hardware = strdup(hw);
    list[(*n)++] = li;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
                  cf_params_list_interface_t ***interfaces) {
    cf_params_list_interface_t **list = calloc(CELLQMI_LIST_MAX, sizeof(*list));
    int n = 0;
    struct dirent *e;
    char device[300];

    *interfaces = list;
    if (list == NULL)
        return 0;

    /* Listing reads sysfs and /dev names only; no node is opened */
    DIR *dir = opendir("/dev");
    if (dir == NULL)
        return 0;

    while ((e = readdir(dir)) != NULL) {
        if (!qmi_node_name_ok(e->d_name))
            continue;
        snprintf(device, sizeof(device), "/dev/%s", e->d_name);
        list_add(list, &n, e->d_name, device);
    }

    closedir(dir);
    return n;
}

static void close_session(local_qmi_t *local) {
    pthread_mutex_lock(&local->lock);
    if (local->session_open) {
        if (local->native)
            mbim_session_close(&local->msession);
        else
            qmi_session_close(&local->session);
        local->session_open = 0;
    }
    pthread_mutex_unlock(&local->lock);
}

/* Checks and plans only: the node is opened by the capture thread.  A cold
 * node can take a minute to hand over a client id (backlog, a recorded id to
 * release first, a retry), and while the open callback runs the helper
 * answers no pings: the server would drop a remote source after 15 s. */
int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
                  char *msg, uint32_t *dlt, char **uuid,
                  cf_params_interface_t **ret_interface,
                  cf_params_spectrum_t **ret_spectrum) {
    local_qmi_t *local = (local_qmi_t *) caph->userdata;
    cellqmi_def_t d;
    qmi_open_plan_t plan;
    char node[PATH_MAX], driver[64], hw[256], desc[512];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    const int pr = parse_definition(definition, &d, msg);
    if (pr == 0)
        snprintf(msg, STATUS_MAX, "cellqmi: not a QMI or MBIM control node; name "
                 "the node (cdc-wdm0) or use cellqmi:device=<path>");
    if (pr != 1)
        return -1;

    dev_t rdev;
    if (!resolve_node(d.device, node, sizeof(node), &rdev, msg))
        return -1;

    qmi_framing_t framing = qmi_node_framing(node, driver, sizeof(driver));
    if (d.framing != QMI_FRAMING_NONE)
        framing = d.framing;
    if (framing == QMI_FRAMING_NONE) {
        snprintf(msg, STATUS_MAX, "cellqmi: cannot tell whether %s speaks QMI or "
                 "MBIM (driver '%s'); set framing=qmux or framing=mbim", d.device,
                 driver[0] ? driver : "unknown");
        return -1;
    }

    qmi_open_plan(node, framing, d.open_req, &plan);
    if (plan.mode == QMI_PLAN_REFUSE) {
        snprintf(msg, STATUS_MAX, "cellqmi: %s", plan.reason);
        return -1;
    }

    if (d.backend == CELLQMI_BACKEND_MBIM && framing != QMI_FRAMING_MBIM) {
        snprintf(msg, STATUS_MAX, "cellqmi: backend=mbim needs an MBIM node; %s "
                 "speaks bare QMUX", d.device);
        return -1;
    }

    /* Nothing should be left from an earlier capture; if a cancelled one
     * left a session, release it rather than overwrite it */
    close_session(local);

    free(local->name);
    free(local->device);
    local->name = strdup(d.iface);
    local->device = strdup(d.device);
    if (local->name == NULL || local->device == NULL) {
        snprintf(msg, STATUS_MAX, "cellqmi: out of memory");
        return -1;
    }
    snprintf(local->node, sizeof(local->node), "%s", node);
    local->node_rdev = rdev;
    snprintf(local->driver, sizeof(local->driver), "%s", driver);
    snprintf(local->plan_reason, sizeof(local->plan_reason), "%s", plan.reason);
    local->framing = framing;
    local->via_proxy = plan.mode == QMI_PLAN_PROXY;
    local->backend = d.backend;
    local->state_path = cid_state_path(node, local->state, sizeof(local->state));
    local->interval_ms = d.interval_ms;
    local->open_req = d.open_req;
    local->no_service = -1;

    describe_node(node, driver, hw, sizeof(hw));
    snprintf(desc, sizeof(desc), "%s, %s", hw,
             planned_kind(framing, local->via_proxy, d.backend));
    (*ret_interface)->capif = strdup(d.device);
    (*ret_interface)->hardware = strdup(desc);
    *uuid = cellqmi_uuid(definition, d.device);

    snprintf(msg, STATUS_MAX, "cellqmi: opening %s, to poll every %u ms (%s)", d.device,
             local->interval_ms, plan.reason);

    return 1;
}

/* Open the session open_callback planned, in the capture thread: 1 open,
 * 0 failed or cancelled (`err`) */
static int session_connect(local_qmi_t *local, char *err, size_t errsz) {
    int ok, native = 0;

    if (local->framing == QMI_FRAMING_MBIM) {
        /* Read what the function offers, then keep the transport for
         * whichever backend reads it: no second MBIM_OPEN */
        ok = mbim_session_open(&local->msession, local->node, local->via_proxy,
                               CELLQMI_TIMEOUT_MS, &local->node_rdev, err, errsz);
        if (ok) {
            const mbim_caps_t *c = &local->msession.caps;
            const int can_native = c->have_base_stations || c->have_atds_location;

            if (local->backend != CELLQMI_BACKEND_MBIM && c->have_qmi) {
                ok = qmi_session_adopt(&local->session, &local->msession,
                                       CELLQMI_TIMEOUT_MS, local->state_path, err, errsz);
            } else if (local->backend == CELLQMI_BACKEND_QMI) {
                snprintf(err, errsz, "the MBIM function offers no QMI service "
                         "(backend=qmi)");
                mbim_session_close(&local->msession);
                ok = 0;
            } else if (!can_native) {
                snprintf(err, errsz, "the MBIM function offers neither QMI, "
                         "BASE_STATIONS_INFO nor the atds location (%d services)",
                         c->services);
                mbim_session_close(&local->msession);
                ok = 0;
            } else {
                native = 1;
            }
        }
    } else {
        ok = qmi_session_open_tracked(&local->session, local->node, local->framing,
                                      local->via_proxy, CELLQMI_TIMEOUT_MS,
                                      local->state_path, &local->node_rdev, err, errsz);
    }

    pthread_mutex_lock(&local->lock);
    local->native = native;
    local->session_open = ok;
    pthread_mutex_unlock(&local->lock);

    return ok;
}

/* What the open found, once it is done */
static void report_open(kis_capture_handler_t *caph, local_qmi_t *local) {
    char note[STATUS_MAX];
    const char *kind_name;

    if (local->native)
        kind_name = local->via_proxy ? "MBIM via mbim-proxy" : "MBIM";
    else
        kind_name = qmi_transport_kind_name(local->session.t.kind);

    snprintf(note, sizeof(note), "cellqmi: polling %s every %u ms (%s; %s)",
             local->device, local->interval_ms, kind_name, local->plan_reason);
    cf_send_message(caph, note, MSGFLAG_INFO);

    if (local->native) {
        const mbim_caps_t *c = &local->msession.caps;
        snprintf(note, sizeof(note), "cellqmi: %s: %s; reading MBIM's own services: "
                 "%s%s", local->device,
                 c->have_qmi ? "QMI over MBIM not used (backend=mbim)" : "no QMI over MBIM",
                 c->have_base_stations ? "BASE_STATIONS_INFO" : "atds location",
                 c->have_base_stations && c->have_atds_location ? ", atds location" : "");
        cf_send_message(caph, note, MSGFLAG_INFO);
    }

    if (!local->native && local->session.stale_released) {
        snprintf(note, sizeof(note), "cellqmi: %s: released NAS client id %u, left "
                 "allocated by an earlier cellqmi that ended without releasing it%s",
                 local->device, (unsigned int) local->session.stale_cid,
                 local->session.stale_answered ? "" : " (the modem did not confirm)");
        cf_send_message(caph, note, MSGFLAG_INFO);
    }

    if (!local->native && local->session.late_released > 0) {
        snprintf(note, sizeof(note), "cellqmi: %s: released %d NAS client id(s) the "
                 "modem granted after their request had timed out", local->device,
                 local->session.late_released);
        cf_send_message(caph, note, MSGFLAG_INFO);
    }

    if (!local->native && local->session.waits_dropped > 0) {
        snprintf(note, sizeof(note), "cellqmi: %s: %d earlier NAS client id "
                 "request(s) were never answered; if the modem granted them anyway, "
                 "those ids stay allocated until it resets", local->device,
                 local->session.waits_dropped);
        cf_send_message(caph, note, MSGFLAG_INFO);
    }
}

/* One native MBIM query: 1 with a successful reply's information buffer
 * copied to `out`, 0 missed or refused, -1 the transport failed */
static int mbim_read(local_qmi_t *local, const uint8_t uuid[16], uint32_t cid,
                     const uint8_t *info, size_t info_len, uint8_t *out, size_t cap,
                     size_t *outlen, char *err, size_t errsz) {
    uint8_t buf[QMI_MSG_MAX];
    mbim_msg_t done;

    const int r = mbim_session_query(&local->msession, uuid, cid, info, info_len, buf,
                                     sizeof(buf), &done, CELLQMI_TIMEOUT_MS, err, errsz);
    if (r != 1)
        return r;
    if (done.status != 0 || done.info_len > cap)
        return 0;
    memcpy(out, done.info, done.info_len);
    *outlen = done.info_len;
    return 1;
}

static int poll_mbim(local_qmi_t *local, char rows[][QMI_OBS_JSON_MAX], int *nrows,
                     qmi_obs_stats_t *st, char *err, size_t errsz) {
    static uint8_t buf[4][QMI_MSG_MAX];
    size_t len[4] = { 0, 0, 0, 0 };
    int got[4] = { 0, 0, 0, 0 };
    uint8_t req[32];
    mbim_register_t reg;
    mbim_base_stations_t bs;
    mbim_atds_location_t loc;
    mbim_atds_signal_t sig;
    struct timeval tv;
    int r;

    *nrows = 0;

    pthread_mutex_lock(&local->lock);
    if (!local->session_open) {
        pthread_mutex_unlock(&local->lock);
        snprintf(err, errsz, "session closed");
        return -1;
    }
    const mbim_caps_t c = local->msession.caps;

    r = mbim_read(local, mbim_uuid_basic_connect, MBIM_CID_REGISTER_STATE, NULL, 0,
                  buf[0], QMI_MSG_MAX, &len[0], err, errsz);
    got[0] = r == 1;
    if (r >= 0 && c.have_base_stations) {
        const size_t rl = mbim_base_stations_req(req, sizeof(req), CELLQMI_MBIM_CELLS_MAX);
        r = mbim_read(local, mbim_uuid_ms_basic_connect_ext, MBIM_CID_BASE_STATIONS,
                      req, rl, buf[1], QMI_MSG_MAX, &len[1], err, errsz);
        got[1] = r == 1;
    }
    if (r >= 0 && c.have_atds_location) {
        r = mbim_read(local, mbim_uuid_atds, MBIM_CID_ATDS_LOCATION, NULL, 0, buf[2],
                      QMI_MSG_MAX, &len[2], err, errsz);
        got[2] = r == 1;
    }
    if (r >= 0 && c.have_atds_signal) {
        r = mbim_read(local, mbim_uuid_atds, MBIM_CID_ATDS_SIGNAL, NULL, 0, buf[3],
                      QMI_MSG_MAX, &len[3], err, errsz);
        got[3] = r == 1;
    }
    pthread_mutex_unlock(&local->lock);

    if (r < 0)
        return -1;
    if (!got[0] && !got[1] && !got[2] && !got[3])
        return 0;

    const int have_reg = got[0] && mbim_register_parse(buf[0], len[0], &reg);
    const int have_bs = got[1] && mbim_base_stations_parse(buf[1], len[1], &bs);
    const int have_loc = got[2] && mbim_atds_location_parse(buf[2], len[2], &loc);
    const int have_sig = got[3] && mbim_atds_signal_parse(buf[3], len[3], &sig);

    gettimeofday(&tv, NULL);
    *nrows = mbim_obs_build(have_reg ? &reg : NULL, have_bs ? &bs : NULL,
                            have_loc ? &loc : NULL, have_sig ? &sig : NULL,
                            (double) tv.tv_sec + tv.tv_usec / 1e6, rows, MBIM_OBS_MAX, st);
    return 1;
}

/* One poll: 1 polled (possibly with no cell), 0 the modem missed it,
 * -1 the transport failed (`err`) */
static int poll_once(local_qmi_t *local, char rows[][QMI_OBS_JSON_MAX], int *nrows,
                     qmi_obs_stats_t *st, char *err, size_t errsz) {
    static const uint16_t msgs[3] = {
        QMI_NAS_GET_SYSTEM_INFO, QMI_NAS_GET_CELL_LOCATION_INFO, QMI_NAS_GET_SIGNAL_INFO,
    };
    uint8_t buf[3][QMI_MSG_MAX];
    qmux_msg_t m[3];
    int got[3] = { 0, 0, 0 };
    qmi_sysinfo_t si;
    qmi_cellloc_t cl;
    qmi_signal_t sig;
    struct timeval tv;

    *nrows = 0;

    if (local->native)
        return poll_mbim(local, rows, nrows, st, err, errsz);

    pthread_mutex_lock(&local->lock);
    if (!local->session_open) {
        pthread_mutex_unlock(&local->lock);
        snprintf(err, errsz, "session closed");
        return -1;
    }
    for (int i = 0; i < 3; i++) {
        const int r = qmi_session_nas(&local->session, msgs[i], buf[i], QMI_MSG_MAX,
                                      &m[i], CELLQMI_TIMEOUT_MS, err, errsz);
        if (r < 0) {
            pthread_mutex_unlock(&local->lock);
            return -1;
        }
        got[i] = r == 1;
    }
    pthread_mutex_unlock(&local->lock);

    if (!got[0] && !got[1] && !got[2])
        return 0;

    const int have_si = got[0] && qmi_nas_sysinfo_decode(&m[0], &si);
    const int have_cl = got[1] && qmi_nas_cellloc_decode(&m[1], &cl);
    const int have_sig = got[2] && qmi_nas_signal_decode(&m[2], &sig);

    gettimeofday(&tv, NULL);
    *nrows = qmi_obs_build(have_si ? &si : NULL, have_cl ? &cl : NULL,
                           have_sig ? &sig : NULL,
                           (double) tv.tv_sec + tv.tv_usec / 1e6, rows, QMI_OBS_MAX, st);
    return 1;
}

static int send_row(kis_capture_handler_t *caph, const char *row) {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    for (;;) {
        const int r = cf_send_json(caph, NULL, 0, NULL, NULL, tv, "CellModem", row);
        if (r > 0)
            return 1;
        if (r < 0)
            return 0;
        if (stopping(caph))
            return 0;
        cf_handler_wait_ringbuffer(caph);
    }
}

void capture_thread(kis_capture_handler_t *caph) {
    local_qmi_t *local = (local_qmi_t *) caph->userdata;
    static char rows[QMI_OBS_MAX][QMI_OBS_JSON_MAX];
    char err[STATUS_MAX], text[STATUS_MAX + 128];
    int missed = 0;

    /* A close or shutdown during the open cancels it (open_stop) */
    if (!session_connect(local, err, sizeof(err))) {
        if (!stopping(caph)) {
            snprintf(text, sizeof(text), "cellqmi: %s: %s", local->device, err);
            cf_send_error(caph, 0, text);
        }
        cf_handler_spindown(caph);
        return;
    }

    report_open(caph, local);

    while (!stopping(caph)) {
        const long start = now_ms();
        qmi_obs_stats_t st;
        int nrows = 0;

        const int r = poll_once(local, rows, &nrows, &st, err, sizeof(err));
        if (r < 0) {
            snprintf(text, sizeof(text), "%s: %s", local->device, err);
            cf_send_error(caph, 0, text);
            break;
        }

        if (r == 0) {
            if (++missed >= CELLQMI_MISSED_MAX) {
                snprintf(text, sizeof(text), "%s: the modem stopped answering %s "
                         "(%d polls missed)", local->device, local->native ? "MBIM" : "QMI",
                         missed);
                cf_send_error(caph, 0, text);
                break;
            }
        } else {
            missed = 0;

            if (st.no_service != local->no_service) {
                if (st.no_service || local->no_service == 1) {
                    snprintf(text, sizeof(text), "%s: %s", local->device,
                             st.no_service ? "no cellular service" : "cellular service back");
                    cf_send_message(caph, text, MSGFLAG_INFO);
                }
                local->no_service = st.no_service;
            }

            for (int i = 0; i < nrows; i++) {
                if (!send_row(caph, rows[i]))
                    break;
            }
        }

        while (!stopping(caph) && now_ms() - start < (long) local->interval_ms)
            usleep(50 * 1000);
    }

    close_session(local);

    cf_handler_spindown(caph);
}

static int open_stop(void *arg) {
    return stopping((kis_capture_handler_t *) arg);
}

int main(int argc, char *argv[]) {
    static local_qmi_t local;

    memset(&local, 0, sizeof(local));
    pthread_mutex_init(&local.lock, NULL);
    local.session.t.fd = -1;
    local.msession.t.fd = -1;
    local.interval_ms = CELLQMI_INTERVAL_MS;
    local.no_service = -1;
    g_local = &local;

    kis_capture_handler_t *caph = cf_handler_init("cellqmi");
    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }
    local.caph = caph;

    cf_handler_set_userdata(caph, &local);
    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
    cf_handler_set_listdevices_cb(caph, list_callback);
    cf_handler_set_capture_cb(caph, capture_thread);
    cf_handler_set_close_grace(caph, CELLQMI_CLOSE_GRACE_MS);
    qmi_transport_set_open_cancel(open_stop, caph);

    int r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    install_signal_release();

    cf_handler_remote_capture(caph);

    /* While still privileged: which processes hold which nodes.  After the
     * capability drop another root process's fd table cannot be read, and
     * those are the holders the open order must see. */
    cell_discover_baseline();

    cf_jail_filesystem(caph);
    cf_drop_most_caps(caph);

    cf_handler_loop(caph);

    /* The loop can end (the server gone) with the capture thread still
     * holding the session */
    close_session(&local);

    cf_handler_shutdown(caph);

    free(local.name);
    free(local.device);

    return 0;
}
