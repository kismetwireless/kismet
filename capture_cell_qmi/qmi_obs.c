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

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "qmi_obs.h"

/* Identity bounds: a 28-bit LTE ECI, a 36-bit NR NCI, a 24-bit NR TAC */
#define LTE_ECI_MAX 0x0FFFFFFFu
#define NR_NCI_MAX  ((UINT64_C(1) << 36) - 1)
#define NR_TAC_MAX  0xFFFFFFu
#define LTE_PCI_MAX 503
#define NR_PCI_MAX  1007

typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    int overflow;
} jbuf_t;

static void jb_add(jbuf_t *j, const char *fmt, ...) {
    va_list ap;

    if (j->overflow)
        return;

    va_start(ap, fmt);
    const int r = vsnprintf(j->buf + j->len, j->cap - j->len, fmt, ap);
    va_end(ap);

    if (r < 0 || (size_t) r >= j->cap - j->len) {
        j->overflow = 1;
        return;
    }

    j->len += (size_t) r;
}

/* A value in tenths, as a JSON number with one decimal */
static void jb_x10(jbuf_t *j, const char *key, int v) {
    const int a = v < 0 ? -v : v;
    jb_add(j, ",\"%s\":%s%d.%d", key, v < 0 ? "-" : "", a / 10, a % 10);
}

static void jb_open(jbuf_t *j, char *buf, size_t cap, const char *rat) {
    j->buf = buf;
    j->cap = cap;
    j->len = 0;
    j->overflow = 0;
    buf[0] = '\0';
    jb_add(j, "{\"rat\":\"%s\"", rat);
}

static int jb_close(jbuf_t *j, int serving, const char *origin, double captured_at) {
    jb_add(j, ",\"is_serving\":%s,\"observation_type\":\"%s\"",
           serving ? "true" : "false", serving ? "serving" : "observation");
    jb_add(j, ",\"prov\":{\"src\":\"qmi\",\"origin\":\"%s\",\"captured_at\":%.3f}}",
           origin, captured_at);
    return !j->overflow;
}

static int status_camped(int s) {
    return s == QMI_SRV_LIMITED || s == QMI_SRV_AVAILABLE;
}

/* System info names every RAT's service status, and decides.  Cell location
 * answers "no network found" both out of coverage and on a camp the network
 * refused (registration denied, forbidden PLMN), where system info still
 * names the cell; only without system info is that answer taken alone. */
static int no_service(const qmi_sysinfo_t *si, const qmi_cellloc_t *cl) {
    if (si != NULL && si->error == 0)
        return !status_camped(si->lte_status) && !status_camped(si->nr_status);

    return cl != NULL && cl->error == QMI_ERR_NO_NETWORK_FOUND;
}

/* A neighbour: PCI plus a proven EARFCN is its whole identity */
static int lte_neighbour(char *row, size_t cap, const qmi_lte_cell_t *c,
                         uint32_t earfcn, double captured_at) {
    jbuf_t j;

    if (c->pci > LTE_PCI_MAX)
        return 0;

    jb_open(&j, row, cap, "LTE");
    jb_add(&j, ",\"pci\":%u,\"earfcn\":%" PRIu32, (unsigned int) c->pci, earfcn);
    jb_x10(&j, "rsrp", c->rsrp_x10);
    jb_x10(&j, "rsrq", c->rsrq_x10);
    jb_x10(&j, "rssi", c->rssi_x10);
    return jb_close(&j, 0, "NAS:0x0043", captured_at);
}

static const qmi_lte_cell_t *find_pci(const qmi_lte_cell_t *cells, int n,
                                      uint16_t pci) {
    for (int i = 0; i < n; i++) {
        if (cells[i].pci == pci)
            return &cells[i];
    }
    return NULL;
}

static int lte_serving_cellloc(char *row, size_t cap, const qmi_cellloc_t *cl,
                               const qmi_signal_t *sig, double captured_at,
                               qmi_obs_stats_t *st) {
    const int full = cl->lte_mcc[0] != '\0' && cl->lte_cell_id > 0 &&
        cl->lte_cell_id <= LTE_ECI_MAX;
    const int pci_ok = cl->lte_pci <= LTE_PCI_MAX;
    jbuf_t j;

    if (!cl->lte_earfcn_proven)
        st->unproven_earfcn++;

    /* Neither a global identity nor PCI + a proven EARFCN: nothing to key */
    if (!full && !(pci_ok && cl->lte_earfcn_proven))
        return 0;

    jb_open(&j, row, cap, "LTE");
    if (full) {
        jb_add(&j, ",\"mcc\":\"%s\",\"mnc\":\"%s\",\"tac\":%u,\"cell_id\":%" PRIu32,
               cl->lte_mcc, cl->lte_mnc, (unsigned int) cl->lte_tac,
               cl->lte_cell_id);
    }
    if (pci_ok)
        jb_add(&j, ",\"pci\":%u", (unsigned int) cl->lte_pci);
    if (cl->lte_earfcn_proven)
        jb_add(&j, ",\"earfcn\":%" PRIu32, cl->lte_earfcn);

    if (sig != NULL && sig->error == 0 && sig->have_lte) {
        jb_add(&j, ",\"rsrp\":%d,\"rsrq\":%d,\"rssi\":%d", (int) sig->lte_rsrp,
               (int) sig->lte_rsrq, (int) sig->lte_rssi);
        jb_x10(&j, "snr", sig->lte_snr_x10);
    } else {
        const qmi_lte_cell_t *c = find_pci(cl->intra, cl->nintra, cl->lte_pci);
        if (c != NULL) {
            jb_x10(&j, "rsrp", c->rsrp_x10);
            jb_x10(&j, "rsrq", c->rsrq_x10);
            jb_x10(&j, "rssi", c->rssi_x10);
        }
    }

    return jb_close(&j, 1, "NAS:0x0043", captured_at);
}

static int nr_serving_cellloc(char *row, size_t cap, const qmi_cellloc_t *cl,
                              double captured_at) {
    const int full = cl->nr_mcc[0] != '\0' && cl->nr_cell_id > 0 &&
        cl->nr_cell_id <= NR_NCI_MAX;
    const int pci_ok = cl->nr_pci <= NR_PCI_MAX;
    jbuf_t j;

    if (!full && !(pci_ok && cl->have_nr_arfcn))
        return 0;

    jb_open(&j, row, cap, "NR");
    if (full) {
        jb_add(&j, ",\"mcc\":\"%s\",\"mnc\":\"%s\",\"cell_id\":%" PRIu64,
               cl->nr_mcc, cl->nr_mnc, cl->nr_cell_id);
        if (cl->nr_tac <= NR_TAC_MAX)
            jb_add(&j, ",\"tac\":%" PRIu32, cl->nr_tac);
    }
    if (pci_ok)
        jb_add(&j, ",\"pci\":%u", (unsigned int) cl->nr_pci);
    if (cl->have_nr_arfcn)
        jb_add(&j, ",\"earfcn\":%" PRIu32, cl->nr_arfcn);
    if (cl->nr_rsrp_x10 != INT16_MIN)
        jb_x10(&j, "rsrp", cl->nr_rsrp_x10);
    if (cl->nr_rsrq_x10 != INT16_MIN)
        jb_x10(&j, "rsrq", cl->nr_rsrq_x10);
    if (cl->nr_snr_x10 != INT16_MIN)
        jb_x10(&j, "snr", cl->nr_snr_x10);

    return jb_close(&j, 1, "NAS:0x0043", captured_at);
}

/* Cell location named no cell of this RAT, but system info did */
static int serving_sysinfo(char *row, size_t cap, const char *rat,
                           const qmi_sysinfo_rat_t *r, int have_id, uint64_t id,
                           uint64_t id_max, int have_tac, uint32_t tac,
                           const qmi_signal_t *sig, double captured_at) {
    jbuf_t j;

    if (!have_id || id == 0 || id > id_max || r->mcc[0] == '\0')
        return 0;

    jb_open(&j, row, cap, rat);
    jb_add(&j, ",\"mcc\":\"%s\",\"mnc\":\"%s\",\"cell_id\":%" PRIu64, r->mcc,
           r->mnc, id);
    if (have_tac)
        jb_add(&j, ",\"tac\":%" PRIu32, tac);

    if (sig != NULL && sig->error == 0) {
        if (strcmp(rat, "LTE") == 0 && sig->have_lte) {
            jb_add(&j, ",\"rsrp\":%d,\"rsrq\":%d,\"rssi\":%d", (int) sig->lte_rsrp,
                   (int) sig->lte_rsrq, (int) sig->lte_rssi);
            jb_x10(&j, "snr", sig->lte_snr_x10);
        } else if (strcmp(rat, "NR") == 0) {
            if (sig->have_nr_rsrp)
                jb_add(&j, ",\"rsrp\":%d", (int) sig->nr_rsrp);
            if (sig->have_nr_rsrq)
                jb_add(&j, ",\"rsrq\":%d", (int) sig->nr_rsrq);
            if (sig->have_nr_snr)
                jb_x10(&j, "snr", sig->nr_snr_x10);
        }
    }

    return jb_close(&j, 1, "NAS:0x004D", captured_at);
}

int qmi_obs_build(const qmi_sysinfo_t *si, const qmi_cellloc_t *cl,
                  const qmi_signal_t *sig, double captured_at,
                  char rows[][QMI_OBS_JSON_MAX], int max_rows,
                  qmi_obs_stats_t *stats) {
    qmi_obs_stats_t scratch;
    qmi_obs_stats_t *st = stats != NULL ? stats : &scratch;
    int n = 0;

    memset(st, 0, sizeof(*st));

    if (no_service(si, cl)) {
        st->no_service = 1;
        return 0;
    }

    const int cl_ok = cl != NULL && cl->error == 0;
    const int si_ok = si != NULL && si->error == 0;

    /* Serving cells */
    if (n < max_rows && cl_ok && cl->have_lte) {
        if (lte_serving_cellloc(rows[n], QMI_OBS_JSON_MAX, cl, sig, captured_at, st))
            n++;
    } else if (n < max_rows && si_ok && status_camped(si->lte_status) && si->lte.have) {
        if (serving_sysinfo(rows[n], QMI_OBS_JSON_MAX, "LTE", &si->lte,
                            si->lte.have_cell_id, si->lte.cell_id, LTE_ECI_MAX,
                            si->lte.have_tac, si->lte.tac, sig, captured_at))
            n++;
    }

    if (n < max_rows && cl_ok && cl->have_nr) {
        if (nr_serving_cellloc(rows[n], QMI_OBS_JSON_MAX, cl, captured_at))
            n++;
    } else if (n < max_rows && si_ok && status_camped(si->nr_status) && si->nr.have) {
        if (serving_sysinfo(rows[n], QMI_OBS_JSON_MAX, "NR", &si->nr,
                            si->have_nr_cell_id, si->nr_cell_id, NR_NCI_MAX,
                            si->have_nr_tac, si->nr_tac, sig, captured_at))
            n++;
    }

    st->serving = n;

    if (!cl_ok || !cl->have_lte)
        return n;

    /* Intra-frequency neighbours share the serving EARFCN */
    for (int i = 0; i < cl->nintra && n < max_rows; i++) {
        if (cl->intra[i].pci == cl->lte_pci)
            continue;
        if (!cl->lte_earfcn_proven) {
            st->unproven_earfcn++;
            continue;
        }
        if (lte_neighbour(rows[n], QMI_OBS_JSON_MAX, &cl->intra[i], cl->lte_earfcn,
                          captured_at))
            n++;
    }

    for (int f = 0; f < cl->ninter; f++) {
        const qmi_lte_freq_t *fq = &cl->inter[f];
        for (int i = 0; i < fq->ncells && n < max_rows; i++) {
            if (!fq->earfcn_proven) {
                st->unproven_earfcn++;
                continue;
            }
            if (lte_neighbour(rows[n], QMI_OBS_JSON_MAX, &fq->cells[i], fq->earfcn,
                              captured_at))
                n++;
        }
    }

    st->neighbours = n - st->serving;
    return n;
}
