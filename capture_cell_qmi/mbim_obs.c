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
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "mbim_obs.h"

#define LTE_ECI_MAX 0x0FFFFFFFu
#define LTE_TAC_MAX 0xFFFFu
#define LTE_PCI_MAX 503u
#define EARFCN_MAX  262143u
/* At or below this, an MBIM EARFCN may be a wrapped 16-bit value */
#define EARFCN_WRAP 65535u

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

/* A value in tenths, as a JSON number with one decimal; nothing if absent */
static void jb_x10(jbuf_t *j, const char *key, int32_t v) {
    if (v == INT32_MIN)
        return;
    const int32_t a = v < 0 ? -v : v;
    jb_add(j, ",\"%s\":%s%d.%d", key, v < 0 ? "-" : "", (int) (a / 10), (int) (a % 10));
}

static void jb_open(jbuf_t *j, char *buf, size_t cap) {
    j->buf = buf;
    j->cap = cap;
    j->len = 0;
    j->overflow = 0;
    buf[0] = '\0';
    jb_add(j, "{\"rat\":\"LTE\"");
}

static int jb_close(jbuf_t *j, int serving, const char *origin, double captured_at) {
    jb_add(j, ",\"is_serving\":%s,\"observation_type\":\"%s\"",
           serving ? "true" : "false", serving ? "serving" : "observation");
    jb_add(j, ",\"prov\":{\"src\":\"mbim\",\"origin\":\"%s\",\"captured_at\":%.3f}}",
           origin, captured_at);
    return !j->overflow;
}

static int earfcn_proven(uint32_t e) {
    return e != MBIM_UNKNOWN_U32 && e > EARFCN_WRAP && e <= EARFCN_MAX;
}

static int cell_id_ok(uint32_t id) {
    return id != MBIM_UNKNOWN_U32 && id > 0 && id <= LTE_ECI_MAX;
}

static int tac_ok(uint32_t tac) {
    return tac != MBIM_UNKNOWN_U32 && tac > 0 && tac <= LTE_TAC_MAX;
}

static int serving_bs(char *row, size_t cap, const mbim_lte_cell_t *c,
                      const mbim_register_t *reg, const mbim_atds_signal_t *sig,
                      double captured_at, qmi_obs_stats_t *st) {
    char mcc[4], mnc[4];
    int have_plmn = mbim_provider_split(c->provider, mcc, mnc);
    jbuf_t j;

    if (!have_plmn && reg != NULL)
        have_plmn = mbim_provider_split(reg->provider, mcc, mnc);

    const int full = have_plmn && cell_id_ok(c->cell_id);
    const int pci_ok = c->pci <= LTE_PCI_MAX;
    const int proven = earfcn_proven(c->earfcn);

    if (!proven && c->earfcn != MBIM_UNKNOWN_U32)
        st->unproven_earfcn++;
    if (!full && !(pci_ok && proven))
        return 0;

    jb_open(&j, row, cap);
    if (full) {
        jb_add(&j, ",\"mcc\":\"%s\",\"mnc\":\"%s\"", mcc, mnc);
        if (tac_ok(c->tac))
            jb_add(&j, ",\"tac\":%" PRIu32, c->tac);
        jb_add(&j, ",\"cell_id\":%" PRIu32, c->cell_id);
    }
    if (pci_ok)
        jb_add(&j, ",\"pci\":%" PRIu32, c->pci);
    if (proven)
        jb_add(&j, ",\"earfcn\":%" PRIu32, c->earfcn);

    int32_t rsrp = mbim_lte_rsrp_x10(c->rsrp), rsrq = mbim_lte_rsrq_x10(c->rsrq);
    if (rsrp == INT32_MIN && sig != NULL)
        rsrp = sig->rsrp_x10;
    if (rsrq == INT32_MIN && sig != NULL)
        rsrq = sig->rsrq_x10;
    jb_x10(&j, "rsrp", rsrp);
    jb_x10(&j, "rsrq", rsrq);
    if (sig != NULL) {
        jb_x10(&j, "snr", sig->snr_x10);
        if (sig->rssi != INT32_MIN)
            jb_add(&j, ",\"rssi\":%d", (int) sig->rssi);
    }

    return jb_close(&j, 1, "MBIM:BSI", captured_at);
}

static int serving_atds(char *row, size_t cap, const mbim_atds_location_t *loc,
                        const mbim_register_t *reg, const mbim_atds_signal_t *sig,
                        double captured_at) {
    char mcc[4], mnc[4];
    jbuf_t j;

    /* A TAC says LTE; a LAC alone is a 2G/3G camp, not read here */
    if (reg == NULL || !mbim_provider_split(reg->provider, mcc, mnc) ||
        !tac_ok(loc->tac) || !cell_id_ok(loc->cell_id))
        return 0;

    jb_open(&j, row, cap);
    jb_add(&j, ",\"mcc\":\"%s\",\"mnc\":\"%s\",\"tac\":%" PRIu32 ",\"cell_id\":%" PRIu32,
           mcc, mnc, loc->tac, loc->cell_id);
    if (sig != NULL) {
        jb_x10(&j, "rsrp", sig->rsrp_x10);
        jb_x10(&j, "rsrq", sig->rsrq_x10);
        jb_x10(&j, "snr", sig->snr_x10);
        if (sig->rssi != INT32_MIN)
            jb_add(&j, ",\"rssi\":%d", (int) sig->rssi);
    }
    return jb_close(&j, 1, "MBIM:ATDS", captured_at);
}

static int neighbour(char *row, size_t cap, const mbim_lte_cell_t *c, double captured_at) {
    jbuf_t j;

    jb_open(&j, row, cap);
    jb_add(&j, ",\"pci\":%" PRIu32 ",\"earfcn\":%" PRIu32, c->pci, c->earfcn);
    jb_x10(&j, "rsrp", mbim_lte_rsrp_x10(c->rsrp));
    jb_x10(&j, "rsrq", mbim_lte_rsrq_x10(c->rsrq));
    return jb_close(&j, 0, "MBIM:BSI", captured_at);
}

int mbim_obs_build(const mbim_register_t *reg, const mbim_base_stations_t *bs,
                   const mbim_atds_location_t *loc, const mbim_atds_signal_t *sig,
                   double captured_at, char rows[][QMI_OBS_JSON_MAX], int max_rows,
                   qmi_obs_stats_t *stats) {
    qmi_obs_stats_t scratch;
    qmi_obs_stats_t *st = stats != NULL ? stats : &scratch;
    int n = 0;

    memset(st, 0, sizeof(*st));

    if (max_rows > 0 && bs != NULL && bs->have_lte_serving) {
        if (serving_bs(rows[n], QMI_OBS_JSON_MAX, &bs->lte_serving, reg, sig,
                       captured_at, st))
            n++;
    } else if (max_rows > 0 && loc != NULL) {
        if (serving_atds(rows[n], QMI_OBS_JSON_MAX, loc, reg, sig, captured_at))
            n++;
    }
    st->serving = n;

    if (bs != NULL) {
        for (int i = 0; i < bs->nneighbours && n < max_rows; i++) {
            const mbim_lte_cell_t *c = &bs->neighbours[i];

            if (c->pci > LTE_PCI_MAX)
                continue;
            if (bs->have_lte_serving && c->pci == bs->lte_serving.pci &&
                (c->earfcn == MBIM_UNKNOWN_U32 || c->earfcn == bs->lte_serving.earfcn))
                continue;
            if (!earfcn_proven(c->earfcn)) {
                st->unproven_earfcn++;
                continue;
            }
            if (neighbour(rows[n], QMI_OBS_JSON_MAX, c, captured_at))
                n++;
        }
    }
    st->neighbours = n - st->serving;

    if (n == 0 && (reg == NULL || !mbim_registered(reg->state)))
        st->no_service = 1;

    return n;
}
