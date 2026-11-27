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

    One poll's NAS replies -> CellModem JSON observations, the record the
    cellular phy already reads from the AT and DIAG sources.

    Rules:
      - An LTE EARFCN is written only when the modem's 32-bit TLV proves it.
        A bare 16-bit value may be a wrapped band 65+ channel, and the phy
        derives a band from any EARFCN it is given.  A neighbour with no
        proven EARFCN has no identity at all, so it is dropped and counted.
      - No service (system info none or power-save on every RAT) produces no
        rows.  Cell location's "no network found" decides only when there is
        no system info: a modem the network refused answers it while system
        info still names the cell it camps on.
      - A limited-service camp (no SIM, registration refused) is still a real
        cell and is reported, from system info when cell location has none.
*/

#ifndef __QMI_OBS_H__
#define __QMI_OBS_H__

#include <stddef.h>

#include "qmi_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QMI_OBS_MAX (1 + QMI_LTE_CELLS_MAX + QMI_LTE_FREQS_MAX * QMI_LTE_CELLS_MAX)
#define QMI_OBS_JSON_MAX 512

typedef struct {
    int no_service;           /* this poll found no cell */
    int serving;              /* serving-cell rows written */
    int neighbours;           /* neighbour rows written */
    int unproven_earfcn;      /* rows dropped or stripped for an unproven EARFCN */
} qmi_obs_stats_t;

/* Build the observations for one poll.  Any reply may be NULL (not read, or
 * the read failed).  Returns the number of rows written to `rows`. */
int qmi_obs_build(const qmi_sysinfo_t *si, const qmi_cellloc_t *cl,
                  const qmi_signal_t *sig, double captured_at,
                  char rows[][QMI_OBS_JSON_MAX], int max_rows,
                  qmi_obs_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif
