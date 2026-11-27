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

    One native-MBIM poll -> CellModem JSON observations (prov.src "mbim"),
    under the rules of the QMI observations (qmi_obs.h):

      - An EARFCN is written only when it is above 65535.  MBIM carries a
        32-bit field, but firmware fills it from a 16-bit value (a band 65+
        channel such as 65636 arrives as 100), so any lower value may be a
        wrapped channel of another band.  A neighbour without a written
        EARFCN has no identity, so it is dropped and counted.
      - The serving cell comes from BASE_STATIONS_INFO when the modem has
        it, else from atds LOCATION.  The PLMN comes from the cell's own
        provider id, else from REGISTER_STATE.
      - No row and no registration is no service.  A registered modem whose
        reads name no cell (NR SA on MBIM 1.0) is not "no service": it is a
        known gap, and no row is written.
      - BASE_STATIONS_INFO lists the serving cell among the neighbours too;
        a neighbour with the serving PCI is not written again.
*/

#ifndef __MBIM_OBS_H__
#define __MBIM_OBS_H__

#include "mbim_wire.h"
#include "qmi_obs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MBIM_OBS_MAX (1 + MBIM_LTE_NEIGHBOURS_MAX)

/* Any input may be NULL (not read, or the read failed) */
int mbim_obs_build(const mbim_register_t *reg, const mbim_base_stations_t *bs,
                   const mbim_atds_location_t *loc, const mbim_atds_signal_t *sig,
                   double captured_at, char rows[][QMI_OBS_JSON_MAX], int max_rows,
                   qmi_obs_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif
