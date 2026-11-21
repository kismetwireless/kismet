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

    cellat_generic -- the generic 3GPP poll's per-source probe state, kept in
    local_cell_t and driven by cellat_std3gpp.inc's stdat_generic_* helpers.
*/

#ifndef __CELLAT_GENERIC_H__
#define __CELLAT_GENERIC_H__

typedef struct {
    int      probed;    /* every test form settled, or the round cap reached */
    int      rounds;
    unsigned skip;      /* bit i: STDAT_GENERIC_READ[i] refused, not polled */
    unsigned settled;   /* bit i: test form answered for good, not re-probed */
} stdat_generic_t;

#endif
