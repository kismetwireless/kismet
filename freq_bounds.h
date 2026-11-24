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

#ifndef __FREQ_BOUNDS_H__
#define __FREQ_BOUNDS_H__

/* Plausible frequencies from any source, in kHz.  Helpers, remotes, logs and JSON
 * decoders may send anything; NaN fails every comparison, and the cap is past every
 * band Kismet handles while keeping the kHz value inside an int.  Below 1 kHz the
 * tracker's int frequency count would truncate it to 0, which means "no frequency".
 * Also included from C (capture_kismetdb); the macro evaluates its argument twice. */
#define FREQ_BOUNDS_MIN_KHZ 1.0
#define FREQ_BOUNDS_MAX_KHZ 1000000000.0
#define FREQ_BOUNDS_KHZ_VALID(v) ((v) >= FREQ_BOUNDS_MIN_KHZ && (v) <= FREQ_BOUNDS_MAX_KHZ)

#ifdef __cplusplus
namespace freq_bounds {
    constexpr double min_khz = FREQ_BOUNDS_MIN_KHZ;
    constexpr double max_khz = FREQ_BOUNDS_MAX_KHZ;

    constexpr bool khz_valid(double v) { return FREQ_BOUNDS_KHZ_VALID(v); }
}
#endif

#endif
