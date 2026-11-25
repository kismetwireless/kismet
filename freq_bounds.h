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
#include <cstddef>

namespace freq_bounds {
    constexpr double min_khz = FREQ_BOUNDS_MIN_KHZ;
    constexpr double max_khz = FREQ_BOUNDS_MAX_KHZ;

    constexpr bool khz_valid(double v) { return FREQ_BOUNDS_KHZ_VALID(v); }

    // Distinct frequencies counted per device and per seen-by source.  Every 20 MHz Wi-Fi
    // channel in 2.4, 4.9, 5 and 6 GHz is about 130, BTLE 40; rtl_433 reports measured
    // frequencies that drift by a few kHz.  Any source can send any frequency, so without
    // a cap one device grows without bound; 256 is about 6 KB at most.
    constexpr size_t max_counted_freqs = 256;

    // Count a packet on a frequency: a frequency already in the map is always counted, a
    // new one only while the map is under the cap.  One lookup, as before the cap.
    template<typename M, typename K>
    void count_freq(M& map, const K& freq) {
        auto i = map.find(freq);

        if (i != map.end()) {
            i->second += 1;
            return;
        }

        if (map.size() < max_counted_freqs)
            map.insert({freq, 1});
    }
}
#endif

#endif
