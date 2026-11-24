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

#ifndef __LINUX_CHANLIST_H__
#define __LINUX_CHANLIST_H__

#include <stddef.h>

/* Builds the Kismet channel list of a mac80211 phy from the enabled
 * frequencies nl80211 reports, without any netlink code, so it can be
 * tested with synthetic phys. */

/* Per-frequency restrictions, from NL80211_FREQUENCY_ATTR_NO_* */
#define MAC80211_FREQ_NO_HT40MINUS      (1 << 0)
#define MAC80211_FREQ_NO_HT40PLUS       (1 << 1)
#define MAC80211_FREQ_NO_80MHZ          (1 << 2)
#define MAC80211_FREQ_NO_160MHZ         (1 << 3)

/* Widths the frequency's band supports, from its HT and VHT capabilities */
#define MAC80211_BAND_HT40              (1 << 0)
#define MAC80211_BAND_HT80              (1 << 1)
#define MAC80211_BAND_HT160             (1 << 2)

/* More than any phy reports; frequencies past it are ignored */
#define MAC80211_MAX_FREQS              512

struct mac80211_freq_info {
    unsigned int freq;
    unsigned int chan;
    unsigned int flags;
    unsigned int band_caps;
};

/* Build the channel list for the enabled frequencies in freqs, in order.
 * extended_flags takes MAC80211_GET_HT and MAC80211_GET_VHT; default_ht20
 * and expand_ht20 are as for mac80211_get_chanlist.
 *
 * HT40, VHT80 and VHT160 channels are offered only when every 20MHz
 * channel they cover is in freqs, the primary allows that HT40 direction,
 * and no covered channel forbids the 80MHz or 160MHz width.
 *
 * Returns the number of channels, with a malloc'd array of malloc'd
 * strings in *ret_chan_list (NULL when there are none), or -1 when out of
 * memory, with nothing returned.
 */
int mac80211_build_chanlist(const struct mac80211_freq_info *freqs, size_t nfreqs,
        unsigned int extended_flags, unsigned int default_ht20, unsigned int expand_ht20,
        char ***ret_chan_list, size_t *ret_num_chans);

#endif
