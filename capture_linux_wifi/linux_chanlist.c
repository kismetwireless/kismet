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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "linux_chanlist.h"
#include "linux_netlink_control.h"
#include "../wifi_ht_channels.h"

/* Base, HT20, HT40-, HT40+, VHT80, VHT160 */
#define MAC80211_MAX_NAMES_PER_FREQ     6

static const struct mac80211_freq_info *find_freq(const struct mac80211_freq_info *freqs,
        size_t nfreqs, unsigned int freq) {
    size_t i;

    for (i = 0; i < nfreqs; i++) {
        if (freqs[i].freq == freq)
            return &freqs[i];
    }

    return NULL;
}

/* Every 20MHz channel of the block centred on center_mhz is enabled and
 * carries none of the prohibited flags, as cfg80211_chandef_usable checks */
static int block_ok(const struct mac80211_freq_info *freqs, size_t nfreqs,
        unsigned int center_mhz, unsigned int width_mhz, unsigned int prohibited) {
    const struct mac80211_freq_info *fi;
    unsigned int f;

    if (center_mhz < width_mhz / 2)
        return 0;

    for (f = center_mhz - width_mhz / 2 + 10; f < center_mhz + width_mhz / 2; f += 20) {
        fi = find_freq(freqs, nfreqs, f);

        if (fi == NULL || (fi->flags & prohibited))
            return 0;
    }

    return 1;
}

static const wifi_channel *find_ht_channel(unsigned int freq) {
    unsigned int i;

    for (i = 0; i <= MAX_WIFI_HT_CHANNEL; i++) {
        if (wifi_ht_channels[i].freq == freq)
            return &wifi_ht_channels[i];
    }

    return NULL;
}

static int add_name(char **list, size_t *n, unsigned int val, const char *suffix) {
    char name[32];

    snprintf(name, sizeof(name), "%u%s", val, suffix);

    if ((list[*n] = strdup(name)) == NULL)
        return -1;

    (*n)++;
    return 0;
}

int mac80211_build_chanlist(const struct mac80211_freq_info *freqs, size_t nfreqs,
        unsigned int extended_flags, unsigned int default_ht20, unsigned int expand_ht20,
        char ***ret_chan_list, size_t *ret_num_chans) {
    const unsigned int ht = (extended_flags & MAC80211_GET_HT) != 0;
    const unsigned int vht = (extended_flags & MAC80211_GET_VHT) != 0;
    const struct mac80211_freq_info *fi;
    const wifi_channel *htc;
    char **list;
    size_t i, n = 0;

    *ret_chan_list = NULL;
    *ret_num_chans = 0;

    if (nfreqs > MAC80211_MAX_FREQS)
        nfreqs = MAC80211_MAX_FREQS;

    if (nfreqs == 0)
        return 0;

    list = (char **) calloc(nfreqs * MAC80211_MAX_NAMES_PER_FREQ, sizeof(char *));
    if (list == NULL)
        return -1;

    for (i = 0; i < nfreqs; i++) {
        fi = &freqs[i];

        /* Default to HT20 if we support HT and are always using it, otherwise
         * default to basic channels */
        if (fi->freq >= 58320) {
            /* Kismet takes 60GHz channel numbers for 2.4GHz ones, so list them
             * by frequency */
            if (add_name(list, &n, fi->freq, "") < 0)
                goto oom;
        } else if (fi->freq >= 5935) {
            if (add_name(list, &n, fi->chan, "W6e") < 0)
                goto oom;
        } else if (ht && default_ht20) {
            if (add_name(list, &n, fi->chan, "HT20") < 0)
                goto oom;
        } else {
            if (add_name(list, &n, fi->chan, "") < 0)
                goto oom;
        }

        if (ht && !default_ht20 && expand_ht20 && fi->freq < 5925) {
            if (add_name(list, &n, fi->chan, "HT20") < 0)
                goto oom;
        }

        if ((htc = find_ht_channel(fi->freq)) == NULL)
            continue;

        if (ht && (fi->band_caps & MAC80211_BAND_HT40)) {
            if ((htc->flags & WIFI_HT_HT40MINUS) && !(fi->flags & MAC80211_FREQ_NO_HT40MINUS) &&
                    block_ok(freqs, nfreqs, fi->freq - 10, 40, 0)) {
                if (add_name(list, &n, fi->chan, "HT40-") < 0)
                    goto oom;
            }

            if ((htc->flags & WIFI_HT_HT40PLUS) && !(fi->flags & MAC80211_FREQ_NO_HT40PLUS) &&
                    block_ok(freqs, nfreqs, fi->freq + 10, 40, 0)) {
                if (add_name(list, &n, fi->chan, "HT40+") < 0)
                    goto oom;
            }
        }

        if (vht && (fi->band_caps & MAC80211_BAND_HT80) && (htc->flags & WIFI_HT_HT80) &&
                block_ok(freqs, nfreqs, (unsigned int) htc->freq80, 80, MAC80211_FREQ_NO_80MHZ)) {
            if (add_name(list, &n, fi->chan, "VHT80") < 0)
                goto oom;
        }

        if (vht && (fi->band_caps & MAC80211_BAND_HT160) && (htc->flags & WIFI_HT_HT160) &&
                block_ok(freqs, nfreqs, (unsigned int) htc->freq160, 160, MAC80211_FREQ_NO_160MHZ)) {
            if (add_name(list, &n, fi->chan, "VHT160") < 0)
                goto oom;
        }
    }

    *ret_chan_list = list;
    *ret_num_chans = n;

    return (int) n;

oom:
    for (i = 0; i < n; i++)
        free(list[i]);
    free(list);

    return -1;
}
