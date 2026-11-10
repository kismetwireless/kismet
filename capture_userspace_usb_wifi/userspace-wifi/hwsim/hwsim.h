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

#ifndef __UWIFI_HWSIM_H__
#define __UWIFI_HWSIM_H__

/* A userspace adapter as a Linux Wi-Fi device: a mac80211_hwsim radio with the adapter's
 * MAC address, for which this process is the medium, as wmediumd is.  Frames the kernel
 * sends on the radio are transmitted by the adapter on the frame's channel; frames the
 * adapter receives are passed to the radio with their channel, rate and signal.  The
 * adapter follows the radio's operating channel and width, and the channel of each frame
 * it sends, so scanning, connecting, AP and monitor modes work through the kernel's own
 * mac80211, cfg80211 and nl80211.
 *
 * Requires mac80211_hwsim, ideally loaded with radios=0. */

#include <signal.h>
#include <stdio.h>

#include "common/uwifi.h"

struct uwifi_hwsim_opts {
    /* wiphy name; the adapter's interface name when NULL */
    const char *name;
    /* Regulatory hint for the radio, such as "US" */
    const char *country;
    /* Prints a status line this often; 0 for none */
    unsigned int stats_interval_s;
};

/* Runs until *stop is set or the adapter is lost; the radio is removed on return.  Returns
 * 0, or a negative errno if the radio couldn't be created. */
int uwifi_hwsim_run(struct uwifi_dev *dev, const struct uwifi_hwsim_opts *opts, volatile sig_atomic_t *stop,
        FILE *out);

#endif
