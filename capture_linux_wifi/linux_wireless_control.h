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

#ifndef __WIRELESS_CONTROL_H__
#define __WIRELESS_CONTROL_H__

#include "../config.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* We need these defs regardless if we have wext */

/* Wireless extensions monitor mode number */
#define LINUX_WLEXT_MONITOR 6
/* Wireless extensions master mode */
#define LINUX_WLEXT_MASTER  3

#ifdef HAVE_LINUX_WIRELESS

#define IW_MAX_PRIV_DEF 256

/* Max version of wext we know about */
#define WE_MAX_VERSION			22

/* Set the current channel of a wireless device.
 *
 * This uses the old-style IOCTLs and should be supplanted by mac80211 for all
 * modern drivers.
 *
 * Because this uses the old-style controls, it cannot configure a different
 * channel width or a wide
 *
 * errstr must be allocated by the caller and must be able to hold STATUS_MAX
 * characters.
 *
 * Returns:
 * -2   No device
 * -1   General error
 *  0   Success
 */
int iwconfig_set_channel(const char *in_dev, int in_ch, char *errstr);

/* Get the current mode of a wireless device (master, monitor, station, etc).
 *
 * This uses the old-style IOCTLs and should be supplanted by mac80211 for all
 * modern drivers.
 *
 * Modern drivers support getting mode, but cannot change the mode on an existing
 * interface.
 *
 * errstr must be allocated by the caller and must be able to hold STATUS_MAX
 * characters.
 *
 * Returns mode in in_mode
 *
 * Returns:
 * -1   Error
 *  0   Success
 */
int iwconfig_get_mode(const char *in_dev, char *errstr, unsigned int *in_mode);


/* Set the current mode of a wireless device (master, monitor, station, etc).
 *
 * This uses the old-style IOCTLs and should be supplanted by mac80211 for all
 * modern drivers.
 *
 * Modern drivers support getting mode, but cannot change the mode on an existing
 * interface - a new vif must be created.
 *
 * errstr must be allocated by the caller and must be able to hold STATUS_MAX
 * characters.
 *
 * Returns:
 * -1   Error
 *  0   Success
 */
int iwconfig_set_mode(const char *in_dev, char *errstr, unsigned int in_mode);

/* Fetch a list of channels, as integers, from a wireless device.
 *
 * As this uses the old IOCTL model, it's not possible to fetch HT capable
 * data, so the channels are returned as a list of unsigned integers and must
 * be converted to proper Kismet format by the caller.
 *
 * Returns a list of integers in *chan_list and the length of the list in 
 * *chan_list_len; Caller is responsible for freeing these objects.
 *
 * Returns:
 * -1   Error
 *  0   Success
 */
int iwconfig_get_chanlist(const char *interface, char *errstr, 
        unsigned int **chan_list, size_t *chan_list_len);

#endif

#endif
