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

#ifdef HAVE_LINUX_WIRELESS

#define IW_MAX_PRIV_DEF 256
/* Wireless extentions monitor mode number */
#define LINUX_WLEXT_MONITOR 6
/* Wireless extentions master mode */
#define LINUX_WLEXT_MASTER  3

/* Max version of wext we know about */
#define WE_MAX_VERSION			22

/* Set a private ioctl that takes 1 or 2 integer parameters
 * A return of -2 means no privctl found that matches, so that the caller
 * can return a more detailed failure message
 *
 * This DOES NOT handle sub-ioctls.  I've never seen them used.  If this
 * blows up some day on some driver, I'll fix it.
 *
 * This uses the old-style wireless IOCTLs and should be supplanted by mac80211
 * for all modern drivers.
 *
 * errstr must be allocated by the caller and must be able to hold STATUS_MAX
 * characters.
 *
 * Returns:
 * -2   Unable to find IOCTL
 * -1   General error
 *  0   Success
 */
int iwconfig_set_intpriv(const char *in_dev, const char *privcmd, 
                         int val1, int val2, char *errstr);

/* Get a single-param private ioctl.  This will have to be changed if we 
 * ever need to remember a two-value privioctl, but hopefully nothing
 * will.
 *
 * This uses the old-style IOCTLs and should be supplanted by mac80211 for all
 * modern drivers.
 *
 * This does NOT handle sub-ioctls.
 *
 * errstr must be allocated by the caller and must be able to hold STATUS_MAX
 * characters.
 *
 * Returns:
 * -2   Unable to find private IOCTL
 * -1   General error
 *  0   Success
 */
int iwconfig_get_intpriv(const char *in_dev, const char *privcmd,
                         int *val, char *errstr);

/* Get the current channel of a wireless device.  
 *
 * This uses the old-style IOCTLs and should be supplanted by mac80211 for all
 * modern drivers.
 *
 * Because this uses the old-style controls, it cannot relay if the channel
 * has any HT or wide-tuning attributes, and returns a pure integer.
 *
 * errstr must be allocated by the caller and must be able to hold STATUS_MAX
 * characters.
 *
 * Returns:
 * -2   No device
 * -1   General error
 * othr Channel or frequency 
 */
int iwconfig_get_channel(const char *in_dev, char *errstr);

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
int iwconfig_get_mode(const char *in_dev, char *errstr, int *in_mode);


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
int iwconfig_set_mode(const char *in_dev, char *errstr, int in_mode);

/* Convert a channel floating value to an integer for formatting for old-style
 * IOCTLs */
int floatchan_to_int(float in_chan);

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
        unsigned int **chan_list, unsigned int *chan_list_len);

#endif

/* Fetch the regulatory domain country code for the system
 *
 * This uses the /sys filesystem to query cfg80211 to see what the country code is
 * set to.
 *
 * *ret_countrycode must be allocated by the caller and be able to hold 4 bytes.
 *
 * Returns:
 * -1   Error, cannot get country code
 *  0   Success
 */
int linux_sys_get_regdom(char *ret_countrycode);

#endif
