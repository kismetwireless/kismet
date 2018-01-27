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

#include "../config.h"

#ifndef __LINUX_NETLINK_CONFIG__
#define __LINUX_NETLINK_CONFIG__

/* Use local copy of nl80211.h */
#include "../nl80211.h"

/* Create a monitor vif using mac80211, based on existing interface *interface
 * and named *newinterface.
 *
 * Flags must be from nl80211_mntr_flags from nl80211.h
 *
 * errstr must be allocated by the caller and be able to hold STATUS_MAX
 * characters.
 *
 * Returns:
 * -1   Error
 *  0   Success
 */
int mac80211_create_monitor_vif(const char *interface, const char *newinterface, 
        unsigned int *flags, unsigned int flags_sz, char *errstr);

/* Connect to nl80211 and resolve the genl and nl80211 ids; this generates the
 * cache state needed for channel control.
 *
 * **nl_sock is allocated by the function, and must be freed with mac80211_nl_disconnect
 * *nl80211_id is populated by the function
 * *if_index is populated with the interface index of the provided interface
 *
 * Returns:
 * -1   Error
 *  0   Success
 */
int mac80211_connect(const char *interface, void **nl_sock, int *nl80211_id, 
        int *if_index, char *errstr);

/* Disconnect from nl80211; frees resources used */
void mac80211_disconnect(void *nl_sock);

/* Set a channel on an interface via mac80211, initiating a new connection
 * to the interface.
 *
 * Generally, it's better to use mac80211_set_channel_cache which re-uses the
 * connected state instead of opening a new mac80211 socket every channel config.
 *
 * Channel must be base frequency or channel number.  Mode must be one of 
 * nl80211_channel_type from nl80211.h.  For setting 80, 160, or 80+80 channels, use
 * mac80211_set_freq
 *
 * errstr must be allocated by the caller and be able to hold STATUS_MAX
 * characters.
 *
 * Returns:
 * -1   Error
 *  0   Success
 */
int mac80211_set_channel(const char *interface, int channel, unsigned int chmode, char *errstr);
int mac80211_set_channel_cache(int ifindex, void *nl_sock, int nl80211_id,
        int channel, unsigned int chmode, char *errstr);

/* Set a device frequency by frequency, width, and center frequency, required for
 * advanced 11AC controls.  This MAY also be used for 11n 40mhz channels.
 *
 * Generally, it's best to use mac80211_set_frequency_cache(...) which re-uses the
 * connected state from mac80211_open.
 *
 * chan_width must be one of nl80211_chan_width from nl80211.h
 *
 * errstr must be allocated by the caller and be able to hold STATUS_MAX characters.
 *
 * Returns:
 * -1   Error  
 *  0   Success
 *
 */
int mac80211_set_frequency(const char *interface, unsigned int control_freq,
        unsigned int chan_width, unsigned int center_freq1, unsigned int center_freq2,
        char *errstr);
int mac80211_set_frequency_cache(int ifidx, void *nl_sock, int nl80211_id, 
        unsigned int control_freq, unsigned int chan_width, unsigned int center_freq1, 
        unsigned int center_freq2, char *errstr);

/* Get the parent phy of an interface.
 *
 * Returns:
 * NULL Error
 * ptr  Pointer to dynamically allocated string containing the parent; the caller
 *      is responsible for freeing this string.
 */
char *mac80211_find_parent(const char *interface);

#define MAC80211_CHANLIST_NO_INTERFACE		-2
#define MAC80211_CHANLIST_NOT_MAC80211		-3
#define MAC80211_CHANLIST_GENERIC			-4

#define MAC80211_GET_HT                     (1 << 0) 
#define MAC80211_GET_VHT                    (1 << 1)

/* Get a complete channel list supported by an interface.
 *
 * This extracts any information about HT40, 80, and 160 from the device specs,
 * and combines it with the pre-defined knowledge about 802.11 channel allocation
 * to compute every channel permutation the interface should support.
 *
 * Channels are returned as Kismet channel definitions, as wifi channel strings; for
 * example:
 * Base channel:    6
 * HT40+ channel:   6HT40+
 * HT40- channel:   6HT40-
 * HT80 channel:    36HT80 (which automatically derives 80mhz control channel)
 * HT160 channel:   36HT160 (which automatically derives 160mhz control channel)
 *
 * Returns channel list array in *ret_chanlist and length in *ret_chanlist_len.
 *
 * Caller is responsible for freeing returned chanlist with mac80211_free_chanlist(..)
 *
 * Returns:
 * -1   Error
 *  0   Success
 *
 */
int mac80211_get_chanlist(const char *interface, unsigned int extended_flags, char *errstr,
        char ***ret_chanlist, unsigned int *ret_chanlist_len);

#endif


