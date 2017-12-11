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

#ifndef __INTERFACE_CONTROL_H__
#define __INTERFACE_CONTROL_H__

#include "config.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/socket.h>

#include <net/if.h>

#ifndef SYS_CYGWIN
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#endif

#ifdef SYS_NETBSD
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#endif

#if defined(SYS_LINUX) || defined(SYS_NETBSD) || defined(SYS_OPENBSD) || \
	defined(SYS_FREEBSD) || defined(SYS_DARWIN)
/* proxy for SIOCGIFFLAGS and SIOCSIFFLAGS
 * delta_flags will fetch the current set of flags and add new ones to it
 *
 * Returns:
 * 0        Success
 * Others   Failure, errno returned 
 */

int ifconfig_set_flags(const char *in_dev, char *errstr, int flags);
int ifconfig_delta_flags(const char *in_dev, char *errstr, int flags);
int ifconfig_get_flags(const char *in_dev, char *errstr, int *flags);

/* Bring an interface up or down by setting up, running, and promisc 
 *
 * Returns:
 * 0        Success
 * Others   Failure, errno returned
 */
int ifconfig_interface_up(const char *in_dev, char *errstr);
int ifconfig_interface_down(const char *in_dev, char *errstr);

#endif

#ifdef SYS_LINUX

/* Linux-specific functions for setting hardware address and MTU */

/* Fetches the current HW address of the device and copies it to ret_hwaddr.
 * ret_hwaddr must be allocated by the caller and be able to hold 6 bytes.
 * Only the first 6 bytes of the interface will be copied.
 *
 * Errstr must be allocated by the caller and be able to hold STATUS_MAX characters.
 *
 * Returns:
 * -1   Error
 *  0   Success
 */
int ifconfig_get_hwaddr(const char *in_dev, char *errstr, uint8_t *ret_hwaddr);

/* Definitions from ethtool-2 */
#define ETHTOOL_BUSINFO_LEN	32
struct ethtool_drvinfo {
	uint32_t cmd;
	char driver[32]; // Driver short name
	char version[32]; // Driver version
	char fw_version[32]; // Driver firmware version
	// We don't really care about anything below here but we need it
	// anyhow.
	char bus_info[ETHTOOL_BUSINFO_LEN]; // Bus info
	char reserved1[32];
	char reserved2[16];
	uint32_t n_stats; // Number of ETHTOOL_GSTATS
	uint32_t testinfo_len;
	uint32_t eedump_len; // Size of ETHTOOL_GEEPROM
	uint32_t regdump_len;
};

#ifndef ETHTOOL_GDRVINFO
#define ETHTOOL_GDRVINFO	0x00000003
#endif

#ifndef SIOCETHTOOL
#define SIOCETHTOOL			0x8946
#endif

/* Get driver info, placed in ethtool_drvinfo.
 *
 * errstr must be allocated by the caller and be able to hold STATUS_MAX characters
 * ethtool_drvinfo must be allocated by the caller.
 *
 * Returns:
 * -1   Error
 *  1   Success
 */
int linux_getdrvinfo(const char *in_dev, char *errstr, struct ethtool_drvinfo *info);

/* Get driver by crawling the /sys filesystem.
 *
 * ret_driver must be allocated by the caller, and be able to hold at least 32
 * characters.
 *
 * Returns:
 * -1   Error
 *  1   Success
 */
int linux_getsysdrv(const char *in_dev, char *ret_driver);

/* Get attribute (file in sys driver directory)
 *
 * Returns:
 * 0    Attribute not available (or interface not found)
 * 1    Attribute present
 */
int linux_getsysdrvattr(const char *in_dev, const char *in_attr);

#endif

#ifdef SYS_DARWIN
/* Fetches the current HW address of the device and copies it to ret_hwaddr.
 * ret_hwaddr must be allocated by the caller and be able to hold 6 bytes.
 * Only the first 6 bytes of the interface will be copied.
 *
 * Errstr must be allocated by the caller and be able to hold STATUS_MAX characters.
 *
 * Returns:
 * -1   Error
 *  0   Success
 */
int ifconfig_get_hwaddr(const char *in_dev, char *errstr, uint8_t *ret_hwaddr);
#endif

#endif
