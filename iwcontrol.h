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

#ifndef __IWCONTROL_H__
#define __IWCONTROL_H__

#include "config.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#ifdef SYS_LINUX
#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#ifdef HAVE_LINUX_WIRELESS
#include <linux/wireless.h>
#else
#include <net/if.h>
#endif

#endif

#include "util.h"

#ifdef HAVE_LINUX_WIRELESS

#define IW_MAX_PRIV_DEF 128
// Wireless extentions monitor mode number
#define LINUX_WLEXT_MONITOR 6
// Wireless extentions master mode
#define LINUX_WLEXT_MASTER  3

// Definitions gratuitiously yoinked from ethtool-2 for getting
// driver info
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

// Get the ethtool info
int Linux_GetDrvInfo(const char *in_dev, char *errstr, 
					 struct ethtool_drvinfo *info);

// remove the SSID of the device.  Some cards seem to need this.
int Iwconfig_Set_SSID(const char *in_dev, char *errstr, char *in_essid);
int Iwconfig_Get_SSID(const char *in_dev, char *errstr, char *in_essid);

// Get the name
int Iwconfig_Get_Name(const char *in_dev, char *errstr, char *in_name);

// Set a private ioctl that takes 1 or 2 integer parameters
// A return of -2 means no privctl found that matches, so that the caller
// can return a more detailed failure message
//
// This DOES NOT handle sub-ioctls.  I've never seen them used.  If this
// blows up some day on some driver, I'll fix it.
int Iwconfig_Set_IntPriv(const char *in_dev, const char *privcmd, 
                         int val1, int val2, char *errstr);

// Get a single-param private ioctl.  This will have to be changed if we 
// ever need to remember a two-value privioctl, but hopefully nothing
// will.
int Iwconfig_Get_IntPriv(const char *in_dev, const char *privcmd,
                         int *val, char *errstr);

// Fetch levels
int Iwconfig_Get_Levels(const char *in_dev, char *in_err, int *level, int *noise);

// Fetch channel
int Iwconfig_Get_Channel(const char *in_dev, char *errstr);
// Set channel
int Iwconfig_Set_Channel(const char *in_dev, int in_ch, char *errstr);

// Get/set mode
int Iwconfig_Get_Mode(const char *in_dev, char *errstr, int *in_mode);
int Iwconfig_Set_Mode(const char *in_dev, char *errstr, int in_mode);

// Info conversion
float IwFreq2Float(iwreq *inreq);
float IwFreq2Float(iwreq *inreq);
int FloatChan2Int(float in_chan);

#endif

#endif
