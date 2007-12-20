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
#include <asm/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#endif

#endif

#include "util.h"

#ifdef HAVE_LINUX_WIRELESS

#define IW_MAX_PRIV_DEF 256
// Wireless extentions monitor mode number
#define LINUX_WLEXT_MONITOR 6
// Wireless extentions master mode
#define LINUX_WLEXT_MASTER  3

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

int Iwconfig_Get_Power(const char *in_dev, char *errstr, void **power);
int Iwconfig_Restore_Power(const char *in_dev, char *errstr, void *in_power);
int Iwconfig_Disable_Power(const char *in_dev, char *errstr);

// Info conversion
float IwFreq2Float(iwreq *inreq);
float IwFreq2Float(iwreq *inreq);
int FloatChan2Int(float in_chan);

#endif

#endif
