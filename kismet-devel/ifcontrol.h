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

#ifndef __IFCONTROL_H__
#define __IFCONTROL_H__

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

#ifdef SYS_LINUX
// Bring up an interface in promisc mode with no IP in linux
int Ifconfig_Set_Linux(const char *in_dev, char *errstr, 
                       struct sockaddr_in *ifaddr, 
                       struct sockaddr_in *dstaddr, 
                       struct sockaddr_in *broadaddr, 
                       struct sockaddr_in *maskaddr, 
                       short flags);

int Ifconfig_Get_Linux(const char *in_dev, char *errstr, 
                       struct sockaddr_in *ifaddr, 
                       struct sockaddr_in *dstaddr, 
                       struct sockaddr_in *broadaddr, 
                       struct sockaddr_in *maskaddr, 
                       short *flags);
#endif

#ifdef HAVE_LINUX_WIRELESS

#define IW_MAX_PRIV_DEF 128
// Wireless extentions monitor mode number
#define LINUX_WLEXT_MONITOR 6

// remove the SSID of the device.  Some cards seem to need this.
int Iwconfig_Set_SSID(const char *in_dev, char *errstr, char *in_essid);
int Iwconfig_Get_SSID(const char *in_dev, char *errstr, char *in_essid);

// Set a private ioctl that takes 1 or 2 integer parameters
// A return of -2 means no privctl found that matches, so that the caller
// can return a more detailed failure message
//
// This DOES NOT handle sub-ioctls.  I've never seen them used.  If this
// blows up some day on some driver, I'll fix it.
int Iwconfig_Set_IntPriv(const char *in_dev, const char *privcmd, 
                         int val1, int val2, char *errstr);

// Fetch levels
int Iwconfig_Get_Levels(const char *in_dev, char *in_err, int *level, int *noise);

// Fetch channel
int Iwconfig_Get_Channel(const char *in_dev, char *errstr);
// Set channel
int Iwconfig_Set_Channel(const char *in_dev, int in_ch, char *errstr);

// Get/set mode
int Iwconfig_Get_Mode(const char *in_dev, char *errstr, int *in_mode);
int Iwconfig_Set_Mode(const char *in_dev, char *errstr, int in_mode);

#endif

#endif
