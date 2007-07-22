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

#include <sys/types.h>
#include <sys/socket.h>

#ifdef SYS_LINUX
#include <asm/types.h>
#include <linux/if.h>
#else
#include <net/if.h>
#endif

#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#ifdef SYS_NETBSD
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#endif

#include "util.h"

#if defined(SYS_LINUX) || defined(SYS_NETBSD) || defined(SYS_OPENBSD) || \
	defined(SYS_FREEBSD) || defined(SYS_DARWIN)
int Ifconfig_Set_Flags(const char *in_dev, char *errstr, int flags);
int Ifconfig_Delta_Flags(const char *in_dev, char *errstr, int flags);
int Ifconfig_Get_Flags(const char *in_dev, char *errstr, int *flags);
#endif

#ifdef SYS_LINUX
int Ifconfig_Get_Hwaddr(const char *in_dev, char *errstr, uint8_t *ret_hwaddr);
int Ifconfig_Set_Hwaddr(const char *in_dev, char *errstr, uint8_t *in_hwaddr);
int Ifconfig_Set_MTU(const char *in_dev, char *errstr, uint16_t in_mtu);
#endif

#endif
