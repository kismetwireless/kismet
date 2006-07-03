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

#include "config.h"
#include "ifcontrol.h"

#ifdef SYS_LINUX

#include <netdb.h>

int Linux_GetDrvInfo(const char *in_dev, char *errstr, 
					 struct ethtool_drvinfo *info) {
	struct ifreq ifr;
	int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, STATUS_MAX, "Failed to create ioctl socket to get "
				 "driver info on %s: %s", in_dev, strerror(errno));
        return -1;
    }

	memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);

	info->cmd = ETHTOOL_GDRVINFO;
	ifr.ifr_data = (caddr_t) info;

    if (ioctl(skfd, SIOCETHTOOL, &ifr) < 0) {
		snprintf(errstr, STATUS_MAX, "Failed to get driver info on %s: %s",
				 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);
    return 0;
}

int Ifconfig_Set_Flags(const char *in_dev, char *errstr, short flags) {
    struct ifreq ifr;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "SetIFFlags: Failed to create AF_INET "
                 "DGRAM socket. %s", strerror(errno));
        return -1;
    }

    // Fetch interface flags
    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
    ifr.ifr_flags = flags;
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, "SetIFFlags: Unknown interface %s: %s", 
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);

    return 0;
}

int Ifconfig_Get_Flags(const char *in_dev, char *errstr, short *flags) {
    struct ifreq ifr;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "GetIFFlags: Failed to create AF_INET "
                 "DGRAM socket. %s", strerror(errno));
        return -1;
    }

    // Fetch interface flags
    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, "GetIFFlags: interface %s: %s", 
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    (*flags) = ifr.ifr_flags;

    close(skfd);

    return 0;
}

int Ifconfig_Delta_Flags(const char *in_dev, char *errstr, short flags) {
    int ret;
    short rflags;

    if ((ret = Ifconfig_Get_Flags(in_dev, errstr, &rflags)) < 0)
        return ret;

    rflags |= flags;

    return Ifconfig_Set_Flags(in_dev, errstr, rflags);
}

int Ifconfig_Get_Hwaddr(const char *in_dev, char *errstr, uint8_t *ret_hwaddr) {
    struct ifreq ifr;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "Getting HWAddr: failed to create AF_INET "
                 "DGRAM socket. %s", strerror(errno));
        return -1;
    }

    // Fetch interface flags
    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, "Getting HWAddr: unknown interface %s: %s", 
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    memcpy(ret_hwaddr, ifr.ifr_hwaddr.sa_data, 6);
    
    close(skfd);

    return 0;
}

int Ifconfig_Set_Hwaddr(const char *in_dev, char *errstr, uint8_t *in_hwaddr) {
    struct ifreq ifr;
    int skfd;
    // struct sockaddr sa;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "Setting HWAddr: failed to create AF_INET "
                 "DGRAM socket. %s", strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
    memcpy(ifr.ifr_hwaddr.sa_data, in_hwaddr, 6);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
     
    // memcpy((char *) &ifr.ifr_hwaddr, (char *) &sa, sizeof(struct sockaddr));
    
    if (ioctl(skfd, SIOCSIFHWADDR, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, "Setting HWAddr: interface %s: %s", 
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);

    return 0;
}

int Ifconfig_Set_MTU(const char *in_dev, char *errstr, uint16_t in_mtu) {
    struct ifreq ifr;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "Setting MTU: failed to create AF_INET "
                 "DGRAM socket. %s", strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
    ifr.ifr_mtu = in_mtu;
    if (ioctl(skfd, SIOCSIFMTU, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, "Setting MTU: unknown interface %s: %s", 
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);

    return 0;
}

int Ifconfig_Set_IP(const char *in_dev, char *errstr, const char *ip) {
	struct ifreq ifr;
	int skfd;
	struct sockaddr_in sin;
	struct hostent *hp;

	sin.sin_family = AF_INET;
	sin.sin_port = 0;

	if ((hp = gethostbyname(ip)) != NULL) {
		memcpy(&(sin.sin_addr), hp->h_addr_list[0], sizeof(struct in_addr));
	} else {
		snprintf(errstr, STATUS_MAX, "Setting IPAddr: unable to resolve address %s",
				 ip);
		return -1;
	}

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "Setting IPAddr: failed to create AF_INET "
                 "DGRAM socket. %s", strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);

	memcpy(&(ifr.ifr_addr), &sin, sizeof(struct sockaddr));

	if (ioctl(skfd, SIOCSIFADDR, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, "Setting IPAddr failed %s: %s", 
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);

	return 0;
}

int Ifconfig_Set_Netmask(const char *in_dev, char *errstr, const char *netmask) {
	struct ifreq ifr;
	int skfd;
	struct sockaddr_in sin;
	struct hostent *hp;

	sin.sin_family = AF_INET;
	sin.sin_port = 0;

	if ((hp = gethostbyname(netmask)) != NULL) {
		memcpy(&(sin.sin_addr), hp->h_addr_list[0], sizeof(struct in_addr));
	} else {
		snprintf(errstr, STATUS_MAX, "Setting netmask: unable to resolve address %s",
				 netmask);
		return -1;
	}

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "Setting netmask: failed to create AF_INET "
                 "DGRAM socket. %s", strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);

	memcpy(&(ifr.ifr_addr), &sin, sizeof(struct sockaddr));

	if (ioctl(skfd, SIOCSIFNETMASK, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, "Setting netmask failed %s: %s", 
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);

	return 0;
}

#endif

