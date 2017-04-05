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
#include "interface_control.h"

#ifdef SYS_LINUX
#include <netdb.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <strings.h>

int ifconfig_set_flags(const char *in_dev, char *errstr, int flags) {
#ifndef SYS_CYGWIN
    struct ifreq ifr;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, 
                "failed to connect to interface '%s' to set flags: %s",
                in_dev, strerror(errno));
        return errno; 
    }

    // Fetch interface flags
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, in_dev, sizeof(ifr.ifr_name)-1);
#if defined(SYS_FREEBSD)
	ifr.ifr_flags = flags & 0xFFFF;
	ifr.ifr_flagshigh = flags >> 16;
#else
    ifr.ifr_flags = flags;
#endif
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX,
                "failed to set flags on interface '%s': %s",
                in_dev, strerror(errno));
        close(skfd);
        return errno;
    }

    close(skfd);
#endif
    return 0;
}

int ifconfig_get_flags(const char *in_dev, char *errstr, int *flags) {
#ifndef SYS_CYGWIN
    struct ifreq ifr;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX,
                "failed to connect to interface '%s' to get flags: %s",
                in_dev, strerror(errno));
        return -1;
    }

    // Fetch interface flags
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, in_dev, sizeof(ifr.ifr_name)-1);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, 
                "failed to get flags on interface '%s': %s",
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

#if defined(SYS_FREEBSD)
	(*flags) = (ifr.ifr_flags & 0xFFFF) | (ifr.ifr_flagshigh << 16);
#else
    (*flags) = ifr.ifr_flags;
#endif

    close(skfd);
#endif
    return 0;
}

int ifconfig_delta_flags(const char *in_dev, char *errstr, int flags) {
#ifndef SYS_CYGWIN
    int ret;
    int rflags;

    if ((ret = ifconfig_get_flags(in_dev, errstr, &rflags)) < 0)
        return ret;

    rflags |= flags;


    return ifconfig_set_flags(in_dev, errstr, rflags);
#endif

	return 0;
}

#ifdef SYS_LINUX

int linux_getdrvinfo(const char *in_dev, char *errstr, 
					 struct ethtool_drvinfo *info) {
	struct ifreq ifr;
	int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, STATUS_MAX, 
                "failed to connect to interface '%s' to fetch driver: %s",
                in_dev, strerror(errno));
        return -1;
    }

	memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);

	info->cmd = ETHTOOL_GDRVINFO;
	ifr.ifr_data = (caddr_t) info;

    if (ioctl(skfd, SIOCETHTOOL, &ifr) < 0) {
		snprintf(errstr, STATUS_MAX, 
                "failed to get driver info from interface '%s': %s",
				 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);
    return 0;
}

int linux_getsysdrv(const char *in_dev, char *ret_driver) {
	char devlinktarget[512];
	ssize_t devlinklen;
    char devlink[1024];
	char *rind = NULL;

    snprintf(devlink, 1024, "/sys/class/net/%s/device/driver", in_dev);
            
	devlinklen = readlink(devlink, devlinktarget, 511);
	if (devlinklen > 0) {
		devlinktarget[devlinklen] = '\0';
		rind = rindex(devlinktarget, '/');
		// If we found it and not at the end of the line
		if (rind != NULL && (rind - devlinktarget) + 1 < devlinklen) {
            snprintf(ret_driver, 32, "%s", rind + 1);
            return 1;
        }
	}

    return 0;
}

int linux_getsysdrvattr(const char *in_dev, const char *attr) {
	char devlink[256];
	struct stat buf;

	snprintf(devlink, 256, "/sys/class/net/%s/%s", in_dev, attr);

	if (stat(devlink, &buf) != 0)
		return 0;

	return 1;
}

int ifconfig_get_hwaddr(const char *in_dev, char *errstr, uint8_t *ret_hwaddr) {
    struct ifreq ifr;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, 
                "failed to connect to interface '%s' to get HW addr: %s",
                in_dev, strerror(errno));
        return -1;
    }

    // Fetch interface flags
    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, 
                "failed to get HW addr from interface '%s': %s",
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    memcpy(ret_hwaddr, ifr.ifr_hwaddr.sa_data, 6);
    
    close(skfd);

    return 0;
}

int ifconfig_set_hwaddr(const char *in_dev, char *errstr, uint8_t *in_hwaddr) {
    struct ifreq ifr;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, 
                "failed to connect to interface '%s' to set HW addr: %s",
                in_dev, strerror(errno));
        return errno; 
    }

    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
    memcpy(ifr.ifr_hwaddr.sa_data, in_hwaddr, 6);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
     
    if (ioctl(skfd, SIOCSIFHWADDR, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, 
                "failed to set hw addr on interface '%s': %s",
                 in_dev, strerror(errno));
        close(skfd);
        return errno;
    }

    close(skfd);

    return 0;
}

int ifconfig_set_mtu(const char *in_dev, char *errstr, uint16_t in_mtu) {
    struct ifreq ifr;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, 
                "failed to connect to interface '%s' to set MTU: %s",
                in_dev, strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
    ifr.ifr_mtu = in_mtu;
    if (ioctl(skfd, SIOCSIFMTU, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, 
                "failed to set MTU on interface '%s': %s",
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);

    return 0;
}

#endif

