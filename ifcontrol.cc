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
int Ifconfig_Linux(const char *in_dev, char *errstr) {
    struct ifreq ifr;
    int skfd;
    struct sockaddr_in sin;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to create AF_INET DGRAM socket. %d:%s",
                 errno, strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, "Unknown interface %s: %s", in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING | IFF_PROMISC);    
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to set interface up, running, and promisc %d:%s", errno, strerror(errno));
        close(skfd);
        return -1;
    }  

    strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
    memset(&sin, 0, sizeof(sockaddr_in));
    sin.sin_family = AF_INET;
    memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
    if (ioctl(skfd, SIOCSIFADDR, &ifr) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to set interface address to 0.0.0.0 %d:%s", errno, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);
    return 0;
}
#endif

#ifdef HAVE_LINUX_WIRELESS
// remove the SSID of the device.  Some cards seem to need this.
int Iwconfig_Blank_SSID(const char *in_dev, char *errstr) {
    struct iwreq wrq;
    int skfd;
    char essid[IW_ESSID_MAX_SIZE + 1] = "\0";

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", 
                 errno, strerror(errno));
        return -1;
    }

    // Zero the ssid
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);
    wrq.u.essid.pointer = (caddr_t) essid;
    wrq.u.essid.length = 1;
    wrq.u.essid.flags = 1;

    if (ioctl(skfd, SIOCSIWESSID, &wrq) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to set SSID %d:%s", errno, 
                 strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);
    return 0;
}

// Set a private ioctl that takes 1 or 2 integer parameters
// A return of -2 means no privctl found that matches, so that the caller
// can return a more detailed failure message
//
// Code largely taken from wireless_tools
int Iwconfig_Set_IntPriv(const char *in_dev, const char *privcmd, 
                         int val1, int val2, char *errstr) {
    struct iwreq wrq;
    int skfd;
    struct iw_priv_args priv[IW_MAX_PRIV_DEF];
    u_char buffer[4096];
    int subcmd = 0;
    int offset = 0;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", 
                 errno, strerror(errno));
        return -1;
    }

    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    wrq.u.data.pointer = (caddr_t) priv;
    wrq.u.data.length = IW_MAX_PRIV_DEF;
    wrq.u.data.flags = 0;

    if (ioctl(skfd, SIOCGIWPRIV, &wrq) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to retrieve list of private ioctls %d:%s",
                 errno, strerror(errno));
        close(skfd);
        return -1;
    }

    int pn = -1;
    while ((++pn < wrq.u.data.length) && strcmp(priv[pn].name, privcmd));

    if (pn == wrq.u.data.length) {
        snprintf(errstr, STATUS_MAX, "Unable to find private ioctl '%s'", privcmd);
        close(skfd);
        return -2;
    }

    // Find subcmds, as if this isn't ugly enough already
    if (priv[pn].cmd < SIOCDEVPRIVATE) {
        int j = -1;

        while ((++j < wrq.u.data.length) && ((priv[j].name[0] != '\0') ||
                                             (priv[j].set_args != priv[pn].set_args) ||
                                             (priv[j].get_args != priv[pn].get_args)));
        
        if (j == wrq.u.data.length) {
            snprintf(errstr, STATUS_MAX, "Unable to find subioctl '%s'", privcmd);
            close(skfd);
            return -2;
        }

        subcmd = priv[pn].cmd;
        offset = sizeof(__u32);
        pn = j;
    }

    // Make sure its an iwpriv we can set
    if (priv[pn].set_args & IW_PRIV_TYPE_MASK == 0 ||
        priv[pn].set_args & IW_PRIV_SIZE_MASK == 0) {
        snprintf(errstr, STATUS_MAX, "Unable to set values for private ioctl '%s'", 
                 privcmd);
        close(skfd);
        return -1;
    }
  
    if ((priv[pn].set_args & IW_PRIV_TYPE_MASK) != IW_PRIV_TYPE_INT) {
        snprintf(errstr, STATUS_MAX, "'%s' does not accept integer parameters.",
                 privcmd);
        return -1;
    }
    
    // Find out how many arguments it takes and die if we can't handle it
    int nargs = (priv[pn].set_args & IW_PRIV_SIZE_MASK);
    if (nargs > 2) {
        snprintf(errstr, STATUS_MAX, "Private ioctl expects more than 2 arguments.");
        close(skfd);
        return -1;
    }

    // Build the set request
    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    // Assign the arguments
    wrq.u.data.length = nargs;     
    ((__s32 *) buffer)[0] = (__s32) val1;
    if (nargs > 1) {
        ((__s32 *) buffer)[1] = (__s32) val2;
    }
       
    // This is terrible!
    // This is also simplified from what iwpriv.c does, because we don't
    // need to worry about get-no-set ioctls
    if ((priv[pn].set_args & IW_PRIV_SIZE_FIXED) &&
        ((sizeof(__u32) * nargs) + offset <= IFNAMSIZ)) {
        if (offset)
            wrq.u.mode = subcmd;
        memcpy(wrq.u.name + offset, buffer, IFNAMSIZ - offset);
    } else {
        wrq.u.data.pointer = (caddr_t) buffer;
        wrq.u.data.flags = 0;
    }

    // Actually do it.
    if (ioctl(skfd, priv[pn].cmd, &wrq) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to set private ioctl '%s': %s",
                 privcmd, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);
    return 0;
}

int Iwconfig_Get_Levels(const char *in_dev, char *in_err, int *level, int *noise) {
    struct iwreq wrq;
    struct iw_range range;
    struct iw_statistics stats;
    char buffer[sizeof(iw_range) * 2];
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", 
                 errno, strerror(errno));
        return -1;
    }

    // Fetch the range
    memset(buffer, 0, sizeof(iw_range) * 2);
    memset(&wrq, 0, sizeof(struct iwreq));
    wrq.u.data.pointer = (caddr_t) buffer;
    wrq.u.data.length = sizeof(buffer);
    wrq.u.data.flags = 0;
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    if (ioctl(skfd, SIOCGIWRANGE, &wrq) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to fetch signal range, %s", strerror(errno));
        close(skfd);
        return -1;
    }

    // Pull it out
    memcpy((char *) &range, buffer, sizeof(iw_range));

    // Fetch the stats
    wrq.u.data.pointer = (caddr_t) &stats;
    wrq.u.data.length = 0;
    wrq.u.data.flags = 1;     /* Clear updated flag */
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    if (ioctl(skfd, SIOCGIWSTATS, &wrq) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to fetch signal stats, %s", strerror(errno));
        close(skfd);
        return -1;
    }

    if (stats.qual.level <= range.max_qual.level) {
        *level = 0;
        *noise = 0;
        return 0;
    }

    *level = stats.qual.level - 0x100;
    *noise = stats.qual.noise - 0x100;

    close(skfd);

    return 0;
}

int Iwconfig_Get_Channel(const char *in_dev, char *in_err) {
    struct iwreq wrq;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", 
                 errno, strerror(errno));
        return -1;
    }

    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    if (ioctl(skfd, SIOCGIWFREQ, &wrq) < 0) {
        snprintf(in_err, STATUS_MAX, "channel get ioctl failed %d:%s",
                 errno, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);
    return (FloatChan2Int(IWFreq2Float(&wrq)));
}

int Iwconfig_Set_Channel(const char *in_dev, int in_ch, char *in_err) {
    struct iwreq wrq;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", 
                 errno, strerror(errno));
        return -1;
    }
    // Set a channel
    memset(&wrq, 0, sizeof(struct iwreq));

    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);
    IWFloat2Freq(in_ch, &wrq.u.freq);

    // Try twice with a tiny delay, some cards (madwifi) need a second chance...
    if (ioctl(skfd, SIOCSIWFREQ, &wrq) < 0) {
        struct timeval tm;
        tm.tv_sec = 0;
        tm.tv_usec = 5000;
        select(0, NULL, NULL, NULL, &tm);

        if (ioctl(skfd, SIOCSIWFREQ, &wrq) < 0) {
            snprintf(in_err, STATUS_MAX, "Failed to set channel %d %d:%s", in_ch,
                     errno, strerror(errno));
            close(skfd);
            return -1;
        }
    }

    close(skfd);
    return 0;
}

#endif

