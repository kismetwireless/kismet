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
// This DOES NOT handle sub-ioctls.  I've never seen them used.  If this
// blows up some day on some driver, I'll fix it.
int Iwconfig_Set_IntPriv(const char *in_dev, const char *privcmd, 
                         int val1, int val2, char *errstr) {
    struct iwreq wrq;
    int skfd;
    struct iw_priv_args priv[IW_MAX_PRIV_DEF];
    u_char buffer[4096];

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
        snprintf(errstr, STATUS_MAX, "Unable to find private ioctl '%s' %d:%s",
                 privcmd, errno, strerror(errno));
        close(skfd);
        return -2;
    }

    // Make sure its an iwpriv we can set
    if (priv[pn].set_args & IW_PRIV_TYPE_MASK == 0 ||
        priv[pn].set_args & IW_PRIV_SIZE_MASK == 0) {
        snprintf(errstr, STATUS_MAX, "Unable to set values for private ioctl '%s'", privcmd);
        close(skfd);
        return -1;
    }
    
    // Find out how many arguments it takes and die if we can't handle it
    int nargs = priv[pn].get_args & IW_PRIV_SIZE_MASK;
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
    if (nargs > 1)
        ((__s32 *) buffer)[1] = (__s32) val2;
       
    // This is terrible!
    // This is also simplified from what iwpriv.c does, because we don't
    // need to worry about get-no-set ioctls
    if ((priv[pn].set_args & IW_PRIV_SIZE_FIXED) &&
        ((sizeof(__u32) * nargs) <= IFNAMSIZ)) {
        memcpy(wrq.u.name, buffer, IFNAMSIZ);
    } else {
        wrq.u.data.pointer = (caddr_t) buffer;
        wrq.u.data.flags = 0;
    }

    // Actually do it.
    if (ioctl(skfd, priv[pn].cmd, &wrq) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to set private ioctl '%s' %d:%s",
                 privcmd, errno, strerror(errno));
        close(skfd);
        return -1;
    }

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

    if (ioctl(skfd, SIOCSIWFREQ, &wrq) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to set channel %d %d:%s", in_ch,
                 errno, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);
    return 0;
}

#endif

