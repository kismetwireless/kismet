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
#include "iwcontrol.h"

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

#ifndef rintf
#define rintf(x) (float) rint((double) (x))
#endif

float IwFreq2Float(iwreq *inreq) {
    return ((float) inreq->u.freq.m) * pow(10,inreq->u.freq.e);
}

void IwFloat2Freq(double in_val, struct iw_freq *out_freq) {
	if (in_val <= 165) {
        out_freq->m = (uint32_t) in_val;            
        out_freq->e = 0;
		return;
	}

    out_freq->e = (short) (floor(log10(in_val)));
    if(out_freq->e > 8) {  
        out_freq->m = ((long) (floor(in_val / pow(10,out_freq->e - 6)))) * 100; 
        out_freq->e -= 8;
    }  
    else {  
        out_freq->m = (uint32_t) in_val;            
        out_freq->e = 0;
    }  
}

int FloatChan2Int(float in_chan) {
	if (in_chan > 0 && in_chan < 165)
		return (int) in_chan;

    int mod_chan = (int) rintf(in_chan / 1000000);
    int x = 0;
    // 80211b frequencies to channels
    int IEEE80211Freq[] = {
        2412, 2417, 2422, 2427, 2432,
        2437, 2442, 2447, 2452, 2457,
        2462, 2467, 2472, 2484,
        5180, 5200, 5210, 5220, 5240,
        5250, 5260, 5280, 5290, 5300, 
        5320, 5745, 5760, 5765, 5785, 
        5800, 5805, 5825,
        -1
    };

    int IEEE80211Ch[] = {
        1, 2, 3, 4, 5,
        6, 7, 8, 9, 10,
        11, 12, 13, 14,
        36, 40, 42, 44, 48,
        50, 52, 56, 58, 60,
        64, 149, 152, 153, 157,
        160, 161, 165
    };

    while (IEEE80211Freq[x] != -1) {
        if (IEEE80211Freq[x] == mod_chan) {
            return IEEE80211Ch[x];
        }
        x++;
    }

    return mod_chan;
}

int Iwconfig_Set_SSID(const char *in_dev, char *errstr, const char *in_essid) {
    struct iwreq wrq;
    int skfd;
    char essid[IW_ESSID_MAX_SIZE + 1];

    if (in_essid == NULL) {
        essid[0] = '\0';
    } else {
        // Trim transparently
        snprintf(essid, IW_ESSID_MAX_SIZE+1, "%s", in_essid);
    }
    
    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to create ioctl socket to set SSID on %s: %s", 
                 in_dev, strerror(errno));
        return -1;
    }

    // Zero the ssid
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);
    wrq.u.essid.pointer = (caddr_t) essid;
    wrq.u.essid.length = strlen(essid)+1;
    wrq.u.essid.flags = 1;

    if (ioctl(skfd, SIOCSIWESSID, &wrq) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to set SSID on %s: %s",  
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);
    return 0;
}

int Iwconfig_Get_SSID(const char *in_dev, char *errstr, char *in_essid) {
    struct iwreq wrq;
    int skfd;
    char essid[IW_ESSID_MAX_SIZE + 1];

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to create socket to fetch SSID on %s: %s", 
                 in_dev, strerror(errno));
        return -1;
    }

    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);
    wrq.u.essid.pointer = (caddr_t) essid;
    wrq.u.essid.length = IW_ESSID_MAX_SIZE+1;
    wrq.u.essid.flags = 0;

    if (ioctl(skfd, SIOCGIWESSID, &wrq) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to fetch SSID from %s: %s", 
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    snprintf(in_essid, kismin(IW_ESSID_MAX_SIZE, wrq.u.essid.length) + 1, "%s", 
             (char *) wrq.u.essid.pointer);

    close(skfd);
    return 0;
}

int Iwconfig_Get_Name(const char *in_dev, char *errstr, char *in_name) {
    struct iwreq wrq;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to create socket to get name on %s: %s",
                 in_dev, strerror(errno));
        return -1;
    }

    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    if (ioctl(skfd, SIOCGIWNAME, &wrq) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to get name on %s :%s", in_dev,
                 strerror(errno));
        close(skfd);
        return -1;
    }

    snprintf(in_name, IFNAMSIZ, "%s", wrq.u.name);

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
	__s32 *sbuffer = (__s32 *) buffer;
    int subcmd = 0;
    int offset = 0;

    memset(priv, 0, sizeof(priv));

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to create socket to set private ioctl on %s: %s",
                 in_dev, strerror(errno));
        return -1;
    }

    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    wrq.u.data.pointer = (caddr_t) priv;
    wrq.u.data.length = IW_MAX_PRIV_DEF;
    wrq.u.data.flags = 0;

    if (ioctl(skfd, SIOCGIWPRIV, &wrq) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to retrieve list of private ioctls on %s: %s",
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    int pn = -1;
    while ((++pn < wrq.u.data.length) && strcmp(priv[pn].name, privcmd));

    if (pn == wrq.u.data.length) {
        snprintf(errstr, STATUS_MAX, "Unable to find private ioctl '%s' on %s", 
                 privcmd, in_dev);
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
            snprintf(errstr, STATUS_MAX, "Unable to find subioctl '%s' on %s", 
                     privcmd, in_dev);
            close(skfd);
            return -2;
        }

        subcmd = priv[pn].cmd;
        offset = sizeof(__u32);
        pn = j;
    }

    // Make sure its an iwpriv we can set
    if ((priv[pn].set_args & IW_PRIV_TYPE_MASK) == 0 ||
        (priv[pn].set_args & IW_PRIV_SIZE_MASK) == 0) {
        snprintf(errstr, STATUS_MAX, "Unable to set values for private ioctl '%s' on %s", 
                 privcmd, in_dev);
        close(skfd);
        return -1;
    }
  
    if ((priv[pn].set_args & IW_PRIV_TYPE_MASK) != IW_PRIV_TYPE_INT) {
        snprintf(errstr, STATUS_MAX, "'%s' on %s does not accept integer parameters.",
                 privcmd, in_dev);
        close(skfd);
        return -1;
    }
    
    // Find out how many arguments it takes and die if we can't handle it
    int nargs = (priv[pn].set_args & IW_PRIV_SIZE_MASK);
    if (nargs > 2) {
        snprintf(errstr, STATUS_MAX, "Private ioctl '%s' on %s expects more than "
                 "2 arguments.", privcmd, in_dev);
        close(skfd);
        return -1;
    }

    // Build the set request
    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    // Assign the arguments
    wrq.u.data.length = nargs;     
    sbuffer[0] = (__s32) val1;
    if (nargs > 1) {
        sbuffer[1] = (__s32) val2;
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
        snprintf(errstr, STATUS_MAX, "Failed to set private ioctl '%s' on %s: %s",
                 privcmd, in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);
    return 0;
}

int Iwconfig_Get_IntPriv(const char *in_dev, const char *privcmd,
                         int *val, char *errstr) {
    struct iwreq wrq;
    int skfd;
    struct iw_priv_args priv[IW_MAX_PRIV_DEF];
    u_char buffer[4096];
	__s32 *sbuffer = (__s32 *) buffer;
    int subcmd = 0;
    int offset = 0;

    memset(priv, 0, sizeof(priv));

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to create socket to fetch private ioctl on %s: %s",
                 in_dev, strerror(errno));
        return -1;
    }

    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    wrq.u.data.pointer = (caddr_t) priv;
    wrq.u.data.length = IW_MAX_PRIV_DEF;
    wrq.u.data.flags = 0;

    if (ioctl(skfd, SIOCGIWPRIV, &wrq) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to retrieve list of private ioctls on %s: %s",
                 in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    int pn = -1;
    while ((++pn < wrq.u.data.length) && strcmp(priv[pn].name, privcmd));

    if (pn == wrq.u.data.length) {
        snprintf(errstr, STATUS_MAX, "Unable to find private ioctl '%s' on %s", 
                 privcmd, in_dev);
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
            snprintf(errstr, STATUS_MAX, "Unable to find subioctl '%s' on %s", 
                     privcmd, in_dev);
            close(skfd);
            return -2;
        }

        subcmd = priv[pn].cmd;
        offset = sizeof(__u32);
        pn = j;
    }

    // Make sure its an iwpriv we can set
    if ((priv[pn].get_args & IW_PRIV_TYPE_MASK) == 0 ||
        (priv[pn].get_args & IW_PRIV_SIZE_MASK) == 0) {
        snprintf(errstr, STATUS_MAX, "Unable to get values for private ioctl '%s' on %s", 
                 privcmd, in_dev);
        close(skfd);
        return -1;
    }
  
    if ((priv[pn].get_args & IW_PRIV_TYPE_MASK) != IW_PRIV_TYPE_INT) {
        snprintf(errstr, STATUS_MAX, "Private ioctl '%s' on %s does not return "
                 "integer parameters.", privcmd, in_dev);
        close(skfd);
        return -1;
    }
    
    // Find out how many arguments it takes and die if we can't handle it
    int nargs = (priv[pn].get_args & IW_PRIV_SIZE_MASK);
    if (nargs > 1) {
        snprintf(errstr, STATUS_MAX, "Private ioctl '%s' on %s returns more than 1 "
                 "parameter and we can't handle that at the moment.", privcmd, in_dev);
        close(skfd);
        return -1;
    }

    // Build the get request
    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    // Assign the arguments
    wrq.u.data.length = 0L;     
       
    // This is terrible!
    // Simplified (again) from iwpriv, since we split the command into
    // a set and a get instead of combining the cases
    if ((priv[pn].get_args & IW_PRIV_SIZE_FIXED) &&
        ((sizeof(__u32) * nargs) + offset <= IFNAMSIZ)) {
        /* Second case : no SET args, GET args fit within wrq */
        if (offset)
            wrq.u.mode = subcmd;
    } else {
        wrq.u.data.pointer = (caddr_t) buffer;
        wrq.u.data.flags = 0;
    }

    // Actually do it.
    if (ioctl(skfd, priv[pn].cmd, &wrq) < 0) {
        snprintf(errstr, STATUS_MAX, "Failed to call get private ioctl '%s' on %s: %s",
                 privcmd, in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    // Where do we get the data from?
    if ((priv[pn].get_args & IW_PRIV_SIZE_FIXED) &&
        ((sizeof(__u32) * nargs) + offset <= IFNAMSIZ))
        memcpy(buffer, wrq.u.name, IFNAMSIZ);

    // Return the value of the ioctl
    (*val) = sbuffer[0];

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

    /*
    if (stats.qual.level <= range.max_qual.level) {
        *level = 0;
        *noise = 0;
        close(skfd);
        return 0;
    }
    */

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
    return (FloatChan2Int(IwFreq2Float(&wrq)));
}

int Iwconfig_Set_Channel(const char *in_dev, int in_ch, char *in_err) {
    struct iwreq wrq;
    int skfd;
	int ret = 0;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", 
                 errno, strerror(errno));
        return -1;
    }
    // Set a channel
    memset(&wrq, 0, sizeof(struct iwreq));

    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);
#ifdef HAVE_LINUX_IWFREQFLAG
	wrq.u.freq.flags = IW_FREQ_FIXED;
#endif
	if (in_ch > 1024) 
		IwFloat2Freq(in_ch * 1e6, &wrq.u.freq);
	else
		IwFloat2Freq(in_ch, &wrq.u.freq);

    // Try twice with a tiny delay, some cards (madwifi) need a second chance...
    if (ioctl(skfd, SIOCSIWFREQ, &wrq) < 0) {
        struct timeval tm;
        tm.tv_sec = 0;
        tm.tv_usec = 5000;
        select(0, NULL, NULL, NULL, &tm);

        if (ioctl(skfd, SIOCSIWFREQ, &wrq) < 0) {
			if (errno == ENODEV) {
				ret = -2;
			} else {
				ret = -1;
			}

            snprintf(in_err, STATUS_MAX, "%s", strerror(errno));
            close(skfd);
            return ret;
        }
    }

    close(skfd);
    return 0;
}

int Iwconfig_Get_Mode(const char *in_dev, char *in_err, int *in_mode) {
    struct iwreq wrq;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", 
                 errno, strerror(errno));
        return -1;
    }

    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    if (ioctl(skfd, SIOCGIWMODE, &wrq) < 0) {
        snprintf(in_err, STATUS_MAX, "mode get ioctl failed %d:%s",
                 errno, strerror(errno));
        close(skfd);
        return -1;
    }

    (*in_mode) = wrq.u.mode;
    
    close(skfd);
    return 0;
}

int Iwconfig_Set_Mode(const char *in_dev, char *in_err, int in_mode) {
    struct iwreq wrq;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", 
                 errno, strerror(errno));
        return -1;
    }

    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);
    wrq.u.mode = in_mode;

    if (ioctl(skfd, SIOCSIWMODE, &wrq) < 0) {
        snprintf(in_err, STATUS_MAX, "mode set ioctl failed %d:%s",
                 errno, strerror(errno));
        close(skfd);
        return -1;
    }

    close(skfd);
    return 0;
}

/* straight from wireless-tools; range struct definitions */
#define IW15_MAX_FREQUENCIES	16
#define IW15_MAX_BITRATES		8
#define IW15_MAX_TXPOWER		8
#define IW15_MAX_ENCODING_SIZES	8
#define IW15_MAX_SPY			8
#define IW15_MAX_AP				8
struct iw15_range {
	uint32_t throughput;
	uint32_t min_nwid;
	uint32_t max_nwid;
	uint16_t num_channels;
	uint8_t num_frequency;
	struct iw_freq freq[IW15_MAX_FREQUENCIES];
	int32_t sensitivity;
	struct iw_quality max_qual;
	uint8_t num_bitrates;
	int32_t bitrate[IW15_MAX_BITRATES];
	int32_t min_rts;
	int32_t max_rts;
	int32_t min_frag;
	int32_t max_frag;
	int32_t min_pmp;
	int32_t max_pmp;
	int32_t min_pmt;
	int32_t max_pmt;
	uint16_t pmp_flags;
	uint16_t pmt_flags;
	uint16_t pm_capa;
	uint16_t encoding_size[IW15_MAX_ENCODING_SIZES];
	uint8_t  num_encoding_sizes;
	uint8_t  max_encoding_tokens;
	uint16_t txpower_capa;
	uint8_t  num_txpower;
	int32_t txpower[IW15_MAX_TXPOWER];
	uint8_t  we_version_compiled;
	uint8_t  we_version_source;
	uint16_t retry_capa;
	uint16_t retry_flags;
	uint16_t r_time_flags;
	int32_t min_retry;
	int32_t max_retry;
	int32_t min_r_time;
	int32_t  max_r_time;
	struct iw_quality avg_qual;
};

union iw_range_raw {
	struct iw15_range range15;	/* WE 9->15 */
	struct iw_range	range;		/* WE 16->current */
};

/*
 * Offsets in iw_range struct
 */
#define iwr15_off(f)	( ((char *) &(((struct iw15_range *) NULL)->f)) - \
			  (char *) NULL)
#define iwr_off(f)	( ((char *) &(((struct iw_range *) NULL)->f)) - \
			  (char *) NULL)

/* Get hw supported channels; rewritten from wireless-tools by Jean Tourilhes */
int Iwconfig_Get_Chanlist(const char *interface, char *errstr, 
						  vector<unsigned int> *chan_list) {
	struct iwreq wrq;
	int skfd;
	char buffer[sizeof(struct iw_range) * 2];
	union iw_range_raw *range_raw;
	struct iw_range range;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, STATUS_MAX, "%s: failed to create ioctl socket on %s: %s",
				 __FUNCTION__, interface, strerror(errno));
		return -1;
	}

	memset(buffer, 0, sizeof(buffer));

	memset(&wrq, 0, sizeof(struct iwreq));

	wrq.u.data.pointer = (caddr_t) buffer;
	wrq.u.data.length = sizeof(buffer);
	wrq.u.data.flags = 0;

	strncpy(wrq.ifr_name, interface, IFNAMSIZ);

	if (ioctl(skfd, SIOCGIWRANGE, &wrq) < 0) {
		snprintf(errstr, STATUS_MAX, "%s: Failed to get frequency range on %s: %s",
				 __FUNCTION__, interface, strerror(errno));
		close(skfd);
		return -1;
	}

	range_raw = (union iw_range_raw *) buffer;

	/* Magic number to detect old versions */
	/* For new versions, we can check the version directly, for old versions
	 * we use magic. 300 bytes is a also magic number, don't touch... */
	if (wrq.u.data.length < 300) {
		snprintf(errstr, STATUS_MAX, "Interface %s using wireless extensions which "
				 "are too old to extract the supported channels list", interface);
		close(skfd);
		return -1;
	}

	/* Direct copy from wireless-tools; mangle the range code and
	 * figure out what we need to do with it */
	if (range_raw->range.we_version_compiled > 15) {
		memcpy((char *) &range, buffer, sizeof(iw_range));
	} else {
		/* Zero unknown fields */
		memset((char *) &range, 0, sizeof(struct iw_range));

		/* Initial part unmoved */
		memcpy((char *) &range, buffer, iwr15_off(num_channels));
		/* Frequencies pushed futher down towards the end */
		memcpy((char *) &range + iwr_off(num_channels),
			   buffer + iwr15_off(num_channels), 
			   iwr15_off(sensitivity) - iwr15_off(num_channels));
		/* This one moved up */
		memcpy((char *) &range + iwr_off(sensitivity),
			   buffer + iwr15_off(sensitivity),
			   iwr15_off(num_bitrates) - iwr15_off(sensitivity));
		/* This one goes after avg_qual */
		memcpy((char *) &range + iwr_off(num_bitrates),
			   buffer + iwr15_off(num_bitrates),
			   iwr15_off(min_rts) - iwr15_off(num_bitrates));
		/* Number of bitrates has changed, put it after */
		memcpy((char *) &range + iwr_off(min_rts),
			   buffer + iwr15_off(min_rts),
			   iwr15_off(txpower_capa) - iwr15_off(min_rts));
		/* Added encoding_login_index, put it after */
		memcpy((char *) &range + iwr_off(txpower_capa),
			   buffer + iwr15_off(txpower_capa),
			   iwr15_off(txpower) - iwr15_off(txpower_capa));
		/* Hum... That's an unexpected glitch. Bummer. */
		memcpy((char *) &range + iwr_off(txpower),
			   buffer + iwr15_off(txpower),
			   iwr15_off(avg_qual) - iwr15_off(txpower));
		/* Avg qual moved up next to max_qual */
		memcpy((char *) &range + iwr_off(avg_qual),
			   buffer + iwr15_off(avg_qual),
			   sizeof(struct iw_quality));
	}

	if (range.we_version_compiled <= 10) {
		snprintf(errstr, STATUS_MAX, "Interface %s using wireless extensions which "
				 "are too old to extract the supported channels list", interface);
		close(skfd);
		return -1;
	}

	if (range.we_version_compiled > WE_MAX_VERSION) {
		snprintf(errstr, STATUS_MAX, "Interface %s using wireless extensions from "
				 "the future; Recompile Kismet with your new kernel before Skynet "
				 "takes over", interface);
		close(skfd);
		return -1;
	}

	if (range.num_frequency > 0) {
		/* Print them all */
		for (int k = 0; k < range.num_frequency; k++) {
			int freq = (((double) range.freq[k].m) * pow(10, range.freq[k].e)) /
				1000000;

			if (freq == 0)
				continue;

			chan_list->push_back(FreqToChan(freq));
		}
	}

	close(skfd);
	return chan_list->size();
}

#endif

#endif // wireless

