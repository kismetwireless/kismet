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

#include "../config.h"

#ifdef SYS_LINUX
#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <math.h>
#include <stdlib.h>

#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>

#ifdef HAVE_LINUX_WIRELESS
#include <asm/types.h>
#include <linux/if.h>
#include <linux/wireless.h>

#ifndef rintf
#define rintf(x) (float) rint((double) (x))
#endif

#include "linux_wireless_control.h"

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


int iwconfig_set_channel(const char *in_dev, int in_ch, char *in_err) {
    struct iwreq wrq;
    int skfd;
	int ret = 0;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(in_err, STATUS_MAX, 
                "failed to connect to interface '%s' to set channel: %s",
                in_dev, strerror(errno));
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

    /* Try twice with a tiny delay, some cards (madwifi) need a second chance... */
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

            snprintf(in_err, STATUS_MAX, 
                    "unable to set channel on interface '%s': %s",
                    in_dev, strerror(errno));

            close(skfd);
            return ret;
        }
    }

    close(skfd);
    return 0;
}

int iwconfig_get_mode(const char *in_dev, char *in_err, unsigned int *in_mode) {
    struct iwreq wrq;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(in_err, STATUS_MAX, 
                "failed to connect to interface '%s' to set mode: %s",
                in_dev, strerror(errno));
        return -1;
    }

    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    if (ioctl(skfd, SIOCGIWMODE, &wrq) < 0) {
        snprintf(in_err, STATUS_MAX, 
                "failed to get mode from interface '%s': %s",
                in_dev, strerror(errno));
        close(skfd);
        return -1;
    }

    (*in_mode) = wrq.u.mode;
    
    close(skfd);
    return 0;
}

int iwconfig_set_mode(const char *in_dev, char *in_err, unsigned int in_mode) {
    struct iwreq wrq;
    int skfd;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(in_err, STATUS_MAX, 
                "failed to connect to interface '%s' to set mode: %s",
                in_dev, strerror(errno));
        return -1;
    }

    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);
    wrq.u.mode = in_mode;

    if (ioctl(skfd, SIOCSIWMODE, &wrq) < 0) {
        snprintf(in_err, STATUS_MAX, "failed to set mode on interface '%s': %s",
                in_dev, strerror(errno));
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
int iwconfig_get_chanlist(const char *interface, char *errstr, 
        unsigned int **chan_list, size_t *chan_list_len) {
	struct iwreq wrq;
	int skfd;
	char buffer[sizeof(struct iw_range) * 2];
	union iw_range_raw *range_raw;
	struct iw_range range;
    int k;

    *chan_list = NULL;
    *chan_list_len = 0;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, STATUS_MAX, 
                "failed to connect to interface '%s' to get channel list: %s",
                interface, strerror(errno));
		return -1;
	}

	memset(buffer, 0, sizeof(buffer));

	memset(&wrq, 0, sizeof(struct iwreq));

	wrq.u.data.pointer = (caddr_t) buffer;
	wrq.u.data.length = sizeof(buffer);
	wrq.u.data.flags = 0;

	strncpy(wrq.ifr_name, interface, IFNAMSIZ);

	if (ioctl(skfd, SIOCGIWRANGE, &wrq) < 0) {
		snprintf(errstr, STATUS_MAX, 
                "failed to get channel list from interface '%s': %s",
                interface, strerror(errno));
		close(skfd);
		return -1;
	}

	range_raw = (union iw_range_raw *) buffer;

	/* Magic number to detect old versions */
	/* For new versions, we can check the version directly, for old versions
	 * we use magic. 300 bytes is a also magic number, don't touch... */
	if (wrq.u.data.length < 300) {
		snprintf(errstr, STATUS_MAX, 
                "failed to get channel list from interface '%s': its drivers "
                "are too old to support fetching the supported channels.",
                interface);
		close(skfd);
		return -1;
	}

	/* Direct copy from wireless-tools; mangle the range code and
	 * figure out what we need to do with it */
	if (range_raw->range.we_version_compiled > 15) {
		memcpy((char *) &range, buffer, sizeof(struct iw_range));
	} else {
		/* Zero unknown fields */
		memset((char *) &range, 0, sizeof(struct iw_range));

		/* Initial part unmoved */
		memcpy((char *) &range, buffer, iwr15_off(num_channels));
		/* Frequencies pushed further down towards the end */
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
		snprintf(errstr, STATUS_MAX, 
                "failed to get channel list from interface '%s': its drivers "
                "are too old to support fetching the supported channels.",
                interface);
		close(skfd);
		return -1;
	}

    /* We don't actually care? 
	if (range.we_version_compiled > WE_MAX_VERSION) {
		snprintf(errstr, STATUS_MAX, "Interface %s using wireless extensions from "
				 "the future; Recompile Kismet with your new kernel before Skynet "
				 "takes over", interface);
		close(skfd);
		return -1;
	}
    */

    /* driver supplied */
    if (range.num_frequency > IW_MAX_FREQUENCIES)
        range.num_frequency = IW_MAX_FREQUENCIES;

    if (range.num_frequency <= 0) {
        *chan_list = NULL;
        *chan_list_len = 0;
        return 0;
    }

    *chan_list = (unsigned int *) malloc(sizeof(unsigned int) * range.num_frequency);
    *chan_list_len = range.num_frequency;

    if (*chan_list == NULL) {
        snprintf(errstr, STATUS_MAX, 
                "failed to get channel list from interface '%s': insufficient memory "
                "to allocate channel list.", interface);
        return -1;
    }

    for (k = 0; k < range.num_frequency; k++) {
        int freq = (((double) range.freq[k].m) * pow(10, range.freq[k].e)) /
            1000000;

        (*chan_list)[k] = freq;
    }

	close(skfd);
    return 0;
}

#endif


#endif // wireless

