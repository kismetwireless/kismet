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

#if defined(HAVE_LIBNL20) || defined(HAVE_LIBNL30) || defined(HAVE_LIBNLTINY)
#define HAVE_LIBNL_NG
#endif

#ifdef SYS_LINUX

#ifdef HAVE_LINUX_NETLINK
#include <sys/types.h>
#include <asm/types.h>
#ifdef HAVE_LIBNLTINY
#include <libnl-tiny/netlink/genl/genl.h>
#include <libnl-tiny/netlink/genl/family.h>
#include <libnl-tiny/netlink/genl/ctrl.h>
#include <libnl-tiny/netlink/msg.h>
#include <libnl-tiny/netlink/attr.h>
#include <libnl-tiny/netlink/netlink.h>
#include <libnl-tiny/netlink/socket.h>
#else
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#endif
#include "nl80211.h"
#include <net/if.h>
#endif

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "linux_netlink_control.h"
#include "wifi_ht_channels.h"

// Libnl1->Libnl2 compatability mode since the API changed, cribbed from 'iw'
#if defined(HAVE_LIBNL10)

#define nl_sock nl_handle

static inline struct nl_handle *nl_socket_alloc(void) {
#ifdef HAVE_LINUX_NETLINK
	return nl_handle_alloc();
#else
    return NULL;
#endif
}

static inline void nl_socket_free(struct nl_sock *h) {
#ifdef HAVE_LINUX_NETLINK
	nl_handle_destroy(h);
#else
    return;
#endif
}

static inline int __genl_ctrl_alloc_cache(struct nl_sock *h, struct nl_cache **cache) {
#ifdef HAVE_LINUX_NETLINK
	struct nl_cache *tmp = genl_ctrl_alloc_cache(h);
	if (!tmp)
		return -1;
	*cache = tmp;
	return 0;
#else
    *cache = NULL;
    return 0;
#endif
}
#define genl_ctrl_alloc_cache __genl_ctrl_alloc_cache
#endif

unsigned int mac80211_chan_to_freq(unsigned int in_chan) {
    /* 802.11 channels to frequency; if it looks like a frequency, return as
     * pure frequency; derived from iwconfig */

    if (in_chan > 250)
        return in_chan;

	if (in_chan == 14)
		return 2484;
	else if (in_chan < 14)
		return 2407 + in_chan * 5;
	else if (in_chan >= 182 && in_chan <= 196)
		return 4000 + in_chan * 5;
	else
		return 5000 + in_chan * 5;

	return in_chan;
}

unsigned int mac80211_freq_to_chan(unsigned int in_freq) {
    if (in_freq < 250)
        return in_freq;

    /* revamped from iw */
    if (in_freq == 2484)
        return 14;

    if (in_freq < 2484)
        return (in_freq - 2407) / 5;

    return in_freq / 5 - 1000;
}

int mac80211_connect(const char *interface, void **handle, void **cache,
					 void **family, char *errstr) {
#ifndef HAVE_LINUX_NETLINK
    snprintf(errstr, STATUS_MAX,
            "failed to connect interface '%s' via netlink/nl80211: Kismet was "
            "not compiled with netlink support, check the output of ./configure "
            "for more information.", interface);
	return -1;
#else
	struct nl_sock *nl_handle;
	struct nl_cache *nl_cache;
	struct genl_family *nl80211;

	if (*handle == NULL) {
		if ((nl_handle = nl_socket_alloc()) == NULL) {
			snprintf(errstr, STATUS_MAX, 
                    "failed to connect interface '%s' via netlink: unable to "
                    "allocate netlink socket.", interface);
			return -1;
		}

		if (genl_connect(nl_handle)) {
			snprintf(errstr, STATUS_MAX, 
                    "failed to connect interface '%s' via netlink: unable to "
                    "connect to netlink: %s", interface, strerror(errno));
			nl_socket_free(nl_handle);
			return -1;
		}
	} else {
		nl_handle = (struct nl_sock *) (*handle);
	}

	if (genl_ctrl_alloc_cache(nl_handle, &nl_cache) != 0) {
		snprintf(errstr, STATUS_MAX, 
                "failed to connect interface '%s' via netlink: unable to allocate "
                "control data.", interface);
		nl_socket_free(nl_handle);
		return -1;
	}

	if ((nl80211 = genl_ctrl_search_by_name(nl_cache, "nl80211")) == NULL) {
		snprintf(errstr, STATUS_MAX, 
                "failed to connect interface '%s' via netlink: failed to find "
                "nl80211 controls, kernel may be very old.", interface);
		nl_socket_free(nl_handle);
		return -1;
	}

	(*handle) = (void *) nl_handle;
	(*cache) = (void *) nl_cache;
	(*family) = (void *) nl80211;

	return 0;
#endif
}

void mac80211_disconnect(void *handle, void *cache) {
#ifdef HAVE_LINUX_NETLINK
	nl_socket_free((struct nl_sock *) handle);
    nl_cache_free((struct nl_cache *) cache);
#endif
}

void mac80211_insert_flags(unsigned int *flags, unsigned int flags_sz, 
        struct nl_msg *msg) {
#ifdef HAVE_LINUX_NETLINK
	struct nl_msg *nl_flags;
    unsigned int x;

	if ((nl_flags = nlmsg_alloc()) == NULL) {
		return;
	}

	for (x = 0; x < flags_sz; x++) {
		NLA_PUT_FLAG(nl_flags, flags[x]);
	}

	nla_put_nested(msg, NL80211_ATTR_MNTR_FLAGS, nl_flags);

nla_put_failure:
	nlmsg_free(nl_flags);
#endif
}

int mac80211_create_monitor_vif(const char *interface, const char *newinterface, 
       unsigned int *flags, unsigned int flags_sz, char *errstr) {
#ifndef HAVE_LINUX_NETLINK
	snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/mac80211 "
			 "support, check the output of ./configure for why");
	return -1;
#else

	struct nl_sock *nl_handle = NULL;
	struct nl_cache *nl_cache = NULL;
	struct genl_family *nl80211 = NULL;
	struct nl_msg *msg;

	if (if_nametoindex(newinterface) > 0) 
		return 1;

	if (mac80211_connect(interface, (void **) &nl_handle, 
						 (void **) &nl_cache, (void **) &nl80211, errstr) < 0)
		return -1;

	if ((msg = nlmsg_alloc()) == NULL) {
		snprintf(errstr, STATUS_MAX, 
                "unable to create monitor vif %s:%s, unable to allocate nl80211 "
                "message", interface, newinterface);
		mac80211_disconnect(nl_handle, nl_cache);
		return -1;
	}

	genlmsg_put(msg, 0, 0, genl_family_get_id(nl80211), 0, 0, 
				NL80211_CMD_NEW_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(interface));
	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, newinterface);
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

    if (flags_sz > 0)
        mac80211_insert_flags(flags, flags_sz, msg);

	if (nl_send_auto_complete(nl_handle, msg) < 0 || nl_wait_for_ack(nl_handle) < 0) {
nla_put_failure:
		snprintf(errstr, STATUS_MAX, 
                "failed to create monitor interface %s:%s",
                interface, newinterface);
		nlmsg_free(msg);
		mac80211_disconnect(nl_handle, nl_cache);
		return -1;
	}

	nlmsg_free(msg);
	mac80211_disconnect(nl_handle, nl_cache);

	if (if_nametoindex(newinterface) <= 0) {
		snprintf(errstr, STATUS_MAX, 
                "creating a monitor interface for %s:%s worked, but couldn't"
                "find that interface after creation.", interface, newinterface);
		return -1;
	}

	return 0;
#endif
}

int mac80211_set_channel_cache(const char *interface, void *handle,
							  void *family, int channel,
							  unsigned int chmode, char *errstr) {
#ifndef HAVE_LINUX_NETLINK
	snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/mac80211 "
			 "support, check the output of ./configure for why");
    return -1;
#else
	struct nl_sock *nl_handle = (struct nl_sock *) handle;
	struct genl_family *nl80211 = (struct genl_family *) family;
	struct nl_msg *msg;
	int ret = 0;

	if (chmode >= 4) {
		snprintf(errstr, STATUS_MAX, 
                "unable to set channel on interface '%s': invalid channel mode",
                interface);
		return -1;
	}

	if ((msg = nlmsg_alloc()) == NULL) {
		snprintf(errstr, STATUS_MAX, 
                "unable to set channel on interface '%s': unable to allocate mac80211 "
                "control message.", interface);
		return -1;
	}

	genlmsg_put(msg, 0, 0, genl_family_get_id(nl80211), 0, 0, NL80211_CMD_SET_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(interface));
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, mac80211_chan_to_freq(channel));
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, chmode);

	if ((ret = nl_send_auto_complete(nl_handle, msg)) >= 0) {
		if ((ret = nl_wait_for_ack(nl_handle)) < 0) 
			goto nla_put_failure;
	}

	nlmsg_free(msg);

	return 0;

nla_put_failure:
	snprintf(errstr, STATUS_MAX, 
            "unable to set channel %u/%u mode %u on interface '%s' via mac80211: "
            "error code %d", channel, mac80211_chan_to_freq(channel), chmode,
            interface, ret);
	nlmsg_free(msg);
	return ret;
#endif
}

int mac80211_set_channel(const char *interface, int channel, 
						unsigned int chmode, char *errstr) {
#ifndef HAVE_LINUX_NETLINK
	snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/mac80211 "
			 "support, check the output of ./configure for why");
    return -1;
#else
	struct nl_sock *nl_handle = NULL;
	struct nl_cache *nl_cache = NULL;
	struct genl_family *nl80211 = NULL;

	if (mac80211_connect(interface, (void **) &nl_handle, 
						 (void **) &nl_cache, (void **) &nl80211, errstr) < 0)
		return -1;

	int ret = 
		mac80211_set_channel_cache(interface, (void *) nl_handle,
                (void *) nl80211, channel, chmode, errstr);

	mac80211_disconnect(nl_handle, nl_cache);

	return ret;
#endif
}

int mac80211_set_frequency_cache(const char *interface, void *handle, void *family, 
        unsigned int control_freq, unsigned int chan_width, 
        unsigned int center_freq1, unsigned int center_freq2,
        char *errstr) {
#ifndef HAVE_LINUX_NETLINK
	snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/mac80211 "
			 "support, check the output of ./configure for why");
    return -1;
#else
	struct nl_sock *nl_handle = (struct nl_sock *) handle;
	struct genl_family *nl80211 = (struct genl_family *) family;
	struct nl_msg *msg;
	int ret = 0;

	if ((msg = nlmsg_alloc()) == NULL) {
		snprintf(errstr, STATUS_MAX, 
                "unable to set channel/frequency on interface '%s': unable to "
                "allocate mac80211 control message.", interface);
		return -1;
	}

	genlmsg_put(msg, 0, 0, genl_family_get_id(nl80211), 0, 0, NL80211_CMD_SET_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(interface));
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, control_freq);
    NLA_PUT_U32(msg, NL80211_ATTR_CHANNEL_WIDTH, chan_width);

    if (center_freq1 != 0) {
        NLA_PUT_U32(msg, NL80211_ATTR_CENTER_FREQ1, center_freq1);
    }

	if ((ret = nl_send_auto_complete(nl_handle, msg)) >= 0) {
		if ((ret = nl_wait_for_ack(nl_handle)) < 0) 
			goto nla_put_failure;
	}

	nlmsg_free(msg);

	return 0;

nla_put_failure:
	snprintf(errstr, STATUS_MAX, 
            "unable to set frequency %u %u %u on interface '%s' via mac80211: "
            "error code %d",
            control_freq, chan_width, center_freq1, interface, ret);
	nlmsg_free(msg);
	return ret;
#endif
}

int mac80211_set_frequency(const char *interface, 
        unsigned int control_freq, unsigned int chan_width,
        unsigned int center_freq1, unsigned int center_freq2,
        char *errstr) {
#ifndef HAVE_LINUX_NETLINK
	snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/mac80211 "
			 "support, check the output of ./configure for why");
    return -1;
#else
	struct nl_sock *nl_handle = NULL;
	struct nl_cache *nl_cache = NULL;
	struct genl_family *nl80211 = NULL;

	if (mac80211_connect(interface, (void **) &nl_handle, 
						 (void **) &nl_cache, (void **) &nl80211, errstr) < 0)
		return -1;

	int ret = 
		mac80211_set_frequency_cache(interface, (void *) nl_handle, (void *) nl80211, 
                control_freq, chan_width, center_freq1, center_freq2, errstr);

	mac80211_disconnect(nl_handle, nl_cache);

	return ret;
#endif
}

struct nl80211_channel_block {
	char *phyname;
	int nfreqs;
	char **channel_list;
};

#ifdef HAVE_LINUX_NETLINK
static int nl80211_freqlist_cb(struct nl_msg *msg, void *arg) {
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *) nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
	struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
	struct nlattr *nl_band, *nl_freq;
	int rem_band, rem_freq, num_freq = 0;
	uint32_t freq;
	struct nl80211_channel_block *chanb = (struct nl80211_channel_block *) arg;
    char channel_str[32];
    int band_ht40, band_ht80, band_ht160;
    unsigned int hti;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb_msg[NL80211_ATTR_WIPHY_BANDS]) {
		return NL_SKIP;
	}

	if (tb_msg[NL80211_ATTR_WIPHY_NAME]) {
		if (strcmp(nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]), 
				   chanb->phyname) != 0) {
			return NL_SKIP;
		}
	}

	// Count the number of channels
	for (nl_band = (struct nlattr *) nla_data(tb_msg[NL80211_ATTR_WIPHY_BANDS]),
		 rem_band = nla_len(tb_msg[NL80211_ATTR_WIPHY_BANDS]);
		 nla_ok(nl_band, rem_band); 
         nl_band = (struct nlattr *) nla_next(nl_band, &rem_band)) {

        band_ht40 = 0;
        band_ht80 = 0;
        band_ht160 = 0;

        nla_parse(tb_band, NL80211_BAND_ATTR_MAX, (struct nlattr *) nla_data(nl_band),
                nla_len(nl_band), NULL);

        /* If we have a HT capability field, examine it for HT40 */
        if (tb_band[NL80211_BAND_ATTR_HT_CAPA]) {
            __u16 cap = nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_CAPA]);

            /* bit 1 is the HT40 bit */
            if (cap & (1 << 1))
                band_ht40 = 1;
        }

        /* If we have a VHT field, we can assume we have HT80 and then we need
         * to examine ht160.  
         * TODO: figure out 160 80+80; do all devices that support 80+80 support
         * 160?  For now we assume they do...
         */
        if (tb_band[NL80211_BAND_ATTR_VHT_CAPA]) {
            band_ht80 = 1;

            __u16 cap = nla_get_u32(tb_band[NL80211_BAND_ATTR_VHT_CAPA]);

            if (((cap >> 2) & 3) == 1) {
                band_ht160 = 1;
            } else if (((cap >> 2) & 3) == 2) {
                fprintf(stderr, "debug - your device supports 160(80+80) mode\n");
                band_ht160 = 1;
            }
        }

		for (nl_freq = (struct nlattr *) nla_data(tb_band[NL80211_BAND_ATTR_FREQS]),
			 rem_freq = nla_len(tb_band[NL80211_BAND_ATTR_FREQS]);
			 nla_ok(nl_freq, rem_freq); 
			 nl_freq = (struct nlattr *) nla_next(nl_freq, &rem_freq)) {

			nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, 
					  (struct nlattr *) nla_data(nl_freq),
					  nla_len(nl_freq), NULL);

			if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
				continue;

			if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
				continue;

            /* We've got at least one actual frequency */
			num_freq++;

			freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);

            /* Look us up in the wifi_ht_channels list and add channels if we
             * need to add HT capabilities.  We could convert this to a channel
             * but it's better to do a frequency lookup */
            for (hti = 0; hti < MAX_WIFI_HT_CHANNEL; hti++) {
                if (wifi_ht_channels[hti].freq == freq) {
                    if (band_ht40) {
                        if (wifi_ht_channels[hti].flags & WIFI_HT_HT40MINUS) 
                            num_freq++;
                        if (wifi_ht_channels[hti].flags & WIFI_HT_HT40PLUS)
                            num_freq++;
                    }

                    if (band_ht80 && wifi_ht_channels[hti].flags & WIFI_HT_HT80) {
                        num_freq++;
                    }

                    if (band_ht160 && wifi_ht_channels[hti].flags & WIFI_HT_HT160) {
                        num_freq++;
                    }

                    break;
                }
            }
		}
	}

	chanb->nfreqs = num_freq;
	chanb->channel_list = malloc(sizeof(char *) * num_freq);
	num_freq = 0;

	// Assemble a return
	for (nl_band = (struct nlattr *) nla_data(tb_msg[NL80211_ATTR_WIPHY_BANDS]),
		 rem_band = nla_len(tb_msg[NL80211_ATTR_WIPHY_BANDS]);
		 nla_ok(nl_band, rem_band); 
		 nl_band = (struct nlattr *) nla_next(nl_band, &rem_band)) {

		nla_parse(tb_band, NL80211_BAND_ATTR_MAX, (struct nlattr *) nla_data(nl_band),
				  nla_len(nl_band), NULL);

		for (nl_freq = (struct nlattr *) nla_data(tb_band[NL80211_BAND_ATTR_FREQS]),
			 rem_freq = nla_len(tb_band[NL80211_BAND_ATTR_FREQS]);
			 nla_ok(nl_freq, rem_freq); 
			 nl_freq = (struct nlattr *) nla_next(nl_freq, &rem_freq)) {

			nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, 
					  (struct nlattr *) nla_data(nl_freq),
					  nla_len(nl_freq), NULL);

			if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
				continue;

			if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
				continue;

			freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);

            snprintf(channel_str, 32, "%u", mac80211_freq_to_chan(freq));
            chanb->channel_list[num_freq++] = strdup(channel_str);

            /* Look us up again, this time making a HT-channel string for 
             * each channel */
            for (hti = 0; hti < MAX_WIFI_HT_CHANNEL; hti++) {
                if (wifi_ht_channels[hti].freq == freq) {
                    if (band_ht40) {
                        if (wifi_ht_channels[hti].flags & WIFI_HT_HT40MINUS) {
                            snprintf(channel_str, 32, 
                                    "%uHT40-", mac80211_freq_to_chan(freq));
                            chanb->channel_list[num_freq++] = strdup(channel_str);
                        } 
                        if (wifi_ht_channels[hti].flags & WIFI_HT_HT40PLUS) {
                            snprintf(channel_str, 32, 
                                    "%uHT40+", mac80211_freq_to_chan(freq));
                            chanb->channel_list[num_freq++] = strdup(channel_str);
                        }
                    }

                    if (band_ht80 && wifi_ht_channels[hti].flags & WIFI_HT_HT80) {
                        snprintf(channel_str, 32, 
                                "%uVHT80", mac80211_freq_to_chan(freq));
                        chanb->channel_list[num_freq++] = strdup(channel_str);
                    }

                    if (band_ht160 && wifi_ht_channels[hti].flags & WIFI_HT_HT160) {
                        snprintf(channel_str, 32, 
                                "%uVHT160", mac80211_freq_to_chan(freq));
                        chanb->channel_list[num_freq++] = strdup(channel_str);
                    }

                    break;
                }
            }
		}
	}

	return NL_SKIP;
}
#endif

#ifdef HAVE_LINUX_NETLINK
static int nl80211_error_cb(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg) {
	int *ret = (int *) arg;
	*ret = err->error;
	return NL_STOP;
}

static int nl80211_finish_cb(struct nl_msg *msg, void *arg) {
	int *ret = (int *) arg;
	*ret = 0;
	return NL_SKIP;
}
#endif

int mac80211_get_chanlist(const char *interface, char *errstr,
        char ***ret_chan_list, unsigned int *ret_num_chans) {
	struct nl80211_channel_block cblock = {
        .phyname = NULL,
        .nfreqs = 0,
        .channel_list = NULL,
    };

#ifndef HAVE_LINUX_NETLINK
	snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/nl80211 "
			 "support, check the output of ./configure for why");
    return -1;
#else
	void *handle = NULL, *cache = NULL, *family = NULL;
	struct nl_cb *cb;
	int err;
	struct nl_msg *msg;

	cblock.phyname = mac80211_find_parent(interface);
	if (strlen(cblock.phyname) == 0) {
		if (if_nametoindex(interface) <= 0) {
			snprintf(errstr, STATUS_MAX, 
                    "failed to get channels from interface '%s': interface does "
                    "not exist.", interface);
            return -1;
		} 

		snprintf(errstr, STATUS_MAX, 
                "failed to find parent phy interface for interface '%s': interface "
                "may not be a mac80211 wifi device?", interface);
        return -1;
	}

	if (mac80211_connect(interface, &handle, &cache, &family, errstr) < 0) {
        return -1;
	}

	msg = nlmsg_alloc();
	cb = nl_cb_alloc(NL_CB_DEFAULT);

	err = 1;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_freqlist_cb, &cblock);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, nl80211_finish_cb, &err);
	nl_cb_err(cb, NL_CB_CUSTOM, nl80211_error_cb, &err);

	genlmsg_put(msg, 0, 0, genl_family_get_id((struct genl_family *) family),
			  0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);

	if (nl_send_auto_complete((struct nl_sock *) handle, msg) < 0) {
		snprintf(errstr, STATUS_MAX, 
                "failed to fetch channels from interface '%s': failed to "
                "write netlink command", interface);
		mac80211_disconnect(handle, cache);
        free(cb);
        return -1;
	}

	while (err)
		nl_recvmsgs((struct nl_sock *) handle, cb);

    free(cb);
	mac80211_disconnect(handle, cache);

	(*ret_num_chans) = cblock.nfreqs;
    (*ret_chan_list) = (cblock.channel_list);

	free(cblock.phyname);

	return (*ret_num_chans);
#endif
}


char *mac80211_find_parent(const char *interface) {
	DIR *devdir;
	struct dirent *devfile;
    char dirpath[2048];
    char *dev;

    snprintf(dirpath, 2048, "/sys/class/net/%s/phy80211/device", interface);

	if ((devdir = opendir(dirpath)) == NULL)
		return strdup("");

	while ((devfile = readdir(devdir)) != NULL) {
		if (strlen(devfile->d_name) < 9)
			continue;

		if (strncmp("ieee80211:phy", devfile->d_name, 13) == 0) {
            dev = strdup(devfile->d_name + 10);
			closedir(devdir);
			return dev;
		}

        if (strncmp("ieee80211", devfile->d_name, 9) == 0) {
            DIR *ieeedir;
            struct dirent *ieeefile;

            snprintf(dirpath, 2048, "/sys/class/net/%s/phy80211/device/ieee80211", 
                    interface);

            if ((ieeedir = opendir(dirpath)) != NULL) {
                while ((ieeefile = readdir(ieeedir)) != NULL) {
                    if (strncmp("phy", ieeefile->d_name, 3) == 0) {
                        dev = strdup(ieeefile->d_name);

                        closedir(ieeedir);
                        closedir(devdir);

                        return dev;
                    }
                }
            }

            closedir(ieeedir);
        }
	}

	closedir(devdir);
    return NULL;
}

#endif /* linux */

