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

#if defined(HAVE_LIBNL20) || defined(HAVE_LIBNL30) || defined(HAVE_LIBNLTINY)
#define HAVE_LIBNL_NG
#endif

#ifdef SYS_LINUX

#ifdef HAVE_LINUX_NETLINK
#include <sys/types.h>
#include <asm/types.h>

#ifdef HAVE_LIBNLTINY
#define _GNU_SOURCE
#endif

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "../nl80211.h"
#include <net/if.h>
#endif

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "linux_netlink_control.h"
#include "../wifi_ht_channels.h"

// Libnl1->Libnl2 compatability mode since the API changed, cribbed from 'iw'
#if defined(HAVE_LIBNL10)

#define nl_sock nl_handle

static inline struct nl_handle *nl_socket_alloc(void) {
	return nl_handle_alloc();
}

static inline void nl_socket_free(struct nl_sock *h) {
	nl_handle_destroy(h);
}

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

int mac80211_connect(const char *interface, void **nl_sock, 
        int *nl80211_id, int *if_index, char *errstr) {
#ifndef HAVE_LINUX_NETLINK
    snprintf(errstr, STATUS_MAX,
            "cannot connect to netlink; not compiled with netlink "
            "support.  Check the output of ./configure for more information");
    return -1;
#else

    if ((*if_index = if_nametoindex(interface)) < 0) {
        snprintf(errstr, STATUS_MAX,
                "cannot connect to netlink:  Could not find interface '%s'", interface);
        return -1;
    }

    *nl_sock = nl_socket_alloc();
    if (!nl_sock) {
        snprintf(errstr, STATUS_MAX, 
                "unable to connect to netlink: could not allocate netlink socket");
        return -1;
    }

    if (genl_connect(*nl_sock)) {
        snprintf(errstr, STATUS_MAX, 
                "unable to connect to netlink: could not connect to generic netlink");
        return -1;
        nl_socket_free(*nl_sock);
    }

    *nl80211_id = genl_ctrl_resolve(*nl_sock, "nl80211");
    if (nl80211_id < 0) {
        snprintf(errstr, STATUS_MAX, 
                "unable to connect to netlink: could not resolve nl80211");
        nl_socket_free(*nl_sock);
    }

    return 0;
#endif
}

void mac80211_disconnect(void *nl_sock) {
#ifdef HAVE_LINUX_NETLINK
    nl_socket_free(nl_sock);
#endif
}

int mac80211_create_monitor_vif(const char *interface, const char *newinterface, 
        unsigned int *in_flags, unsigned int flags_sz, char *errstr) {
#ifndef HAVE_LINUX_NETLINK
    snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/mac80211 "
            "support, check the output of ./configure for why");
    return -1;
#else

    void *nl_sock;
    int nl80211_id;

    struct nl_msg *msg;
    struct nl_msg *flags;

    unsigned int x;

    if (if_nametoindex(newinterface) > 0) 
        return 1;

    nl_sock = nl_socket_alloc();
    if (!nl_sock) {
        snprintf(errstr, STATUS_MAX, 
                "unable to create monitor vif %s:%s, unable to allocate netlink socket",
                interface, newinterface);
        return -1;
    }

    if (genl_connect(nl_sock)) {
        snprintf(errstr, STATUS_MAX, 
                "unable to create monitor vif %s:%s, unable to connect generic netlink",
                interface, newinterface);
        nl_socket_free(nl_sock);
    }

    nl80211_id = genl_ctrl_resolve(nl_sock, "nl80211");
    if (nl80211_id < 0) {
        snprintf(errstr, STATUS_MAX, 
                "unable to create monitor vif %s:%s, unable to resolve nl80211",
                interface, newinterface);
        nl_socket_free(nl_sock);
    }

    if ((msg = nlmsg_alloc()) == NULL) {
        snprintf(errstr, STATUS_MAX, 
                "unable to create monitor vif %s:%s, unable to allocate nl80211 "
                "message", interface, newinterface);
        nl_socket_free(nl_sock);
        return -1;
    }

    if ((flags = nlmsg_alloc()) == NULL) {
        snprintf(errstr, STATUS_MAX, 
                "unable to create monitor vif %s:%s, unable to allocate nl80211 flags",
                interface, newinterface);
        nl_socket_free(nl_sock);
        return -1;
    }

    genlmsg_put(msg, 0, 0, nl80211_id, 0, 0, NL80211_CMD_NEW_INTERFACE, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(interface));
    NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, newinterface);
    NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

    for (x = 0; x < flags_sz; x++) {
        NLA_PUT_FLAG(flags, in_flags[x]);
    }
    
    if (flags_sz > 0)
        nla_put_nested(msg, NL80211_ATTR_MNTR_FLAGS, flags);

    if (nl_send_auto_complete(nl_sock, msg) < 0 || nl_wait_for_ack(nl_sock) < 0) {
nla_put_failure:
        snprintf(errstr, STATUS_MAX, "failed to create monitor interface %s:%s",
                interface, newinterface);
        nl_socket_free(nl_sock);
        nlmsg_free(msg);
        nlmsg_free(flags);
        return -1;
    }

    nl_socket_free(nl_sock);
    nlmsg_free(msg);
    nlmsg_free(flags);

    if (if_nametoindex(newinterface) <= 0) {
        snprintf(errstr, STATUS_MAX, 
                "creating a monitor interface for %s:%s worked, but couldn't"
                "find that interface after creation.", interface, newinterface);
        return -1;
    }

    return 0;
#endif
}

int mac80211_set_channel_cache(int ifindex, void *nl_sock,
        int nl80211_id, int channel, unsigned int chmode, char *errstr) {
#ifndef HAVE_LINUX_NETLINK
    snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/mac80211 "
            "support, check the output of ./configure for why");
    return -1;
#else
    struct nl_msg *msg;
    int ret = 0;

    if (chmode >= 4) {
        snprintf(errstr, STATUS_MAX, "unable to set channel: invalid channel mode");
        return -1;
    }

    if ((msg = nlmsg_alloc()) == NULL) {
        snprintf(errstr, STATUS_MAX, 
                "unable to set channel: unable to allocate mac80211 control message.");
        return -1;
    }

    genlmsg_put(msg, 0, 0, nl80211_id, 0, 0, NL80211_CMD_SET_WIPHY, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, mac80211_chan_to_freq(channel));
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, chmode);

    if ((ret = nl_send_auto_complete(nl_sock, msg)) >= 0) {
        if ((ret = nl_wait_for_ack(nl_sock)) < 0) 
            goto nla_put_failure;
    }

    nlmsg_free(msg);

    return 0;

nla_put_failure:
    snprintf(errstr, STATUS_MAX, 
            "unable to set channel %u/%u mode %u via mac80211: "
            "error code %d", channel, mac80211_chan_to_freq(channel), chmode, ret);
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
    void *nl_sock;
    int nl80211_id;
    int ifidx;

    if (mac80211_connect(interface, &nl_sock, &nl80211_id, &ifidx, errstr) < 0)
        return -1;

    int ret = 
        mac80211_set_channel_cache(ifidx, nl_sock, nl80211_id, channel, chmode, errstr);

    mac80211_disconnect(nl_sock);

    return ret;
#endif
}

int mac80211_set_frequency_cache(int ifindex, void *nl_sock, int nl80211_id, 
        unsigned int control_freq, unsigned int chan_width, 
        unsigned int center_freq1, unsigned int center_freq2,
        char *errstr) {
#ifndef HAVE_LINUX_NETLINK
	snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/mac80211 "
			 "support, check the output of ./configure for why");
    return -1;
#else
    struct nl_msg *msg;
    int ret = 0;

    if ((msg = nlmsg_alloc()) == NULL) {
        snprintf(errstr, STATUS_MAX, 
                "unable to set channel/frequency: unable to allocate "
                "mac80211 control message.");
        return -1;
    }

    genlmsg_put(msg, 0, 0, nl80211_id, 0, 0, NL80211_CMD_SET_WIPHY, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, 
            mac80211_chan_to_freq(control_freq));
    NLA_PUT_U32(msg, NL80211_ATTR_CHANNEL_WIDTH, chan_width);

    switch (chan_width) {
        case NL80211_CHAN_WIDTH_20_NOHT:
            NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_NO_HT);
            break;
        case NL80211_CHAN_WIDTH_20:
            NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_HT20);
            break;
        case NL80211_CHAN_WIDTH_40:
            if (control_freq > center_freq1)
                NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_HT40MINUS);
            else
                NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_HT40PLUS);
            break;
        default:
            break;
    }

    if (center_freq1 != 0) {
        NLA_PUT_U32(msg, NL80211_ATTR_CENTER_FREQ1, 
                mac80211_chan_to_freq(center_freq1));
    }

    if ((ret = nl_send_auto_complete(nl_sock, msg)) >= 0) {
        if ((ret = nl_wait_for_ack(nl_sock)) < 0) 
            goto nla_put_failure;
    }

    nlmsg_free(msg);

    return 0;

nla_put_failure:
	snprintf(errstr, STATUS_MAX, 
            "unable to set frequency %u %u %u via mac80211: error code %d",
            control_freq, chan_width, center_freq1, ret);
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
    void *nl_sock;
    int ifidx;
    int nl80211_id;

    if (mac80211_connect(interface, &nl_sock, &nl80211_id, &ifidx, errstr) < 0) {
        return -1;
    }

    int ret = 
        mac80211_set_frequency_cache(ifidx, nl_sock, nl80211_id, 
                control_freq, chan_width, center_freq1, center_freq2, errstr);

    mac80211_disconnect(nl_sock);

    return ret;
#endif
}

struct nl80211_channel_list {
    char *channel;
    struct nl80211_channel_list *next;
};

struct nl80211_channel_block {
	char *phyname;

	int nfreqs;
    unsigned int extended_flags;

    struct nl80211_channel_list *channel_list;
    struct nl80211_channel_list *chan_list_last;
};


#ifdef HAVE_LINUX_NETLINK
static int nl80211_freqlist_cb(struct nl_msg *msg, void *arg) {
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = (struct genlmsghdr *) nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
    struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
    struct nlattr *nl_band, *nl_freq;
    int rem_band, rem_freq;
    uint32_t freq;
    struct nl80211_channel_block *chanb = (struct nl80211_channel_block *) arg;
    char channel_str[32];
    int band_ht40, band_ht80, band_ht160;
    unsigned int hti;

    struct nl80211_channel_list *chan_list_new;

    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (tb_msg[NL80211_ATTR_WIPHY_NAME]) {
        if (strcmp(nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]), chanb->phyname) != 0) {
            return NL_SKIP;
        }
    }

    if (tb_msg[NL80211_ATTR_WIPHY_BANDS]) {
        nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band) {
            band_ht40 = band_ht80 = band_ht160 = 0;

            nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band),
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

            // fprintf(stderr, "debug - %u %u %u\n", band_ht40, band_ht80, band_ht160);

            if (tb_band[NL80211_BAND_ATTR_FREQS]) {
                nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], rem_freq) {
                    nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, nla_data(nl_freq),
                            nla_len(nl_freq), NULL);

                    if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
                        continue;

                    if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
                        continue;

                    /* We've got at least one actual frequency */
                    freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);

                    chan_list_new = (struct nl80211_channel_list *) malloc(sizeof(struct nl80211_channel_list));

                    snprintf(channel_str, 32, "%u", mac80211_freq_to_chan(freq));
                    chan_list_new->channel = strdup(channel_str);

                    chan_list_new->next = NULL;
                    chanb->nfreqs++;
                    chanb->chan_list_last->next = chan_list_new;
                    chanb->chan_list_last = chan_list_new;

                    /* Look us up in the wifi_ht_channels list and add channels if we
                     * need to add HT capabilities.  We could convert this to a channel
                     * but it's better to do a frequency lookup */
                    for (hti = 0; hti < MAX_WIFI_HT_CHANNEL; hti++) {
                        if (wifi_ht_channels[hti].freq == freq) {
                            if (band_ht40 && (chanb->extended_flags & MAC80211_GET_HT)) {
                                if (wifi_ht_channels[hti].flags & WIFI_HT_HT40MINUS) {
                                    chan_list_new = (struct nl80211_channel_list *) malloc(sizeof(struct nl80211_channel_list));
                                    snprintf(channel_str, 32, 
                                            "%uHT40-", mac80211_freq_to_chan(freq));
                                    chan_list_new->channel = strdup(channel_str);

                                    chan_list_new->next = NULL;
                                    chanb->nfreqs++;
                                    chanb->chan_list_last->next = chan_list_new;
                                    chanb->chan_list_last = chan_list_new;
                                }

                                if (wifi_ht_channels[hti].flags & WIFI_HT_HT40PLUS) {
                                    chan_list_new = (struct nl80211_channel_list *) malloc(sizeof(struct nl80211_channel_list));

                                    snprintf(channel_str, 32, 
                                            "%uHT40+", mac80211_freq_to_chan(freq));
                                    chan_list_new->channel = strdup(channel_str);

                                    chan_list_new->next = NULL;
                                    chanb->nfreqs++;
                                    chanb->chan_list_last->next = chan_list_new;
                                    chanb->chan_list_last = chan_list_new;
                                }
                            }

                            if (band_ht80 && wifi_ht_channels[hti].flags & WIFI_HT_HT80 &&
                                    (chanb->extended_flags & MAC80211_GET_VHT)) {
                                chan_list_new = (struct nl80211_channel_list *) malloc(sizeof(struct nl80211_channel_list));
                                snprintf(channel_str, 32, 
                                        "%uVHT80", mac80211_freq_to_chan(freq));
                                chan_list_new->channel = strdup(channel_str);

                                chan_list_new->next = NULL;
                                chanb->nfreqs++;
                                chanb->chan_list_last->next = chan_list_new;
                                chanb->chan_list_last = chan_list_new;
                            }

                            if (band_ht160 && wifi_ht_channels[hti].flags & WIFI_HT_HT160 &&
                                    (chanb->extended_flags & MAC80211_GET_VHT)) {
                                chan_list_new = (struct nl80211_channel_list *) malloc(sizeof(struct nl80211_channel_list));
                                snprintf(channel_str, 32, 
                                        "%uVHT160", mac80211_freq_to_chan(freq));
                                chan_list_new->channel = strdup(channel_str);

                                chan_list_new->next = NULL;
                                chanb->nfreqs++;
                                chanb->chan_list_last->next = chan_list_new;
                                chanb->chan_list_last = chan_list_new;
                            }

                            break;
                        }
                    }
                }
            }
        }
    }

    return NL_SKIP;
}
#endif

#ifdef HAVE_LINUX_NETLINK
static int nl80211_error_cb(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
	int *ret = (int *) arg;
	*ret = err->error;
	return NL_STOP;
}

static int nl80211_finish_cb(struct nl_msg *msg, void *arg) {
	int *ret = (int *) arg;
	*ret = 0;
	return NL_SKIP;
}

static int nl80211_ack_cb(struct nl_msg *msg, void *arg) {
    int *ret = arg;
    *ret = 0;
    return NL_STOP;
}
#endif

int mac80211_get_chanlist(const char *interface, unsigned int extended_flags, char *errstr,
        char ***ret_chan_list, unsigned int *ret_num_chans) {
    struct nl80211_channel_block cblock = {
        .phyname = NULL,
        .nfreqs = 0,
        .channel_list = NULL,
        .chan_list_last = NULL
    };

    unsigned int num_freq;
    struct nl80211_channel_list *chan_list_cur, *chan_list_old;

#ifndef HAVE_LINUX_NETLINK
    snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/nl80211 "
            "support, check the output of ./configure for why");
    return -1;
#else

    void *nl_sock;
    int nl80211_id;

    struct nl_cb *cb;
    int err;
    struct nl_msg *msg;

    cblock.extended_flags = extended_flags;

    cblock.phyname = mac80211_find_parent(interface);
    if (strlen(cblock.phyname) == 0) {
        if (if_nametoindex(interface) <= 0) {
            snprintf(errstr, STATUS_MAX, 
                    "failed to get channels from interface '%s': interface does "
                    "not exist.", interface);
            free(cblock.phyname);
            return -1;
        } 

        snprintf(errstr, STATUS_MAX, 
                "failed to find parent phy interface for interface '%s': interface "
                "may not be a mac80211 wifi device?", interface);
        free(cblock.phyname);
        return -1;
    }

    nl_sock = nl_socket_alloc();
    if (!nl_sock) {
        snprintf(errstr, STATUS_MAX, "FATAL: Failed to allocate netlink socket");
        free(cblock.phyname);
        return -1;
    }

    if (genl_connect(nl_sock)) {
        snprintf(errstr, STATUS_MAX, "FATAL: Failed to connect to generic netlink");
        nl_socket_free(nl_sock);
        free(cblock.phyname);
        return -1;
    }

    nl80211_id = genl_ctrl_resolve(nl_sock, "nl80211");
    if (nl80211_id < 0) {
        snprintf(errstr, STATUS_MAX, "FATAL: Failed to resolve nl80211");
        nl_socket_free(nl_sock);
        free(cblock.phyname);
        return -1;
    }

    msg = nlmsg_alloc();

    cb = nl_cb_alloc(NL_CB_DEFAULT);

    err = 1;

    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nl80211_freqlist_cb, &cblock);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, nl80211_ack_cb, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, nl80211_finish_cb, &err);
    nl_cb_err(cb, NL_CB_CUSTOM, nl80211_error_cb, &err);

    genlmsg_put(msg, 0, 0, nl80211_id, 0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);

    /* Initialize the empty first channel list item */
    cblock.channel_list = (struct nl80211_channel_list *) malloc(sizeof(struct nl80211_channel_list));
    cblock.channel_list->channel = NULL;
    cblock.channel_list->next = NULL;
    cblock.chan_list_last = cblock.channel_list;

    if (nl_send_auto_complete((struct nl_sock *) nl_sock, msg) < 0) {
        snprintf(errstr, STATUS_MAX, 
                "failed to fetch channels from interface '%s': failed to "
                "write netlink command", interface);
        nlmsg_free(msg);
        nl_cb_put(cb);
        nl_socket_free(nl_sock);
        free(cblock.phyname);
        return -1;
    }

    while (err)
        nl_recvmsgs((struct nl_sock *) nl_sock, cb);

    nl_cb_put(cb);
    nlmsg_free(msg);
    nl_socket_free(nl_sock);

    /* Convert our linked list into a channel block */

    (*ret_num_chans) = cblock.nfreqs;
    (*ret_chan_list) = malloc(sizeof(char *) * cblock.nfreqs);

    num_freq = 0;

    /* Skip the first item which is our placeholder */
    chan_list_cur = cblock.channel_list->next;

    while (chan_list_cur != NULL && num_freq < cblock.nfreqs) {
        /* Use the dup'd string directly */
        (*ret_chan_list)[num_freq++] = chan_list_cur->channel;

        // fprintf(stderr, "debug - %u %s\n", num_freq, chan_list_cur->channel);

        /* Shuffle the pointers */
        chan_list_old = chan_list_cur;
        chan_list_cur = chan_list_cur->next;
        free(chan_list_old);
    }

    /* If we didn't process all the channels before we hit the end of the list... */
    if (chan_list_cur != NULL || num_freq != cblock.nfreqs) {
        fprintf(stderr, "ERROR - linux_netlink_control miscalculated the number of "
                "channels somehow...\n");

        /* Clean up list overrun */
        while (chan_list_cur != NULL) {
            chan_list_old = chan_list_cur;
            chan_list_cur = chan_list_cur->next;
            free(chan_list_old);
        }

        /* Clean up list underrun */
        for ( ; num_freq < cblock.nfreqs; num_freq++) {
            (*ret_chan_list)[num_freq] = NULL;
        }
    }

    /* remove the list head ptr */
    free(cblock.channel_list);
    /* Remove the phyname */
    free(cblock.phyname);

    // (*ret_chan_list)[0] = strdup("45");

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

            if (ieeedir != NULL)
                closedir(ieeedir);
        }
    }

    closedir(devdir);
    return NULL;
}

#endif /* linux */

