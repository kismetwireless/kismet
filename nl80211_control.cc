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

#ifdef SYS_LINUX

#ifdef HAVE_LINUX_NETLINK
#include <sys/types.h>
#include <asm/types.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include "nl80211.h"
#include <net/if.h>
#endif

#include <stdio.h>

#include "util.h"

// Libnl1->Libnl2 compatability mode since the API changed, cribbed from 'iw'
#ifndef HAVE_LIBNL20
#define nl_sock nl_handle

static inline struct nl_handle *nl_socket_alloc(void) {
	return nl_handle_alloc();
}

static inline void nl_socket_free(struct nl_sock *h) {
	nl_handle_destroy(h);
}

static inline int __genl_ctrl_alloc_cache(struct nl_sock *h, struct nl_cache **cache) {
	struct nl_cache *tmp = genl_ctrl_alloc_cache(h);
	if (!tmp)
		return -ENOMEM;
	*cache = tmp;
	return 0;
}
#define genl_ctrl_alloc_cache __genl_ctrl_alloc_cache
#endif

int mac80211_connect(const char *interface, void **handle, void **cache,
					 void **family, char *errstr) {
#ifndef HAVE_LINUX_NETLINK
	snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/mac80211 "
			 "support, check the output of ./configure for why");
	return -1;
#else
	struct nl_sock *nl_handle;
	struct nl_cache *nl_cache;
	struct genl_family *nl80211;

	if ((nl_handle = nl_socket_alloc()) == NULL) {
		snprintf(errstr, STATUS_MAX, "mac80211_setchannel() failed to "
				 "allocate nlhandle");
		return -1;
	}

	if (genl_connect(nl_handle)) {
		snprintf(errstr, STATUS_MAX, "mac80211_setchannel() failed to connect "
				 "to generic netlink");
		nl_socket_free(nl_handle);
		return -1;
	}

	if (genl_ctrl_alloc_cache(nl_handle, &nl_cache) != 0) {
		snprintf(errstr, STATUS_MAX, "mac80211_setchannel() failed to allocate generic "
				 "netlink cache");
		nl_socket_free(nl_handle);
		return -1;
	}

	if ((nl80211 = genl_ctrl_search_by_name(nl_cache, "nl80211")) == NULL) {
		snprintf(errstr, STATUS_MAX, "mac80211_setchannel() failed to find nl80211 "
				 "controls, kernel may be too old");
		nl_socket_free(nl_handle);
		return -1;
	}

	(*handle) = (void *) nl_handle;
	(*cache) = (void *) nl_cache;
	(*family) = (void *) nl80211;

	return 1;
#endif
}

void mac80211_disconnect(void *handle) {
#ifdef HAVE_LINUX_NETLINK
	nl_socket_free((nl_sock *) handle);
#endif
}

int mac80211_createvap(const char *interface, const char *newinterface, char *errstr) {
#ifndef HAVE_LINUX_NETLINK
	snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/mac80211 "
			 "support, check the output of ./configure for why");
	return -1;
#else

	struct nl_sock *nl_handle;
	struct nl_cache *nl_cache;
	struct genl_family *nl80211;
	struct nl_msg *msg;

	if (if_nametoindex(newinterface) > 0) 
		return 1;

	if (mac80211_connect(interface, (void **) &nl_handle, 
						 (void **) &nl_cache, (void **) &nl80211, errstr) < 0)
		return -1;

	if ((msg = nlmsg_alloc()) == NULL) {
		snprintf(errstr, STATUS_MAX, "mac80211_createvap() failed to allocate "
				 "message");
		mac80211_disconnect(nl_handle);
		return -1;
	}

	genlmsg_put(msg, 0, 0, genl_family_get_id(nl80211), 0, 0, 
				NL80211_CMD_NEW_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(interface));
	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, newinterface);
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

	if (nl_send_auto_complete(nl_handle, msg) < 0 || nl_wait_for_ack(nl_handle) < 0) {
nla_put_failure:
		snprintf(errstr, STATUS_MAX, "mac80211_createvap() failed to create "
				 "interface '%s'", newinterface);
		nlmsg_free(msg);
		mac80211_disconnect(nl_handle);
		return -1;
	}

	nlmsg_free(msg);

	mac80211_disconnect(nl_handle);

	if (if_nametoindex(newinterface) <= 0) {
		snprintf(errstr, STATUS_MAX, "mac80211_createvap() thought we made a vap, "
				 "but it wasn't there when we looked");
		return -1;
	}

	return 0;
#endif
}

int mac80211_setchannel_cache(const char *interface, void *handle,
							  void *family, int channel,
							  unsigned int chmode, char *errstr) {
#ifndef HAVE_LINUX_NETLINK
	snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/mac80211 "
			 "support, check the output of ./configure for why");
	// Return the same error as we get if the device doesn't support nlfreq
	return -22;
#else
	struct nl_sock *nl_handle = (struct nl_sock *) handle;
	struct genl_family *nl80211 = (struct genl_family *) family;
	struct nl_msg *msg;
	int ret = 0;

	int chanmode[] = {
		NL80211_CHAN_NO_HT, NL80211_CHAN_HT20, 
		NL80211_CHAN_HT40PLUS, NL80211_CHAN_HT40MINUS
	};

	if (chmode > 4) {
		snprintf(errstr, STATUS_MAX, "Invalid channel mode\n");
		return -1;
	}

	if ((msg = nlmsg_alloc()) == NULL) {
		snprintf(errstr, STATUS_MAX, "mac80211_setchannel() failed to allocate "
				 "message");
		return -1;
	}

	genlmsg_put(msg, 0, 0, genl_family_get_id(nl80211), 0, 0, 
				NL80211_CMD_SET_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(interface));
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, ChanToFreq(channel));
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, chanmode[chmode]);

	if ((ret = nl_send_auto_complete(nl_handle, msg)) >= 0) {
		if ((ret = nl_wait_for_ack(nl_handle)) < 0) 
			goto nla_put_failure;
	}

	// fprintf(stderr, "debug - nl channel set success\n");

	nlmsg_free(msg);

	return 0;

nla_put_failure:
	snprintf(errstr, STATUS_MAX, "mac80211_setchannel() could not set channel "
			 "%d/%d on interface '%s' err %d", channel, ChanToFreq(channel), 
			 interface, ret);
	nlmsg_free(msg);
	return ret;
#endif
}

int mac80211_setchannel(const char *interface, int channel, 
						unsigned int chmode, char *errstr) {
#ifndef HAVE_LINUX_NETLINK
	snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/mac80211 "
			 "support, check the output of ./configure for why");
	// Return the same error as if the device doesn't support nl freq control
	// so we catch it elsewhere
	return -22;
#else
	struct nl_sock *nl_handle;
	struct nl_cache *nl_cache;
	struct genl_family *nl80211;

	if (mac80211_connect(interface, (void **) &nl_handle, 
						 (void **) &nl_cache, (void **) &nl80211, errstr) < 0)
		return -1;

	int ret = 
		mac80211_setchannel_cache(interface, (void *) nl_handle,
								  (void *) nl80211, channel, chmode, errstr);

	mac80211_disconnect(nl_handle);

	return ret;
#endif
}

#endif /* linux */

