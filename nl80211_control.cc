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
#include <linux/nl80211.h>
#include <net/if.h>
#endif

int mac80211_createvap(const char *interface, const char *newinterface, char *errstr) {
#ifndef HAVE_LINUX_NETLINK
	snprintf(errstr, STATUS_MAX, "Kismet was not compiled with netlink/mac80211 "
			 "support, check the output of ./configure for why");
	return -1;
#else

	struct nl_handle *nl_handle;
	struct nl_cache *nl_cache;
	struct genl_family *nl80211;
	struct nl_msg *msg;

	if (if_nametoindex(newinterface) > 0) 
		return 1;

	if ((nl_handle = nl_handle_alloc()) == NULL) {
		snprintf(errstr, STATUS_MAX, "mac80211_createvap() failed to allocate nlhandle");
		return -1;
	}

	if (genl_connect(nl_handle)) {
		snprintf(errstr, STATUS_MAX, "mac80211_createvap() failed to connect to generic "
				 "netlink");
		nl_handle_destroy(nl_handle);
		return -1;
	}

	if ((nl_cache = genl_ctrl_alloc_cache(nl_handle)) == NULL) {
		snprintf(errstr, STATUS_MAX, "mac80211_createvap() failed to allocate generic "
				 "netlink cache");
		nl_handle_destroy(nl_handle);
		return -1;
	}

	if ((nl80211 = genl_ctrl_search_by_name(nl_cache, "nl80211")) == NULL) {
		snprintf(errstr, STATUS_MAX, "mac80211_createvap() failed to find nl80211 "
				 "controls, kernel may be too old");
		nl_handle_destroy(nl_handle);
		return -1;
	}

	if ((msg = nlmsg_alloc()) == NULL) {
		snprintf(errstr, STATUS_MAX, "mac80211_createvap() failed to allocate "
				 "message");
		nl_handle_destroy(nl_handle);
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
		nl_handle_destroy(nl_handle);
		return -1;
	}

	nlmsg_free(msg);
	nl_handle_destroy(nl_handle);

	if (if_nametoindex(newinterface) <= 0) {
		snprintf(errstr, STATUS_MAX, "mac80211_createvap() thought we made a vap, "
				 "but it wasn't there when we looked");
		return -1;
	}

	return 0;
#endif
}

#endif /* linux */

