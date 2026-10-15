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

#ifndef __KCOMPAT_NETLINK_H__
#define __KCOMPAT_NETLINK_H__

/* Netlink types referenced by cfg80211.h; there is no netlink transport */

#include "stubs.h"

struct nlattr {
    u16 nla_len;
    u16 nla_type;
};
struct nla_policy {
    u8 type;
    u8 validation_type;
    u16 len;
};
struct netlink_ext_ack {
    const char *_msg;
};
struct genl_info;
struct netlink_callback;
#define NLA_UNSPEC 0
#define NLA_U8 1
#define NLA_U16 2
#define NLA_U32 3
#define NLA_U64 4
#define NLA_STRING 5
#define NLA_FLAG 6
#define NLA_NESTED 9
#define NLA_BINARY 11
#define NL_SET_ERR_MSG(ack, msg) do { if (ack) (ack)->_msg = (msg); } while (0)
#define NL_SET_ERR_MSG_MOD NL_SET_ERR_MSG
#define NL_SET_ERR_MSG_ATTR(ack, attr, msg) NL_SET_ERR_MSG(ack, msg)
#define nla_data(a) ((void *) ((u8 *) (a) + 4))
#define nla_len(a) ((int) (a)->nla_len - 4)
#define nla_get_u8(a) (*(u8 *) nla_data(a))
#define nla_get_u16(a) (*(u16 *) nla_data(a))
#define nla_get_u32(a) (*(u32 *) nla_data(a))
#define nla_put(skb, t, l, d) (-EMSGSIZE)
#define nla_put_u8(skb, t, v) (-EMSGSIZE)
#define nla_put_u16(skb, t, v) (-EMSGSIZE)
#define nla_put_u32(skb, t, v) (-EMSGSIZE)
#define nla_nest_start(skb, t) NULL
#define nla_nest_end(skb, a) 0
#define nla_parse_nested_deprecated(tb, max, nla, pol, ack) (-EINVAL)
#define nla_for_each_nested(pos, nla, rem) for ((pos) = NULL, (rem) = 0; (pos); )

/* ethtool */
#define ETH_GSTRING_LEN 32
#define ETHTOOL_FWVERS_LEN 32
#define ETH_SS_TEST 0
#define ETH_SS_STATS 1
struct ethtool_stats {
    u32 cmd;
    u32 n_stats;
    u64 data[];
};
struct ethtool_drvinfo {
    char driver[32];
};

/* rfkill */
struct rfkill;
#define rfkill_pause_polling(r) do { (void) (r); } while (0)
#define rfkill_resume_polling(r) do { (void) (r); } while (0)

/* IPv6, for offload structures */
struct in6_addr {
    u8 s6_addr[16];
};
struct inet6_dev;

#endif
