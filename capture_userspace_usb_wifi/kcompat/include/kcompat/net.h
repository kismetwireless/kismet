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

#ifndef __KCOMPAT_NET_H__
#define __KCOMPAT_NET_H__

/* Ethernet helpers, net_device and NAPI.  There is no network stack: net_device exists
 * for drivers which allocate a dummy one, and NAPI polls run synchronously from
 * napi_schedule(). */

#include "skb.h"

#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_TLEN 2
#define ETH_ZLEN 60
#define ETH_DATA_LEN 1500
#define ETH_FRAME_LEN 1514
#define ETH_FCS_LEN 4
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define ETH_P_IPV6 0x86DD
#define ETH_P_PAE 0x888E
#define ETH_P_TDLS 0x890D
#define ETH_P_802_3 0x0001
#define ETH_P_80211_RAW 0x0019
#define ETH_P_802_3_MIN 0x0600
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_P_LINK_CTL 0x886c
#define ETH_P_TEB 0x6558
#define ETH_P_AARP 0x80F3
#define ETH_P_IPX 0x8137
#define NETIF_F_RXCSUM (1ULL << 29)
#define NETIF_F_HW_CSUM (1ULL << 3)
#define NETIF_F_SG (1ULL << 0)
#define IFNAMSIZ 16
#define NETDEV_ALIGN 32
typedef u64 netdev_features_t;
struct net {
    int unused;
};
typedef struct {
    struct net *net;
} possible_net_t;
static inline struct net *read_pnet(const possible_net_t *p) { return p->net; }
static inline void write_pnet(possible_net_t *p, struct net *n) { p->net = n; }
extern struct net init_net;
enum tc_setup_type {
    TC_SETUP_QDISC_MQPRIO,
    TC_SETUP_BLOCK = 6,
    TC_SETUP_FT = 9,
};

struct ethhdr {
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    __be16 h_proto;
} __packed;

static inline void eth_zero_addr(u8 *a) { memset(a, 0, ETH_ALEN); }
static inline void eth_broadcast_addr(u8 *a) { memset(a, 0xff, ETH_ALEN); }
static inline void ether_addr_copy(u8 *dst, const u8 *src) { memcpy(dst, src, ETH_ALEN); }
static inline bool ether_addr_equal(const u8 *a, const u8 *b) { return memcmp(a, b, ETH_ALEN) == 0; }
#define ether_addr_equal_unaligned ether_addr_equal
static inline bool ether_addr_equal_masked(const u8 *a, const u8 *b, const u8 *m) {
    for (int i = 0; i < ETH_ALEN; i++)
        if ((a[i] ^ b[i]) & m[i])
            return false;
    return true;
}
static inline bool is_zero_ether_addr(const u8 *a) {
    return (a[0] | a[1] | a[2] | a[3] | a[4] | a[5]) == 0;
}
static inline bool is_multicast_ether_addr(const u8 *a) { return a[0] & 0x01; }
static inline bool is_unicast_ether_addr(const u8 *a) { return !is_multicast_ether_addr(a); }
static inline bool is_broadcast_ether_addr(const u8 *a) {
    return (a[0] & a[1] & a[2] & a[3] & a[4] & a[5]) == 0xff;
}
static inline bool is_local_ether_addr(const u8 *a) { return a[0] & 0x02; }
static inline bool is_valid_ether_addr(const u8 *a) {
    return !is_multicast_ether_addr(a) && !is_zero_ether_addr(a);
}
void eth_random_addr(u8 *addr);
static inline u64 ether_addr_to_u64(const u8 *a) {
    u64 u = 0;
    for (int i = 0; i < ETH_ALEN; i++)
        u = u << 8 | a[i];
    return u;
}
static inline void u64_to_ether_addr(u64 u, u8 *a) {
    for (int i = ETH_ALEN - 1; i >= 0; i--) {
        a[i] = u & 0xff;
        u >>= 8;
    }
}
#define eth_type_trans(skb, dev) ((__be16) 0)
static inline int skb_network_offset(const struct sk_buff *skb) { (void) skb; return 0; }
static inline u8 *skb_network_header(const struct sk_buff *skb) { return skb->data; }
static inline u8 *skb_mac_header(const struct sk_buff *skb) { return skb->data; }
static inline u8 *skb_transport_header(const struct sk_buff *skb) { return skb->data; }

struct netdev_hw_addr_list;
struct net_device_path_ctx;
struct net_device_path;

/* net_device */
struct net_device_stats {
    unsigned long rx_packets;
    unsigned long tx_packets;
};
struct net_device {
    char name[IFNAMSIZ];
    unsigned char dev_addr[ETH_ALEN];
    unsigned char perm_addr[ETH_ALEN];
    unsigned int flags;
    unsigned int mtu;
    struct device dev;
    struct net_device_stats stats;
    void *ml_priv;
    int threaded;
    u8 priv[] __aligned(8);
};
static inline void *netdev_priv(const struct net_device *dev) { return (void *) dev->priv; }
struct net_device *alloc_netdev_dummy(int sizeof_priv);
void free_netdev(struct net_device *dev);
#define init_dummy_netdev(d) do { (void) (d); } while (0)
#define netif_carrier_ok(d) 1
#define netif_running(d) 1
#define netdev_err(dev, fmt, ...) pr_err(fmt, ##__VA_ARGS__)
#define netdev_warn(dev, fmt, ...) pr_warn(fmt, ##__VA_ARGS__)
#define netdev_info(dev, fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#define netdev_dbg(dev, fmt, ...) pr_debug(fmt, ##__VA_ARGS__)
#define SET_NETDEV_DEV(net, pdev) do { (void) (net); (void) (pdev); } while (0)
#define dev_net(d) NULL
#define NETDEV_TX_OK 0
#define NETDEV_TX_BUSY 0x10
typedef int netdev_tx_t;

/* NAPI; poll runs immediately on the scheduling thread */
struct napi_struct {
    int (*poll)(struct napi_struct *, int);
    struct net_device *dev;
    unsigned long state;
    int weight;
};
#define NAPI_POLL_WEIGHT 64
#define NAPI_STATE_SCHED 0
static inline void netif_napi_add(struct net_device *dev, struct napi_struct *n,
        int (*poll)(struct napi_struct *, int)) {
    n->dev = dev; n->poll = poll; n->weight = NAPI_POLL_WEIGHT; n->state = 0;
}
#define netif_napi_add_tx netif_napi_add
#define netif_napi_add_weight(dev, n, poll, w) netif_napi_add(dev, n, poll)
#define netif_napi_del(n) do { (void) (n); } while (0)
#define napi_enable(n) do { (void) (n); } while (0)
#define napi_disable(n) do { (void) (n); } while (0)
#define napi_synchronize(n) do { (void) (n); } while (0)
void napi_schedule(struct napi_struct *n);
#define __napi_schedule napi_schedule
#define napi_schedule_prep(n) 1
static inline bool napi_complete_done(struct napi_struct *n, int work) { (void) n; (void) work; return true; }
#define napi_complete(n) napi_complete_done(n, 0)
#define napi_gro_receive(n, skb) do { (void) (n); kfree_skb(skb); } while (0)
#define netif_receive_skb(skb) do { kfree_skb(skb); } while (0)
#define netif_receive_skb_list(l) do { (void) (l); } while (0)
#define dev_set_threaded(d, t) 0
#define napi_set_threaded(n, t) 0

#endif
