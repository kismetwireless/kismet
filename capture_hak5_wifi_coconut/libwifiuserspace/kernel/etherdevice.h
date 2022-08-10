/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  NET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Ethernet handlers.
 *
 * Version:	@(#)eth.h	1.0.4	05/13/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		Relocated to include/linux where it belongs by Alan Cox 
 *							<gw4pts@gw4pts.ampr.org>
 */

/*
 * Userspace port (c) 2019 Hak5
 */

#ifndef __USERSPACE_ETHERDEVICE_H__
#define __USERSPACE_ETHERDEVICE_H__ 

#include <stdbool.h>

#include "kernel/endian.h"
#include "kernel/if_ether.h"
#include "kernel/kernel.h"
#include "kernel/types.h"

/* Reserved Ethernet Addresses per IEEE 802.1Q */
static const u8 eth_reserved_addr_base[ETH_ALEN] __aligned(2) =
{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };
#define eth_stp_addr eth_reserved_addr_base

/**
 * is_link_local_ether_addr - Determine if given Ethernet address is link-local
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if address is link local reserved addr (01:80:c2:00:00:0X) per
 * IEEE 802.1Q 8.6.3 Frame filtering.
 *
 * Please note: addr must be aligned to u16.
 */
static inline bool is_link_local_ether_addr(const u8 *addr)
{
	__be16 *a = (__be16 *)addr;
	static const __be16 *b = (const __be16 *)eth_reserved_addr_base;
	__be16 m = cpu_to_be16(0xfff0);

#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	return (((*(const u32 *)addr) ^ (*(const u32 *)b)) |
		(__force int)((a[2] ^ b[2]) & m)) == 0;
#else
	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | ((a[2] ^ b[2]) & m)) == 0;
#endif
}

/**
 * is_zero_ether_addr - Determine if give Ethernet address is all zeros.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is all zeroes.
 *
 * Please note: addr must be aligned to u16.
 */
static inline bool is_zero_ether_addr(const u8 *addr)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	return ((*(const u32 *)addr) | (*(const u16 *)(addr + 4))) == 0;
#else
	return (*(const u16 *)(addr + 0) |
		*(const u16 *)(addr + 2) |
		*(const u16 *)(addr + 4)) == 0;
#endif
}


#endif /* ifndef USERSPACE_ETHERDEVICE_H */
