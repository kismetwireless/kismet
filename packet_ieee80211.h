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

#ifndef __PACKET_IEEE80211_H__
#define __PACKET_IEEE80211_H__

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include "macaddr.h"

#ifndef SSID_SIZE
#define SSID_SIZE 32
#endif

#ifndef BEACON_INFO_LEN
#define BEACON_INFO_LEN 128
#endif

// packet conversion and extraction utilities
// Packet types, these should correspond to the frame header types
enum ieee_80211_type {
    packet_noise = -2,  // We're too short or otherwise corrupted
    packet_unknown = -1, // What are we?
    packet_management = 0, // LLC management
    packet_phy = 1, // Physical layer packets, most drivers can't provide these
    packet_data = 2 // Data frames
};

// Subtypes are a little odd because we re-use values depending on the type
enum ieee_80211_subtype {
    packet_sub_unknown = -1,
    // Management subtypes
    packet_sub_association_req = 0,
    packet_sub_association_resp = 1,
    packet_sub_reassociation_req = 2,
    packet_sub_reassociation_resp = 3,
    packet_sub_probe_req = 4,
    packet_sub_probe_resp = 5,
    packet_sub_beacon = 8,
    packet_sub_atim = 9,
    packet_sub_disassociation = 10,
    packet_sub_authentication = 11,
    packet_sub_deauthentication = 12,
	packet_sub_action = 13,
	packet_sub_action_noack = 14,
	packet_sub_aruba = 15,

    // Phy subtypes
    packet_sub_vht_ndp = 5,
    packet_sub_block_ack_req = 8,
    packet_sub_block_ack = 9,
	packet_sub_pspoll = 10,
    packet_sub_rts = 11,
    packet_sub_cts = 12,
    packet_sub_ack = 13,
    packet_sub_cf_end = 14,
    packet_sub_cf_end_ack = 15,

    // Data subtypes
    packet_sub_data = 0,
    packet_sub_data_cf_ack = 1,
    packet_sub_data_cf_poll = 2,
    packet_sub_data_cf_ack_poll = 3,
    packet_sub_data_null = 4,
    packet_sub_cf_ack = 5,
    packet_sub_cf_ack_poll = 6,
    packet_sub_data_qos_data = 8,
    packet_sub_data_qos_data_cf_ack = 9,
    packet_sub_data_qos_data_cf_poll = 10,
    packet_sub_data_qos_data_cf_ack_poll = 11,
    packet_sub_data_qos_null = 12,
    packet_sub_data_qos_cf_poll_nod = 14,
    packet_sub_data_qos_cf_ack_poll = 15
};

// distribution directions
enum ieee_80211_disttype {
    distrib_unknown, distrib_from, distrib_to,
    distrib_inter, distrib_adhoc
};

// Signalling layer info - what protocol are we seeing data on?
// Not all of these types are currently supported, of course
enum phy_carrier_type {
    carrier_unknown,
    carrier_80211b,
    carrier_80211bplus,
    carrier_80211a,
    carrier_80211g,
    carrier_80211fhss,
    carrier_80211dsss,
	carrier_80211n20,
	carrier_80211n40
};

// Packet encoding info - how are packets encoded?
enum phy_encoding_type {
    encoding_unknown,
    encoding_cck,
    encoding_pbcc,
    encoding_ofdm,
	encoding_dynamiccck,
	encoding_gfsk
};

// Turbocell modes
enum turbocell_type {
    turbocell_unknown,
    turbocell_ispbase, // 0xA0
    turbocell_pollbase, // 0x80
    turbocell_nonpollbase, // 0x00
    turbocell_base // 0x40
};

// IAPP crypt enums
enum iapp_type {
    iapp_announce_request = 0,
    iapp_announce_response = 1,
    iapp_handover_request = 2,
    iapp_handover_response = 3
};

enum iapp_pdu {
    iapp_pdu_ssid = 0x00,
    iapp_pdu_bssid = 0x01,
    iapp_pdu_oldbssid = 0x02,
    iapp_pdu_msaddr = 0x03,
    iapp_pdu_capability = 0x04,
    iapp_pdu_announceint = 0x05,
    iapp_pdu_hotimeout = 0x06,
    iapp_pdu_messageid = 0x07,
    iapp_pdu_phytype = 0x10,
    iapp_pdu_regdomain = 0x11,
    iapp_pdu_channel = 0x12,
    iapp_pdu_beaconint = 0x13,
    iapp_pdu_ouiident = 0x80,
    iapp_pdu_authinfo = 0x81
};

enum iapp_cap {
    iapp_cap_forwarding = 0x40,
    iapp_cap_wep = 0x20
};

enum iapp_phy {
    iapp_phy_prop = 0x00,
    iapp_phy_fhss = 0x01,
    iapp_phy_dsss = 0x02,
    iapp_phy_ir = 0x03,
    iapp_phy_ofdm = 0x04
};

enum iapp_dom {
    iapp_dom_fcc = 0x10,
    iapp_dom_ic = 0x20,
    iapp_dom_etsi = 0x30,
    iapp_dom_spain = 0x31,
    iapp_dom_france = 0x32,
    iapp_dom_mkk = 0x40
};

enum iapp_auth {
    iapp_auth_status = 0x01,
    iapp_auth_username = 0x02,
    iapp_auth_provname = 0x03,
    iapp_auth_rxpkts = 0x04,
    iapp_auth_txpkts = 0x05,
    iapp_auth_rxbytes = 0x06,
    iapp_auth_txbytes = 0x07,
    iapp_auth_logintime = 0x08,
    iapp_auth_timelimit = 0x09,
    iapp_auth_vollimit = 0x0a,
    iapp_auth_acccycle = 0x0b,
    iapp_auth_rxgwords = 0x0c,
    iapp_auth_txgwords = 0x0d,
    iapp_auth_ipaddr = 0x0e,
    iapp_auth_trailer = 0xff
};

typedef struct {
    unsigned iapp_version : 8;
    unsigned iapp_type : 8;
} __attribute__ ((packed)) iapp_header;

typedef struct {
    unsigned pdu_type : 8;
    unsigned pdu_len : 16;
} __attribute__ ((packed)) iapp_pdu_header;

// New 64-bit encryption field describing the overall state, plus broken out 
// group/pairwise and keying ciphers.

// General capabilities/summaries
#define dot11_crypt_general_open            0ULL
#define dot11_crypt_general_wep             (1ULL << 0)
#define dot11_crypt_general_wpa             (1ULL << 1)
#define dot11_crypt_general_wpa1            (1ULL << 2)
#define dot11_crypt_general_wpa2            (1ULL << 3)
#define dot11_crypt_general_wpa3            (1ULL << 4)
#define dot11_crypt_general_reserve1        (1ULL << 5)
#define dot11_crypt_general_reserve2        (1ULL << 6)

// multicast ciphers
#define dot11_crypt_group_wep40             (1ULL << 7)
#define dot11_crypt_group_wep104            (1ULL << 8)
#define dot11_crypt_group_tkip              (1ULL << 9)
#define dot11_crypt_group_ccmp128           (1ULL << 10)
#define dot11_crypt_group_bip_cmac128       (1ULL << 11)
#define dot11_crypt_group_gcmp128           (1ULL << 12)
#define dot11_crypt_group_gcmp256           (1ULL << 13)
#define dot11_crypt_group_ccmp256           (1ULL << 14)
#define dot11_crypt_group_bip_gmac128       (1ULL << 15)
#define dot11_crypt_group_bip_gmac256       (1ULL << 16)
#define dot11_crypt_group_bip_cmac256       (1ULL << 17)
#define dot11_crypt_group_ocb               (1ULL << 18)
#define dot11_crypt_group_reserve2          (1ULL << 19)
#define dot11_crypt_group_reserve3          (1ULL << 20)
#define dot11_crypt_group_reserve4          (1ULL << 21)
#define dot11_crypt_group_reserve5          (1ULL << 22)

// unicast ciphers
#define dot11_crypt_pairwise_wep40          (1ULL << 23)
#define dot11_crypt_pairwise_wep104         (1ULL << 24)
#define dot11_crypt_pairwise_tkip           (1ULL << 25)
#define dot11_crypt_pairwise_ccmp128        (1ULL << 26)
#define dot11_crypt_pairwise_bip_cmac128    (1ULL << 27)
#define dot11_crypt_pairwise_gcmp128        (1ULL << 28)
#define dot11_crypt_pairwise_gcmp256        (1ULL << 29)
#define dot11_crypt_pairwise_ccmp256        (1ULL << 30)
#define dot11_crypt_pairwise_bip_gmac128    (1ULL << 31)
#define dot11_crypt_pairwise_bip_gmac256    (1ULL << 32)
#define dot11_crypt_pairwise_bip_cmac256    (1ULL << 33)
#define dot11_crypt_pairwise_ocb            (1ULL << 34)
#define dot11_crypt_pairwise_reserve2       (1ULL << 35)
#define dot11_crypt_pairwise_reserve3       (1ULL << 36)

// Key exchange types
#define dot11_crypt_akm_1x                  (1ULL << 37)
#define dot11_crypt_akm_psk                 (1ULL << 38)
#define dot11_crypt_akm_1x_ft               (1ULL << 39)
#define dot11_crypt_akm_psk_ft              (1ULL << 40)
#define dot11_crypt_akm_1x_sha256           (1ULL << 41)
#define dot11_crypt_akm_psk_sha256          (1ULL << 42)
#define dot11_crypt_akm_tdls                (1ULL << 43)
#define dot11_crypt_akm_sae                 (1ULL << 44)
#define dot11_crypt_akm_sae_ft              (1ULL << 45)
#define dot11_crypt_akm_ap_peer             (1ULL << 46)
#define dot11_crypt_akm_1x_suiteb_sha256    (1ULL << 47)
#define dot11_crypt_akm_1x_suiteb_sha384    (1ULL << 48)
#define dot11_crypt_akm_1x_ft_sha384        (1ULL << 49)
#define dot11_crypt_akm_fils_sha256         (1ULL << 50)
#define dot11_crypt_akm_fils_sha384         (1ULL << 51)
#define dot11_crypt_akm_fils_sha256_ft      (1ULL << 52)
#define dot11_crypt_akm_fils_sha384_ft      (1ULL << 53)
#define dot11_crypt_akm_owe                 (1ULL << 54)
#define dot11_crypt_akm_psk_sha384_ft       (1ULL << 55)
#define dot11_crypt_akm_psk_sha384          (1ULL << 56)
#define dot11_crypt_akm_psk_sha384          (1ULL << 56)
#define dot11_crypt_akm_wps                 (1ULL << 57)

// EAP types
#define dot11_crypt_eap_leap                (1ULL << 58)
#define dot11_crypt_eap_tls                 (1ULL << 59)
#define dot11_crypt_eap_ttls                (1ULL << 60)
#define dot11_crypt_eap_peap                (1ULL << 61)
#define dot11_crypt_eap_identity            (1ULL << 62)
#define dot11_crypt_eap_reserve1            (1ULL << 63)

// Old bitfield; to be phased out, currently co-populated (2023) to not break old tools;
// will not contain all the info of the new one!

// Basic types
#define crypt_none 			0
#define crypt_unknown		1
#define crypt_wep			(1 << 1)
#define crypt_layer3		(1 << 2)
// Derived from WPA IEs
#define crypt_wep40			(1 << 3)
#define crypt_wep104		(1 << 4)
#define crypt_tkip			(1 << 5)
#define crypt_wpa			(1 << 6)
#define crypt_psk			(1 << 7)
#define crypt_aes_ocb		(1 << 8)
#define crypt_aes_ccm		(1 << 9)
//WPA Migration Mode
#define crypt_wpa_migmode	(1 << 10)
#define crypt_eap			(1 << 11)
#define crypt_leap			(1 << 12)
#define crypt_ttls			(1 << 13)
#define crypt_tls			(1 << 14)
#define crypt_peap			(1 << 15)
#define crypt_sae           (1 << 16)
#define crypt_wpa_owe       (1 << 17)
// Lower byte mask - cryptset & protectmask yields basic setting, ie cannot be
// WEP+PEAP, but COULD be WEP+ISAKMP or WEP+WPS
#define crypt_protectmask 	0xFFFFF
#define crypt_isakmp		(1 << 20)
#define crypt_pptp			(1 << 21)
#define crypt_fortress		(1 << 22)
#define crypt_keyguard		(1 << 23)
#define crypt_unknown_protected 	(1 << 24)
#define crypt_unknown_nonwep		(1 << 25)
#define crypt_wps 					(1 << 26)
#define crypt_version_wpa   (1 << 27)
#define crypt_version_wpa2  (1 << 28)
#define crypt_version_wpa3  (1 << 29)
// L3 encryption mask
#define crypt_l3_mask		0x300004
// L2 encryption mask
#define crypt_l2_mask		0xFBFA

// Deciphering by casting.  This is bad, and non portable, and we need to not
// do it in the future but for now it'll work until we redo it with bitmanip
#ifdef WORDS_BIGENDIAN
// Byte ordering for bigendian systems.  Bitwise strcts are so funky.
typedef struct {
    unsigned short subtype : 4;
    unsigned short type : 2;
    unsigned short version : 2;

    unsigned short order : 1;
    unsigned short wep : 1;
    unsigned short more_data : 1;
    unsigned short power_management : 1;

    unsigned short retry : 1;
    unsigned short more_fragments : 1;
    unsigned short from_ds : 1;
    unsigned short to_ds : 1;
} __attribute__ ((packed)) frame_control;

typedef struct {
    unsigned short frag : 12;
    unsigned short sequence : 4;
} __attribute__ ((packed)) wireless_fragseq;

typedef struct {
    uint64_t timestamp;

    // This field must be converted to host-endian before being used
    unsigned int beacon : 16;

    unsigned short agility : 1;
    unsigned short pbcc : 1;
    unsigned short short_preamble : 1;
    unsigned short wep : 1;

    unsigned short unused2 : 1;
    unsigned short unused1 : 1;
    unsigned short ibss : 1;
    unsigned short ess : 1;

    unsigned int coordinator : 8;

} __attribute__ ((packed)) fixed_parameters;

#else
// And 802.11 packet frame header
typedef struct {
    unsigned short version : 2;
    unsigned short type : 2;
    unsigned short subtype : 4;

    unsigned short to_ds : 1;
    unsigned short from_ds : 1;
    unsigned short more_fragments : 1;
    unsigned short retry : 1;

    unsigned short power_management : 1;
    unsigned short more_data : 1;
    unsigned short wep : 1;
    unsigned short order : 1;
} __attribute__ ((packed)) frame_control;

typedef struct {
    unsigned short frag : 4;
    unsigned short sequence : 12;
} __attribute__ ((packed)) wireless_fragseq;

typedef struct {
    uint64_t timestamp;

    // This field must be converted to host-endian before being used
    unsigned int beacon : 16;

    unsigned short ess : 1;
    unsigned short ibss : 1;
    unsigned short unused1 : 1;
    unsigned short unused2 : 1;

    unsigned short wep : 1;
    unsigned short short_preamble : 1;
    unsigned short pbcc : 1;
    unsigned short agility : 1;

    unsigned int coordinator : 8;
} __attribute__ ((packed)) fixed_parameters;

#endif


#endif

