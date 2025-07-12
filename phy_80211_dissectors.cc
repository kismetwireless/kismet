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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <map>
#include <iomanip>
#include <sstream>
#include <iostream>

#include <functional>

#include "endian_magic.h"
#include "phy_80211.h"
#include "phy_80211_packetsignatures.h"
#include "packetchain.h"
#include "alertracker.h"
#include "configfile.h"

#include "kaitai/kaitaistream.h"
#include "dot11_parsers/dot11_wpa_eap.h"
#include "dot11_parsers/dot11_action.h"
#include "dot11_parsers/dot11_ie.h"
#include "dot11_parsers/dot11_ie_7_country.h"
#include "dot11_parsers/dot11_ie_11_qbss.h"
#include "dot11_parsers/dot11_ie_33_power.h"
#include "dot11_parsers/dot11_ie_36_supported_channels.h"
#include "dot11_parsers/dot11_ie_45_ht_cap.h"
#include "dot11_parsers/dot11_ie_48_rsn.h"
#include "dot11_parsers/dot11_ie_52_rmm_neighbor.h"
#include "dot11_parsers/dot11_ie_54_mobility.h"
#include "dot11_parsers/dot11_ie_61_ht_op.h"
#include "dot11_parsers/dot11_ie_133_cisco_ccx.h"
#include "dot11_parsers/dot11_ie_150_vendor.h"
#include "dot11_parsers/dot11_ie_150_cisco_powerlevel.h"
#include "dot11_parsers/dot11_ie_191_vht_cap.h"
#include "dot11_parsers/dot11_ie_192_vht_op.h"
#include "dot11_parsers/dot11_ie_221_vendor.h"
#include "dot11_parsers/dot11_ie_221_dji_droneid.h"
#include "dot11_parsers/dot11_ie_221_ms_wmm.h"
#include "dot11_parsers/dot11_ie_221_ms_wps.h"
#include "dot11_parsers/dot11_ie_221_wfa_wpa.h"
#include "dot11_parsers/dot11_ie_221_cisco_client_mfp.h"
#include "dot11_parsers/dot11_ie_221_wpa_transition.h"
#include "dot11_parsers/dot11_ie_221_rsn_pmkid.h"
#include "dot11_parsers/dot11_ie_221_wfa.h"
#include "dot11_parsers/dot11_p2p_ie.h"

#include "crc32.h"

// For 802.11n MCS calculations
const int CH20GI800 = 0;
const int CH20GI400 = 1;
const int CH40GI800 = 2;
const int CH40GI400 = 3;

const double mcs_table[][4] = {
    {6.5,7.2,13.5,15},
    {13,14.4,27,30},
    {19.5,21.7,40.5,45},
    {26,28.9,54,60},
    {39,43.3,81,90},
    {52,57.8,108,120},
    {58.5,65,121.5,135},
    {65,72.2,135,150},
    {13,14.4,27,30},
    {26,28.9,54,60},
    {39,43.3,81,90},
    {52,57.8,108,120},
    {78,86.7,162,180},
    {104,115.6,216,240},
    {117,130,243,270},
    {130,144.4,270,300},
    {19.5,21.7,40.5,45},
    {39,43.3,81,90},
    {58.5,65,121.5,135},
    {78,86.7,162,180},
    {117,130,243,270},
    {156,173.3,324,360},
    {175.5,195,364.5,405},
    {195,216.7,405,450},
    {26,28.8,54,60},
    {52,57.6,108,120},
    {78,86.8,162,180},
    {104,115.6,216,240},
    {156,173.2,324,360},
    {208,231.2,432,480},
    {234,260,486,540},
    {260,288.8,540,600},
    {0, 0, 6.0, 6.7},
};
const int MCS_MAX = 32;

// Indexed by VHT MCS index; contains base rates + extended vht
// rates ordered as 0-9 per stream

const int CH80GI800 = 4;
const int CH80GI400 = 5;
const int CH160GI800 = 6;
const int CH160GI400 = 7;

const double vht_mcs_table[][8] {
    // Stream 0 0-9
    {6.5, 7.2, 13.5, 15, 29.3, 32.5, 58.5, 65},
    {13, 14.4, 27, 30, 58.5, 65, 117, 130},
    {19.5, 21.7, 40.5, 45, 87.8, 97.5, 175.5, 195},
    {26, 28.9, 54, 60, 117, 130, 234, 260},
    {39, 43.3, 81, 90, 175.5, 195, 351, 390},
    {52, 57.8, 108, 120, 234, 260, 468, 520},
    {58.5, 65, 121.5, 135, 263.3, 292.5, 526.5, 585},
    {65, 72.2, 135, 150, 292.5, 325, 585, 650},
    {78, 86.7, 162, 180, 351, 390, 702, 780},
    {0, 0, 180, 200, 390, 433.3, 780, 866.7},

    // Stream 1 0-9
    {13, 14.4, 27, 30, 58.5, 65, 117, 130},
    {26, 28.9, 54, 60, 117, 130, 234, 260},
    {39, 43.3, 81, 90, 175.5, 195, 351, 390},
    {52, 57.8, 108, 120, 234, 260, 468, 520},
    {78, 86.7, 162, 180, 351, 390, 702, 780},
    {104, 115.6, 216, 240, 468, 520, 936, 1040},
    {117, 130, 243, 270, 526.5, 585, 1053, 1170},
    {130, 144.4, 270, 300, 585, 650, 1170, 1300},
    {156, 173.3, 324, 360, 702, 780, 1404, 1560},
    {0, 0, 360, 400, 780, 866.7, 1560, 1733.3 },

    // Stream 3, 0-9
    {19.5, 21.7, 40.5, 45, 87.8, 97.5, 175.5, 195},
    {39, 43.3, 81, 90, 175.5, 195, 351, 390},
    {58.5, 65, 121.5, 135, 263.3, 292.5, 526.5, 585},
    {78, 86.7, 162, 180, 351, 390, 702, 780},
    {117, 130, 243, 270, 526.5, 585, 1053, 1170},
    {156, 173.3, 324, 360, 702, 780, 1404, 1560},
    {175.5, 195, 364.5, 405, 0, 0, 1579.5, 1755},
    {195, 216.7, 405, 450, 877.5, 975, 1755, 1950},
    {234, 260, 486, 540, 1053, 1170, 2106, 2340},
    {260, 288.9, 540, 600, 1170, 1300, 0, 0},

    // Stream 4, 0-9
    {26, 28.8, 54, 60, 117, 130, 234, 260},
    {52, 57.6, 108, 120, 234, 260, 468, 520},
    {78, 86.8, 162, 180, 351, 390, 702, 780},
    {104, 115.6, 216, 240, 468, 520, 936, 1040},
    {156, 173.2, 324, 360, 702, 780, 1404, 1560},
    {208, 231.2, 432, 480, 936, 1040, 1872, 2080},
    {234, 260, 486, 540, 1053, 1170, 2106, 2340},
    {260, 288.8, 540, 600, 1170, 1300, 2340, 2600},
    {312, 346.7, 648, 720, 1404, 1560, 2808, 3120},
    {0, 0, 720, 800, 1560, 1733.3, 3120, 3466.7}
};
const int VHT_MCS_MAX = 40;

// CRC32 index for verifying WEP - cribbed from ethereal
static const uint32_t dot11_wep_crc32_table[256] = {
    0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
    0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
    0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
    0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
    0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
    0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
    0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
    0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
    0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
    0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
    0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
    0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
    0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
    0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
    0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
    0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
    0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
    0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
    0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
    0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
    0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
    0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
    0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
    0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
    0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
    0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
    0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
    0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
    0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
    0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
    0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
    0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
    0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
    0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
    0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
    0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
    0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
    0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
    0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
    0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
    0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
    0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
    0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
    0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
    0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
    0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
    0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
    0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
    0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
    0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
    0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
    0x2d02ef8dL
};

uint64_t kis_80211_phy::wpa_rsn_pairwise_conv(ie48_rsn_cipher cipher) {
    uint64_t ret = 0;

    switch (cipher) {
        case ie48_rsn_cipher::rsn_wep_40:
            ret |= dot11_crypt_general_wep;
            ret |= dot11_crypt_pairwise_wep40;
            break;
        case ie48_rsn_cipher::rsn_tkip:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_pairwise_tkip;
            break;
        case ie48_rsn_cipher::rsn_aes_ocb:
            ret |= dot11_crypt_general_wpa2;
            ret |= dot11_crypt_pairwise_ocb;
            break;
        case ie48_rsn_cipher::rsn_aes_ccm:
            ret |= dot11_crypt_general_wpa2;
            ret |= dot11_crypt_pairwise_ccmp128;
            break;
        case ie48_rsn_cipher::rsn_wep_104:
            ret |= dot11_crypt_general_wep;
            ret |= dot11_crypt_pairwise_wep104;
            break;
        case ie48_rsn_cipher::rsn_bip_128:
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_pairwise_bip_cmac128;
            break;
        case ie48_rsn_cipher::rsn_gcmp_128:
            ret |= dot11_crypt_general_wpa2;
            ret |= dot11_crypt_pairwise_gcmp128;
            break;
        case ie48_rsn_cipher::rsn_gcmp_256:
            ret |= dot11_crypt_general_wpa2;
            ret |= dot11_crypt_pairwise_gcmp256;
            break;
        case ie48_rsn_cipher::rsn_ccmp_256:
            ret |= dot11_crypt_general_wpa2;
            ret |= dot11_crypt_pairwise_ccmp256;
            break;
        case ie48_rsn_cipher::rsn_bip_gmac_128:
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_pairwise_bip_gmac128;
            break;
        case ie48_rsn_cipher::rsn_bip_gmac_256:
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_pairwise_bip_gmac256;
            break;
        case ie48_rsn_cipher::rsn_bip_cmac_256:
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_pairwise_bip_cmac256;
            break;
        case ie48_rsn_cipher::rsn_cipher_none:
        case ie48_rsn_cipher::rsn_no_group:
            break;
    }

    return ret;
}

uint64_t kis_80211_phy::wpa_rsn_group_conv(ie48_rsn_cipher cipher) {
    uint64_t ret = 0;

    switch (cipher) {
        case ie48_rsn_cipher::rsn_wep_40:
            ret |= dot11_crypt_general_wep;
            ret |= dot11_crypt_group_wep40;
            break;
        case ie48_rsn_cipher::rsn_tkip:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_tkip;
            break;
        case ie48_rsn_cipher::rsn_aes_ocb:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_ocb;
            break;
        case ie48_rsn_cipher::rsn_aes_ccm:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_ccmp128;
            break;
        case ie48_rsn_cipher::rsn_wep_104:
            ret |= dot11_crypt_general_wep;
            ret |= dot11_crypt_group_wep104;
            break;
        case ie48_rsn_cipher::rsn_bip_128:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_bip_cmac128;
            break;
        case ie48_rsn_cipher::rsn_gcmp_128:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_gcmp128;
            break;
        case ie48_rsn_cipher::rsn_gcmp_256:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_gcmp256;
            break;
        case ie48_rsn_cipher::rsn_ccmp_256:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_ccmp256;
            break;
        case ie48_rsn_cipher::rsn_bip_gmac_128:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_bip_gmac128;
            break;
        case ie48_rsn_cipher::rsn_bip_gmac_256:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_bip_gmac256;
            break;
        case ie48_rsn_cipher::rsn_bip_cmac_256:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_bip_cmac256;
            break;
        case ie48_rsn_cipher::rsn_cipher_none:
        case ie48_rsn_cipher::rsn_no_group:
            break;
    }

    return ret;
}

uint64_t kis_80211_phy::wpa_rsn_auth_conv(ie48_rsn_mgmt cipher) {
    uint64_t ret = 0;

    switch (cipher) {
        case ie48_rsn_mgmt::mgmt_1x:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_akm_1x;
            break;
        case ie48_rsn_mgmt::mgmt_psk:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_akm_psk;
            break;
        case ie48_rsn_mgmt::mgmt_ft_dot1x:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_akm_1x_ft;
            break;
        case ie48_rsn_mgmt::mgmt_ft_psk:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_akm_psk_ft;
            break;
        case ie48_rsn_mgmt::mgmt_1x_sha256:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_akm_1x_sha256;
            break;
        case ie48_rsn_mgmt::mgmt_psk_sha256:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_akm_psk_sha256;
            break;
        case ie48_rsn_mgmt::mgmt_tdls_sha256:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_akm_tdls;
            break;
        case ie48_rsn_mgmt::mgmt_sae_sha256:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_akm_sae;
            break;
        case ie48_rsn_mgmt::mgmt_ft_sae:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_akm_sae_ft;
            break;
        case ie48_rsn_mgmt::mgmt_ap_peerkey:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_akm_ap_peer;
            break;
        case ie48_rsn_mgmt::mgmt_1x_sha256_suite_b:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_akm_1x_suiteb_sha256;
            break;
        case ie48_rsn_mgmt::mgmt_1x_sha384_suite_b:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_akm_1x_suiteb_sha384;
            break;
        case ie48_rsn_mgmt::mgmt_ft_dot1x_sha384:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_akm_1x_ft_sha384;
            break;
        case ie48_rsn_mgmt::mgmt_fils_sha256:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_akm_fils_sha256;
            break;
        case ie48_rsn_mgmt::mgmt_fils_sha384:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_akm_fils_sha384;
            break;
        case ie48_rsn_mgmt::mgmt_ft_fils_sha256:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_akm_fils_sha256_ft;
            break;
        case ie48_rsn_mgmt::mgmt_ft_fils_sha384:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_akm_fils_sha384_ft;
            break;
        case ie48_rsn_mgmt::mgmt_owe:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_akm_owe;
            break;
        case ie48_rsn_mgmt::mgmt_ft_psk_sha384:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_akm_psk_sha384_ft;
            break;
        case ie48_rsn_mgmt::mgmt_psk_sha384:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_general_wpa3;
            ret |= dot11_crypt_akm_psk_sha384;
            break;
        case ie48_rsn_mgmt::mgmt_pasn:
        case ie48_rsn_mgmt::mgmt_none:
            break;
    }

    return ret;
}

uint64_t kis_80211_phy::wfa_pairwise_conv(ie221_wfa_cipher cipher) {
    uint64_t ret = 0;

    switch (cipher) {
        case ie221_wfa_cipher::wfa_wep_40:
            ret |= dot11_crypt_general_wep;
            ret |= dot11_crypt_pairwise_wep40;
            break;
        case ie221_wfa_cipher::wfa_tkip:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_pairwise_tkip;
            break;
        case ie221_wfa_cipher::wfa_aes_ocb:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_pairwise_ocb;
            break;
        case ie221_wfa_cipher::wfa_aes_ccm:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_pairwise_ccmp128;
            break;
        case ie221_wfa_cipher::wfa_wep_104:
            ret |= dot11_crypt_general_wep;
            ret |= dot11_crypt_pairwise_wep104;
            break;
        case ie221_wfa_cipher::wfa_bip:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_pairwise_bip_cmac128;
            break;
        case ie221_wfa_cipher::wfa_none:
        case ie221_wfa_cipher::wfa_no_group:
            break;
    }

    return ret;
}

uint64_t kis_80211_phy::wfa_group_conv(ie221_wfa_cipher cipher) {
    uint64_t ret = 0;

    switch (cipher) {
        case ie221_wfa_cipher::wfa_wep_40:
            ret |= dot11_crypt_general_wep;
            ret |= dot11_crypt_group_wep40;
            break;
        case ie221_wfa_cipher::wfa_tkip:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_tkip;
            break;
        case ie221_wfa_cipher::wfa_aes_ocb:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_ocb;
            break;
        case ie221_wfa_cipher::wfa_aes_ccm:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_ccmp128;
            break;
        case ie221_wfa_cipher::wfa_wep_104:
            ret |= dot11_crypt_general_wep;
            ret |= dot11_crypt_group_wep104;
            break;
        case ie221_wfa_cipher::wfa_bip:
            ret |= dot11_crypt_general_wpa;
            ret |= dot11_crypt_group_bip_cmac128;
            break;
        case ie221_wfa_cipher::wfa_none:
        case ie221_wfa_cipher::wfa_no_group:
            break;
    }

    return ret;
}

uint64_t kis_80211_phy::wfa_auth_conv(ie221_wfa_mgmt cipher) {
    uint64_t ret = 0;

    ret |= dot11_crypt_general_wpa;

    switch (cipher) {
        case ie221_wfa_mgmt::wfa_mgmt_wpa:
            ret |= dot11_crypt_akm_1x;
            break;
        case ie221_wfa_mgmt::wfa_mgmt_psk:
            ret |= dot11_crypt_akm_psk;
            break;
        case ie221_wfa_mgmt::wfa_mgmt_ft_dot1x:
            ret |= dot11_crypt_akm_1x_ft;
            break;
        case ie221_wfa_mgmt::wfa_mgmt_ft_psk:
            ret |= dot11_crypt_akm_psk_ft;
            break;
        case ie221_wfa_mgmt::wfa_mgmt_wpa_sha256:
            ret |= dot11_crypt_akm_1x_sha256;
            break;
        case ie221_wfa_mgmt::wfa_mgmt_psk_sha256:
            ret |= dot11_crypt_akm_psk_sha256;
            break;
        case ie221_wfa_mgmt::wfa_mgmt_tdls_tpk:
            ret |= dot11_crypt_akm_tdls;
            break;
        case ie221_wfa_mgmt::wfa_mgmt_none:
            break;
    }

    return ret;
}

// This needs to be optimized and it needs to not use casting to do its magic
int kis_80211_phy::packet_dot11_dissector(const std::shared_ptr<kis_packet>& in_pack) {
    if (in_pack->error) {
        return 0;
    }

    // Extract data, bail if it doesn't exist, make a local copy of what we're
    // inserting into the frame.
    std::shared_ptr<dot11_packinfo> packinfo;
    auto chunk = in_pack->fetch<kis_datachunk>(pack_comp_decap, pack_comp_linkframe);

    if (chunk == nullptr) {
        return 0;
    }

    // If we don't have a dot11 frame, throw it away
    if (chunk->dlt != KDLT_IEEE802_11) {
        return 0;
    }

    // Flat-out dump if it's not big enough to be 80211, don't even bother making a
    // packinfo record for it because we're completely broken
    if (chunk->length() < 10) {
        return 0;
    }

    auto pack_l1info = in_pack->fetch<kis_layer1_packinfo>(pack_comp_l1info);
    auto common = in_pack->fetch<kis_common_info>(pack_comp_common);

    // If we're a duplicate packet and haven't processed the dot11 content yet,
    // we have to process.  This prevents a desync between the postcap thread and
    // the bulk packet processing threads.
    if (in_pack->duplicate && packinfo != nullptr) {
        return 0;
    }


    if (common == NULL) {
        common = packetchain->new_packet_component<kis_common_info>();
        in_pack->insert(pack_comp_common, common);
    }

    common->phyid = phyid;

    if (pack_l1info != NULL)
        common->freq_khz = pack_l1info->freq_khz;

    packinfo = packetchain->new_packet_component<dot11_packinfo>();

    const auto fc = reinterpret_cast<const frame_control *>(chunk->data());

#if 0
    // Privacy no longer means wep; figure out new way to denote classic wep.
    // Likely preserve privacy flag in packinfo and compare if no rsn or wpa ie
    // tags?
    if (fc->wep) {
        packinfo->cryptset |= dot11_crypt_general_wep;
        common->basic_crypt_set |= KIS_DEVICE_BASICCRYPT_ENCRYPTED;
    }
#endif

    uint16_t duration = 0;

    // 18 bytes of normal address ranges
    const uint8_t *addr0 = NULL;
    const uint8_t *addr1 = NULL;
    const uint8_t *addr2 = NULL;
    // And an optional 6 bytes of address range for ds=0x03 packets
    const uint8_t *addr3 = NULL;

    // We'll fill these in as we go
    packinfo->type = packet_unknown;
    packinfo->subtype = packet_sub_unknown;
    packinfo->distrib = distrib_unknown;

    // Endian swap the duration  ** Optimize this in the future **
    memcpy(&duration, &(chunk->data()[2]), 2);
    duration = kis_ntoh16(duration);

    // 2 bytes of sequence and fragment counts
    const wireless_fragseq *sequence;

    // We always have addr0 even on phy
    addr0 = reinterpret_cast<const uint8_t *>(&chunk->data()[4]);

    // We may have addr1
    if (chunk->length() >= 16)
        addr1 = reinterpret_cast<const uint8_t *>(&chunk->data()[10]);

    if (fc->more_fragments)
        packinfo->fragmented = 1;

    if (fc->retry)
        packinfo->retry = 1;

    // Assign the distribution direction this packet is traveling
    if (fc->to_ds == 0 && fc->from_ds == 0)
        packinfo->distrib = distrib_adhoc;
    else if (fc->to_ds == 0 && fc->from_ds == 1)
        packinfo->distrib = distrib_from;
    else if (fc->to_ds == 1 && fc->from_ds == 0)
        packinfo->distrib = distrib_to;
    else if (fc->to_ds == 1 && fc->from_ds == 1)
        packinfo->distrib = distrib_inter;

    // Shortcut PHYs here because they're shorter than normal packets
    if (fc->type == packet_phy) {
        packinfo->type = packet_phy;
        common->type = packet_basic_phy;

        if (fc->subtype == 5) {
            packinfo->subtype = packet_sub_vht_ndp;

            if (addr0 == NULL || addr1 == NULL) {
                packinfo->corrupt = 1;
                in_pack->insert(pack_comp_80211, packinfo);
                return 0;
            }

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);

        } else if (fc->subtype == 8) {
            packinfo->subtype = packet_sub_block_ack_req;

            if (addr0 == NULL || addr1 == NULL) {
                packinfo->corrupt = 1;
                in_pack->insert(pack_comp_80211, packinfo);
                return 0;
            }

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);

        } else if (fc->subtype == 9) {
            packinfo->subtype = packet_sub_block_ack;

            if (addr0 == NULL || addr1 == NULL) {
                packinfo->corrupt = 1;
                in_pack->insert(pack_comp_80211, packinfo);
                return 0;
            }

            packinfo->source_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->dest_mac = mac_addr(addr1, PHY80211_MAC_LEN);
        } else if (fc->subtype == 10) {
            packinfo->subtype = packet_sub_pspoll;

            if (addr0 == NULL) {
                packinfo->corrupt = 1;
                in_pack->insert(pack_comp_80211, packinfo);
                return 0;
            }

            packinfo->source_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr0, PHY80211_MAC_LEN);

        } else if (fc->subtype == 11) {
            packinfo->subtype = packet_sub_rts;

            if (addr0 == NULL || addr1 == NULL) {
                packinfo->corrupt = 1;
                in_pack->insert(pack_comp_80211, packinfo);
                return 0;
            }

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);

        } else if (fc->subtype == 12) {
            packinfo->subtype = packet_sub_cts;

            if (addr0 == NULL) {
                packinfo->corrupt = 1;
                in_pack->insert(pack_comp_80211, packinfo);
                return 0;
            }

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr0, PHY80211_MAC_LEN);

        } else if (fc->subtype == 13) {
            packinfo->subtype = packet_sub_ack;

            if (addr0 == NULL) {
                packinfo->corrupt = 1;
                in_pack->insert(pack_comp_80211, packinfo);
                return 0;
            }

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr0, PHY80211_MAC_LEN);

        } else if (fc->subtype == 14) {
            packinfo->subtype = packet_sub_cf_end;

        } else if (fc->subtype == 15) {
            packinfo->subtype = packet_sub_cf_end_ack;

        } else {
            // fmt::print(stderr, "debug - unknown type - {} {}\n", fc->type, fc->subtype);
            packinfo->subtype = packet_sub_unknown;
        }

        // Fill in the common addressing before we bail on a phy
        common->source = packinfo->source_mac;
        common->dest = packinfo->dest_mac;
        common->network = packinfo->bssid_mac;
        common->transmitter = packinfo->transmit_mac;

        // Nothing more to do if we get a phy
        in_pack->insert(pack_comp_80211, packinfo);
        return 1;
    }

    // Anything from this point on can't be less than 24 bytes since we need
    // a full 802.11 header, so throw it out
    if (chunk->length() < 24) {
        packinfo->corrupt = 1;
        in_pack->insert(pack_comp_80211, packinfo);
        return 0;
    }

    // We must have room for addr0..2 in 24 bytes
    addr1 = reinterpret_cast<const uint8_t *>(&chunk->data()[10]);
    addr2 = reinterpret_cast<const uint8_t *>(&chunk->data()[16]);
    sequence = reinterpret_cast<const wireless_fragseq *>(&chunk->data()[22]);

    // addr3 goes up to byte 30 so before we can use it, make sure we know we've got the data
    addr3 = reinterpret_cast<const uint8_t *>(&chunk->data()[24]);

    packinfo->sequence_number = sequence->sequence;
    packinfo->frag_number = sequence->frag;

    // Rip apart management frames
    if (fc->type == packet_management) {
        packinfo->type = packet_management;
        common->type = packet_basic_mgmt;

        packinfo->distrib = distrib_unknown;

        // Throw away large management frames that don't make any sense.  512b is
        // an arbitrary number to pick, but this should keep some drivers from messing
        // with us
        // TODO: Make this a driver option
        /*
        if (chunk->length > 512) {
            packinfo->corrupt = 1;
            in_pack->insert(pack_comp_80211, packinfo);
            return 0;
        }
        */

        if (addr0 == NULL || addr1 == NULL || addr2 == NULL) {
            packinfo->corrupt = 1;
            in_pack->insert(pack_comp_80211, packinfo);
            return 0;
        }

        const fixed_parameters *fixparm = NULL;

        switch (fc->subtype) {
            case 0:
                if (chunk->length() < 36) {
                    packinfo->corrupt = 1;
                    in_pack->insert(pack_comp_80211, packinfo);
                    return 0;
                }

                if (chunk->data() == nullptr) {
                    return 0;
                }

                fixparm = reinterpret_cast<const fixed_parameters *>(&chunk->data()[24]);
                packinfo->header_offset = 24 + 4;

                packinfo->subtype = packet_sub_association_req;

                packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
                packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
                packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

                packinfo->ietag_csum =
                    crc32_fast(chunk->data() + packinfo->header_offset,
                            chunk->length() - packinfo->header_offset);

                break;

            case 1:
                if (chunk->length() < 36) {
                    packinfo->corrupt = 1;
                    in_pack->insert(pack_comp_80211, packinfo);
                    return 0;
                }

                if (chunk->data() == nullptr) {
                    return 0;
                }

                fixparm = reinterpret_cast<const fixed_parameters *>(&chunk->data()[24]);
                packinfo->header_offset = 24 + 12;

                packinfo->subtype = packet_sub_association_resp;

                packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
                packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
                packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

                packinfo->ietag_csum =
                    crc32_fast(chunk->data() + packinfo->header_offset,
                            chunk->length() - packinfo->header_offset);

                break;

            case 2:
                if (chunk->length() < 36) {
                    packinfo->corrupt = 1;
                    in_pack->insert(pack_comp_80211, packinfo);
                    return 0;
                }

                if (chunk->data() == nullptr) {
                    return 0;
                }


                fixparm = reinterpret_cast<const fixed_parameters *>(&chunk->data()[24]);
                packinfo->header_offset = 24 + 10;

                packinfo->subtype = packet_sub_reassociation_req;

                packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
                packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
                packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

                packinfo->ietag_csum =
                    crc32_fast(chunk->data() + packinfo->header_offset,
                            chunk->length() - packinfo->header_offset);

                break;

            case 3:
                packinfo->subtype = packet_sub_reassociation_resp;

                packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
                packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
                packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);
                break;

            case 4:
                if (chunk->data() == nullptr)
                    return 0;

                packinfo->subtype = packet_sub_probe_req;

                packinfo->distrib = distrib_to;

                packinfo->header_offset = 24;
                fixparm = NULL;

                packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
                packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
                packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

                packinfo->ietag_csum =
                    crc32_fast(chunk->data() + packinfo->header_offset,
                            chunk->length() - packinfo->header_offset);

                break;

            case 5:
                if (chunk->length() < 36) {
                    packinfo->corrupt = 1;
                    in_pack->insert(pack_comp_80211, packinfo);
                    return 0;
                }

                if (chunk->data() == nullptr) {
                    return 0;
                }

                fixparm = reinterpret_cast<const fixed_parameters *>(&chunk->data()[24]);
                packinfo->header_offset = 24 + 12;

                packinfo->subtype = packet_sub_probe_resp;

                packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
                packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
                packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

                packinfo->ietag_csum =
                    crc32_fast(chunk->data() + packinfo->header_offset,
                                           chunk->length() - packinfo->header_offset);

                break;

            case 8:
                if (chunk->length() < 36) {
                    packinfo->corrupt = 1;
                    in_pack->insert(pack_comp_80211, packinfo);
                    return 0;
                }

                if (chunk->data() == nullptr) {
                    return 0;
                }

                fixparm = reinterpret_cast<const fixed_parameters *>(&chunk->data()[24]);
                packinfo->header_offset = 24 + 12;

                packinfo->subtype = packet_sub_beacon;

                packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
                packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
                packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

#if 0
                // Again, privacy in fc no longer means wep per se
                if (fixparm->wep) {
                    packinfo->cryptset |= dot11_crypt_general_wep;
                    common->basic_crypt_set |= KIS_DEVICE_BASICCRYPT_ENCRYPTED;
                }
#endif

                // Look for MSF opcode beacons before tag decode
                if (packinfo->source_mac == msfopcode_mac) {
                    _ALERT(alert_msfbcomssid_ref, in_pack, packinfo,
                           "MSF-style poisoned beacon packet for Broadcom drivers detected");
                }

                if (chunk->length() >= 1184) {
                    if (memcmp(&(chunk->data()[1180]), "\x6a\x39\x58\x01", 4) == 0)
                        _ALERT(alert_msfnetgearbeacon_ref, in_pack, packinfo,
                               "MSF-style poisoned options in over-sized beacon for Netgear "
                               "driver attack");
                }

                packinfo->beacon_interval = kis_letoh16(fixparm->beacon);

                packinfo->ietag_csum =
                    crc32_fast(chunk->data() + packinfo->header_offset,
                            chunk->length() - packinfo->header_offset);

                break;

            case 9:
                if (chunk->length() < 36) {
                    packinfo->corrupt = 1;
                    in_pack->insert(pack_comp_80211, packinfo);
                    return 0;
                }

                fixparm = reinterpret_cast<const fixed_parameters *>(&chunk->data()[24]);
                packinfo->header_offset = 24 + 12;

                packinfo->subtype = packet_sub_atim;

                packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
                packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
                packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

                packinfo->distrib = distrib_unknown;
                break;

            case 10:
                packinfo->subtype = packet_sub_disassociation;

                packinfo->header_offset = 24;
                fixparm = NULL;

                packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
                packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
                packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

                packinfo->mgt_reason_code = (uint16_t) *((uint16_t *) &(chunk->data()[24]));

                if ((packinfo->mgt_reason_code >= 25 && packinfo->mgt_reason_code <= 31) ||
                    packinfo->mgt_reason_code > 45) {

                    _ALERT(alert_disconinvalid_ref, in_pack, packinfo,
                           "Unknown disassociation code " +
                           n_to_string<unsigned int>(packinfo->mgt_reason_code, 0, 1) +
                           " from network " + packinfo->bssid_mac.mac_to_string());
                }

                break;

            case 11:
                packinfo->subtype = packet_sub_authentication;

                packinfo->header_offset = 24;
                fixparm = NULL;

                packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
                packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
                packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

                packinfo->mgt_reason_code = (uint16_t) *((uint16_t *) &(chunk->data()[24]));
                break;

            case 12:
                packinfo->subtype = packet_sub_deauthentication;

                packinfo->header_offset = 24;
                fixparm = NULL;

                packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
                packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
                packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

                packinfo->mgt_reason_code = (uint16_t) *((uint16_t *) &(chunk->data()[24]));

                if ((packinfo->mgt_reason_code >= 25 && packinfo->mgt_reason_code <= 31) ||
                    packinfo->mgt_reason_code > 45) {

                    _ALERT(alert_deauthinvalid_ref, in_pack, packinfo,
                           "Unknown deauthentication code " +
                           n_to_string<unsigned int>(packinfo->mgt_reason_code, 0, 1) +
                           " from network " + packinfo->bssid_mac.mac_to_string());
                }

                break;

            case 13:
                if (chunk->length() < 30) {
                    packinfo->corrupt = 1;
                    in_pack->insert(pack_comp_80211, packinfo);
                    return 0;
                }

                packinfo->subtype = packet_sub_action;

                packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
                packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
                packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

                // Action frames have their own structure and a non-traditional
                // fixed parameters field, handle it all here
                packinfo->header_offset = 22;
                fixparm = NULL;

                // Action frames can be encrypted; we can't do anything with them if they are.

                if (!fc->wep) {
                    membuf pack_membuf((char *) &chunk->data()[packinfo->header_offset],
                                       (char *) &(chunk->data()[chunk->length()]));
                    std::istream pack_stream(&pack_membuf);

                    auto action = Globalreg::new_from_pool<dot11_action>();

                    try {
                        std::shared_ptr<kaitai::kstream> ks(new kaitai::kstream(&pack_stream));
                        action->parse(ks);
                    } catch (const std::exception& e) {
                        // fprintf(stderr, "debug - unable to parse action frame - %s\n", e.what());
                        packinfo->corrupt = 1;
                        in_pack->insert(pack_comp_80211, packinfo);
                        return 0;
                    }

                    // We only care about RMM for wids purposes right now
                    std::shared_ptr<dot11_action::action_rmm> action_rmm;
                    if (action->category_code() == dot11_action::category_code_radio_measurement &&
                        (action_rmm = action->action_frame_rmm()) != NULL) {
                        // Scan the action IE tags
                        auto rmm_tags = Globalreg::new_from_pool<dot11_ie>();

                        try {
                            rmm_tags->parse(action_rmm->tags_data_stream());
                        } catch (const std::exception& e) {
                            // fprintf(stderr, "debug - invalid ie rmm tags: %s\n", e.what());
                            packinfo->corrupt = 1;
                            in_pack->insert(pack_comp_80211, packinfo);
                            return 0;
                        }

                        for (auto t : *(rmm_tags->tags())) {
                            if (t->tag_num() == 52) {
                                try {
                                    dot11_ie_52_rmm ie_rmm;
                                    ie_rmm.parse(t->tag_data());

                                    if (ie_rmm.channel_number() > 0xE0) {
                                        std::stringstream ss;

                                        ss << "IEE80211 Access Point BSSID " <<
                                            packinfo->bssid_mac.mac_to_string() << " reporting an 802.11k " <<
                                            "neighbor channel of " << ie_rmm.channel_number() << " which is " <<
                                            "greater than the maximum channel, 224.  This may be an " <<
                                            "exploit attempt against Broadcom chipsets used in mobile " <<
                                            "devices.";

                                        alertracker->raise_alert(alert_11kneighborchan_ref, in_pack,
                                                                 packinfo->bssid_mac, packinfo->source_mac,
                                                                 packinfo->dest_mac, packinfo->other_mac,
                                                                 packinfo->channel, ss.str());
                                    }

                                } catch (const std::exception& e) {
                                    // fprintf(stderr, "debug - unable to parse rmm neighbor - %s\n", e.what());
                                }
                            }
                        }
                    }
                }

                break;

            case 14:
                if (chunk->length() < 30) {
                    packinfo->corrupt = 1;
                    in_pack->insert(pack_comp_80211, packinfo);
                    return 0;
                }

                packinfo->subtype = packet_sub_action_noack;

                fixparm = nullptr;

                packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
                packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
                packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);
                break;

            default:
                packinfo->subtype = packet_sub_unknown;
                break;
        }

        if (fixparm != nullptr) {
            // Set the transmitter info
            packinfo->ess = fixparm->ess;
            packinfo->ibss = fixparm->ibss;

            // Pull the fixparm ibss info
            if (fixparm->ess == 0 && fixparm->ibss == 1) {
                packinfo->distrib = distrib_adhoc;
            }

            // Pull the fixparm timestamp
#ifdef WORDS_BIGENDIAN
            packinfo->timestamp = kis_swap64(fixparm->timestamp);
#else
            packinfo->timestamp = fixparm->timestamp;
#endif
        }

    } else if (fc->type == packet_data) {
        packinfo->type = packet_data;
        common->type = packet_basic_data;

        switch (fc->subtype) {
            case 0:
                packinfo->subtype = packet_sub_data;
                break;
            case 1:
                packinfo->subtype = packet_sub_data_cf_ack;
                break;
            case 2:
                packinfo->subtype = packet_sub_data_cf_poll;
                break;
            case 3:
                packinfo->subtype = packet_sub_data_cf_ack_poll;
                break;
            case 4:
                packinfo->subtype = packet_sub_data_null;
                break;
            case 5:
                packinfo->subtype = packet_sub_cf_ack;
                break;
            case 6:
                packinfo->subtype = packet_sub_cf_ack_poll;
                break;
            case 8:
                packinfo->subtype = packet_sub_data_qos_data;
                packinfo->header_offset += 2;
                break;
            case 9:
                packinfo->subtype = packet_sub_data_qos_data_cf_ack;
                packinfo->header_offset += 2;
                break;
            case 10:
                packinfo->subtype = packet_sub_data_qos_data_cf_poll;
                packinfo->header_offset += 2;
                break;
            case 11:
                packinfo->subtype = packet_sub_data_qos_data_cf_ack_poll;
                packinfo->header_offset += 2;
                break;
            case 12:
                packinfo->subtype = packet_sub_data_qos_null;
                packinfo->header_offset += 2;
                break;
            case 14:
                packinfo->subtype = packet_sub_data_qos_cf_poll_nod;
                packinfo->header_offset += 2;
                break;
            case 15:
                packinfo->subtype = packet_sub_data_qos_cf_ack_poll;
                packinfo->header_offset += 2;
                break;
            default:
                packinfo->corrupt = 1;
                packinfo->subtype = packet_sub_unknown;
                in_pack->insert(pack_comp_80211, packinfo);
                return 0;
        }

        // Extract ID's
        switch (packinfo->distrib) {
        case distrib_adhoc:

            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr2, PHY80211_MAC_LEN);

            if (packinfo->bssid_mac.longmac == 0)
                packinfo->bssid_mac = packinfo->source_mac;

            packinfo->header_offset += 24;
            break;
        case distrib_from:
            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->bssid_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr2, PHY80211_MAC_LEN);

            packinfo->header_offset += 24;
            break;
        case distrib_to:
            packinfo->bssid_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->dest_mac = mac_addr(addr2, PHY80211_MAC_LEN);

            packinfo->header_offset += 24;
            break;
        case distrib_inter:
            // If we aren't long enough to hold a intra-ds packet, bail
            if (chunk->length() < 30) {
                // fprintf(stderr, "debug - distrib unknown, chunk %d\n", chunk->length);
                packinfo->corrupt = 1;
                in_pack->insert(pack_comp_80211, packinfo);
                return 0;
            }

            packinfo->receive_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->transmit_mac = mac_addr(addr1, PHY80211_MAC_LEN);
            packinfo->dest_mac = mac_addr(addr2, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr3, PHY80211_MAC_LEN);

            packinfo->distrib = distrib_inter;

            // First byte of offsets
            packinfo->header_offset += 30;
            break;

        case distrib_unknown:
            // If we aren't long enough to hold a intra-ds packet, bail
            if (chunk->length() < 30) {
                packinfo->corrupt = 1;
                in_pack->insert(pack_comp_80211, packinfo);
                return 0;
            }

            packinfo->bssid_mac = mac_addr(addr0, PHY80211_MAC_LEN);
            packinfo->source_mac = mac_addr(addr3, PHY80211_MAC_LEN);
            packinfo->dest_mac = mac_addr(addr0, PHY80211_MAC_LEN);

            packinfo->distrib = distrib_inter;

            // First byte of offsets
            packinfo->header_offset += 30;
            break;
        default:
            packinfo->corrupt = 1;
            in_pack->insert(pack_comp_80211, packinfo);
            return 0;
            break;
        }

        // WEP/Protected on data frames means encrypted, not WEP, sometimes
        if (fc->wep) {
            bool alt_crypt = false;

            // We can't really know if it's WPA1 or WPA2 from just a data frame so
            // set a generic 'wpa'
            if (packinfo->header_offset + 2 < chunk->length()) {
                if (chunk->data()[packinfo->header_offset + 2] == 0) {
                    packinfo->cryptset |= dot11_crypt_general_wpa;
                    common->basic_crypt_set |= KIS_DEVICE_BASICCRYPT_ENCRYPTED;
                    alt_crypt = true;
                }  else if (chunk->data()[packinfo->header_offset + 1] & 0x20) {
                    packinfo->cryptset |= dot11_crypt_general_wpa;
                    common->basic_crypt_set |= KIS_DEVICE_BASICCRYPT_ENCRYPTED;
                    alt_crypt = true;
                }
            }

            // Try setting wep if we can't determine what it is otherwise
            if (!alt_crypt) {
                packinfo->cryptset |= dot11_crypt_general_wep;
                common->basic_crypt_set |= KIS_DEVICE_BASICCRYPT_ENCRYPTED;
            }
        }

        // Calculate the data size based on the original capture length, but use chunk length for
        // all other operations since that's the size of the buffer
        ssize_t datasize = chunk->length() - packinfo->header_offset;
        if (datasize > 0) {
            packinfo->datasize = datasize;
            common->datasize = datasize;
        }

        if (packinfo->cryptset == 0 && dissect_data && datasize > 0) {
            // Keep whatever datachunk we already found
            auto datachunk = in_pack->fetch<kis_datachunk>(pack_comp_datapayload);

            if (datachunk == nullptr) {
                // Don't set a DLT on the data payload, since we don't know what it is
                // but it's not 802.11.
                datachunk = packetchain->new_packet_component<kis_datachunk>();
                datachunk->set_data(chunk->substr(packinfo->header_offset,
                            chunk->length() - packinfo->header_offset));
                in_pack->insert(pack_comp_datapayload, datachunk);
            }

            // Dot1x frames
            // +1 for the version byte at header_offset + hot1x off
            // +3 for the offset past LLC_UI
            if ((LLC_UI_OFFSET + 4 + sizeof(DOT1X_PROTO)) < chunk->length() &&
                memcmp(&(chunk->data()[LLC_UI_OFFSET + 3]), DOT1X_PROTO, sizeof(DOT1X_PROTO)) == 0) {

                auto datainfo = packetchain->new_packet_component<kis_data_packinfo>();

                datainfo->proto = proto_eap;

                // printf("debug - dot1x frame?\n");
                // It's dot1x, is it LEAP?
                //
                // Make sure its an EAP socket
                unsigned int offset = DOT1X_OFFSET;

                // Dot1x bits
                uint8_t dot1x_version = chunk->data()[offset];
                uint8_t dot1x_type = chunk->data()[offset + 1];
                // uint16_t dot1x_length = kis_extract16(&(chunk->data[offset + 2]));

                offset += EAP_OFFSET;

                if (dot1x_version != 1 || dot1x_type != 0 ||
                    offset + EAP_PACKET_SIZE > chunk->length()) {
                    goto eap_end;
                }

                // Eap bits
                uint8_t eap_code = chunk->data()[offset];
                // uint8_t eap_id = chunk->data[offset + 1];
                uint16_t eap_length = kis_extractBE16(&(chunk->data()[offset + 2]));
                uint8_t eap_type = chunk->data()[offset + 4];

                unsigned int rawlen;
                char *rawid;

                if (offset + eap_length > chunk->length()) {
                    goto eap_end;
                }

                packinfo->cryptset |= crypt_eap;
                common->basic_crypt_set |= KIS_DEVICE_BASICCRYPT_ENCRYPTED;
                switch (eap_type) {
                    case EAP_TYPE_LEAP:
                        datainfo->field1 = eap_code;
                        packinfo->cryptset |= dot11_crypt_eap_leap;
                        break;
                    case EAP_TYPE_TLS:
                        datainfo->field1 = eap_code;
                        packinfo->cryptset |= dot11_crypt_eap_tls;
                        break;
                    case EAP_TYPE_TTLS:
                        datainfo->field1 = eap_code;
                        packinfo->cryptset |= dot11_crypt_eap_ttls;
                        break;
                    case EAP_TYPE_PEAP:
                        // printf("debug - peap!\n");
                        datainfo->field1 = eap_code;
                        packinfo->cryptset |= dot11_crypt_eap_peap;
                        break;
                    case EAP_TYPE_IDENTITY:
                        if (eap_code == EAP_CODE_RESPONSE) {
                            rawlen = eap_length - 5;
                            rawid = new char[rawlen + 1];
                            memcpy(rawid, &(chunk->data()[offset + 5]), rawlen);
                            rawid[rawlen] = 0;

                            datainfo->auxstring = munge_to_printable(std::string(rawid, rawlen));
                            delete[] rawid;
                        }

                        break;
                    default:
                        break;
                }

                in_pack->insert(pack_comp_basicdata, datainfo);
            }

eap_end:
            ;

        }
    }

    // Populate the common addressing
    common->source = packinfo->source_mac;
    common->dest = packinfo->dest_mac;
    common->network = packinfo->bssid_mac;
    common->transmitter = packinfo->transmit_mac;

    common->type = packet_basic_data;

    in_pack->insert(pack_comp_80211, packinfo);

    uint32_t aid = 0;
    aid = adler32_checksum(&common->source.longmac, sizeof(common->source.longmac));
    aid = adler32_append_checksum(&common->dest.longmac, sizeof(common->dest.longmac), aid);
    aid = adler32_append_checksum(&common->network.longmac, sizeof(common->network.longmac), aid);
    aid = adler32_append_checksum(&common->transmitter.longmac, sizeof(common->transmitter.longmac), aid);

    in_pack->assignment_id = aid;

    return 1;
}

std::shared_ptr<std::vector<kis_80211_phy::ie_tag_tuple>> kis_80211_phy::packet_dot11_ie_list(
        const std::shared_ptr<kis_packet>& in_pack,
        const std::shared_ptr<dot11_packinfo>& packinfo) {
    if (packinfo->ie_tags_listed != nullptr)
        return packinfo->ie_tags_listed;

    packinfo->ie_tags_listed =
        Globalreg::new_from_pool<std::vector<ie_tag_tuple>>();

    if (packinfo->ie_tags == nullptr) {
        // If we can't have IE tags at all
        if (packinfo->type != packet_management || !(
                    packinfo->subtype == packet_sub_beacon ||
                    packinfo->subtype == packet_sub_probe_req ||
                    packinfo->subtype == packet_sub_probe_resp ||
                    packinfo->subtype == packet_sub_association_req ||
                    packinfo->subtype == packet_sub_reassociation_req)) {
            return packinfo->ie_tags_listed;
        }

        // If we can't grab an 802.11 chunk, grab the raw link frame
        auto chunk = in_pack->fetch<kis_datachunk>(pack_comp_decap, pack_comp_linkframe);

        if (chunk == nullptr) {
            return packinfo->ie_tags_listed;
        }

        // If we don't have a dot11 frame, throw it away
        if (chunk->dlt != KDLT_IEEE802_11)
            return packinfo->ie_tags_listed;

        membuf tags_membuf((char *) &(chunk->data()[packinfo->header_offset]),
                (char *) &(chunk->data()[chunk->length()]));
        std::istream istream_ietags(&tags_membuf);

		packinfo->ie_tags = Globalreg::new_from_pool<dot11_ie>();

        try {
            std::shared_ptr<kaitai::kstream> stream_ietags(new kaitai::kstream(&istream_ietags));
            packinfo->ie_tags->parse(stream_ietags);
        } catch (const std::exception& e) {
            return packinfo->ie_tags_listed;
        }
    }

    for (const auto& ie_tag : *(packinfo->ie_tags->tags())) {
        if (ie_tag->tag_num() == 150) {
            try {
				auto vendor = Globalreg::new_from_pool<dot11_ie_150_vendor>();
                vendor->parse(ie_tag->tag_data());

                packinfo->ie_tags_listed->push_back(ie_tag_tuple{150, vendor->vendor_oui_int(), vendor->vendor_oui_type()});
            } catch (const std::exception &e) {
                return packinfo->ie_tags_listed;
            }
        } else if (ie_tag->tag_num() == 221) {
            try {
				auto vendor = Globalreg::new_from_pool<dot11_ie_221_vendor>();
                vendor->parse(ie_tag->tag_data());

                packinfo->ie_tags_listed->push_back(ie_tag_tuple{221, vendor->vendor_oui_int(), vendor->vendor_oui_type()});
            } catch (const std::exception &e) {
                return packinfo->ie_tags_listed;
            }
        } else {
            packinfo->ie_tags_listed->push_back(ie_tag_tuple{ie_tag->tag_num(), 0, 0});
        }
    }

    return packinfo->ie_tags_listed;
}

int kis_80211_phy::packet_dot11_ie_dissector(const std::shared_ptr<kis_packet>& in_pack,
        const std::shared_ptr<dot11_packinfo>& packinfo) {

	// Called opportunistically by the main dot11 processor when the checksum over all IE
	// tags has changed

    // If we can't have IE tags at all
    if (packinfo->type != packet_management || !(
                packinfo->subtype == packet_sub_beacon ||
                packinfo->subtype == packet_sub_probe_req ||
                packinfo->subtype == packet_sub_probe_resp ||
                packinfo->subtype == packet_sub_association_req ||
                packinfo->subtype == packet_sub_reassociation_req))
        return 0;

    auto chunk = in_pack->fetch<kis_datachunk>(pack_comp_decap, pack_comp_linkframe);

    // If we can't grab an 802.11 chunk, grab the raw link frame
    if (chunk == nullptr) {
        return 0;
    }

    // If we don't have a dot11 frame, throw it away
    if (chunk->dlt != KDLT_IEEE802_11)
        return 0;

	// Do a first-order processing of the tags to make sure it's a valid frame
    if (packinfo->ie_tags == nullptr) {
        membuf tags_membuf((char *) &(chunk->data()[packinfo->header_offset]),
                (char *) &(chunk->data()[chunk->length()]));
        std::istream istream_ietags(&tags_membuf);

		packinfo->ie_tags = Globalreg::new_from_pool<dot11_ie>();

        try {
			auto ks = kaitai::kstream(&istream_ietags);
            packinfo->ie_tags->parse(ks);
        } catch (const std::exception& e) {
            // fmt::print(stderr, "debug - IE tag structure corrupt\n");
            packinfo->corrupt = 1;
            return -1;
        }
    }

    auto common = in_pack->fetch<kis_common_info>(pack_comp_common);

    // Track if we've seen some of these tags already
    unsigned int wmmtspec_responses = 0;

    for (const auto& ie_tag : *(packinfo->ie_tags->tags())) {
        auto hash = std::hash<std::string>{};

        if (ie_tag->tag_num() == 150) {
            try {
				auto vendor = Globalreg::new_from_pool<dot11_ie_150_vendor>();
                vendor->parse(ie_tag->tag_data());

                packinfo->ietag_hash_map.insert(std::make_pair(ie_tag_tuple{150, vendor->vendor_oui_int(),
                    vendor->vendor_oui_type()}, hash(ie_tag->tag_data())));
            } catch (const std::exception& e) {
                packinfo->corrupt = 1;
                return -1;
            }
        } else if (ie_tag->tag_num() == 221) {
            try {
				auto vendor = Globalreg::new_from_pool<dot11_ie_221_vendor>();
                vendor->parse(ie_tag->tag_data());

                packinfo->ietag_hash_map.insert(std::make_pair(ie_tag_tuple{221, vendor->vendor_oui_int(),
                    vendor->vendor_oui_type()}, hash(ie_tag->tag_data())));
            } catch (const std::exception& e) {
                packinfo->corrupt = 1;
                return -1;
            }
        } else {
            packinfo->ietag_hash_map.insert(std::make_pair(ie_tag_tuple{ie_tag->tag_num(), 0, 0},
                                                           hash(ie_tag->tag_data())));
        }

        // IE 0 SSID
        if (ie_tag->tag_num() == 0) {
            /*
            if (seen_ssid) {
                fprintf(stderr, "debug - multiple SSID ie tags?\n");
            }

            seen_ssid = true;
            */

            packinfo->ssid_len = ie_tag->tag_data().length();
            packinfo->ssid_csum = kis_80211_phy::ssid_hash(ie_tag->tag_data().data(),
                    ie_tag->tag_data().length());

            if (packinfo->ssid_len == 0) {
                packinfo->ssid_blank = true;
                continue;
            }

            if (packinfo->ssid_len <= DOT11_PROTO_SSID_LEN) {
                if (ie_tag->tag_data().find_first_not_of('\0') == std::string::npos) {
                    packinfo->ssid_blank = true;
                } else {
                    packinfo->ssid = munge_to_printable(ie_tag->tag_data().data());
                }
            } else {
                _ALERT(alert_longssid_ref, in_pack, packinfo,
                        "Invalid SSID (ssid advertised as more than 32 bytes) seen, "
                        "this may indicate an exploit attempt against a Wi-Fi driver which "
                        "does not properly handle invalid packets.");
                // Otherwise we're corrupt, set it and stop processing
                packinfo->corrupt = 1;
                return -1;
            }

            continue;
        }

        // IE 1 Basic Rates
        // IE 50 Extended Rates
        if (ie_tag->tag_num() == 1 || ie_tag->tag_num() == 50) {
            if (ie_tag->tag_num() == 1) {
                /*
                if (seen_basicrates) {
                    fprintf(stderr, "debug - seen multiple basicrates?\n");
                }

                seen_basicrates = true;
                */

            }

            if (ie_tag->tag_num() == 50) {
                /*
                if (seen_extendedrates) {
                    fprintf(stderr, "debug - seen multiple extendedrates?\n");
                }

                seen_extendedrates = true;
                */
            }

            if (ie_tag->tag_data().find("\x75\xEB\x49") != std::string::npos) {
                _ALERT(alert_msfdlinkrate_ref, in_pack, packinfo,
                        "MSF-style poisoned rate field in beacon for network " +
                        packinfo->bssid_mac.mac_to_string() + ", exploit attempt "
                        "against D-Link drivers");

                packinfo->corrupt = 1;
                return -1;
            }

            std::vector<std::string> basicrates;
            for (uint8_t r : ie_tag->tag_data()) {
                std::string rate;

                switch (r) {
                    case 0x02:
                        rate = "1";
                        break;
                    case 0x03:
                        rate = "1.5";
                        break;
                    case 0x04:
                        rate = "2";
                        break;
                    case 0x05:
                        rate = "2.5";
                        break;
                    case 0x06:
                        rate = "3";
                        break;
                    case 0x09:
                        rate = "4.5";
                        break;
                    case 0x0B:
                        rate = "5.5";
                        break;
                    case 0x0C:
                        rate = "6";
                        break;
                    case 0x12:
                        rate = "9";
                        break;
                    case 0x16:
                        rate = "11";
                        break;
                    case 0x18:
                        rate = "12";
                        break;
                    case 0x1B:
                        rate = "13.5";
                        break;
                    case 0x24:
                        rate = "18";
                        break;
                    case 0x2C:
                        rate = "22";
                        break;
                    case 0x30:
                        rate = "24";
                        break;
                    case 0x36:
                        rate = "27";
                        break;
                    case 0x42:
                        rate = "33";
                        break;
                    case 0x48:
                        rate = "36";
                        break;
                    case 0x60:
                        rate = "48";
                        break;
                    case 0x6C:
                        rate = "54";
                        break;
                    case 0x82:
                        rate = "1B";
                        break;
                    case 0x83:
                        rate = "1.5B";
                        break;
                    case 0x84:
                        rate = "2B";
                        break;
                    case 0x85:
                        rate = "2.5B";
                        break;
                    case 0x86:
                        rate = "3B";
                        break;
                    case 0x89:
                        rate = "4.5B";
                        break;
                    case 0x8B:
                        rate = "5.5B";
                        break;
                    case 0x8C:
                        rate = "6B";
                        break;
                    case 0x92:
                        rate = "9B";
                        break;
                    case 0x96:
                        rate = "11B";
                        break;
                    case 0x98:
                        rate = "12B";
                        break;
                    case 0x9B:
                        rate = "13.5B";
                        break;
                    case 0xA4:
                        rate = "18B";
                        break;
                    case 0xAC:
                        rate = "22B";
                        break;
                    case 0xB0:
                        rate = "24B";
                        break;
                    case 0xB6:
                        rate = "27B";
                        break;
                    case 0xC2:
                        rate = "33B";
                        break;
                    case 0xC8:
                        rate = "36B";
                        break;
                    case 0xE0:
                        rate = "48B";
                        break;
                    case 0xEC:
                        rate = "54B";
                        break;
                    case 0xFF:
                        rate = "HT";
                        break;
                    default:
                        rate = "UNK";
                        break;
                }

                double m;
                if (sscanf(rate.c_str(), "%lf", &m) == 1) {
                    if (packinfo->maxrate < m)
                        packinfo->maxrate = m;
                }

                basicrates.push_back(rate);
            }

            packinfo->basic_rates = basicrates;
            continue;
        }

        // IE 3 channel
        if (ie_tag->tag_num() == 3) {
            if (ie_tag->tag_len() > 1) {
                std::string al = fmt::format("IEEE80211 packet from {0} to {1} BSSID {2} included an IE "
                        "tag {3} entry with an invalid length; IE {3} should be {4} bytes, but was {5}. "
                        "This may be indicative of an as-yet-unknown buffer overflow attempt against "
                        "the Wi-Fi drivers or firmware, but could also be caused by a misconfigured device.",
                        packinfo->source_mac, packinfo->dest_mac, packinfo->bssid_mac,
                        3, 1, ie_tag->tag_len());

                alertracker->raise_alert(alert_bad_fixlen_ie, in_pack,
                        packinfo->bssid_mac, packinfo->source_mac,
                        packinfo->dest_mac, packinfo->other_mac,
                        packinfo->channel, al);
                packinfo->corrupt = 1;
                return -1;
            }

            packinfo->channel = fmt::format("{}", (uint8_t) (ie_tag->tag_data()[0]));
            continue;
        }

        // IE 7 802.11d
        if (ie_tag->tag_num() == 7) {
            try {
                dot11_ie_7_country dot11d;
                // Allow fragmented 11d, take what we can parse
                dot11d.set_allow_fragments(true);
                dot11d.parse(ie_tag->tag_data());

                packinfo->dot11d_country = munge_to_printable(dot11d.country_code());

                if (process_11d_country_list) {
                    dot11d.parse_channels(ie_tag->tag_data());

                    for (auto c : *(dot11d.country_list())) {
                        dot11_packinfo_dot11d_entry ri;

                        ri.startchan = c->first_channel();
                        ri.numchan = c->num_channels();
                        ri.txpower = c->max_power();

                        packinfo->dot11d_vec.push_back(ri);
                    }
                }
            } catch (const std::exception& e) {
                // Corrupt dot11 isn't a fatal condition
                // fprintf(stderr, "debug - corrupt dot11d: %s\n", e.what());
            }

            continue;
        }

        // IE 11 QBSS
        if (ie_tag->tag_num() == 11) {
            try {
				auto qbss = Globalreg::new_from_pool<dot11_ie_11_qbss>();
                qbss->parse(ie_tag->tag_data());
                packinfo->qbss = qbss;
            } catch (const std::exception& e) {
                // fprintf(stderr, "debug - corrupt QBSS %s\n", e.what());
                packinfo->corrupt = 1;
                return -1;
            }

            continue;
        }

        // IE 33 advertised txpower in probe req
        if (ie_tag->tag_num() == 33) {
            try {
				packinfo->tx_power = Globalreg::new_from_pool<dot11_ie_33_power>();
                packinfo->tx_power->parse(ie_tag->tag_data());
            } catch (const std::exception& e) {
                // fmt::print(stderr, "debug - corrupt IE33 power: {}\n", e.what());
            }

        }

#if 0
        // We don't use this, don't decode
        // IE 36, advertised supported channels in probe req
        if (ie_tag->tag_num() == 36) {
            try {
				packinfo->supported_channels = Globalreg::new_from_pool<dot11_ie_36_supported_channels>();
                packinfo->supported_channels->parse(ie_tag->tag_data_stream());
            } catch (const std::exception& e) {
                // fmt::print(stderr, "debug  corrupt ie36 supported channels: {}\n", e.what());
            }
        }
#endif

        if (ie_tag->tag_num() == 45) {
            /*
            if (seen_mcsrates) {
                fprintf(stderr, "debug - duplicate ie45 mcs rates\n");
            }

            seen_mcsrates = true;
            */

            std::vector<std::string> mcsrates;

            try {
				auto ht = Globalreg::new_from_pool<dot11_ie_45_ht_cap>();
                ht->parse(ie_tag->tag_data());

                std::stringstream mcsstream;

                // See if we support 40mhz channels and aren't 40mhz intolerant
                bool ch40 = (ht->ht_cap_40mhz_channel() && !ht->ht_cap_40mhz_intolerant());

                bool gi20 = ht->ht_cap_20mhz_shortgi();
                bool gi40 = ht->ht_cap_40mhz_shortgi();

                uint8_t mcs_byte;
                uint8_t mcs_offt = 0;

                for (int x = 0; x < 4; x++) {
                    mcs_byte = ht->mcs()->rx_mcs()[x];
                    for (int i = 0; i < 8; i++) {
                        if (mcs_byte & (1 << i)) {
                            int mcsindex = mcs_offt + i;
                            if (mcsindex < 0 || mcsindex > MCS_MAX)
                                continue;

                            if (mcsindex == 32) {
                                if (ch40) {
                                    mcsstream.str("");
                                    mcsstream << "MCS" << mcsindex << "(" <<
                                        "HTDUP" << ")";
                                    mcsrates.push_back(mcsstream.str());
                                }

                                continue;
                            }

                            double rate;

                            mcsstream.str("");
                            mcsstream << "MCS" << mcsindex;

                            if (ch40 && gi40) {
                                rate = mcs_table[mcsindex][CH40GI400];
                            } else if (ch40) {
                                rate = mcs_table[mcsindex][CH40GI800];
                            } else if (gi20) {
                                rate = mcs_table[mcsindex][CH20GI400];
                            } else {
                                rate = mcs_table[mcsindex][CH20GI800];
                            }

                            if (packinfo->maxrate < rate)
                                packinfo->maxrate = rate;

                            mcsrates.push_back(mcsstream.str());
                        }
                    }

                    mcs_offt += 8;
                }

            } catch (const std::exception& e) {
                // fprintf(stderr, "debug -corrupt HT\n");
                packinfo->corrupt = 1;
                return -1;
            }

            packinfo->mcs_rates = mcsrates;
            continue;
        }

        // IE 48, RSN
        if (ie_tag->tag_num() == 48) {
            bool rsn_invalid = false;

            try {
				auto rsn = Globalreg::new_from_pool<dot11_ie_48_rsn>();
                rsn->parse(ie_tag->tag_data());

                packinfo->cryptset |= wpa_rsn_group_conv(rsn->group_cipher()->cipher_type());

                for (auto i : *(rsn->pairwise_ciphers())) {
                    packinfo->cryptset |= wpa_rsn_pairwise_conv(i->cipher_type());
                }

                // Merge the authkey types
                for (auto i : *(rsn->akm_ciphers())) {
                    packinfo->cryptset |= dot11_crypt_general_wpa;
                    packinfo->cryptset |= wpa_rsn_auth_conv(i->management_type());
                }

                common->basic_crypt_set |= KIS_DEVICE_BASICCRYPT_ENCRYPTED;
                packinfo->rsn = rsn;
            } catch (const std::exception& e) {
                rsn_invalid = true;
                packinfo->corrupt = 1;
            }

            // Re-parse using the limited RSN object to see if we're
            // getting hit with something that looks like
            // https://pleasestopnamingvulnerabilities.com/
            // CVE-2017-9714
            if (rsn_invalid) {
                try {
					auto rsn = Globalreg::new_from_pool<dot11_ie_48_rsn_partial>();
                    rsn->parse(ie_tag->tag_data());

                    if (rsn->pairwise_count() > 1024) {
                        alertracker->raise_alert(alert_atheros_rsnloop_ref,
                                in_pack,
                                packinfo->bssid_mac, packinfo->source_mac,
                                packinfo->dest_mac, packinfo->other_mac,
                                packinfo->channel,
                                "Invalid 802.11i RSN IE seen with extremely "
                                "large number of pairwise ciphers; this could "
                                "be an attack against Atheros drivers per "
                                "CVE-2017-9714 and "
                                "https://pleasestopnamingvulnerabilities.com/ but "
                                "may also simply be a device performing unusually.");
                    }

                } catch (const std::exception& e) {
                    // Do nothing with the secondary error; we already know
                    // something is wrong we're just trying to extract the
                    // better errors
                }

                return -1;
            }

            continue;
        }

        // IE 54 Mobility
        if (ie_tag->tag_num() == 54) {
            try {
				auto mobility = Globalreg::new_from_pool<dot11_ie_54_mobility>();
                mobility->parse(ie_tag->tag_data());
                packinfo->dot11r_mobility = mobility;
            } catch (const std::exception& e) {
                packinfo->corrupt = 1;
                return -1;
            }
            continue;
        }

        // IE 61 HT
        if (ie_tag->tag_num() == 61) {
            try {
				auto ht = Globalreg::new_from_pool<dot11_ie_61_ht_op>();
                ht->parse(ie_tag->tag_data());
                packinfo->dot11ht = ht;
            } catch (const std::exception& e) {
                // fprintf(stderr, "debug - unparsable HT\n");
                // Don't consider unparsable HT a corrupt packet (for now)
                continue;
            }

            continue;
        }

        // IE 133 CISCO CCX
        if (ie_tag->tag_num() == 133) {
            try {
				auto ccx1 = Globalreg::new_from_pool<dot11_ie_133_cisco_ccx>();
                ccx1->parse(ie_tag->tag_data());
                packinfo->beacon_info = munge_to_printable(ccx1->ap_name());
            } catch (const std::exception& e) {
                // fprintf(stderr, "debug - ccx error %s\n", e.what());
                continue;
            }

            continue;
        }

        if (ie_tag->tag_num() == 127) {
            if (ie_tag->tag_len() > 13) {
                std::string al = fmt::format("IEEE80211 Access Point BSSID {} sent a beacon with "
                    "an invalid IE 127 Extended Capabilities tag; this may indicate attempts to "
                    "exploit Qualcomm drivers using the CVE-2019-10539 vulnerability.  Extended "
                    "capability tags should typically have 10-11 bytes, but saw {}.",
                    packinfo->bssid_mac, ie_tag->tag_len());

                alertracker->raise_alert(alert_qcom_extended_ref, in_pack,
                        packinfo->bssid_mac, packinfo->source_mac,
                        packinfo->dest_mac, packinfo->other_mac,
                        packinfo->channel, al);

            }

			continue;
        }

		// IE 113 Mesh ID field
		if (ie_tag->tag_num() == 113) {
			// If we have no SSID tag, use the mesh ID as the SSID checksum to differentiate
			// between multiple mesh advertisements; otherwise use the SSID
			if (packinfo->ssid_len == 0) {
				packinfo->ssid_csum = kis_80211_phy::ssid_hash(ie_tag->tag_data().data(),
						ie_tag->tag_data().length());
			}

            continue;
		}

        // IE 191 VHT Capabilities TODO compbine with VHT OP to derive actual usable
        // rate
        if (ie_tag->tag_num() == 191) {
            try {
				auto vht = Globalreg::new_from_pool<dot11_ie_191_vht_cap>();
                vht->parse(ie_tag->tag_data());

                bool gi80 = vht->vht_cap_80mhz_shortgi();
                bool gi160 = vht->vht_cap_160mhz_shortgi();
                bool supp160 = vht->vht_cap_160mhz();

                int stream = -1;
                unsigned int mcs = 0;
                unsigned int gi = 0;

                if (supp160) {
                    if (gi160) {
                        gi = CH160GI400;
                    } else {
                        gi = CH160GI800;
                    }
                } else {
                    if (gi80) {
                        gi = CH80GI400;
                    } else {
                        gi = CH80GI800;
                    }
                }

                // Count back from stream 4 looking for the highest MCS setting
                if (vht->rx_mcs_s4() == 2) {
                    stream = 3;
                    mcs = 9;
                } else if (vht->rx_mcs_s4() == 1) {
                    stream = 3;
                    mcs = 7;
                } else if (vht->rx_mcs_s3() == 2) {
                    stream = 2;
                    mcs = 9;
                } else if (vht->rx_mcs_s3() == 1) {
                    stream = 2;
                    mcs = 7;
                } else if (vht->rx_mcs_s2() == 2) {
                    stream = 1;
                    mcs = 9;
                } else if (vht->rx_mcs_s2() == 1) {
                    stream = 1;
                    mcs = 7;
                } else if (vht->rx_mcs_s1() == 2) {
                    stream = 0;
                    mcs = 9;
                } else if (vht->rx_mcs_s1() == 1) {
                    stream = 0;
                    mcs = 7;
                }

                // What?  Invalid steam index
                if (stream < 0 || stream > 3) {
                    continue;
                }

                // Get the index
                int mcsofft = (stream * 10) + mcs;
                if (mcsofft < 0 || mcsofft > VHT_MCS_MAX)
                    continue;

                double speed = vht_mcs_table[mcsofft][gi];

                if (packinfo->maxrate < speed)
                    packinfo->maxrate = speed;


            } catch (const std::exception& e) {
                fprintf(stderr, "debug - vht 191 error %s\n", e.what());
                // Don't consider this a corrupt packet just because we didn't parse it
            }

            continue;
        }


        // Vendor 150 collection
        if (ie_tag->tag_num() == 150) {
            try {
				auto vendor = Globalreg::new_from_pool<dot11_ie_150_vendor>();
                vendor->parse(ie_tag->tag_data());

                if (vendor->vendor_oui_int() == dot11_ie_150_cisco_powerlevel::cisco_oui()) {
					auto ccx_power = Globalreg::new_from_pool<dot11_ie_150_cisco_powerlevel>();
                    ccx_power->parse(vendor->vendor_tag());
                    packinfo->ccx_txpower = ccx_power->cisco_ccx_txpower();
                }
            } catch (const std::exception& e) {
                // fprintf(stderr, "debug - ie150 vendor tag error: %s\n", e.what());
                // Don't consider this a corrupt packet because ie150 can be highly variable
            }

            continue;
        }

        // IE 192 VHT Operation
        if (ie_tag->tag_num() == 192) {
            try {
				auto vht = Globalreg::new_from_pool<dot11_ie_192_vht_op>();
                vht->parse(ie_tag->tag_data());
                packinfo->dot11vht = vht;

            } catch (const std::exception& e) {
                // fprintf(stderr, "debug - vht 192 error %s\n", e.what());
                // Don't consider this a corrupt packet just because we didn't parse it
            }

            continue;
        }

        if (ie_tag->tag_num() == 221) {
            try {
				auto vendor = Globalreg::new_from_pool<dot11_ie_221_vendor>();
                vendor->parse(ie_tag->tag_data());

                // Match mis-sized WMM
                if (packinfo->subtype == packet_sub_beacon &&
                        vendor->vendor_oui_int() == 0x0050f2 &&
                        vendor->vendor_oui_type() == 2 &&
                        ie_tag->tag_data().length() > 24) {

                    std::string al = "IEEE80211 Access Point BSSID " +
                        packinfo->bssid_mac.mac_to_string() + " sent association "
                        "response with an invalid WMM length; this may "
                        "indicate attempts to exploit driver vulnerabilities "
                        "such as BroadPwn";

                    alertracker->raise_alert(alert_wmm_ref, in_pack,
                            packinfo->bssid_mac, packinfo->source_mac,
                            packinfo->dest_mac, packinfo->other_mac,
                            packinfo->channel, al);
                }

                // Count wmmtspec frames; per
                // CVE-2017-11013
                // https://pleasestopnamingvulnerabilities.com/
                if (packinfo->subtype == packet_sub_association_resp &&
                        vendor->vendor_oui_int() == 0x0050f2 &&
                        vendor->vendor_oui_type() == 2) {
                    dot11_ie_221_ms_wmm wmm;
                    wmm.parse(vendor->vendor_tag());

                    if (wmm.wme_subtype() == 0x02) {
                        wmmtspec_responses++;
                    }

                }

                // Overflow of responses
                if (wmmtspec_responses > 4) {
                    std::string al = "IEEE80211 Access Point BSSID " +
                        packinfo->bssid_mac.mac_to_string() + " sent association "
                        "response with more than 4 WMM-TSPEC responses; this "
                        "may be attempt to exploit embedded Atheros drivers using "
                        "CVE-2017-11013";

                    alertracker->raise_alert(alert_atheros_wmmtspec_ref, in_pack,
                            packinfo->bssid_mac, packinfo->source_mac,
                            packinfo->dest_mac, packinfo->other_mac,
                            packinfo->channel, al);
                }

                if (vendor->vendor_oui_int() == dot11_ie_221_dji_droneid::vendor_oui()) {
                    // Look for DJI DroneID OUIs
					auto droneid = Globalreg::new_from_pool<dot11_ie_221_dji_droneid>();
                    droneid->parse(vendor->vendor_tag());

                    packinfo->droneid = droneid;
                } else if (vendor->vendor_oui_int() == dot11_ie_221_wfa_wpa::ms_wps_oui() &&
                        vendor->vendor_oui_type() == dot11_ie_221_wfa_wpa::wfa_wpa_subtype()) {
                    // Look for MS/WFA WPA
					auto wpa = Globalreg::new_from_pool<dot11_ie_221_wfa_wpa>();
                    wpa->parse(vendor->vendor_tag());

                    // Merge the group cipher
                    packinfo->cryptset |=
                        wfa_group_conv(static_cast<ie221_wfa_cipher>(wpa->multicast_cipher()->cipher_type()));

                    // Merge the unicast ciphers
                    for (auto i : *(wpa->unicast_ciphers())) {
                        packinfo->cryptset |= wfa_pairwise_conv(static_cast<ie221_wfa_cipher>(i->cipher_type()));
                    }

                    // Merge the authkey types
                    for (auto i : *(wpa->akm_ciphers())) {
                        packinfo->cryptset |= wfa_auth_conv(static_cast<ie221_wfa_mgmt>(i->cipher_type()));
                    }

                    if (wpa->wpa_version() == 1)
                        packinfo->cryptset |= dot11_crypt_general_wpa1;
                    if (wpa->wpa_version() == 2)
                        packinfo->cryptset |= dot11_crypt_general_wpa2;
                    if (wpa->wpa_version() == 3)
                        packinfo->cryptset |= dot11_crypt_general_wpa3;

                    common->basic_crypt_set |= KIS_DEVICE_BASICCRYPT_ENCRYPTED;
                } else if (vendor->vendor_oui_int() == dot11_ie_221_cisco_client_mfp::cisco_oui() &&
                        vendor->vendor_oui_type() == dot11_ie_221_cisco_client_mfp::client_mfp_subtype()) {
                    // Look for cisco client MFP
					auto mfp = Globalreg::new_from_pool<dot11_ie_221_cisco_client_mfp>();
                    mfp->parse(vendor->vendor_tag());

                    packinfo->cisco_client_mfp = mfp->client_mfp();
                } else if (vendor->vendor_oui_int() == dot11_ie_221_owe_transition::vendor_oui()) {
                    // Look for wpa owe transitional tags
                    if (vendor->vendor_oui_type() == dot11_ie_221_owe_transition::owe_transition_subtype()) {
						auto owe_trans = Globalreg::new_from_pool<dot11_ie_221_owe_transition>();
                        owe_trans->parse(vendor->vendor_tag());
                        packinfo->owe_transition = owe_trans;
                        packinfo->cryptset |= crypt_wpa_owe;
                    }
                } else if (vendor->vendor_oui_int() == dot11_ie_221_wfa::wfa_oui()) {
                    // Look for WFA p2p to check the rtlwifi exploit
					auto wfa = Globalreg::new_from_pool<dot11_ie_221_wfa>();
                    wfa->parse(vendor->vendor_tag());

                    if (wfa->wfa_subtype() == dot11_ie_221_wfa::wfa_sub_p2p()) {
						auto ietags = Globalreg::new_from_pool<dot11_wfa_p2p_ie>();
                        ietags->parse(wfa->wfa_content());

                        for (const auto& wfa_ie_tag : *(ietags->tags())) {
                            if (ie_tag->tag_num() == 12) {
                                // Affected code in rtlwifi:
                                // noa_num = (noa_len - 2) / 13;
                                // if (noa_num > P2P_MAX_NOA_NUM)
                                // and P2P_MAX_NOA_NUM is 2, therefor:
                                if (wfa_ie_tag->tag_len() > 28) {
                                    alertracker->raise_alert(alert_rtlwifi_p2p_ref, in_pack,
                                            packinfo->bssid_mac, packinfo->source_mac,
                                            packinfo->dest_mac, packinfo->other_mac,
                                            packinfo->channel,
                                            "A Wi-Fi Direct P2P packet with an over-long Notification of Absence report "
                                            "seen.  This may indicate an attempt to exploit a bug "
                                            "in the Linux RTLWIFI drivers as detailed in CVE-2019-17666");
                                }
                            }
                        }
                    }
                } else if (vendor->vendor_oui_int() == dot11_ie_221_ms_wps::ms_wps_oui() &&
                        vendor->vendor_oui_type() == dot11_ie_221_ms_wps::ms_wps_subtype()) {
                    // Look for WPS MS
					auto wps = Globalreg::new_from_pool<dot11_ie_221_ms_wps>();
                    wps->parse(vendor->vendor_tag());

                    for (const auto& wpselem : *(wps->wps_elements())) {
                        auto version = wpselem->sub_element_version();
                        if (version != NULL) {
                            packinfo->wps_version = version->version();
                            continue;
                        }

                        auto state = wpselem->sub_element_state();
                        if (state != NULL) {
                            if (state->wps_state_configured()) {
                                packinfo->wps |= DOT11_WPS_CONFIGURED;
                            } else {
                                packinfo->wps |= DOT11_WPS_NOT_CONFIGURED;
                            }

                            continue;
                        }

                        auto ap_setup = wpselem->sub_element_ap_setup();
                        if (ap_setup != NULL) {
                            if (ap_setup->ap_setup_locked()) {
                                packinfo->wps |= DOT11_WPS_LOCKED;
                            }

                            continue;
                        }

                        auto config_methods = wpselem->sub_element_config_methods();
                        if (config_methods != NULL) {
                            packinfo->wps_config_methods = config_methods->wps_config_methods();
                            continue;
                        }

                        auto device_name = wpselem->sub_element_name();
                        if (device_name != NULL) {
                            packinfo->wps_device_name = munge_to_printable(device_name->str());

                            continue;
                        }

                        auto manuf = wpselem->sub_element_manuf();
                        if (manuf != NULL) {
                            packinfo->wps_manuf = munge_to_printable(manuf->str());
                            continue;
                        }

                        auto model = wpselem->sub_element_model();
                        if (model != NULL) {
                            packinfo->wps_model_name = munge_to_printable(model->str());
                            continue;
                        }

                        auto model_num = wpselem->sub_element_model_num();
                        if (model_num != NULL) {
                            packinfo->wps_model_number = munge_to_printable(model_num->str());
                            continue;
                        }

                        auto serial_num = wpselem->sub_element_serial();
                        if (serial_num != NULL) {
                            packinfo->wps_serial_number = munge_to_printable(serial_num->str());
                            continue;
                        }

#if 0
                        auto euuid = wpselem->sub_element_uuid_e();
                        if (euuid != nullptr) {
                            packinfo->wps_uuid_e = munge_to_printable(euuid->str());
                            continue;
                        }
#endif
                    }
                } else if (vendor->vendor_oui_int() == 0x00000b86 && vendor->vendor_oui_type() == 1) {
                    // Aruba/HP AP name field
					membuf d_membuf(vendor->vendor_tag().data(), vendor->vendor_tag().data() + vendor->vendor_tag().length());
					std::istream is(&d_membuf);
					kaitai::kstream p_io(&is);

                    p_io.read_bytes(1);
                    auto sub = p_io.read_u1();

                    if (sub == 3) {
                        p_io.read_bytes(1);
                        auto name = p_io.read_bytes_full();
                        packinfo->beacon_info = munge_to_printable(name);
                    }
                } else if (vendor->vendor_oui_int() == 0x005c5b35 && vendor->vendor_oui_type() == 1) {
                    // Mist Systems AP name
					membuf d_membuf(vendor->vendor_tag().data(), vendor->vendor_tag().data() + vendor->vendor_tag().length());
					std::istream is(&d_membuf);
					kaitai::kstream p_io(&is);

                    p_io.seek(0);
                    p_io.read_bytes(1);
                    auto name = p_io.read_bytes_full();
                    packinfo->beacon_info = munge_to_printable(name);
                } else if (vendor->vendor_oui_int() == 0x00001174 && vendor->vendor_oui_type() == 0) {
                    // Mojo / Arista AP name
					membuf d_membuf(vendor->vendor_tag().data(), vendor->vendor_tag().data() + vendor->vendor_tag().length());
					std::istream is(&d_membuf);
					kaitai::kstream p_io(&is);

                    p_io.seek(0);
                    p_io.read_bytes(1);
                    auto sub = p_io.read_u1();

					if (sub == 6) {
						p_io.read_bytes(1);
						auto name = p_io.read_bytes_full();
						packinfo->beacon_info = munge_to_printable(name);
					}
				} else if (vendor->vendor_oui_int() == 0x00001392 && vendor->vendor_oui_type() == 3) {
					// Ruckus AP name
					membuf d_membuf(vendor->vendor_tag().data(), vendor->vendor_tag().data() + vendor->vendor_tag().length());
					std::istream is(&d_membuf);
					kaitai::kstream p_io(&is);

                    p_io.seek(0);
                    p_io.read_bytes(1);
                    auto name = p_io.read_bytes_full();
                    packinfo->beacon_info = munge_to_printable(name);
                } else if (vendor->vendor_oui_int() == 0x00001977 && vendor->vendor_oui_type() == 33) {
                    // Extreme / Aerohive
					membuf d_membuf(vendor->vendor_tag().data(), vendor->vendor_tag().data() + vendor->vendor_tag().length());
					std::istream is(&d_membuf);
					kaitai::kstream p_io(&is);

                    p_io.seek(0);
                    p_io.read_bytes(1);

                    auto version = p_io.read_u1();
                    auto subtype = p_io.read_u1();

                    if (version == 1 && subtype == 0) {
                        auto len = p_io.read_u1();
                        auto name = p_io.read_bytes(len);
                        packinfo->beacon_info = munge_to_printable(name);
                    }
                } else if (vendor->vendor_oui_int() == 0x0000090f && vendor->vendor_oui_type() == 10) {
                    // Fortinet
					membuf d_membuf(vendor->vendor_tag().data(), vendor->vendor_tag().data() + vendor->vendor_tag().length());
					std::istream is(&d_membuf);
					kaitai::kstream p_io(&is);

                    p_io.seek(0);
                    p_io.read_bytes(1);

                    auto subtype = p_io.read_u1();
                    auto type = p_io.read_u1();

                    if (subtype == 10 && type == 1) {
                        auto len = p_io.read_u1();
                        auto name = p_io.read_bytes(len);
                        packinfo->beacon_info = munge_to_printable(name);
                    }
                }
            } catch (const std::exception &e) {
                // fprintf(stderr, "debug - 221 ie tag corrupt %s\n", e.what());
                packinfo->corrupt = 1;
                return -1;
            }

            continue;
        }

    }

    return 1;
}

std::shared_ptr<kis_datachunk> kis_80211_phy::DecryptWEP(const std::shared_ptr<dot11_packinfo>& in_packinfo,
        const std::shared_ptr<kis_datachunk>& in_chunk,
        unsigned char *in_key, int in_key_len,
        unsigned char *in_id) {

    std::shared_ptr<kis_datachunk> manglechunk;

    // printf("debug - decryptwep\n");
    if (in_packinfo->corrupt)
        return NULL;

    // printf("debug - decryptwep dlt %u want %u\n", in_chunk->dlt, KDLT_IEEE802_11);
    // If we don't have a dot11 frame, throw it away
    if (in_chunk->dlt != KDLT_IEEE802_11)
        return NULL;

    // printf("debug - decryptwep size len %u offt %u\n", in_chunk->length, in_packinfo->header_offset);
    // Bail on size check
    if (in_chunk->length() < in_packinfo->header_offset ||
        in_chunk->length() - in_packinfo->header_offset <= 8)
        return NULL;

    // printf("debug - decryptwep data header offt %u test head %02x %02x %02x %02x offt %02x %02x %02x %02x\n", in_packinfo->header_offset, in_chunk->data[0], in_chunk->data[1], in_chunk->data[2], in_chunk->data[3], in_chunk->data[in_packinfo->header_offset], in_chunk->data[in_packinfo->header_offset+1], in_chunk->data[in_packinfo->header_offset+2], in_chunk->data[in_packinfo->header_offset+3]);

    // printf("debug - password\n");
    // Password field
    char pwd[WEPKEY_MAX + 3];
    memset(pwd, 0, WEPKEY_MAX + 3);

    // Extract the IV and add it to the key
    pwd[0] = in_chunk->data()[in_packinfo->header_offset + 0] & 0xFF;
    pwd[1] = in_chunk->data()[in_packinfo->header_offset + 1] & 0xFF;
    pwd[2] = in_chunk->data()[in_packinfo->header_offset + 2] & 0xFF;

    // Add the supplied password to the key
    memcpy(pwd + 3, in_key, WEPKEY_MAX);
    int pwdlen = 3 + in_key_len;

    // printf("debug - wep stuff\n");

    // Prepare the keyblock for the rc4 cipher
    unsigned char keyblock[256];
    memcpy(keyblock, in_id, 256);
    int kba = 0, kbb = 0;
    for (kba = 0; kba < 256; kba++) {
        kbb = (kbb + keyblock[kba] + pwd[kba % pwdlen]) & 0xFF;
        unsigned char oldkey = keyblock[kba];
        keyblock[kba] = keyblock[kbb];
        keyblock[kbb] = oldkey;
    }


    // Allocate the mangled chunk -- 4 byte IV/Key# gone, 4 byte ICV gone
    char manglebuf[in_chunk->length() - 8];

    // Decrypt the data payload and check the CRC
    kba = kbb = 0;
    uint32_t crc = ~0;
    uint8_t c_crc[4];
    uint8_t icv[4];

    // Copy the ICV into the CRC buffer for checking
    memcpy(icv, &(in_chunk->data()[in_chunk->length() - 4]), 4);

    for (unsigned int dpos = in_packinfo->header_offset + 4;
         dpos < in_chunk->length() - 4; dpos++) {
        kba = (kba + 1) & 0xFF;
        kbb = (kbb + keyblock[kba]) & 0xFF;

        unsigned char oldkey = keyblock[kba];
        keyblock[kba] = keyblock[kbb];
        keyblock[kbb] = oldkey;

        // Decode the packet into the mangle chunk
        manglebuf[dpos - 4] =
            in_chunk->data()[dpos] ^ keyblock[(keyblock[kba] + keyblock[kbb]) & 0xFF];

        crc = dot11_wep_crc32_table[(crc ^ manglebuf[dpos - 4]) & 0xFF] ^ (crc >> 8);
    }

    // Check the CRC
    crc = ~crc;
    c_crc[0] = crc;
    c_crc[1] = crc >> 8;
    c_crc[2] = crc >> 16;
    c_crc[3] = crc >> 24;

    int crcfailure = 0;
    for (unsigned int crcpos = 0; crcpos < 4; crcpos++) {
        kba = (kba + 1) & 0xFF;
        kbb = (kbb + keyblock[kba]) & 0xFF;

        unsigned char oldkey = keyblock[kba];
        keyblock[kba] = keyblock[kbb];
        keyblock[kbb] = oldkey;

        if ((c_crc[crcpos] ^ keyblock[(keyblock[kba] +
                                       keyblock[kbb]) & 0xFF]) != icv[crcpos]) {
            crcfailure = 1;
            break;
        }
    }

    // If the CRC check failed, delete the moddata
    if (crcfailure) {
        return NULL;
    }

    // Remove the privacy flag in the mangled data
    auto fc = reinterpret_cast<frame_control *>(manglebuf);
    fc->wep = 0;

    manglechunk = std::make_shared<kis_datachunk>();
    manglechunk->dlt = KDLT_IEEE802_11;
    manglechunk->copy_raw_data(manglebuf, in_chunk->length() - 8);


    return manglechunk;
}

int kis_80211_phy::packet_wep_decryptor(const std::shared_ptr<kis_packet>& in_pack) {
    std::shared_ptr<kis_datachunk> manglechunk;

    if (in_pack->error)
        return 0;

    // Grab the 80211 info, compare, bail
    auto packinfo = in_pack->fetch<dot11_packinfo>(pack_comp_80211);

    if (packinfo == nullptr)
        return 0;

    if (packinfo->corrupt)
        return 0;

    if (packinfo->type != packet_data ||
        (packinfo->subtype != packet_sub_data &&
         packinfo->subtype != packet_sub_data_qos_data))
        return 0;

    // No need to look at data that's already been decoded
    if (packinfo->cryptset == 0 || packinfo->decrypted == 1)
        return 0;

    // Grab the 80211 frame, if that doesn't exist, grab the link frame
    auto chunk = in_pack->fetch<kis_datachunk>(pack_comp_decap, pack_comp_linkframe);

    if (chunk == nullptr)
        return 0;

    // If we don't have a dot11 frame, throw it away
    if (chunk->dlt != KDLT_IEEE802_11)
        return 0;

    // Bail if we can't find a key match
    auto bwmitr = wepkeys.find(packinfo->bssid_mac);
    if (bwmitr == wepkeys.end())
        return 0;

    manglechunk = DecryptWEP(packinfo, chunk, (bwmitr->second)->key, (bwmitr->second)->len, wep_identity);

    if (manglechunk == NULL) {
        (bwmitr->second)->failed++;
        return 0;
    }

    (bwmitr->second)->decrypted++;
    packinfo->decrypted = 1;

    in_pack->insert(pack_comp_mangleframe, manglechunk);

    in_pack->erase(pack_comp_datapayload);

    if (manglechunk->length() > packinfo->header_offset) {
        auto datachunk = packetchain->new_packet_component<kis_datachunk>();

        datachunk->set_data(manglechunk->substr(packinfo->header_offset, manglechunk->length() -
                                                packinfo->header_offset));

        in_pack->insert(pack_comp_datapayload, datachunk);
    }

    return 1;
}

int kis_80211_phy::packet_dot11_wps_m3(const std::shared_ptr<kis_packet>& in_pack) {
    if (in_pack->error) {
        return 0;
    }

    auto packinfo = in_pack->fetch<dot11_packinfo>(pack_comp_80211);
    if (packinfo == nullptr)
        return 0;

    if (packinfo->corrupt)
        return 0;

    if (packinfo->type != packet_data ||
        (packinfo->subtype != packet_sub_data &&
         packinfo->subtype != packet_sub_data_qos_data))
        return 0;

    // If it's encrypted it's not eapol
    if (packinfo->cryptset)
        return 0;

    // Grab the 80211 frame, if that doesn't exist, grab the link frame
    auto chunk = in_pack->fetch<kis_datachunk>(pack_comp_decap, pack_comp_linkframe);
    if (chunk == nullptr)
        return 0;

    // If we don't have a dot11 frame, throw it away
    if (chunk->dlt != KDLT_IEEE802_11)
        return 0;

    if (packinfo->header_offset >= chunk->length())
        return 0;

    unsigned int pos = packinfo->header_offset;

    uint8_t eapol_llc[] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e };

    if (pos + sizeof(eapol_llc) >= chunk->length())
        return 0;

    if (memcmp(&(chunk->data()[pos]), eapol_llc, sizeof(eapol_llc)))
        return 0;

    // printf("debug - potential eapol frame, matched llc\n");

    pos += sizeof(eapol_llc);

    // Make an in-memory zero-copy stream instance to the packet contents after
    // the SNAP/LLC header
    membuf eapol_membuf((char *) &(chunk->data()[pos]), (char *) &(chunk->data()[chunk->length()]));
    std::istream eapol_stream(&eapol_membuf);

    try {
        // Make a kaitai parser and parse with our wpaeap handler
        std::shared_ptr<kaitai::kstream> ks(new kaitai::kstream(&eapol_stream));
        dot11_wpa_eap eap;
        eap.parse(ks);

        // We only care about EAPOL packets for WPS decoding
        if (eap.dot1x_type() != dot11_wpa_eap::dot1x_type_eap_packet) {
            return 0;
        }

        // Assign the eapol packet parser
        auto eapol_packet = eap.dot1x_content_eap_packet();

        // We only catch M3 in this test so we only care about requests
        if (eapol_packet->eapol_type() != dot11_wpa_eap::dot1x_eap_packet::eapol_type_request) {
            return 0;
        }

        // Make sure we're a WPS expanded type
        if (eapol_packet->eapol_expanded_type() !=
                dot11_wpa_eap::dot1x_eap_packet::eapol_expanded_wfa_wps) {
            return 0;
        }

        // Assign the expanded WFA WPS subframe
        auto wfa_wps = eapol_packet->eapol_content_wpa_wps();

        // Go through the fields until we find the MESSAGE_TYPE field
        for (auto i : *(wfa_wps->fields())) {
            auto msg = i->content_message_type();

            if (msg != NULL && msg->messagetype() ==
                    dot11_wpa_eap::dot1x_eap_packet::eapol_extended_wpa_wps::eapol_wpa_field::eapol_field_message_type::eapol_messagetype_m3)
                return 1;
        }

        // We got here but didn't get anything out of the packet, return false for m3
        return 0;

    } catch (const std::exception& e) {
        return 0;
    }


    return 0;
}

std::shared_ptr<dot11_tracked_eapol>
kis_80211_phy::packet_dot11_eapol_handshake(const std::shared_ptr<kis_packet>& in_pack,
    const std::shared_ptr<dot11_tracked_device>& dot11dev) {

    if (in_pack->error) {
        return NULL;
    }

    auto packinfo = in_pack->fetch<dot11_packinfo>(pack_comp_80211);
    if (packinfo == nullptr)
        return NULL;

    if (packinfo->corrupt) {
        return NULL;
    }

    if (packinfo->type != packet_data ||
            (packinfo->subtype != packet_sub_data &&
             packinfo->subtype != packet_sub_data_qos_data)) {
        return NULL;
    }

    // If it's encrypted it's not eapol
    if (packinfo->cryptset) {
        return NULL;
    }

    auto chunk = in_pack->fetch<kis_datachunk>(pack_comp_decap, pack_comp_linkframe);
    if (chunk == nullptr)
        return NULL;

    if (chunk->dlt != KDLT_IEEE802_11) {
        return NULL;
    }

    if (packinfo->header_offset >= chunk->length()) {
        return NULL;
    }

    unsigned int pos = packinfo->header_offset;

    uint8_t eapol_llc[] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e };

    if (pos + sizeof(eapol_llc) >= chunk->length()) {
        return NULL;
    }

    if (memcmp(&(chunk->data()[pos]), eapol_llc, sizeof(eapol_llc))) {
        return NULL;
    }

    pos += sizeof(eapol_llc);

    // Make an in-memory zero-copy stream instance to the packet contents after
    // the SNAP/LLC header
    membuf eapol_membuf((char *) &(chunk->data()[pos]),
                        (char *) &(chunk->data()[chunk->length()]));
    std::istream eapol_stream(&eapol_membuf);

    try {
        // Make a kaitai parser and parse with our wpaeap handler
        std::shared_ptr<kaitai::kstream> ks(new kaitai::kstream(&eapol_stream));
        dot11_wpa_eap eap;
        eap.parse(ks);

        // We only care about RSN keys
        if (eap.dot1x_type() != dot11_wpa_eap::dot1x_type_eap_key) {
            return nullptr;
        }

        // Look for rtl8195 overflows
        if (eap.dot1x_len() > 512) {
            alertracker->raise_alert(alert_rtl8195_vdoo_ref, in_pack,
                    packinfo->bssid_mac, packinfo->source_mac,
                    packinfo->dest_mac, packinfo->other_mac,
                    packinfo->channel,
                    fmt::format("RSN key frame has a length of {}; lengths greater than "
                        "512 may be used to exploit RTL8195 driver implementations",
                        eap.dot1x_len()));
        }

        auto dot1xkey = eap.dot1x_content_key();

        dot1xkey->parse(eap.dot1x_data());

        auto rsnkey = dot1xkey->key_content_eapolrsn();

        if (rsnkey == nullptr) {
            return nullptr;
        }

        rsnkey->parse(dot1xkey->key_content_data());

        // Set a packet tag for handshakes
        in_pack->tag_map["DOT11_WPAHANDSHAKE"] = true;

        if (!keep_eapol_packets) {
            return nullptr;
        }

        std::shared_ptr<dot11_tracked_eapol> eapol = dot11dev->create_eapol_packet();

        eapol->set_eapol_time(ts_to_double(in_pack->ts));
        eapol->set_eapol_dir(packinfo->distrib);

        std::shared_ptr<kis_tracked_packet> tp = eapol->get_eapol_packet();

        tp->set_ts_sec(in_pack->ts.tv_sec);
        tp->set_ts_usec(in_pack->ts.tv_usec);

        tp->set_dlt(chunk->dlt);
        tp->set_source(chunk->source_id);

        tp->get_data()->set(chunk->data(), chunk->length());

        if (rsnkey->key_info_key_ack() && !rsnkey->key_info_key_mic() &&
                !rsnkey->key_info_install()) {
            eapol->set_eapol_msg_num(1);
        } else if (rsnkey->key_info_key_mic() && !rsnkey->key_info_key_ack() &&
                !rsnkey->key_info_install()) {
            if (rsnkey->wpa_key_data_len()) {
                eapol->set_eapol_msg_num(2);
            } else {
                // Look for attempts to set an empty nonce; only on group keys
                if (!rsnkey->key_info_pairwise_key() &&
                        rsnkey->wpa_key_nonce().find_first_not_of(std::string("\x00", 1)) == std::string::npos) {
                    alertracker->raise_alert(alert_nonce_zero_ref, in_pack,
                            packinfo->bssid_mac, packinfo->source_mac,
                            packinfo->dest_mac, packinfo->other_mac,
                            packinfo->channel,
                            "WPA EAPOL RSN frame seen with an empty key and zero nonce; "
                            "this may indicate a WPA degradation attack such as the "
                            "vanhoefm attack against OpenBSD Wi-Fi supplicants.");
                }

                eapol->set_eapol_msg_num(4);
            }
        } else if (rsnkey->key_info_key_mic() && rsnkey->key_info_key_ack() &&
                rsnkey->key_info_key_ack()) {
            eapol->set_eapol_msg_num(3);
        }

        eapol->set_eapol_install(rsnkey->key_info_install());
        eapol->set_eapol_nonce_bytes(rsnkey->wpa_key_nonce());
        eapol->set_eapol_replay_counter(rsnkey->replay_counter());

        // Parse key data as an IE tag stream; do this in our own try/catch because we don't
        // want to discard the entire packet if something went wrong in the pmkid parsing.
        try {
            if (rsnkey->wpa_key_data_len() != 0) {

                // Look for CVE-2020-27301, a third handshake packet key > 0x101
                if (rsnkey->key_info_install() &&
                        rsnkey->key_info_key_ack() &&
                        packinfo->distrib == distrib_from) {

                    if ((rsnkey->key_info_descriptor_version() ==
                                dot11_wpa_eap::dot1x_key::eapol_key_rsn::eapol_key_descriptor_version::eapol_key_aes_sha1 ||
                                rsnkey->key_info_descriptor_version() ==
                                dot11_wpa_eap::dot1x_key::eapol_key_rsn::eapol_key_descriptor_version::eapol_key_aes_sha1) &&
                            rsnkey->wpa_key_data_len() > 0x80) {
                        auto altxt = fmt::format("Suspiciously long WPA AES key in handshake "
                                "({} bytes) which may be an attempt to exploit the CVE-2020-27302 RTL "
                                "vulnerability (however chances of seeing this in the wild are "
                                "likely very slim)", rsnkey->wpa_key_data_len());

                        alertracker->raise_alert(alert_vdoo_2020_27302_ref, in_pack,
                                packinfo->bssid_mac, packinfo->source_mac,
                                packinfo->dest_mac, packinfo->other_mac,
                                packinfo->channel, altxt);

                    } else if (rsnkey->wpa_key_data_len() > 0x101) {
                        auto altxt = fmt::format("Suspiciously long WPA key in handshake ({} bytes) "
                                "which may be an attempt to exploit the CVE-2020-27301 RTL "
                                "vulnerability (however chances of seeing this in the wild are "
                                "likely very slim)", rsnkey->wpa_key_data_len());

                        alertracker->raise_alert(alert_vdoo_2020_27301_ref, in_pack,
                                packinfo->bssid_mac, packinfo->source_mac,
                                packinfo->dest_mac, packinfo->other_mac,
                                packinfo->channel, altxt);
                    }
                }

				auto ietags = Globalreg::new_from_pool<dot11_ie>();
                ietags->parse(rsnkey->wpa_key_data());

                for (auto ie_tag : *(ietags->tags())) {
                    if (ie_tag->tag_num() == 221) {
						auto vendor = Globalreg::new_from_pool<dot11_ie_221_vendor>();
                        vendor->parse(ie_tag->tag_data());

                        if (vendor->vendor_oui_int() == dot11_ie_221_rsn_pmkid::vendor_oui() &&
                                vendor->vendor_oui_type() == dot11_ie_221_rsn_pmkid::rsnpmkid_subtype()) {
                            dot11_ie_221_rsn_pmkid pmkid;
                            pmkid.parse(vendor->vendor_tag());

                            // Log the pmkid for the decoders
                            eapol->set_rsnpmkid_bytes(pmkid.pmkid());

                            // Tag the packet
                            in_pack->tag_map["DOT11_RSNPMKID"] = true;
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            // Do nothing
        }

        return eapol;
    } catch (const std::exception& e) {
        // fprintf(stderr, "debug - eap exception %s\n", e.what());
        return NULL;
    }

    return NULL;
}


#if 0
void KisBuiltinDissector::add_wep_key(mac_addr bssid, uint8_t *key, unsigned int len,
                                    int temp) {
    if (len > WEPKEY_MAX)
        return;

    wep_key_info *winfo = new wep_key_info;

    winfo->decrypted = 0;
    winfo->failed = 0;
    winfo->bssid = bssid;
    winfo->fragile = temp;
    winfo->len = len;

    memcpy(winfo->key, key, len);

    // Replace exiting ones
    if (wepkeys.find(winfo->bssid) != wepkeys.end()) {
        delete wepkeys[winfo->bssid];
        wepkeys[winfo->bssid] = winfo;
        return;
    }

    wepkeys.insert(winfo->bssid, winfo);
}

int KisBuiltinDissector::cmd_listwepkeys(CLIENT_PARMS) {
    if (client_wepkey_allowed == 0) {
        snprintf(errstr, 1024, "Server does not allow clients to fetch keys");
        return -1;
    }

    if (wepkeys.size() == 0) {
        snprintf(errstr, 1024, "Server has no WEP keys");
        return -1;
    }

    if (_NPM(PROTO_REF_WEPKEY) < 0) {
        snprintf(errstr, 1024, "Unable to find WEPKEY protocol");
        return -1;
    }

    for (macmap<wep_key_info *>::iterator wkitr = wepkeys.begin();
         wkitr != wepkeys.end(); wkitr++) {
        globalreg->kisnetserver->SendToClient(in_clid, _NPM(PROTO_REF_WEPKEY),
                                              (void *) wkitr->second, NULL);
    }

    return 1;
}

int KisBuiltinDissector::cmd_addwepkey(CLIENT_PARMS) {
    if (parsedcmdline->size() != 1) {
        snprintf(errstr, 1024, "Illegal addwepkey request");
        return -1;
    }

    vector<string> keyvec = str_tokenize((*parsedcmdline)[1].word, ",");
    if (keyvec.size() != 2) {
        snprintf(errstr, 1024, "Illegal addwepkey request");
        return -1;
    }

    mac_addr bssid = keyvec[0].c_str();
    if (bssid.state.error) {
        snprintf(errstr, 1024, "Illegal BSSID for addwepkey");
        return -1;
    }

    unsigned char key[WEPKEY_MAX];
    int len = hex_to_uchar((unsigned char *) keyvec[1].c_str(), key);

    add_wep_key(bssid, key, len, 1);

    snprintf(errstr, 1024, "Added key %s length %d for BSSID %s",
             (*parsedcmdline)[0].word.c_str(), len,
             bssid.mac_to_string().c_str());

    _MSG(errstr, MSGFLAG_INFO);

    return 1;
}

int KisBuiltinDissector::cmd_delwepkey(CLIENT_PARMS) {
    if (client_wepkey_allowed == 0) {
        snprintf(errstr, 1024, "Server does not allow clients to modify keys");
        return -1;
    }

    if (parsedcmdline->size() != 1) {
        snprintf(errstr, 1024, "Illegal delwepkey command");
        return -1;
    }

    mac_addr bssid_mac = (*parsedcmdline)[0].word.c_str();

    if (bssid_mac.state.error) {
        snprintf(errstr, 1024, "Illegal delwepkey bssid");
        return -1;
    }

    if (wepkeys.find(bssid_mac) == wepkeys.end()) {
        snprintf(errstr, 1024, "Unknown delwepkey bssid");
        return -1;
    }

    delete wepkeys[bssid_mac];
    wepkeys.erase(bssid_mac);

    snprintf(errstr, 1024, "Deleted key for BSSID %s",
             bssid_mac.mac_to_string().c_str());
    _MSG(errstr, MSGFLAG_INFO);

    return 1;
}

int KisBuiltinDissector::cmd_strings(CLIENT_PARMS) {
    // FIXME: write this
    if (parsedcmdline->size() < 1) {
        snprintf(errstr, 1024, "Illegal string request");
        _MSG(errstr, MSGFLAG_ERROR);
        return -1;
    }

    int req;
    if (sscanf(((*parsedcmdline)[0]).word.c_str(), "%d", &req) != 1) {
        snprintf(errstr, 1024, "Illegal string request");
        _MSG(errstr, MSGFLAG_ERROR);
        return -1;
    }

    if (dissect_strings == 2) {
        if (req == 0)
            _MSG("String dissection cannot be disabled because it is required "
                 "by another component", MSGFLAG_INFO);
        return 1;
    }

    if (parsedcmdline->size() > 1) {
        mac_addr ma = mac_addr((*parsedcmdline)[0].word.c_str());

        if (ma.state.error) {
            snprintf(errstr, 1024, "String dissection, got invalid MAC address");
            _MSG(errstr, MSGFLAG_ERROR);
            return -1;
        }

        if (req) {
            string_nets.insert(ma, 1);
            _MSG("String dissection turned on for " + ma.mac_to_string(), MSGFLAG_INFO);
        } else {
            string_nets.erase(ma);
            _MSG("String dissection turned off for " + ma.mac_to_string(), MSGFLAG_INFO);
        }

    } else {
        if (req) {
            _MSG("String dissection from data frames enabled", MSGFLAG_INFO);
            dissect_all_strings = 1;
        } else {
            _MSG("String dissection from data frames disabled", MSGFLAG_INFO);
            dissect_all_strings = 0;
        }
    }

    dissect_strings = req;

    return 1;
}

int KisBuiltinDissector::cmd_stringsfilter(CLIENT_PARMS) {
    if (parsedcmdline->size() != 1) {
        snprintf(errstr, 1024, "Illegal addstringsfilter request");
        _MSG(errstr, MSGFLAG_ERROR);
        return -1;
    }

    if (string_filter->AddFilterLine((*parsedcmdline)[0].word) < 0) {
        snprintf(errstr, 1024, "Failed to insert strings filter");
        _MSG(errstr, MSGFLAG_ERROR);
        return -1;
    }

    _MSG("Added string filter '" + (*parsedcmdline)[0].word + "'",
         MSGFLAG_INFO);

    return 1;
}
#endif

