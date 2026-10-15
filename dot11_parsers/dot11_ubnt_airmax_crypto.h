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

#ifndef __DOT11_UBNT_AIRMAX_CRYPTO_H__
#define __DOT11_UBNT_AIRMAX_CRYPTO_H__

/* Ubiquiti AirMAX vendor IE payloads are AES-128-ECB, keyed with
 * HMAC-SHA1(dst_mac, src_mac)[:16].  The key is derived from public MACs,
 * so this is obfuscation, not security.
 *
 * Based on wiremax (https://github.com/infobyte/wiremax) and pyrmax,
 * MIT licensed, Copyright (c) 2026 Faraday Security
 */

#include <string>

#include "macaddr.h"

namespace ubnt_airmax {
    // Largest ciphertext which fits in an IE
    constexpr size_t max_ciphertext_len = 255;

    // Decrypts the whole AES blocks of the ciphertext; false if there are none or
    // decryption fails
    bool decrypt(const std::string& ciphertext, const mac_addr& src, const mac_addr& dst,
            std::string& plaintext);
}

#endif /* __DOT11_UBNT_AIRMAX_CRYPTO_H__ */
