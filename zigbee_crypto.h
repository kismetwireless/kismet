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

#ifndef __ZIGBEE_CRYPTO_H__
#define __ZIGBEE_CRYPTO_H__

// Zigbee security (Zigbee specification 4.5, annex A and B): CCM* with a 4-octet MIC, the MMO
// hash and the keyed hash that derives the key-transport and key-load keys from a link key.  Only
// what recognizing a frame secured with a known key needs: decryption and MIC verification.

#include <cstring>
#include <string>
#include <vector>

#include <stdint.h>
#include <stddef.h>

#include "aes_ctr.h"

namespace zigbee_crypto {

// The well-known Trust Center link key of Zigbee Home Automation 1.2 and Zigbee 3.0 joining
inline constexpr uint8_t za09_link_key[16] = {
    'Z', 'i', 'g', 'B', 'e', 'e', 'A', 'l', 'l', 'i', 'a', 'n', 'c', 'e', '0', '9'
};

// The default network key of TI Z-Stack (DEFAULT_KEY), which Zigbee2MQTT also used by default
// before it generated a key per network
inline constexpr uint8_t zstack_network_key[16] = {
    0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0D
};

// AES-128 encryption of one block in place
class aes_block : public kis_aes::aes128 {
public:
    explicit aes_block(const uint8_t key[16]) {
        const uint8_t iv[16] = {0};
        set(key, iv);
    }

    void encrypt(uint8_t b[16]) {
        cipher(reinterpret_cast<kis_aes::state_t *>(b));
    }
};

// The Matyas-Meyer-Oseas hash (B.6) of a message shorter than 2^16 bits
inline void mmo_hash(const uint8_t *m, size_t n, uint8_t out[16]) {
    std::vector<uint8_t> buf(m, m + n);
    const size_t bits = n * 8;

    buf.push_back(0x80);
    while (buf.size() % 16 != 14)
        buf.push_back(0x00);
    buf.push_back((uint8_t) (bits >> 8));
    buf.push_back((uint8_t) bits);

    uint8_t h[16] = {0};

    for (size_t i = 0; i < buf.size(); i += 16) {
        uint8_t c[16];
        memcpy(c, &buf[i], 16);
        aes_block(h).encrypt(c);
        for (unsigned int j = 0; j < 16; j++)
            h[j] = c[j] ^ buf[i + j];
    }

    memcpy(out, h, 16);
}

// The keyed hash (B.1.4) of one octet: 0x00 gives the key-transport key of a link key, 0x02 its
// key-load key (4.5.3)
inline void hmac_mmo_octet(const uint8_t key[16], uint8_t octet, uint8_t out[16]) {
    uint8_t inner_in[17], outer_in[32], inner[16];

    for (unsigned int i = 0; i < 16; i++) {
        inner_in[i] = key[i] ^ 0x36;
        outer_in[i] = key[i] ^ 0x5c;
    }

    inner_in[16] = octet;
    mmo_hash(inner_in, sizeof(inner_in), inner);
    memcpy(outer_in + 16, inner, 16);
    mmo_hash(outer_in, sizeof(outer_in), out);
}

// CCM* decryption with a 4-octet MIC (security level 5) and L = 2: c, the ciphertext followed by
// the encrypted MIC, under the 13-octet nonce, with a authenticated.  True, with the plaintext,
// only when the MIC verifies.
inline bool ccm_star_decrypt(const uint8_t key[16], const uint8_t nonce[13],
        const uint8_t *a, size_t la, const uint8_t *c, size_t lc, std::string& plain) {
    constexpr size_t mic_len = 4;

    if (lc < mic_len || la > 0xfeff)
        return false;

    const size_t lm = lc - mic_len;
    aes_block aes(key);

    auto counter_block = [&](uint8_t blk[16], unsigned int i) {
        blk[0] = 0x01;
        memcpy(blk + 1, nonce, 13);
        blk[14] = (uint8_t) (i >> 8);
        blk[15] = (uint8_t) i;
        aes.encrypt(blk);
    };

    plain.assign(lm, '\0');

    for (size_t i = 0; i < lm; i += 16) {
        uint8_t s[16];
        counter_block(s, (unsigned int) (i / 16 + 1));
        for (size_t j = 0; j < 16 && i + j < lm; j++)
            plain[i + j] = (char) (c[i + j] ^ s[j]);
    }

    // The MIC: CBC-MAC over B0, the length-prefixed authenticated data and the plaintext, each
    // padded to whole blocks
    uint8_t x[16];
    x[0] = (la ? 0x40 : 0x00) | ((mic_len - 2) / 2) << 3 | 0x01;
    memcpy(x + 1, nonce, 13);
    x[14] = (uint8_t) (lm >> 8);
    x[15] = (uint8_t) lm;
    aes.encrypt(x);

    std::vector<uint8_t> auth;
    if (la) {
        auth.push_back((uint8_t) (la >> 8));
        auth.push_back((uint8_t) la);
        auth.insert(auth.end(), a, a + la);
        auth.resize((auth.size() + 15) / 16 * 16, 0x00);
    }

    auth.insert(auth.end(), plain.begin(), plain.end());
    auth.resize((auth.size() + 15) / 16 * 16, 0x00);

    for (size_t i = 0; i < auth.size(); i += 16) {
        for (unsigned int j = 0; j < 16; j++)
            x[j] ^= auth[i + j];
        aes.encrypt(x);
    }

    uint8_t s0[16];
    counter_block(s0, 0);

    for (size_t j = 0; j < mic_len; j++) {
        if ((uint8_t) (x[j] ^ s0[j]) != c[lm + j]) {
            plain.clear();
            return false;
        }
    }

    return true;
}

// The CCM* nonce of a Zigbee auxiliary security header: the source's extended address and the
// frame counter, both in the order they are sent, then the security control field with the security
// level that is not sent (5) filled in
inline void make_nonce(const uint8_t src_as_sent[8], const uint8_t counter_as_sent[4],
        uint8_t security_control, uint8_t nonce[13]) {
    memcpy(nonce, src_as_sent, 8);
    memcpy(nonce + 8, counter_as_sent, 4);
    nonce[12] = security_control;
}

}

#endif
