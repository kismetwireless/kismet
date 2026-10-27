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
#include <vector>

#include <stdint.h>
#include <stddef.h>

#include "aes_ctr.h"

namespace zigbee_crypto {

// Keys anyone can know.  Each is tried as a network key (NWK security) and as a link key (APS
// security: the key itself, and the key-transport and key-load keys hashed from it); a frame only
// counts as secured with one when its MIC verifies, so a key that no product uses costs time but
// never makes a false finding.
struct known_key {
    const char *name;
    uint8_t key[16];
};

inline constexpr known_key known_keys[] = {
    // the Trust Center link key of Zigbee Home Automation 1.2, and of Zigbee 3.0 joining without
    // an install code
    {"ZigBeeAlliance09", {'Z', 'i', 'g', 'B', 'e', 'e', 'A', 'l', 'l', 'i', 'a', 'n', 'c', 'e', '0', '9'}},
    // the Trust Center link key of Zigbee Light Link devices joining a centralized network
    {"ZLL link key", {0x81, 0x42, 0x86, 0x86, 0x5D, 0xC1, 0xC8, 0xB2, 0xC8, 0xCB, 0xC5, 0x2E, 0x5D, 0x65, 0xD1, 0xB8}},
    // the Zigbee 3.0 distributed security global link key (networks without a Trust Center)
    {"Zigbee 3.0 distributed link key", {0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF}},
    // the default network key of TI Z-Stack (DEFAULT_KEY), which Zigbee2MQTT also used by default
    // before it generated a key per network
    {"TI Z-Stack default key", {0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0D}},
    // keys published as product or example defaults
    {"Nordic example key", {0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"Legrand key", {'L', 'E', 'G', 'R', 'A', 'N', 'D', ' ', 'B', 'A', 'N', 'D', ' ', 'K', 'E', 'Y'}},
    // a key never set
    {"all-zero key", {0}},
};

inline constexpr size_t n_known_keys = sizeof(known_keys) / sizeof(known_keys[0]);

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

// A key's ciphers, its AES schedule expanded once: as the network key, and as a link key by APS
// key identifier (0 the link key itself, the data key; 2 its key-transport key, 3 its key-load
// key; 1, the network key, is tried with the link key as well)
struct key_ciphers {
    explicit key_ciphers(const uint8_t key[16]) :
        nwk{key}, aps{aes_block{key}, aes_block{key}, aes_block{derived(key, 0x00)},
            aes_block{derived(key, 0x02)}} { }

    aes_block nwk;
    aes_block aps[4];

private:
    struct derived_key {
        uint8_t k[16];
        operator const uint8_t *() const { return k; }
    };

    static derived_key derived(const uint8_t key[16], uint8_t octet) {
        derived_key d;
        hmac_mmo_octet(key, octet, d.k);
        return d;
    }
};

// The ciphers of the known keys, in known_keys order, built once; the AES state is only read
// after that, so they are shared by every packet thread
inline std::vector<key_ciphers>& known_ciphers() {
    static std::vector<key_ciphers> table = [] {
        std::vector<key_ciphers> t;
        t.reserve(n_known_keys);
        for (size_t k = 0; k < n_known_keys; k++)
            t.emplace_back(known_keys[k].key);
        return t;
    }();

    return table;
}

// Longest CCM* payload checked; an 802.15.4 frame is at most 127 octets
constexpr size_t max_ccm_len = 256;

// CCM* decryption with a 4-octet MIC (security level 5) and L = 2: c, the ciphertext followed by
// the encrypted MIC, under the 13-octet nonce, with a authenticated.  True, with the plaintext in
// plain (lc - 4 octets, plain holding max_ccm_len), only when the MIC verifies.
inline bool ccm_star_decrypt(aes_block& aes, const uint8_t nonce[13], const uint8_t *a, size_t la,
        const uint8_t *c, size_t lc, uint8_t *plain, size_t& plain_len) {
    constexpr size_t mic_len = 4;

    if (lc < mic_len || lc > max_ccm_len || la > 0xfeff)
        return false;

    const size_t lm = lc - mic_len;

    auto counter_block = [&](uint8_t blk[16], unsigned int i) {
        blk[0] = 0x01;
        memcpy(blk + 1, nonce, 13);
        blk[14] = (uint8_t) (i >> 8);
        blk[15] = (uint8_t) i;
        aes.encrypt(blk);
    };

    for (size_t i = 0; i < lm; i += 16) {
        uint8_t s[16];
        counter_block(s, (unsigned int) (i / 16 + 1));
        for (size_t j = 0; j < 16 && i + j < lm; j++)
            plain[i + j] = c[i + j] ^ s[j];
    }

    // The MIC: CBC-MAC over B0, the length-prefixed authenticated data and the plaintext, each
    // padded to whole blocks
    uint8_t x[16];
    x[0] = (la ? 0x40 : 0x00) | ((mic_len - 2) / 2) << 3 | 0x01;
    memcpy(x + 1, nonce, 13);
    x[14] = (uint8_t) (lm >> 8);
    x[15] = (uint8_t) lm;
    aes.encrypt(x);

    size_t pos = 0;

    auto absorb = [&](const uint8_t *d, size_t n) {
        for (size_t i = 0; i < n; i++) {
            x[pos++] ^= d[i];
            if (pos == 16) {
                aes.encrypt(x);
                pos = 0;
            }
        }
    };

    auto pad = [&]() {
        if (pos != 0) {
            aes.encrypt(x);
            pos = 0;
        }
    };

    if (la) {
        const uint8_t la_be[2] = {(uint8_t) (la >> 8), (uint8_t) la};
        absorb(la_be, 2);
        absorb(a, la);
        pad();
    }

    absorb(plain, lm);
    pad();

    uint8_t s0[16];
    counter_block(s0, 0);

    for (size_t j = 0; j < mic_len; j++) {
        if ((uint8_t) (x[j] ^ s0[j]) != c[lm + j])
            return false;
    }

    plain_len = lm;
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
