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

#ifndef __AES_CTR_H__
#define __AES_CTR_H__

#include <cstring>
#include <stdexcept>
#include <string>

#include <stdint.h>
#include <stddef.h>

// Simple implementation of aes_ctr128 and aes_ctr256

namespace kis_aes {

using state_t = uint8_t[4][4];

inline constexpr size_t aes256_blocklen = 16;
inline constexpr size_t aes256_keylen = 32;
inline constexpr size_t aes256_key_exp_size = 240;

inline constexpr size_t nk256 = 8;
inline constexpr size_t nr256 = 14;
inline constexpr size_t nb256 = 4;


inline constexpr size_t aes128_blocklen = 16;
inline constexpr size_t aes128_keylen = 16;
inline constexpr size_t aes128_key_exp_size = 176;

inline constexpr size_t nk128 = 4;
inline constexpr size_t nr128 = 10;
inline constexpr size_t nb128 = 4;

inline constexpr uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

inline constexpr uint8_t rcon[] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Zero key material in a way the compiler won't optimize out
inline void secure_zero(void *buf, size_t len) {
    volatile uint8_t *p = static_cast<volatile uint8_t *>(buf);
    while (len--)
        *p++ = 0;
}


class aes256 {
public:
    aes256() {
        memset(iv_, 0, aes256_blocklen);
        memset(round_key_, 0, aes256_key_exp_size);
    }

    aes256(const std::string& key, const std::string& iv) {
        if (key.length() != aes256_keylen)
            throw std::runtime_error("aes invalid key length");
        if (iv.length() != aes256_blocklen)
            throw std::runtime_error("aes invalid iv length");

        memcpy(iv_, iv.data(), aes256_blocklen);
        expand_key(key);
    }

    aes256(const uint8_t key[aes256_keylen], const uint8_t iv[aes256_blocklen]) {
        memcpy(iv_, iv, aes256_blocklen);
        expand_key(std::string((const char *) key, aes256_keylen));
    }

    ~aes256() {
        secure_zero(round_key_, sizeof(round_key_));
        secure_zero(iv_, sizeof(iv_));
    }

    void set(const uint8_t key[aes256_keylen], const uint8_t iv[aes256_blocklen]) {
        memcpy(iv_, iv, aes256_blocklen);
        expand_key(std::string((const char *) key, aes256_keylen));
    }

    // encrypt/decrypt a buffer
    std::string ctr_crypt(const std::string& buffer) {
        std::string ret(buffer.length(), 0x00);
        uint8_t state[16];
        size_t i;
        int bi;

        for (i = 0, bi = aes256_blocklen; i < buffer.length(); ++i, ++bi) {
            if (bi == aes256_blocklen) {
                memcpy(state, iv_, aes256_blocklen);
                cipher(reinterpret_cast<state_t *>(state));

                for (bi = (aes256_blocklen - 1); bi >= 0; --bi) {
                    if (iv_[bi] == 255) {
                        iv_[bi] = 0;
                        continue;
                    }
                    iv_[bi] += 1;
                    break;
                }

                bi = 0;
            }

            ret[i] = (buffer[i] ^ state[bi]);
        }

        return ret;
    }

    void ctr_crypt(const std::string& buffer, std::string& wbuffer) {
        wbuffer = ctr_crypt(buffer);
    }

protected:
    void expand_key(const std::string& key) {
        unsigned int i, j, k;
        uint8_t tempa[4];

        for (i = 0; i < nk256; ++i) {
            round_key_[(i * 4) + 0] = key.data()[(i * 4) + 0];
            round_key_[(i * 4) + 1] = key.data()[(i * 4) + 1];
            round_key_[(i * 4) + 2] = key.data()[(i * 4) + 2];
            round_key_[(i * 4) + 3] = key.data()[(i * 4) + 3];
        }

        for (i = nk256; i < nb256 * (nr256 + 1); ++i) {
            k = (i - 1) * 4;
            tempa[0] = round_key_[k + 0];
            tempa[1] = round_key_[k + 1];
            tempa[2] = round_key_[k + 2];
            tempa[3] = round_key_[k + 3];

            if (i % nk256 == 0) {
                const uint8_t ta0 = tempa[0];

                tempa[0] = sbox[tempa[1]];
                tempa[1] = sbox[tempa[2]];
                tempa[2] = sbox[tempa[3]];
                tempa[3] = sbox[ta0];

                tempa[0] = tempa[0] ^ rcon[i/nk256];
            }

            if (i % nk256 == 4) {
                tempa[0] = sbox[tempa[0]];
                tempa[1] = sbox[tempa[1]];
                tempa[2] = sbox[tempa[2]];
                tempa[3] = sbox[tempa[3]];
            }

            j = i * 4;
            k = (i - nk256) * 4;

            round_key_[j + 0] = round_key_[k + 0] ^ tempa[0];
            round_key_[j + 1] = round_key_[k + 1] ^ tempa[1];
            round_key_[j + 2] = round_key_[k + 2] ^ tempa[2];
            round_key_[j + 3] = round_key_[k + 3] ^ tempa[3];
        }
    }

    inline void add_round_key(uint8_t round, state_t *state) {
        uint8_t i, j;

        for (i = 0; i < 4; ++i) {
            for (j = 0; j < 4; ++j) {
                (*state)[i][j] ^= round_key_[(round * nb256 * 4) + (i * nb256) + j];
            }
        }
    }

    inline void subbytes(state_t *state) {
        uint8_t i, j;
        for (i = 0; i < 4; ++i) {
            for (j = 0; j < 4; ++j) {
                (*state)[j][i] = sbox[(*state)[j][i]];
            }
        }
    }

    inline void shiftrows(state_t *state) {
        uint8_t temp;

        temp = (*state)[0][1];
        (*state)[0][1] = (*state)[1][1];
        (*state)[1][1] = (*state)[2][1];
        (*state)[2][1] = (*state)[3][1];
        (*state)[3][1] = temp;

        temp = (*state)[0][2];
        (*state)[0][2] = (*state)[2][2];
        (*state)[2][2] = temp;

        temp = (*state)[1][2];
        (*state)[1][2] = (*state)[3][2];
        (*state)[3][2] = temp;

        temp = (*state)[0][3];
        (*state)[0][3] = (*state)[3][3];
        (*state)[3][3] = (*state)[2][3];
        (*state)[2][3] = (*state)[1][3];
        (*state)[1][3] = temp;
    }

    static constexpr uint8_t xtime(uint8_t x) {
        return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
    }

    inline void mixcolumns(state_t *state) {
        uint8_t i;
        uint8_t tmp, tm, t;

        for (i = 0; i < 4; ++i) {
            t = (*state)[i][0];
            tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];

            tm = (*state)[i][0] ^ (*state)[i][1];
            tm = xtime(tm);
            (*state)[i][0] ^= tm ^ tmp;

            tm = (*state)[i][1] ^ (*state)[i][2];
            tm = xtime(tm);
            (*state)[i][1] ^= tm ^ tmp;

            tm = (*state)[i][2] ^ (*state)[i][3];
            tm = xtime(tm);
            (*state)[i][2] ^= tm ^ tmp;

            tm = (*state)[i][3] ^ t;
            tm = xtime(tm);
            (*state)[i][3] ^= tm ^ tmp;
        }
    }

    void cipher(state_t *state) {
        uint8_t round = 0;

        add_round_key(0, state);

        for (round = 1; ; ++round) {
            subbytes(state);
            shiftrows(state);
            if (round == nr256)
                break;
            mixcolumns(state);
            add_round_key(round, state);
        }

        add_round_key(nr256, state);
    }

    uint8_t round_key_[aes256_key_exp_size];
    uint8_t iv_[aes256_blocklen];
};

class aes128 {
public:
    aes128() {
        memset(iv_, 0, aes128_blocklen);
        memset(round_key_, 0, aes128_key_exp_size);
    }

    aes128(const std::string& key, const std::string& iv) {
        if (key.length() != aes128_keylen)
            throw std::runtime_error("aes invalid key length");
        if (iv.length() != aes128_blocklen)
            throw std::runtime_error("aes invalid iv length");

        memcpy(iv_, iv.data(), aes128_blocklen);
        expand_key((const uint8_t *) key.data());
    }

    aes128(const uint8_t key[aes128_keylen], const uint8_t iv[aes128_blocklen]) {
        memcpy(iv_, iv, aes128_blocklen);
        expand_key(key);
    }

    ~aes128() {
        secure_zero(round_key_, sizeof(round_key_));
        secure_zero(iv_, sizeof(iv_));
    }

    void set(const uint8_t key[aes128_keylen], const uint8_t iv[aes128_blocklen]) {
        memcpy(iv_, iv, aes128_blocklen);
        expand_key(key);
    }

    // encrypt/decrypt a buffer
    std::string ctr_crypt(const std::string& buffer) {
        std::string ret(buffer.length(), 0x00);
        uint8_t state[16];
        size_t i;
        int bi;

        for (i = 0, bi = aes128_blocklen; i < buffer.length(); ++i, ++bi) {
            if (bi == aes128_blocklen) {
                memcpy(state, iv_, aes128_blocklen);
                cipher(reinterpret_cast<state_t *>(state));

                for (bi = (aes128_blocklen - 1); bi >= 0; --bi) {
                    if (iv_[bi] == 255) {
                        iv_[bi] = 0;
                        continue;
                    }
                    iv_[bi] += 1;
                    break;
                }

                bi = 0;
            }

            ret[i] = (buffer[i] ^ state[bi]);
        }

        return ret;
    }

    void ctr_crypt(const std::string& buffer, std::string& wbuffer) {
        wbuffer = ctr_crypt(buffer);
    }

protected:
    void expand_key(const uint8_t *key) {
        unsigned int i, j, k;
        uint8_t tempa[4];

        for (i = 0; i < nk128; ++i) {
            round_key_[(i * 4) + 0] = key[(i * 4) + 0];
            round_key_[(i * 4) + 1] = key[(i * 4) + 1];
            round_key_[(i * 4) + 2] = key[(i * 4) + 2];
            round_key_[(i * 4) + 3] = key[(i * 4) + 3];
        }

        for (i = nk128; i < nb128 * (nr128 + 1); ++i) {
            {
                k = (i - 1) * 4;
                tempa[0] = round_key_[k + 0];
                tempa[1] = round_key_[k + 1];
                tempa[2] = round_key_[k + 2];
                tempa[3] = round_key_[k + 3];
            }

            if (i % nk128 == 0) {
                const uint8_t ta0 = tempa[0];

                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = ta0;

                tempa[0] = sbox[tempa[0]];
                tempa[1] = sbox[tempa[1]];
                tempa[2] = sbox[tempa[2]];
                tempa[3] = sbox[tempa[3]];

                tempa[0] = tempa[0] ^ rcon[i / nk128];
            }

            j = i * 4;
            k = (i - nk128) * 4;

            round_key_[j + 0] = round_key_[k + 0] ^ tempa[0];
            round_key_[j + 1] = round_key_[k + 1] ^ tempa[1];
            round_key_[j + 2] = round_key_[k + 2] ^ tempa[2];
            round_key_[j + 3] = round_key_[k + 3] ^ tempa[3];
        }
    }

    inline void add_round_key(uint8_t round, state_t *state) {
        uint8_t i, j;

        for (i = 0; i < 4; ++i) {
            for (j = 0; j < 4; ++j) {
                (*state)[i][j] ^= round_key_[(round * nb128 * 4) + (i * nb128) + j];
            }
        }
    }

    inline void subbytes(state_t *state) {
        uint8_t i, j;
        for (i = 0; i < 4; ++i) {
            for (j = 0; j < 4; ++j) {
                (*state)[j][i] = sbox[(*state)[j][i]];
            }
        }
    }

    inline void shiftrows(state_t *state) {
        uint8_t temp;

        temp = (*state)[0][1];
        (*state)[0][1] = (*state)[1][1];
        (*state)[1][1] = (*state)[2][1];
        (*state)[2][1] = (*state)[3][1];
        (*state)[3][1] = temp;

        temp = (*state)[0][2];
        (*state)[0][2] = (*state)[2][2];
        (*state)[2][2] = temp;

        temp = (*state)[1][2];
        (*state)[1][2] = (*state)[3][2];
        (*state)[3][2] = temp;

        temp = (*state)[0][3];
        (*state)[0][3] = (*state)[3][3];
        (*state)[3][3] = (*state)[2][3];
        (*state)[2][3] = (*state)[1][3];
        (*state)[1][3] = temp;
    }

    static constexpr uint8_t xtime(uint8_t x) {
        return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
    }

    inline void mixcolumns(state_t *state) {
        uint8_t i;
        uint8_t tmp, tm, t;
        for (i = 0; i < 4; ++i) {
            t = (*state)[i][0];
            tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];

            tm = (*state)[i][0] ^ (*state)[i][1];
            tm = xtime(tm);
            (*state)[i][0] ^= tm ^ tmp;

            tm = (*state)[i][1] ^ (*state)[i][2];
            tm = xtime(tm);
            (*state)[i][1] ^= tm ^ tmp;

            tm = (*state)[i][2] ^ (*state)[i][3];
            tm = xtime(tm);
            (*state)[i][2] ^= tm ^ tmp;

            tm = (*state)[i][3] ^ t;
            tm = xtime(tm);
            (*state)[i][3] ^= tm ^ tmp;
        }
    }

    void cipher(state_t *state) {
        uint8_t round = 0;

        add_round_key(0, state);

        for (round = 1; ; ++round) {
            subbytes(state);
            shiftrows(state);
            if (round == nr128)
                break;
            mixcolumns(state);
            add_round_key(round, state);
        }

        add_round_key(nr128, state);
    }

    uint8_t round_key_[aes128_key_exp_size];
    uint8_t iv_[aes128_blocklen];
};

}
#endif /* __AES_CTR_H__ */
