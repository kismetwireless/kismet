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

#include <memory>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "dot11_ubnt_airmax_crypto.h"

namespace {
    constexpr size_t aes_block_len = 16;
    constexpr size_t mac_len = 6;

    void mac_to_bytes(const mac_addr& mac, unsigned char (&buf)[mac_len]) {
        for (size_t i = 0; i < mac_len; i++)
            buf[i] = mac[i];
    }
}

bool ubnt_airmax::decrypt(const std::string& ciphertext, const mac_addr& src, const mac_addr& dst,
        std::string& plaintext) {
    plaintext.clear();

    // ECB only decrypts whole blocks; a trailing partial block is ignored
    const size_t ct_len = ciphertext.length() - (ciphertext.length() % aes_block_len);

    if (ct_len == 0 || ct_len > max_ciphertext_len)
        return false;

    unsigned char src_b[mac_len], dst_b[mac_len];
    mac_to_bytes(src, src_b);
    mac_to_bytes(dst, dst_b);

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    if (HMAC(EVP_sha1(), dst_b, mac_len, src_b, mac_len, md, &md_len) == nullptr || md_len < aes_block_len)
        return false;

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(),
            EVP_CIPHER_CTX_free);

    if (ctx == nullptr)
        return false;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, md, nullptr) != 1)
        return false;

    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

    // Room for the final block, which is always empty without padding
    unsigned char out[max_ciphertext_len + aes_block_len];
    int out_len = 0, final_len = 0;

    if (EVP_DecryptUpdate(ctx.get(), out, &out_len,
                reinterpret_cast<const unsigned char *>(ciphertext.data()), static_cast<int>(ct_len)) != 1)
        return false;

    if (EVP_DecryptFinal_ex(ctx.get(), out + out_len, &final_len) != 1)
        return false;

    plaintext.assign(reinterpret_cast<const char *>(out), out_len + final_len);

    return true;
}
