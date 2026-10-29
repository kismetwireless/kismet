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

#ifndef __KIS_HTTPD_SSL_H__
#define __KIS_HTTPD_SSL_H__

#include "config.h"

#include <string>
#include <vector>

// Certificates for the optional HTTPS listener.
//
// Without a certificate of their own, Kismet makes a small certificate
// authority of its own and signs a server certificate with it.  Installing
// that CA on a phone lets the web UI run there as an installed app, which
// browsers only allow over trusted HTTPS.  The CA is limited by name
// constraints to private addresses and local names, so if its key were ever
// taken it couldn't be used to impersonate other sites to those phones.

namespace kis_httpd_ssl {
    struct generated {
        // Server certificate followed by the CA, and the server key
        std::string chain_file;
        std::string key_file;

        // The CA certificate, PEM, for clients to install
        std::string ca_pem;
        // SHA-256 fingerprint of the CA certificate, colon separated hex
        std::string ca_fingerprint;

        // Names the server certificate covers
        std::vector<std::string> names;
    };

    // Make the CA if there isn't one in dir, and a server certificate for the
    // given extra names plus this host's name and addresses if there's no
    // current one.  Throws std::runtime_error on failure.
    generated ensure(const std::string& dir, const std::vector<std::string>& extra_names);

    // SHA-256 fingerprint of the first certificate in a PEM file, colon separated hex
    std::string fingerprint_file(const std::string& pem_file);
}

#endif
