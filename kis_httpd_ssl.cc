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

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "fmt.h"
#include "kis_httpd_ssl.h"
#include "messagebus.h"

namespace {

constexpr long ca_days = 3650;
// Apple refuses server certificates valid for more than 825 days, and
// publicly trusted ones for more than 398
constexpr long server_days = 397;
constexpr long renew_days = 30;
constexpr size_t max_name_len = 253;

// Private and local address ranges the CA may sign for
constexpr std::array<const char *, 9> permitted_ip = {
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128",
};

// Local name suffixes the CA may sign for
constexpr std::array<const char *, 5> permitted_dns = {
    "local", "lan", "home.arpa", "internal", "localhost",
};

struct pkey_free { void operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); } };
struct pkey_ctx_free { void operator()(EVP_PKEY_CTX *p) const { EVP_PKEY_CTX_free(p); } };
struct x509_free { void operator()(X509 *p) const { X509_free(p); } };
struct bio_free { void operator()(BIO *p) const { BIO_free_all(p); } };
struct bn_free { void operator()(BIGNUM *p) const { BN_free(p); } };
struct ext_free { void operator()(X509_EXTENSION *p) const { X509_EXTENSION_free(p); } };

using pkey_ptr = std::unique_ptr<EVP_PKEY, pkey_free>;
using x509_ptr = std::unique_ptr<X509, x509_free>;
using bio_ptr = std::unique_ptr<BIO, bio_free>;

std::string ssl_error(const std::string& what) {
    auto e = ERR_get_error();
    char buf[256];
    if (e == 0)
        return what;
    ERR_error_string_n(e, buf, sizeof(buf));
    ERR_clear_error();
    return fmt::format("{}: {}", what, buf);
}

// A name or address from the config, checked before it goes anywhere near an
// OpenSSL extension string (where a comma would start a new entry)
bool valid_dns(const std::string& n) {
    if (n.empty() || n.length() > max_name_len || n.front() == '.' || n.back() == '.' || n.front() == '-')
        return false;
    return std::all_of(n.begin(), n.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                c == '-' || c == '.';
        });
}

struct ip_addr {
    int family = 0;
    std::array<uint8_t, 16> bytes{};
    size_t len = 0;
};

bool parse_ip(const std::string& s, ip_addr& out) {
    in_addr a4;
    in6_addr a6;
    if (inet_pton(AF_INET, s.c_str(), &a4) == 1) {
        out.family = AF_INET;
        out.len = 4;
        std::memcpy(out.bytes.data(), &a4, 4);
        return true;
    }
    if (inet_pton(AF_INET6, s.c_str(), &a6) == 1) {
        out.family = AF_INET6;
        out.len = 16;
        std::memcpy(out.bytes.data(), &a6, 16);
        return true;
    }
    return false;
}

bool in_prefix(const ip_addr& a, const std::string& cidr) {
    auto slash = cidr.find('/');
    ip_addr net;
    if (slash == std::string::npos || !parse_ip(cidr.substr(0, slash), net) || net.family != a.family)
        return false;
    auto bits = static_cast<size_t>(std::stoul(cidr.substr(slash + 1)));
    if (bits > a.len * 8)
        return false;
    for (size_t i = 0; i < a.len && bits > 0; i++) {
        uint8_t mask = bits >= 8 ? 0xFF : static_cast<uint8_t>(0xFF << (8 - bits));
        if ((a.bytes[i] & mask) != (net.bytes[i] & mask))
            return false;
        bits = bits >= 8 ? bits - 8 : 0;
    }
    return true;
}

std::string ip_text(const ip_addr& a) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(a.family, a.bytes.data(), buf, sizeof(buf));
    return buf;
}

// "10.0.0.0/8" as OpenSSL's address/mask form for name constraints
std::string nc_ip(const std::string& cidr) {
    auto slash = cidr.find('/');
    ip_addr net;
    parse_ip(cidr.substr(0, slash), net);
    auto bits = static_cast<size_t>(std::stoul(cidr.substr(slash + 1)));
    ip_addr mask;
    mask.family = net.family;
    mask.len = net.len;
    for (size_t i = 0; i < mask.len; i++) {
        mask.bytes[i] = bits >= 8 ? 0xFF : static_cast<uint8_t>(0xFF << (8 - bits));
        bits = bits >= 8 ? bits - 8 : 0;
    }
    return fmt::format("{}/{}", ip_text(net), ip_text(mask));
}

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return "";
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Replace a file atomically, with the given mode, never following a link
void write_file(const std::string& path, const std::string& data, mode_t mode) {
    auto tmp = path + ".tmp";
    unlink(tmp.c_str());
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0)
        throw std::runtime_error(fmt::format("could not write {}: {}", tmp, strerror(errno)));
    size_t off = 0;
    while (off < data.size()) {
        auto w = write(fd, data.data() + off, data.size() - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            auto err = errno;
            close(fd);
            unlink(tmp.c_str());
            throw std::runtime_error(fmt::format("could not write {}: {}", tmp, strerror(err)));
        }
        off += static_cast<size_t>(w);
    }
    fsync(fd);
    close(fd);
    if (rename(tmp.c_str(), path.c_str()) < 0) {
        auto err = errno;
        unlink(tmp.c_str());
        throw std::runtime_error(fmt::format("could not write {}: {}", path, strerror(err)));
    }
}

pkey_ptr make_key() {
    std::unique_ptr<EVP_PKEY_CTX, pkey_ctx_free> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    EVP_PKEY *raw = nullptr;
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <= 0 ||
            EVP_PKEY_keygen(ctx.get(), &raw) <= 0)
        throw std::runtime_error(ssl_error("could not make a key"));
    return pkey_ptr(raw);
}

void add_ext(X509 *cert, X509 *issuer, int nid, const std::string& value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    std::unique_ptr<X509_EXTENSION, ext_free> ext(X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str()));
    if (!ext || !X509_add_ext(cert, ext.get(), -1))
        throw std::runtime_error(ssl_error(fmt::format("could not add certificate extension {}", OBJ_nid2sn(nid))));
}

x509_ptr new_cert(EVP_PKEY *key, const std::string& cn, long days) {
    x509_ptr cert(X509_new());
    if (!cert)
        throw std::runtime_error(ssl_error("could not make a certificate"));

    X509_set_version(cert.get(), 2);

    // A random, positive serial
    unsigned char serial[16];
    if (RAND_bytes(serial, sizeof(serial)) != 1)
        throw std::runtime_error(ssl_error("could not make a serial number"));
    serial[0] &= 0x7F;
    std::unique_ptr<BIGNUM, bn_free> bn(BN_bin2bn(serial, sizeof(serial), nullptr));
    if (!bn || !BN_to_ASN1_INTEGER(bn.get(), X509_get_serialNumber(cert.get())))
        throw std::runtime_error(ssl_error("could not set the serial number"));

    // An hour early, for clocks that are a little behind
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), days * 24 * 3600);
    X509_set_pubkey(cert.get(), key);

    auto name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_UTF8, reinterpret_cast<const unsigned char *>("Kismet"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, reinterpret_cast<const unsigned char *>(cn.c_str()), -1, -1, 0);

    return cert;
}

std::string cert_pem(X509 *cert) {
    bio_ptr bio(BIO_new(BIO_s_mem()));
    if (!bio || !PEM_write_bio_X509(bio.get(), cert))
        throw std::runtime_error(ssl_error("could not write a certificate"));
    char *data;
    auto len = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, len);
}

std::string key_pem(EVP_PKEY *key) {
    bio_ptr bio(BIO_new(BIO_s_mem()));
    if (!bio || !PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr))
        throw std::runtime_error(ssl_error("could not write a key"));
    char *data;
    auto len = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, len);
}

x509_ptr load_cert(const std::string& path) {
    bio_ptr bio(BIO_new_file(path.c_str(), "r"));
    if (!bio)
        return nullptr;
    return x509_ptr(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

pkey_ptr load_key(const std::string& path) {
    bio_ptr bio(BIO_new_file(path.c_str(), "r"));
    if (!bio)
        return nullptr;
    return pkey_ptr(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
}

std::string fingerprint(X509 *cert) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (!X509_digest(cert, EVP_sha256(), md, &len))
        throw std::runtime_error(ssl_error("could not fingerprint a certificate"));
    std::string out;
    for (unsigned int i = 0; i < len; i++)
        out += fmt::format("{}{:02X}", i ? ":" : "", md[i]);
    return out;
}

std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string line;
    while (std::getline(ss, line))
        if (!line.empty())
            out.push_back(line);
    return out;
}

std::string join(const std::vector<std::string>& v, const std::string& sep) {
    std::string out;
    for (const auto& s : v)
        out += (out.empty() ? "" : sep) + s;
    return out;
}

// What a CA permits: DNS suffixes and "addr/bits" ranges, as recorded when it was made
struct permits {
    std::vector<std::string> dns;
    std::vector<std::string> ip;

    bool allows_dns(const std::string& n) const {
        for (const auto& d : dns) {
            if (strcasecmp(n.c_str(), d.c_str()) == 0)
                return true;
            if (n.length() > d.length() + 1 && n[n.length() - d.length() - 1] == '.' &&
                    strcasecmp(n.c_str() + n.length() - d.length(), d.c_str()) == 0)
                return true;
        }
        return false;
    }

    bool allows_ip(const ip_addr& a) const {
        return std::any_of(ip.begin(), ip.end(), [&](const std::string& p) { return in_prefix(a, p); });
    }
};

std::string host_name() {
    char buf[256];
    if (gethostname(buf, sizeof(buf) - 1) != 0)
        return "";
    buf[sizeof(buf) - 1] = 0;
    std::string h(buf);
    return valid_dns(h) ? h : "";
}

// This host's own IPv4 addresses, without link-local ones.  IPv6 ones are left to
// httpd_ssl_names, since temporary addresses would change the certificate every day.
std::vector<ip_addr> local_addresses() {
    std::vector<ip_addr> out;
    struct ifaddrs *ifa = nullptr;
    if (getifaddrs(&ifa) != 0)
        return out;
    for (auto i = ifa; i != nullptr; i = i->ifa_next) {
        if (i->ifa_addr == nullptr || !(i->ifa_flags & IFF_UP))
            continue;
        ip_addr a;
        if (i->ifa_addr->sa_family == AF_INET) {
            a.family = AF_INET;
            a.len = 4;
            std::memcpy(a.bytes.data(), &reinterpret_cast<sockaddr_in *>(i->ifa_addr)->sin_addr, 4);
        } else {
            continue;
        }
        if (in_prefix(a, "169.254.0.0/16"))
            continue;
        if (std::none_of(out.begin(), out.end(), [&](const ip_addr& o) { return ip_text(o) == ip_text(a); }))
            out.push_back(a);
    }
    freeifaddrs(ifa);
    return out;
}

}

namespace kis_httpd_ssl {

std::string fingerprint_file(const std::string& pem_file) {
    auto cert = load_cert(pem_file);
    if (!cert)
        throw std::runtime_error(fmt::format("could not read a certificate from {}", pem_file));
    return fingerprint(cert.get());
}

generated ensure(const std::string& in_dir, const std::vector<std::string>& extra_names) {
    auto dir = in_dir;
    while (dir.length() > 1 && dir.back() == '/')
        dir.pop_back();

    struct stat st;
    if (lstat(dir.c_str(), &st) != 0) {
        if (errno != ENOENT || mkdir(dir.c_str(), 0700) != 0)
            throw std::runtime_error(fmt::format("could not make {}: {}", dir, strerror(errno)));
    } else if (!S_ISDIR(st.st_mode)) {
        throw std::runtime_error(fmt::format("{} is not a directory", dir));
    } else if (st.st_uid != geteuid()) {
        throw std::runtime_error(fmt::format("{} belongs to another user", dir));
    }

    const auto ca_file = dir + "/kismet_ca.pem";
    const auto ca_key_file = dir + "/kismet_ca.key";
    const auto ca_permits_file = dir + "/kismet_ca.permits";
    const auto chain_file = dir + "/kismet_server.pem";
    const auto key_file = dir + "/kismet_server.key";
    const auto names_file = dir + "/kismet_server.names";

    auto host = host_name();

    // The names asked for: this host, the configured ones, and this host's addresses
    std::vector<std::string> dns_names;
    std::vector<ip_addr> ips;
    auto add_dns = [&](const std::string& n) {
        if (std::none_of(dns_names.begin(), dns_names.end(),
                    [&](const std::string& d) { return strcasecmp(d.c_str(), n.c_str()) == 0; }))
            dns_names.push_back(n);
    };
    auto add_ip = [&](const ip_addr& a) {
        if (std::none_of(ips.begin(), ips.end(), [&](const ip_addr& o) { return ip_text(o) == ip_text(a); }))
            ips.push_back(a);
    };

    add_dns("localhost");
    ip_addr loop6;
    parse_ip("::1", loop6);
    add_ip(loop6);
    if (!host.empty()) {
        add_dns(host);
        if (host.find('.') == std::string::npos)
            add_dns(host + ".local");
    }
    std::vector<std::string> configured_dns;
    std::vector<ip_addr> configured_ip;
    for (const auto& n : extra_names) {
        ip_addr a;
        if (parse_ip(n, a)) {
            configured_ip.push_back(a);
            add_ip(a);
        } else if (valid_dns(n)) {
            configured_dns.push_back(n);
            add_dns(n);
        } else {
            _MSG_ERROR("HTTPS: ignoring '{}' in httpd_ssl_names, which is not a host name or address", n);
        }
    }
    for (const auto& a : local_addresses())
        add_ip(a);

    // The CA, made once
    auto ca = load_cert(ca_file);
    auto ca_key = load_key(ca_key_file);
    permits allowed;

    if (!ca || !ca_key || X509_check_private_key(ca.get(), ca_key.get()) != 1) {
        allowed.dns.assign(permitted_dns.begin(), permitted_dns.end());
        allowed.ip.assign(permitted_ip.begin(), permitted_ip.end());
        if (!host.empty() && !allowed.allows_dns(host))
            allowed.dns.push_back(host);
        for (const auto& n : configured_dns)
            if (!allowed.allows_dns(n))
                allowed.dns.push_back(n);
        for (const auto& a : configured_ip)
            if (!allowed.allows_ip(a))
                allowed.ip.push_back(fmt::format("{}/{}", ip_text(a), a.len * 8));

        std::vector<std::string> nc;
        for (const auto& d : allowed.dns)
            nc.push_back(fmt::format("permitted;DNS:{}", d));
        for (const auto& p : allowed.ip)
            nc.push_back(fmt::format("permitted;IP:{}", nc_ip(p)));

        unsigned char tag[3];
        RAND_bytes(tag, sizeof(tag));
        auto key = make_key();
        auto cert = new_cert(key.get(), fmt::format("Kismet CA {} {:02x}{:02x}{:02x}",
                    host.empty() ? "server" : host, tag[0], tag[1], tag[2]), ca_days);
        X509_set_issuer_name(cert.get(), X509_get_subject_name(cert.get()));
        add_ext(cert.get(), cert.get(), NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
        add_ext(cert.get(), cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
        add_ext(cert.get(), cert.get(), NID_subject_key_identifier, "hash");
        add_ext(cert.get(), cert.get(), NID_name_constraints, "critical," + join(nc, ","));
        if (!X509_sign(cert.get(), key.get(), EVP_sha256()))
            throw std::runtime_error(ssl_error("could not sign the CA certificate"));

        write_file(ca_key_file, key_pem(key.get()), 0600);
        write_file(ca_file, cert_pem(cert.get()), 0644);
        write_file(ca_permits_file, join(allowed.dns, "\n") + "\n" + join(allowed.ip, "\n") + "\n", 0644);
        // Any server certificate is from an old CA now
        unlink(names_file.c_str());

        ca = std::move(cert);
        ca_key = std::move(key);
        _MSG_INFO("HTTPS: made a new Kismet CA in {}; install {} on phones and browsers to trust this server",
                dir, ca_file);
    } else {
        for (const auto& l : split_lines(read_file(ca_permits_file))) {
            if (l.find('/') != std::string::npos)
                allowed.ip.push_back(l);
            else
                allowed.dns.push_back(l);
        }
    }

    // Only the names the CA is allowed to sign
    std::vector<std::string> san;
    std::vector<std::string> names;
    for (const auto& n : dns_names) {
        if (!allowed.allows_dns(n)) {
            _MSG_ERROR("HTTPS: the Kismet CA in {} can't sign for {}; to add it, remove the CA files there "
                    "to make a new CA, and install the new one on your devices", dir, n);
            continue;
        }
        san.push_back("DNS:" + n);
        names.push_back(n);
    }
    for (const auto& a : ips) {
        if (!allowed.allows_ip(a)) {
            if (std::any_of(configured_ip.begin(), configured_ip.end(),
                        [&](const ip_addr& c) { return ip_text(c) == ip_text(a); }))
                _MSG_ERROR("HTTPS: the Kismet CA in {} can't sign for {}; to add it, remove the CA files there "
                        "to make a new CA, and install the new one on your devices", dir, ip_text(a));
            continue;
        }
        san.push_back("IP:" + ip_text(a));
        names.push_back(ip_text(a));
    }

    auto names_sorted = names;
    std::sort(names_sorted.begin(), names_sorted.end());
    const auto names_text = join(names_sorted, "\n") + "\n";

    // A new server certificate when the names change, it's close to expiring,
    // or it's from another CA
    auto server = load_cert(chain_file);
    auto server_key = load_key(key_file);
    bool fresh = server && server_key && X509_check_private_key(server.get(), server_key.get()) == 1 &&
        X509_check_issued(ca.get(), server.get()) == X509_V_OK &&
        read_file(names_file) == names_text;
    if (fresh) {
        time_t soon = time(nullptr) + renew_days * 24 * 3600;
        fresh = X509_cmp_time(X509_get0_notAfter(server.get()), &soon) > 0;
    }

    if (!fresh) {
        if (san.empty())
            throw std::runtime_error("no names or addresses to put in the HTTPS certificate");
        auto key = make_key();
        auto cert = new_cert(key.get(), host.empty() ? "kismet" : host, server_days);
        X509_set_issuer_name(cert.get(), X509_get_subject_name(ca.get()));
        add_ext(cert.get(), ca.get(), NID_basic_constraints, "critical,CA:FALSE");
        add_ext(cert.get(), ca.get(), NID_key_usage, "critical,digitalSignature");
        add_ext(cert.get(), ca.get(), NID_ext_key_usage, "serverAuth");
        add_ext(cert.get(), ca.get(), NID_subject_key_identifier, "hash");
        add_ext(cert.get(), ca.get(), NID_authority_key_identifier, "keyid:always");
        add_ext(cert.get(), ca.get(), NID_subject_alt_name, join(san, ","));
        if (!X509_sign(cert.get(), ca_key.get(), EVP_sha256()))
            throw std::runtime_error(ssl_error("could not sign the server certificate"));

        write_file(key_file, key_pem(key.get()), 0600);
        write_file(chain_file, cert_pem(cert.get()) + cert_pem(ca.get()), 0644);
        write_file(names_file, names_text, 0644);
        _MSG_INFO("HTTPS: made a server certificate for {}", join(names, ", "));
    }

    generated g;
    g.chain_file = chain_file;
    g.key_file = key_file;
    g.ca_pem = cert_pem(ca.get());
    g.ca_fingerprint = fingerprint(ca.get());
    g.names = names;
    return g;
}

}
