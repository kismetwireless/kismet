/* Prints the PHY rate Kismet decodes for every frame of a radiotap or PPI pcap, one line per
 * frame, for the cross-check against tshark (rate_pcaps.py writes the captures):
 *
 *   frame mode mcs nss bw_mhz gi_ns ru flags rate_kbps
 *
 * It applies the decoders the way kis_dlt_radiotap.cc and kis_dlt_ppi.cc do: the radiotap
 * walk feeding dot11_radiotap_rate, then the TLV list; PPI's common rate unless an 802.11n
 * MAC+PHY field gives one.
 *
 *   make test/dot11_rate/rate_dump && test/dot11_rate/rate_dump capture.pcap
 */

#include <cstdint>
#include <cstdio>
#include <vector>

#include "dot11_phy_rate.h"
#include "radiotap_walk.h"

namespace {

constexpr uint32_t dlt_radiotap = 127;
constexpr uint32_t dlt_ppi = 192;
constexpr uint16_t ppi_field_common = 2;
constexpr uint16_t ppi_field_11n_mac = 3;
constexpr uint16_t ppi_field_11n_macphy = 4;
constexpr size_t max_record = 65536;

uint16_t le16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

uint32_t le32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

dot11_phy_rate radiotap_rate(const std::vector<uint8_t>& pkt) {
    if (pkt.size() < kis_radiotap::header_min_len)
        return {};
    const size_t it_len = le16(&pkt[2]);
    if (it_len < kis_radiotap::header_min_len || it_len > pkt.size())
        return {};

    const std::span<const uint8_t> hdr(pkt.data(), it_len);
    dot11_radiotap_rate rate(false);

    const auto walked = kis_radiotap::walk(hdr, [&](unsigned int bit, size_t, std::span<const uint8_t> f) {
            rate.field(bit, f);
        }, false);
    if (walked.status == kis_radiotap::walk_status::malformed)
        return {};

    if (walked.tlv_offset) {
        size_t off = *walked.tlv_offset;
        while (it_len - off >= 4) {
            const uint16_t type = le16(&hdr[off]);
            const uint16_t len = le16(&hdr[off + 2]);
            off += 4;
            if (len > it_len - off)
                break;
            rate.tlv(type, hdr.subspan(off, len));
            const size_t padded = (static_cast<size_t>(len) + 3) & ~size_t{3};
            if (padded > it_len - off)
                break;
            off += padded;
        }
    }

    return rate.finish();
}

dot11_phy_rate ppi_rate(const std::vector<uint8_t>& pkt) {
    if (pkt.size() < 8)
        return {};
    const size_t ph_len = le16(&pkt[2]);
    if (ph_len < 8 || ph_len > pkt.size())
        return {};

    dot11_phy_rate r;
    size_t off = 8;
    while (ph_len - off >= 4) {
        const uint16_t type = le16(&pkt[off]);
        const size_t len = le16(&pkt[off + 2]);
        if (len > ph_len - off - 4)
            break;
        const std::span<const uint8_t> field(&pkt[off], len + 4);

        // 802.11 common: TSF u64, flags, rate (500 kbps), ...
        if (type == ppi_field_common && len >= 20 && r.mode == dot11_phy_mode::none)
            r = dot11_rate_legacy(le16(&pkt[off + 4 + 10]));
        else if (type == ppi_field_11n_mac && len >= 12 &&
                (r.mode == dot11_phy_mode::none || r.mode == dot11_phy_mode::legacy))
            r = dot11_rate_ppi_11n_mac(field);
        else if (type == ppi_field_11n_macphy && len >= 48)
            r = dot11_rate_ppi_11n(field);

        off += 4 + len;
    }

    return r;
}

}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: rate_dump capture.pcap\n");
        return 2;
    }

    FILE *f = fopen(argv[1], "rb");
    if (f == nullptr) {
        perror(argv[1]);
        return 2;
    }

    uint8_t gh[24];
    if (fread(gh, 1, sizeof(gh), f) != sizeof(gh) || le32(gh) != 0xa1b2c3d4) {
        fprintf(stderr, "not a little-endian microsecond pcap\n");
        fclose(f);
        return 2;
    }
    const uint32_t dlt = le32(gh + 20);

    uint8_t rh[16];
    std::vector<uint8_t> pkt;
    unsigned int frame = 0;

    while (fread(rh, 1, sizeof(rh), f) == sizeof(rh)) {
        const uint32_t caplen = le32(rh + 8);
        if (caplen > max_record)
            break;
        pkt.resize(caplen);
        if (fread(pkt.data(), 1, caplen, f) != caplen)
            break;
        frame++;

        const auto r = dlt == dlt_radiotap ? radiotap_rate(pkt) : dlt == dlt_ppi ? ppi_rate(pkt) : dot11_phy_rate{};
        printf("%u %u %u %u %u %u %u %u %u\n", frame, static_cast<unsigned int>(r.mode), r.mcs, r.nss, r.bw_mhz,
                dot11_gi_ns(r.mode, r.gi_code), static_cast<unsigned int>(r.ru_code), r.flags, r.rate_kbps);
    }

    fclose(f);
    return 0;
}
