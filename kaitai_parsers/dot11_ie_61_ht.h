#ifndef DOT11_IE_61_HT_H_
#define DOT11_IE_61_HT_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_61_ht_t : public kaitai::kstruct {

public:
    class ht_info_subset_1_t;
    class ht_info_subset_2_t;
    class ht_info_subset_3_t;

    enum secondary_offset_type_t {
        SECONDARY_OFFSET_TYPE_NO_SECONDARY = 0,
        SECONDARY_OFFSET_TYPE_SECONDARY_ABOVE = 1,
        SECONDARY_OFFSET_TYPE_RESERVED = 2,
        SECONDARY_OFFSET_TYPE_SECONDARY_BELOW = 3
    };

    dot11_ie_61_ht_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_61_ht_t* p_root = 0);
    ~dot11_ie_61_ht_t();

    class ht_info_subset_1_t : public kaitai::kstruct {

    public:

        ht_info_subset_1_t(kaitai::kstream* p_io, dot11_ie_61_ht_t* p_parent = 0, dot11_ie_61_ht_t* p_root = 0);
        ~ht_info_subset_1_t();

    private:
        uint64_t m_ssi;
        bool m_psmp_only;
        bool m_rifs;
        bool m_channel_width;
        secondary_offset_type_t m_secondary_offset;
        dot11_ie_61_ht_t* m__root;
        dot11_ie_61_ht_t* m__parent;

    public:
        uint64_t ssi() const { return m_ssi; }
        bool psmp_only() const { return m_psmp_only; }
        bool rifs() const { return m_rifs; }
        bool channel_width() const { return m_channel_width; }
        secondary_offset_type_t secondary_offset() const { return m_secondary_offset; }
        dot11_ie_61_ht_t* _root() const { return m__root; }
        dot11_ie_61_ht_t* _parent() const { return m__parent; }
    };

    class ht_info_subset_2_t : public kaitai::kstruct {

    public:

        ht_info_subset_2_t(kaitai::kstream* p_io, dot11_ie_61_ht_t* p_parent = 0, dot11_ie_61_ht_t* p_root = 0);
        ~ht_info_subset_2_t();

    private:
        uint64_t m_reserved0;
        bool m_non_ht_present;
        bool m_tx_burst_limit;
        bool m_non_greenfield_present;
        uint64_t m_operating_mode;
        uint64_t m_reserved1;
        dot11_ie_61_ht_t* m__root;
        dot11_ie_61_ht_t* m__parent;

    public:
        uint64_t reserved0() const { return m_reserved0; }
        bool non_ht_present() const { return m_non_ht_present; }
        bool tx_burst_limit() const { return m_tx_burst_limit; }
        bool non_greenfield_present() const { return m_non_greenfield_present; }
        uint64_t operating_mode() const { return m_operating_mode; }
        uint64_t reserved1() const { return m_reserved1; }
        dot11_ie_61_ht_t* _root() const { return m__root; }
        dot11_ie_61_ht_t* _parent() const { return m__parent; }
    };

    class ht_info_subset_3_t : public kaitai::kstruct {

    public:

        ht_info_subset_3_t(kaitai::kstream* p_io, dot11_ie_61_ht_t* p_parent = 0, dot11_ie_61_ht_t* p_root = 0);
        ~ht_info_subset_3_t();

    private:
        bool m_dual_cts_required;
        bool m_dual_beacon_tx;
        uint64_t m_reserved0;
        uint64_t m_reserved1;
        bool m_pco_phase;
        bool m_pco_phase_enabled;
        bool m_lsig_txop_protection;
        bool m_beacon_id;
        dot11_ie_61_ht_t* m__root;
        dot11_ie_61_ht_t* m__parent;

    public:
        bool dual_cts_required() const { return m_dual_cts_required; }
        bool dual_beacon_tx() const { return m_dual_beacon_tx; }
        uint64_t reserved0() const { return m_reserved0; }
        uint64_t reserved1() const { return m_reserved1; }
        bool pco_phase() const { return m_pco_phase; }
        bool pco_phase_enabled() const { return m_pco_phase_enabled; }
        bool lsig_txop_protection() const { return m_lsig_txop_protection; }
        bool beacon_id() const { return m_beacon_id; }
        dot11_ie_61_ht_t* _root() const { return m__root; }
        dot11_ie_61_ht_t* _parent() const { return m__parent; }
    };

private:
    uint8_t m_primary_channel;
    ht_info_subset_1_t* m_info_subset_1;
    ht_info_subset_2_t* m_info_subset_2;
    ht_info_subset_3_t* m_info_subset_3;
    uint16_t m_rx_coding_scheme;
    dot11_ie_61_ht_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t primary_channel() const { return m_primary_channel; }
    ht_info_subset_1_t* info_subset_1() const { return m_info_subset_1; }
    ht_info_subset_2_t* info_subset_2() const { return m_info_subset_2; }
    ht_info_subset_3_t* info_subset_3() const { return m_info_subset_3; }
    uint16_t rx_coding_scheme() const { return m_rx_coding_scheme; }
    dot11_ie_61_ht_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_61_HT_H_
