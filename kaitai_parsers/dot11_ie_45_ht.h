#ifndef DOT11_IE_45_HT_H_
#define DOT11_IE_45_HT_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_45_ht_t : public kaitai::kstruct {

public:
    class rx_mcs_t;

    dot11_ie_45_ht_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_45_ht_t* p_root = 0);
    ~dot11_ie_45_ht_t();

    class rx_mcs_t : public kaitai::kstruct {

    public:

        rx_mcs_t(kaitai::kstream* p_io, dot11_ie_45_ht_t* p_parent = 0, dot11_ie_45_ht_t* p_root = 0);
        ~rx_mcs_t();

    private:
        bool f_ht_num_streams;
        int32_t m_ht_num_streams;

    public:
        int32_t ht_num_streams();

    private:
        uint8_t m_rx_mcs_b0;
        uint8_t m_rx_mcs_b1;
        uint8_t m_rx_mcs_b2;
        uint8_t m_rx_mcs_b3;
        uint8_t m_rx_mcs_b4;
        uint8_t m_rx_mcs_b5;
        uint8_t m_rx_mcs_b6;
        uint8_t m_rx_mcs_b7;
        uint8_t m_rx_mcs_b8;
        uint8_t m_rx_mcs_b9;
        uint16_t m_supported_data_rate;
        uint8_t m_txflags;
        dot11_ie_45_ht_t* m__root;
        dot11_ie_45_ht_t* m__parent;

    public:
        uint8_t rx_mcs_b0() const { return m_rx_mcs_b0; }
        uint8_t rx_mcs_b1() const { return m_rx_mcs_b1; }
        uint8_t rx_mcs_b2() const { return m_rx_mcs_b2; }
        uint8_t rx_mcs_b3() const { return m_rx_mcs_b3; }
        uint8_t rx_mcs_b4() const { return m_rx_mcs_b4; }
        uint8_t rx_mcs_b5() const { return m_rx_mcs_b5; }
        uint8_t rx_mcs_b6() const { return m_rx_mcs_b6; }
        uint8_t rx_mcs_b7() const { return m_rx_mcs_b7; }
        uint8_t rx_mcs_b8() const { return m_rx_mcs_b8; }
        uint8_t rx_mcs_b9() const { return m_rx_mcs_b9; }
        uint16_t supported_data_rate() const { return m_supported_data_rate; }
        uint8_t txflags() const { return m_txflags; }
        dot11_ie_45_ht_t* _root() const { return m__root; }
        dot11_ie_45_ht_t* _parent() const { return m__parent; }
    };

private:
    bool f_ht_cap_dss_40mhz;
    int32_t m_ht_cap_dss_40mhz;

public:
    int32_t ht_cap_dss_40mhz();

private:
    bool f_ht_cap_rx_stbc;
    int32_t m_ht_cap_rx_stbc;

public:
    int32_t ht_cap_rx_stbc();

private:
    bool f_ht_cap_max_amsdu_len;
    int32_t m_ht_cap_max_amsdu_len;

public:
    int32_t ht_cap_max_amsdu_len();

private:
    bool f_ht_cap_40mhz_intolerant;
    int32_t m_ht_cap_40mhz_intolerant;

public:
    int32_t ht_cap_40mhz_intolerant();

private:
    bool f_ht_cap_sm_powersave;
    int32_t m_ht_cap_sm_powersave;

public:
    int32_t ht_cap_sm_powersave();

private:
    bool f_ht_cap_tx_stbc;
    int32_t m_ht_cap_tx_stbc;

public:
    int32_t ht_cap_tx_stbc();

private:
    bool f_ht_cap_greenfield;
    int32_t m_ht_cap_greenfield;

public:
    int32_t ht_cap_greenfield();

private:
    bool f_ht_cap_ldpc;
    int32_t m_ht_cap_ldpc;

public:
    int32_t ht_cap_ldpc();

private:
    bool f_ht_cap_20mhz_shortgi;
    int32_t m_ht_cap_20mhz_shortgi;

public:
    int32_t ht_cap_20mhz_shortgi();

private:
    bool f_ht_cap_delayed_block_ack;
    int32_t m_ht_cap_delayed_block_ack;

public:
    int32_t ht_cap_delayed_block_ack();

private:
    bool f_ht_cap_lsig_txop;
    int32_t m_ht_cap_lsig_txop;

public:
    int32_t ht_cap_lsig_txop();

private:
    bool f_ht_cap_40mhz_shortgi;
    int32_t m_ht_cap_40mhz_shortgi;

public:
    int32_t ht_cap_40mhz_shortgi();

private:
    bool f_ht_cap_psmp_intolerant;
    int32_t m_ht_cap_psmp_intolerant;

public:
    int32_t ht_cap_psmp_intolerant();

private:
    uint16_t m_ht_capabilities;
    uint8_t m_ampdu;
    rx_mcs_t* m_mcs;
    uint16_t m_ht_extended_caps;
    uint32_t m_txbf_caps;
    uint8_t m_asel_caps;
    dot11_ie_45_ht_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint16_t ht_capabilities() const { return m_ht_capabilities; }
    uint8_t ampdu() const { return m_ampdu; }
    rx_mcs_t* mcs() const { return m_mcs; }
    uint16_t ht_extended_caps() const { return m_ht_extended_caps; }
    uint32_t txbf_caps() const { return m_txbf_caps; }
    uint8_t asel_caps() const { return m_asel_caps; }
    dot11_ie_45_ht_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_45_HT_H_
