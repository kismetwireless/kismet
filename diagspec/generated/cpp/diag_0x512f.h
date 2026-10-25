// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "kaitai/kaitaistruct.h"
#include <stdint.h>
#include <memory>

#if KAITAI_STRUCT_VERSION < 9000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.9 or later is required"
#endif

class diag_0x512f_t : public kaitai::kstruct {

public:
    class l3_block_t;
    class si3_t;
    class si4_t;

    diag_0x512f_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = nullptr, diag_0x512f_t* p__root = nullptr);

private:
    void _read();
    void _clean_up();

public:
    ~diag_0x512f_t();

    class l3_block_t : public kaitai::kstruct {

    public:

        l3_block_t(kaitai::kstream* p__io, diag_0x512f_t* p__parent = nullptr, diag_0x512f_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~l3_block_t();

    private:
        uint8_t m_pseudo_length_octet;
        uint64_t m_skip_indicator;
        uint64_t m_protocol_discriminator;
        uint8_t m_message_type;
        std::unique_ptr<kaitai::kstruct> m_body;
        bool n_body;

    public:
        bool _is_null_body() { body(); return n_body; };

    private:
        diag_0x512f_t* m__root;
        diag_0x512f_t* m__parent;
        std::string m__raw_body;
        std::unique_ptr<kaitai::kstream> m__io__raw_body;

    public:
        uint8_t pseudo_length_octet() const { return m_pseudo_length_octet; }
        uint64_t skip_indicator() const { return m_skip_indicator; }
        uint64_t protocol_discriminator() const { return m_protocol_discriminator; }
        uint8_t message_type() const { return m_message_type; }
        kaitai::kstruct* body() const { return m_body.get(); }
        diag_0x512f_t* _root() const { return m__root; }
        diag_0x512f_t* _parent() const { return m__parent; }
        std::string _raw_body() const { return m__raw_body; }
        kaitai::kstream* _io__raw_body() const { return m__io__raw_body.get(); }
    };

    class si3_t : public kaitai::kstruct {

    public:

        si3_t(kaitai::kstream* p__io, diag_0x512f_t::l3_block_t* p__parent = nullptr, diag_0x512f_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~si3_t();

    private:
        uint16_t m_cell_identity;
        uint64_t m_mcc_digit2;
        uint64_t m_mcc_digit1;
        uint64_t m_mnc_digit3;
        uint64_t m_mcc_digit3;
        uint64_t m_mnc_digit2;
        uint64_t m_mnc_digit1;
        uint16_t m_lac;
        std::string m_rest;
        diag_0x512f_t* m__root;
        diag_0x512f_t::l3_block_t* m__parent;

    public:
        uint16_t cell_identity() const { return m_cell_identity; }
        uint64_t mcc_digit2() const { return m_mcc_digit2; }
        uint64_t mcc_digit1() const { return m_mcc_digit1; }
        uint64_t mnc_digit3() const { return m_mnc_digit3; }
        uint64_t mcc_digit3() const { return m_mcc_digit3; }
        uint64_t mnc_digit2() const { return m_mnc_digit2; }
        uint64_t mnc_digit1() const { return m_mnc_digit1; }
        uint16_t lac() const { return m_lac; }
        std::string rest() const { return m_rest; }
        diag_0x512f_t* _root() const { return m__root; }
        diag_0x512f_t::l3_block_t* _parent() const { return m__parent; }
    };

    class si4_t : public kaitai::kstruct {

    public:

        si4_t(kaitai::kstream* p__io, diag_0x512f_t::l3_block_t* p__parent = nullptr, diag_0x512f_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~si4_t();

    private:
        uint64_t m_mcc_digit2;
        uint64_t m_mcc_digit1;
        uint64_t m_mnc_digit3;
        uint64_t m_mcc_digit3;
        uint64_t m_mnc_digit2;
        uint64_t m_mnc_digit1;
        uint16_t m_lac;
        std::string m_rest;
        diag_0x512f_t* m__root;
        diag_0x512f_t::l3_block_t* m__parent;

    public:
        uint64_t mcc_digit2() const { return m_mcc_digit2; }
        uint64_t mcc_digit1() const { return m_mcc_digit1; }
        uint64_t mnc_digit3() const { return m_mnc_digit3; }
        uint64_t mcc_digit3() const { return m_mcc_digit3; }
        uint64_t mnc_digit2() const { return m_mnc_digit2; }
        uint64_t mnc_digit1() const { return m_mnc_digit1; }
        uint16_t lac() const { return m_lac; }
        std::string rest() const { return m_rest; }
        diag_0x512f_t* _root() const { return m__root; }
        diag_0x512f_t::l3_block_t* _parent() const { return m__parent; }
    };

private:
    bool f_si4_decoded;
    bool m_si4_decoded;

public:
    bool si4_decoded();

private:
    bool f_l2_pseudo_length;
    int32_t m_l2_pseudo_length;
    bool n_l2_pseudo_length;

public:
    bool _is_null_l2_pseudo_length() { l2_pseudo_length(); return n_l2_pseudo_length; };

private:

public:
    int32_t l2_pseudo_length();

private:
    bool f_skip_indicator;
    uint64_t m_skip_indicator;
    bool n_skip_indicator;

public:
    bool _is_null_skip_indicator() { skip_indicator(); return n_skip_indicator; };

private:

public:
    uint64_t skip_indicator();

private:
    bool f_lac;
    uint16_t m_lac;
    bool n_lac;

public:
    bool _is_null_lac() { lac(); return n_lac; };

private:

public:
    uint16_t lac();

private:
    bool f_si3_decoded;
    bool m_si3_decoded;

public:
    bool si3_decoded();

private:
    bool f_rr_decoded;
    bool m_rr_decoded;

public:
    bool rr_decoded();

private:
    bool f_cell_identity;
    uint16_t m_cell_identity;
    bool n_cell_identity;

public:
    bool _is_null_cell_identity() { cell_identity(); return n_cell_identity; };

private:

public:
    uint16_t cell_identity();

private:
    bool f_protocol_discriminator;
    uint64_t m_protocol_discriminator;
    bool n_protocol_discriminator;

public:
    bool _is_null_protocol_discriminator() { protocol_discriminator(); return n_protocol_discriminator; };

private:

public:
    uint64_t protocol_discriminator();

private:
    uint8_t m_channel;
    uint8_t m_rr_message_type;
    uint8_t m_l3_length;
    std::unique_ptr<l3_block_t> m_l3;
    diag_0x512f_t* m__root;
    kaitai::kstruct* m__parent;
    std::string m__raw_l3;
    std::unique_ptr<kaitai::kstream> m__io__raw_l3;

public:
    uint8_t channel() const { return m_channel; }
    uint8_t rr_message_type() const { return m_rr_message_type; }
    uint8_t l3_length() const { return m_l3_length; }
    l3_block_t* l3() const { return m_l3.get(); }
    diag_0x512f_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
    std::string _raw_l3() const { return m__raw_l3; }
    kaitai::kstream* _io__raw_l3() const { return m__io__raw_l3.get(); }
};
