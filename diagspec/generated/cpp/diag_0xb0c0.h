// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "kaitai/kaitaistruct.h"
#include <stdint.h>
#include <memory>

#if KAITAI_STRUCT_VERSION < 9000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.9 or later is required"
#endif

class diag_0xb0c0_t : public kaitai::kstruct {

public:

    diag_0xb0c0_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = nullptr, diag_0xb0c0_t* p__root = nullptr);

private:
    void _read();
    void _clean_up();

public:
    ~diag_0xb0c0_t();

private:
    bool f_rrc_ver_minor;
    uint8_t m_rrc_ver_minor;
    bool n_rrc_ver_minor;

public:
    bool _is_null_rrc_ver_minor() { rrc_ver_minor(); return n_rrc_ver_minor; };

private:

public:
    uint8_t rrc_ver_minor();

private:
    bool f_sfn_subfn;
    uint16_t m_sfn_subfn;

public:
    uint16_t sfn_subfn();

private:
    bool f_earfcn_u16;
    uint16_t m_earfcn_u16;
    bool n_earfcn_u16;

public:
    bool _is_null_earfcn_u16() { earfcn_u16(); return n_earfcn_u16; };

private:

public:
    uint16_t earfcn_u16();

private:
    bool f_sib_mask;
    uint32_t m_sib_mask;
    bool n_sib_mask;

public:
    bool _is_null_sib_mask() { sib_mask(); return n_sib_mask; };

private:

public:
    uint32_t sib_mask();

private:
    bool f_nonv20_header_size;
    int32_t m_nonv20_header_size;

public:
    int32_t nonv20_header_size();

private:
    bool f_rrc_ver_major;
    uint8_t m_rrc_ver_major;
    bool n_rrc_ver_major;

public:
    bool _is_null_rrc_ver_major() { rrc_ver_major(); return n_rrc_ver_major; };

private:

public:
    uint8_t rrc_ver_major();

private:
    bool f_msg_data_len;
    uint16_t m_msg_data_len;

public:
    uint16_t msg_data_len();

private:
    bool f_msg_data;
    std::string m_msg_data;

public:
    std::string msg_data();

private:
    bool f_msg_length_nonv20;
    uint16_t m_msg_length_nonv20;
    bool n_msg_length_nonv20;

public:
    bool _is_null_msg_length_nonv20() { msg_length_nonv20(); return n_msg_length_nonv20; };

private:

public:
    uint16_t msg_length_nonv20();

private:
    bool f_channel_type;
    uint8_t m_channel_type;

public:
    uint8_t channel_type();

private:
    bool f_nonv20_msglen_offset;
    int32_t m_nonv20_msglen_offset;

public:
    int32_t nonv20_msglen_offset();

private:
    bool f_header_size;
    int32_t m_header_size;

public:
    int32_t header_size();

private:
    bool f_subfn;
    int32_t m_subfn;

public:
    int32_t subfn();

private:
    bool f_ext;
    int8_t m_ext;

public:
    int8_t ext();

private:
    bool f_sfn;
    int32_t m_sfn;

public:
    int32_t sfn();

private:
    bool f_earfcn;
    uint32_t m_earfcn;

public:
    uint32_t earfcn();

private:
    bool f_msg_length;
    uint16_t m_msg_length;

public:
    uint16_t msg_length();

private:
    bool f_pci;
    uint16_t m_pci;

public:
    uint16_t pci();

private:
    bool f_nonv20_has_mask;
    bool m_nonv20_has_mask;

public:
    bool nonv20_has_mask();

private:
    bool f_nonv20_len_offset;
    int32_t m_nonv20_len_offset;

public:
    int32_t nonv20_len_offset();

private:
    bool f_channel_pos;
    int32_t m_channel_pos;

public:
    int32_t channel_pos();

private:
    bool f_radio_bearer_id;
    uint8_t m_radio_bearer_id;
    bool n_radio_bearer_id;

public:
    bool _is_null_radio_bearer_id() { radio_bearer_id(); return n_radio_bearer_id; };

private:

public:
    uint8_t radio_bearer_id();

private:
    bool f_msg_length_v20;
    uint16_t m_msg_length_v20;
    bool n_msg_length_v20;

public:
    bool _is_null_msg_length_v20() { msg_length_v20(); return n_msg_length_v20; };

private:

public:
    uint16_t msg_length_v20();

private:
    bool f_narrow;
    bool m_narrow;

public:
    bool narrow();

private:
    bool f_nonv20_test_len;
    uint16_t m_nonv20_test_len;
    bool n_nonv20_test_len;

public:
    bool _is_null_nonv20_test_len() { nonv20_test_len(); return n_nonv20_test_len; };

private:

public:
    uint16_t nonv20_test_len();

private:
    bool f_earfcn_u32;
    uint32_t m_earfcn_u32;
    bool n_earfcn_u32;

public:
    bool _is_null_earfcn_u32() { earfcn_u32(); return n_earfcn_u32; };

private:

public:
    uint32_t earfcn_u32();

private:
    bool f_pdu_number;
    int8_t m_pdu_number;

public:
    int8_t pdu_number();

private:
    uint8_t m_version;
    uint8_t m_rrc_release;
    diag_0xb0c0_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t version() const { return m_version; }
    uint8_t rrc_release() const { return m_rrc_release; }
    diag_0xb0c0_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};
