// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "kaitai/kaitaistruct.h"
#include <stdint.h>
#include <memory>

#if KAITAI_STRUCT_VERSION < 9000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.9 or later is required"
#endif

class diag_0xb0e3_t : public kaitai::kstruct {

public:

    diag_0xb0e3_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = nullptr, diag_0xb0e3_t* p__root = nullptr);

private:
    void _read();
    void _clean_up();

public:
    ~diag_0xb0e3_t();

private:
    bool f_nas_pdu;
    std::string m_nas_pdu;

public:
    std::string nas_pdu();

private:
    bool f_is_esm;
    bool m_is_esm;

public:
    bool is_esm();

private:
    bool f_prot_disc;
    int32_t m_prot_disc;

public:
    int32_t prot_disc();

private:
    bool f_seq_num;
    int32_t m_seq_num;
    bool n_seq_num;

public:
    bool _is_null_seq_num() { seq_num(); return n_seq_num; };

private:

public:
    int32_t seq_num();

private:
    bool f_short_mac_value;
    uint16_t m_short_mac_value;
    bool n_short_mac_value;

public:
    bool _is_null_short_mac_value() { short_mac_value(); return n_short_mac_value; };

private:

public:
    uint16_t short_mac_value();

private:
    bool f_sec_hdr_type;
    int32_t m_sec_hdr_type;
    bool n_sec_hdr_type;

public:
    bool _is_null_sec_hdr_type() { sec_hdr_type(); return n_sec_hdr_type; };

private:

public:
    int32_t sec_hdr_type();

private:
    bool f_pti;
    uint8_t m_pti;
    bool n_pti;

public:
    bool _is_null_pti() { pti(); return n_pti; };

private:

public:
    uint8_t pti();

private:
    bool f_nas_b0;
    uint8_t m_nas_b0;

public:
    uint8_t nas_b0();

private:
    bool f_ksi;
    int32_t m_ksi;
    bool n_ksi;

public:
    bool _is_null_ksi() { ksi(); return n_ksi; };

private:

public:
    int32_t ksi();

private:
    bool f_eps_bearer_id;
    int32_t m_eps_bearer_id;
    bool n_eps_bearer_id;

public:
    bool _is_null_eps_bearer_id() { eps_bearer_id(); return n_eps_bearer_id; };

private:

public:
    int32_t eps_bearer_id();

private:
    bool f_msg_type;
    uint8_t m_msg_type;
    bool n_msg_type;

public:
    bool _is_null_msg_type() { msg_type(); return n_msg_type; };

private:

public:
    uint8_t msg_type();

private:
    bool f_nas_b1;
    uint8_t m_nas_b1;
    bool n_nas_b1;

public:
    bool _is_null_nas_b1() { nas_b1(); return n_nas_b1; };

private:

public:
    uint8_t nas_b1();

private:
    bool f_is_service_request;
    bool m_is_service_request;

public:
    bool is_service_request();

private:
    uint8_t m_version;
    uint8_t m_rrc_rel;
    uint8_t m_rrc_ver_major;
    uint8_t m_rrc_ver_minor;
    diag_0xb0e3_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t version() const { return m_version; }
    uint8_t rrc_rel() const { return m_rrc_rel; }
    uint8_t rrc_ver_major() const { return m_rrc_ver_major; }
    uint8_t rrc_ver_minor() const { return m_rrc_ver_minor; }
    diag_0xb0e3_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};
