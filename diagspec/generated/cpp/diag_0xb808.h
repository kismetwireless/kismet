// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "kaitai/kaitaistruct.h"
#include <stdint.h>
#include <memory>

#if KAITAI_STRUCT_VERSION < 9000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.9 or later is required"
#endif

class diag_0xb808_t : public kaitai::kstruct {

public:

    diag_0xb808_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = nullptr, diag_0xb808_t* p__root = nullptr);

private:
    void _read();
    void _clean_up();

public:
    ~diag_0xb808_t();

private:
    bool f_nas_pdu;
    std::string m_nas_pdu;

public:
    std::string nas_pdu();

private:
    bool f_seq;
    uint8_t m_seq;
    bool n_seq;

public:
    bool _is_null_seq() { seq(); return n_seq; };

private:

public:
    uint8_t seq();

private:
    bool f_mac;
    uint32_t m_mac;
    bool n_mac;

public:
    bool _is_null_mac() { mac(); return n_mac; };

private:

public:
    uint32_t mac();

private:
    bool f_inner_sec_hdr_type;
    uint8_t m_inner_sec_hdr_type;
    bool n_inner_sec_hdr_type;

public:
    bool _is_null_inner_sec_hdr_type() { inner_sec_hdr_type(); return n_inner_sec_hdr_type; };

private:

public:
    uint8_t inner_sec_hdr_type();

private:
    bool f_sec_hdr_type;
    uint8_t m_sec_hdr_type;
    bool n_sec_hdr_type;

public:
    bool _is_null_sec_hdr_type() { sec_hdr_type(); return n_sec_hdr_type; };

private:

public:
    uint8_t sec_hdr_type();

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
    bool f_is_protected;
    bool m_is_protected;

public:
    bool is_protected();

private:
    bool f_epd;
    uint8_t m_epd;

public:
    uint8_t epd();

private:
    bool f_inner_epd;
    uint8_t m_inner_epd;
    bool n_inner_epd;

public:
    bool _is_null_inner_epd() { inner_epd(); return n_inner_epd; };

private:

public:
    uint8_t inner_epd();

private:
    bool f_inner_ok;
    bool m_inner_ok;

public:
    bool inner_ok();

private:
    bool f_pdu_session_id;
    uint8_t m_pdu_session_id;
    bool n_pdu_session_id;

public:
    bool _is_null_pdu_session_id() { pdu_session_id(); return n_pdu_session_id; };

private:

public:
    uint8_t pdu_session_id();

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
    bool f_is_integrity_only;
    bool m_is_integrity_only;

public:
    bool is_integrity_only();

private:
    bool f_inner_msg_type;
    uint8_t m_inner_msg_type;
    bool n_inner_msg_type;

public:
    bool _is_null_inner_msg_type() { inner_msg_type(); return n_inner_msg_type; };

private:

public:
    uint8_t inner_msg_type();

private:
    bool f_is_5gsm;
    bool m_is_5gsm;

public:
    bool is_5gsm();

private:
    bool f_inner_epd_probe;
    uint8_t m_inner_epd_probe;
    bool n_inner_epd_probe;

public:
    bool _is_null_inner_epd_probe() { inner_epd_probe(); return n_inner_epd_probe; };

private:

public:
    uint8_t inner_epd_probe();

private:
    uint32_t m_version;
    uint8_t m_rrc_rel;
    uint8_t m_rrc_ver_major;
    uint8_t m_rrc_ver_minor;
    diag_0xb808_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint32_t version() const { return m_version; }
    uint8_t rrc_rel() const { return m_rrc_rel; }
    uint8_t rrc_ver_major() const { return m_rrc_ver_major; }
    uint8_t rrc_ver_minor() const { return m_rrc_ver_minor; }
    diag_0xb808_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};
