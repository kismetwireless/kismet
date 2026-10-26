// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "kaitai/kaitaistruct.h"
#include <stdint.h>
#include <memory>

#if KAITAI_STRUCT_VERSION < 9000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.9 or later is required"
#endif

class diag_0xb0e1_t : public kaitai::kstruct {

public:

    diag_0xb0e1_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = nullptr, diag_0xb0e1_t* p__root = nullptr);

private:
    void _read();
    void _clean_up();

public:
    ~diag_0xb0e1_t();

private:
    bool f_sec_hdr_type;
    int32_t m_sec_hdr_type;

public:
    int32_t sec_hdr_type();

private:
    bool f_prot_disc;
    int32_t m_prot_disc;

public:
    int32_t prot_disc();

private:
    bool f_nas_pdu;
    std::string m_nas_pdu;

public:
    std::string nas_pdu();

private:
    uint8_t m_version;
    uint8_t m_rrc_rel;
    uint8_t m_rrc_ver_major;
    uint8_t m_rrc_ver_minor;
    uint8_t m_sec_b0;
    uint32_t m_nas_mac;
    uint8_t m_nas_seq;
    std::string m_inner_pdu;
    diag_0xb0e1_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t version() const { return m_version; }
    uint8_t rrc_rel() const { return m_rrc_rel; }
    uint8_t rrc_ver_major() const { return m_rrc_ver_major; }
    uint8_t rrc_ver_minor() const { return m_rrc_ver_minor; }
    uint8_t sec_b0() const { return m_sec_b0; }
    uint32_t nas_mac() const { return m_nas_mac; }
    uint8_t nas_seq() const { return m_nas_seq; }
    std::string inner_pdu() const { return m_inner_pdu; }
    diag_0xb0e1_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};
