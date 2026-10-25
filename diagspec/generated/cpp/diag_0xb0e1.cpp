// SPDX-License-Identifier: GPL-2.0-or-later
// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "diag_0xb0e1.h"

diag_0xb0e1_t::diag_0xb0e1_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, diag_0xb0e1_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    f_sec_hdr_type = false;
    f_prot_disc = false;
    f_nas_pdu = false;
    _read();
}

void diag_0xb0e1_t::_read() {
    m_version = m__io->read_u1();
    m_rrc_rel = m__io->read_u1();
    m_rrc_ver_major = m__io->read_u1();
    m_rrc_ver_minor = m__io->read_u1();
    m_sec_b0 = m__io->read_u1();
    m_nas_mac = m__io->read_u4be();
    m_nas_seq = m__io->read_u1();
    m_inner_pdu = m__io->read_bytes_full();
}

diag_0xb0e1_t::~diag_0xb0e1_t() {
    _clean_up();
}

void diag_0xb0e1_t::_clean_up() {
    if (f_nas_pdu) {
    }
}

int32_t diag_0xb0e1_t::sec_hdr_type() {
    if (f_sec_hdr_type)
        return m_sec_hdr_type;
    m_sec_hdr_type = ((sec_b0() >> 4) & 15);
    f_sec_hdr_type = true;
    return m_sec_hdr_type;
}

int32_t diag_0xb0e1_t::prot_disc() {
    if (f_prot_disc)
        return m_prot_disc;
    m_prot_disc = (sec_b0() & 15);
    f_prot_disc = true;
    return m_prot_disc;
}

std::string diag_0xb0e1_t::nas_pdu() {
    if (f_nas_pdu)
        return m_nas_pdu;
    std::streampos _pos = m__io->pos();
    m__io->seek(4);
    m_nas_pdu = m__io->read_bytes((_io()->size() - 4));
    m__io->seek(_pos);
    f_nas_pdu = true;
    return m_nas_pdu;
}
