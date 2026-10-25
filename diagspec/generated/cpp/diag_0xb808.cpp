// SPDX-License-Identifier: GPL-2.0-or-later
// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "diag_0xb808.h"

diag_0xb808_t::diag_0xb808_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, diag_0xb808_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    f_nas_pdu = false;
    f_seq = false;
    f_mac = false;
    f_inner_sec_hdr_type = false;
    f_sec_hdr_type = false;
    f_pti = false;
    f_is_protected = false;
    f_epd = false;
    f_inner_epd = false;
    f_inner_ok = false;
    f_pdu_session_id = false;
    f_msg_type = false;
    f_is_integrity_only = false;
    f_inner_msg_type = false;
    f_is_5gsm = false;
    f_inner_epd_probe = false;
    _read();
}

void diag_0xb808_t::_read() {
    m_version = m__io->read_u4le();
    m_rrc_rel = m__io->read_u1();
    m_rrc_ver_major = m__io->read_u1();
    m_rrc_ver_minor = m__io->read_u1();
}

diag_0xb808_t::~diag_0xb808_t() {
    _clean_up();
}

void diag_0xb808_t::_clean_up() {
    if (f_nas_pdu) {
    }
    if (f_seq && !n_seq) {
    }
    if (f_mac && !n_mac) {
    }
    if (f_inner_sec_hdr_type && !n_inner_sec_hdr_type) {
    }
    if (f_sec_hdr_type && !n_sec_hdr_type) {
    }
    if (f_pti && !n_pti) {
    }
    if (f_epd) {
    }
    if (f_inner_epd && !n_inner_epd) {
    }
    if (f_pdu_session_id && !n_pdu_session_id) {
    }
    if (f_msg_type && !n_msg_type) {
    }
    if (f_inner_msg_type && !n_inner_msg_type) {
    }
    if (f_inner_epd_probe && !n_inner_epd_probe) {
    }
}

std::string diag_0xb808_t::nas_pdu() {
    if (f_nas_pdu)
        return m_nas_pdu;
    std::streampos _pos = m__io->pos();
    m__io->seek(7);
    m_nas_pdu = m__io->read_bytes((_io()->size() - 7));
    m__io->seek(_pos);
    f_nas_pdu = true;
    return m_nas_pdu;
}

uint8_t diag_0xb808_t::seq() {
    if (f_seq)
        return m_seq;
    n_seq = true;
    if (is_protected()) {
        n_seq = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(13);
        m_seq = m__io->read_u1();
        m__io->seek(_pos);
        f_seq = true;
    }
    return m_seq;
}

uint32_t diag_0xb808_t::mac() {
    if (f_mac)
        return m_mac;
    n_mac = true;
    if (is_protected()) {
        n_mac = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(9);
        m_mac = m__io->read_u4be();
        m__io->seek(_pos);
        f_mac = true;
    }
    return m_mac;
}

uint8_t diag_0xb808_t::inner_sec_hdr_type() {
    if (f_inner_sec_hdr_type)
        return m_inner_sec_hdr_type;
    n_inner_sec_hdr_type = true;
    if ( ((inner_ok()) && (inner_epd_probe() != 46)) ) {
        n_inner_sec_hdr_type = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(15);
        m_inner_sec_hdr_type = m__io->read_u1();
        m__io->seek(_pos);
        f_inner_sec_hdr_type = true;
    }
    return m_inner_sec_hdr_type;
}

uint8_t diag_0xb808_t::sec_hdr_type() {
    if (f_sec_hdr_type)
        return m_sec_hdr_type;
    n_sec_hdr_type = true;
    if (epd() != 46) {
        n_sec_hdr_type = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(8);
        m_sec_hdr_type = m__io->read_u1();
        m__io->seek(_pos);
        f_sec_hdr_type = true;
    }
    return m_sec_hdr_type;
}

uint8_t diag_0xb808_t::pti() {
    if (f_pti)
        return m_pti;
    n_pti = true;
    if (epd() == 46) {
        n_pti = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(9);
        m_pti = m__io->read_u1();
        m__io->seek(_pos);
        f_pti = true;
    }
    return m_pti;
}

bool diag_0xb808_t::is_protected() {
    if (f_is_protected)
        return m_is_protected;
    m_is_protected =  ((epd() != 46) && (sec_hdr_type() != 0)) ;
    f_is_protected = true;
    return m_is_protected;
}

uint8_t diag_0xb808_t::epd() {
    if (f_epd)
        return m_epd;
    std::streampos _pos = m__io->pos();
    m__io->seek(7);
    m_epd = m__io->read_u1();
    m__io->seek(_pos);
    f_epd = true;
    return m_epd;
}

uint8_t diag_0xb808_t::inner_epd() {
    if (f_inner_epd)
        return m_inner_epd;
    n_inner_epd = true;
    if (inner_ok()) {
        n_inner_epd = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(14);
        m_inner_epd = m__io->read_u1();
        m__io->seek(_pos);
        f_inner_epd = true;
    }
    return m_inner_epd;
}

bool diag_0xb808_t::inner_ok() {
    if (f_inner_ok)
        return m_inner_ok;
    m_inner_ok =  ((is_integrity_only()) && (_io()->size() >= 17) && ( ((inner_epd_probe() != 46) || (_io()->size() >= 18)) )) ;
    f_inner_ok = true;
    return m_inner_ok;
}

uint8_t diag_0xb808_t::pdu_session_id() {
    if (f_pdu_session_id)
        return m_pdu_session_id;
    n_pdu_session_id = true;
    if (epd() == 46) {
        n_pdu_session_id = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(8);
        m_pdu_session_id = m__io->read_u1();
        m__io->seek(_pos);
        f_pdu_session_id = true;
    }
    return m_pdu_session_id;
}

uint8_t diag_0xb808_t::msg_type() {
    if (f_msg_type)
        return m_msg_type;
    n_msg_type = true;
    if ( ((epd() == 46) || (sec_hdr_type() == 0)) ) {
        n_msg_type = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(((epd() == 46) ? (10) : (9)));
        m_msg_type = m__io->read_u1();
        m__io->seek(_pos);
        f_msg_type = true;
    }
    return m_msg_type;
}

bool diag_0xb808_t::is_integrity_only() {
    if (f_is_integrity_only)
        return m_is_integrity_only;
    m_is_integrity_only =  ((is_protected()) && ( ((sec_hdr_type() == 1) || (sec_hdr_type() == 3)) )) ;
    f_is_integrity_only = true;
    return m_is_integrity_only;
}

uint8_t diag_0xb808_t::inner_msg_type() {
    if (f_inner_msg_type)
        return m_inner_msg_type;
    n_inner_msg_type = true;
    if (inner_ok()) {
        n_inner_msg_type = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(((inner_epd_probe() == 46) ? (17) : (16)));
        m_inner_msg_type = m__io->read_u1();
        m__io->seek(_pos);
        f_inner_msg_type = true;
    }
    return m_inner_msg_type;
}

bool diag_0xb808_t::is_5gsm() {
    if (f_is_5gsm)
        return m_is_5gsm;
    m_is_5gsm = epd() == 46;
    f_is_5gsm = true;
    return m_is_5gsm;
}

uint8_t diag_0xb808_t::inner_epd_probe() {
    if (f_inner_epd_probe)
        return m_inner_epd_probe;
    n_inner_epd_probe = true;
    if ( ((is_integrity_only()) && (_io()->size() >= 17)) ) {
        n_inner_epd_probe = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(14);
        m_inner_epd_probe = m__io->read_u1();
        m__io->seek(_pos);
        f_inner_epd_probe = true;
    }
    return m_inner_epd_probe;
}
