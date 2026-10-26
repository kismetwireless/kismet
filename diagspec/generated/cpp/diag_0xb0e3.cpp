// SPDX-License-Identifier: GPL-2.0-or-later
// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "diag_0xb0e3.h"

diag_0xb0e3_t::diag_0xb0e3_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, diag_0xb0e3_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    f_nas_pdu = false;
    f_is_esm = false;
    f_prot_disc = false;
    f_seq_num = false;
    f_short_mac_value = false;
    f_sec_hdr_type = false;
    f_pti = false;
    f_nas_b0 = false;
    f_ksi = false;
    f_eps_bearer_id = false;
    f_msg_type = false;
    f_nas_b1 = false;
    f_is_service_request = false;
    _read();
}

void diag_0xb0e3_t::_read() {
    m_version = m__io->read_u1();
    m_rrc_rel = m__io->read_u1();
    m_rrc_ver_major = m__io->read_u1();
    m_rrc_ver_minor = m__io->read_u1();
}

diag_0xb0e3_t::~diag_0xb0e3_t() {
    _clean_up();
}

void diag_0xb0e3_t::_clean_up() {
    if (f_nas_pdu) {
    }
    if (f_short_mac_value && !n_short_mac_value) {
    }
    if (f_pti && !n_pti) {
    }
    if (f_nas_b0) {
    }
    if (f_msg_type && !n_msg_type) {
    }
    if (f_nas_b1 && !n_nas_b1) {
    }
}

std::string diag_0xb0e3_t::nas_pdu() {
    if (f_nas_pdu)
        return m_nas_pdu;
    std::streampos _pos = m__io->pos();
    m__io->seek(4);
    m_nas_pdu = m__io->read_bytes((_io()->size() - 4));
    m__io->seek(_pos);
    f_nas_pdu = true;
    return m_nas_pdu;
}

bool diag_0xb0e3_t::is_esm() {
    if (f_is_esm)
        return m_is_esm;
    m_is_esm = prot_disc() == 2;
    f_is_esm = true;
    return m_is_esm;
}

int32_t diag_0xb0e3_t::prot_disc() {
    if (f_prot_disc)
        return m_prot_disc;
    m_prot_disc = (nas_b0() & 15);
    f_prot_disc = true;
    return m_prot_disc;
}

int32_t diag_0xb0e3_t::seq_num() {
    if (f_seq_num)
        return m_seq_num;
    n_seq_num = true;
    if (is_service_request()) {
        n_seq_num = false;
        m_seq_num = (nas_b1() & 31);
    }
    f_seq_num = true;
    return m_seq_num;
}

uint16_t diag_0xb0e3_t::short_mac_value() {
    if (f_short_mac_value)
        return m_short_mac_value;
    n_short_mac_value = true;
    if (is_service_request()) {
        n_short_mac_value = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(6);
        m_short_mac_value = m__io->read_u2be();
        m__io->seek(_pos);
        f_short_mac_value = true;
    }
    return m_short_mac_value;
}

int32_t diag_0xb0e3_t::sec_hdr_type() {
    if (f_sec_hdr_type)
        return m_sec_hdr_type;
    n_sec_hdr_type = true;
    if (prot_disc() != 2) {
        n_sec_hdr_type = false;
        m_sec_hdr_type = ((nas_b0() >> 4) & 15);
    }
    f_sec_hdr_type = true;
    return m_sec_hdr_type;
}

uint8_t diag_0xb0e3_t::pti() {
    if (f_pti)
        return m_pti;
    n_pti = true;
    if (prot_disc() == 2) {
        n_pti = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(5);
        m_pti = m__io->read_u1();
        m__io->seek(_pos);
        f_pti = true;
    }
    return m_pti;
}

uint8_t diag_0xb0e3_t::nas_b0() {
    if (f_nas_b0)
        return m_nas_b0;
    std::streampos _pos = m__io->pos();
    m__io->seek(4);
    m_nas_b0 = m__io->read_u1();
    m__io->seek(_pos);
    f_nas_b0 = true;
    return m_nas_b0;
}

int32_t diag_0xb0e3_t::ksi() {
    if (f_ksi)
        return m_ksi;
    n_ksi = true;
    if (is_service_request()) {
        n_ksi = false;
        m_ksi = ((nas_b1() >> 5) & 7);
    }
    f_ksi = true;
    return m_ksi;
}

int32_t diag_0xb0e3_t::eps_bearer_id() {
    if (f_eps_bearer_id)
        return m_eps_bearer_id;
    n_eps_bearer_id = true;
    if (prot_disc() == 2) {
        n_eps_bearer_id = false;
        m_eps_bearer_id = ((nas_b0() >> 4) & 15);
    }
    f_eps_bearer_id = true;
    return m_eps_bearer_id;
}

uint8_t diag_0xb0e3_t::msg_type() {
    if (f_msg_type)
        return m_msg_type;
    n_msg_type = true;
    if ( ((prot_disc() == 2) || (sec_hdr_type() != 12)) ) {
        n_msg_type = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(((prot_disc() == 2) ? (6) : (5)));
        m_msg_type = m__io->read_u1();
        m__io->seek(_pos);
        f_msg_type = true;
    }
    return m_msg_type;
}

uint8_t diag_0xb0e3_t::nas_b1() {
    if (f_nas_b1)
        return m_nas_b1;
    n_nas_b1 = true;
    if (is_service_request()) {
        n_nas_b1 = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(5);
        m_nas_b1 = m__io->read_u1();
        m__io->seek(_pos);
        f_nas_b1 = true;
    }
    return m_nas_b1;
}

bool diag_0xb0e3_t::is_service_request() {
    if (f_is_service_request)
        return m_is_service_request;
    m_is_service_request =  ((prot_disc() != 2) && (sec_hdr_type() == 12)) ;
    f_is_service_request = true;
    return m_is_service_request;
}
