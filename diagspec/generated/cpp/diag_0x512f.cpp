// SPDX-License-Identifier: GPL-2.0-or-later
// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "diag_0x512f.h"

diag_0x512f_t::diag_0x512f_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, diag_0x512f_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    m_l3 = nullptr;
    m__io__raw_l3 = nullptr;
    f_si4_decoded = false;
    f_l2_pseudo_length = false;
    f_skip_indicator = false;
    f_lac = false;
    f_si3_decoded = false;
    f_rr_decoded = false;
    f_cell_identity = false;
    f_protocol_discriminator = false;
    _read();
}

void diag_0x512f_t::_read() {
    m_channel = m__io->read_u1();
    m_rr_message_type = m__io->read_u1();
    m_l3_length = m__io->read_u1();
    m__raw_l3 = m__io->read_bytes(l3_length());
    m__io__raw_l3 = std::unique_ptr<kaitai::kstream>(new kaitai::kstream(m__raw_l3));
    m_l3 = std::unique_ptr<l3_block_t>(new l3_block_t(m__io__raw_l3.get(), this, m__root));
}

diag_0x512f_t::~diag_0x512f_t() {
    _clean_up();
}

void diag_0x512f_t::_clean_up() {
}

diag_0x512f_t::l3_block_t::l3_block_t(kaitai::kstream* p__io, diag_0x512f_t* p__parent, diag_0x512f_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    m__io__raw_body = nullptr;
    _read();
}

void diag_0x512f_t::l3_block_t::_read() {
    m_pseudo_length_octet = m__io->read_u1();
    m_skip_indicator = m__io->read_bits_int_be(4);
    m_protocol_discriminator = m__io->read_bits_int_be(4);
    m__io->align_to_byte();
    m_message_type = m__io->read_u1();
    n_body = true;
    switch (message_type()) {
    case 27: {
        n_body = false;
        m__raw_body = m__io->read_bytes_full();
        m__io__raw_body = std::unique_ptr<kaitai::kstream>(new kaitai::kstream(m__raw_body));
        m_body = std::unique_ptr<si3_t>(new si3_t(m__io__raw_body.get(), this, m__root));
        break;
    }
    case 28: {
        n_body = false;
        m__raw_body = m__io->read_bytes_full();
        m__io__raw_body = std::unique_ptr<kaitai::kstream>(new kaitai::kstream(m__raw_body));
        m_body = std::unique_ptr<si4_t>(new si4_t(m__io__raw_body.get(), this, m__root));
        break;
    }
    default: {
        m__raw_body = m__io->read_bytes_full();
        break;
    }
    }
}

diag_0x512f_t::l3_block_t::~l3_block_t() {
    _clean_up();
}

void diag_0x512f_t::l3_block_t::_clean_up() {
    if (!n_body) {
    }
}

diag_0x512f_t::si3_t::si3_t(kaitai::kstream* p__io, diag_0x512f_t::l3_block_t* p__parent, diag_0x512f_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    _read();
}

void diag_0x512f_t::si3_t::_read() {
    m_cell_identity = m__io->read_u2be();
    m_mcc_digit2 = m__io->read_bits_int_be(4);
    m_mcc_digit1 = m__io->read_bits_int_be(4);
    m_mnc_digit3 = m__io->read_bits_int_be(4);
    m_mcc_digit3 = m__io->read_bits_int_be(4);
    m_mnc_digit2 = m__io->read_bits_int_be(4);
    m_mnc_digit1 = m__io->read_bits_int_be(4);
    m__io->align_to_byte();
    m_lac = m__io->read_u2be();
    m_rest = m__io->read_bytes_full();
}

diag_0x512f_t::si3_t::~si3_t() {
    _clean_up();
}

void diag_0x512f_t::si3_t::_clean_up() {
}

diag_0x512f_t::si4_t::si4_t(kaitai::kstream* p__io, diag_0x512f_t::l3_block_t* p__parent, diag_0x512f_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    _read();
}

void diag_0x512f_t::si4_t::_read() {
    m_mcc_digit2 = m__io->read_bits_int_be(4);
    m_mcc_digit1 = m__io->read_bits_int_be(4);
    m_mnc_digit3 = m__io->read_bits_int_be(4);
    m_mcc_digit3 = m__io->read_bits_int_be(4);
    m_mnc_digit2 = m__io->read_bits_int_be(4);
    m_mnc_digit1 = m__io->read_bits_int_be(4);
    m__io->align_to_byte();
    m_lac = m__io->read_u2be();
    m_rest = m__io->read_bytes_full();
}

diag_0x512f_t::si4_t::~si4_t() {
    _clean_up();
}

void diag_0x512f_t::si4_t::_clean_up() {
}

bool diag_0x512f_t::si4_decoded() {
    if (f_si4_decoded)
        return m_si4_decoded;
    m_si4_decoded =  ((rr_decoded()) && (l3()->message_type() == 28) && (l3_length() >= 13)) ;
    f_si4_decoded = true;
    return m_si4_decoded;
}

int32_t diag_0x512f_t::l2_pseudo_length() {
    if (f_l2_pseudo_length)
        return m_l2_pseudo_length;
    n_l2_pseudo_length = true;
    if (rr_decoded()) {
        n_l2_pseudo_length = false;
        m_l2_pseudo_length = (l3()->pseudo_length_octet() >> 2);
    }
    f_l2_pseudo_length = true;
    return m_l2_pseudo_length;
}

uint64_t diag_0x512f_t::skip_indicator() {
    if (f_skip_indicator)
        return m_skip_indicator;
    n_skip_indicator = true;
    if (rr_decoded()) {
        n_skip_indicator = false;
        m_skip_indicator = l3()->skip_indicator();
    }
    f_skip_indicator = true;
    return m_skip_indicator;
}

uint16_t diag_0x512f_t::lac() {
    if (f_lac)
        return m_lac;
    n_lac = true;
    if ( ((si3_decoded()) || (si4_decoded())) ) {
        n_lac = false;
        m_lac = ((si3_decoded()) ? (static_cast<diag_0x512f_t::si3_t*>(l3()->body())->lac()) : (static_cast<diag_0x512f_t::si4_t*>(l3()->body())->lac()));
    }
    f_lac = true;
    return m_lac;
}

bool diag_0x512f_t::si3_decoded() {
    if (f_si3_decoded)
        return m_si3_decoded;
    m_si3_decoded =  ((rr_decoded()) && (l3()->message_type() == 27) && (l3_length() >= 19)) ;
    f_si3_decoded = true;
    return m_si3_decoded;
}

bool diag_0x512f_t::rr_decoded() {
    if (f_rr_decoded)
        return m_rr_decoded;
    m_rr_decoded =  (( ((channel() == 129) || (channel() == 131)) ) && (l3_length() >= 3) && ((l3()->pseudo_length_octet() & 3) == 1) && (l3()->protocol_discriminator() == 6)) ;
    f_rr_decoded = true;
    return m_rr_decoded;
}

uint16_t diag_0x512f_t::cell_identity() {
    if (f_cell_identity)
        return m_cell_identity;
    n_cell_identity = true;
    if (si3_decoded()) {
        n_cell_identity = false;
        m_cell_identity = static_cast<diag_0x512f_t::si3_t*>(l3()->body())->cell_identity();
    }
    f_cell_identity = true;
    return m_cell_identity;
}

uint64_t diag_0x512f_t::protocol_discriminator() {
    if (f_protocol_discriminator)
        return m_protocol_discriminator;
    n_protocol_discriminator = true;
    if (rr_decoded()) {
        n_protocol_discriminator = false;
        m_protocol_discriminator = l3()->protocol_discriminator();
    }
    f_protocol_discriminator = true;
    return m_protocol_discriminator;
}
