// SPDX-License-Identifier: GPL-2.0-or-later
// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "diag_0xb821.h"

diag_0xb821_t::diag_0xb821_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, diag_0xb821_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    f_msg_len_offset = false;
    f_sfn_offset = false;
    f_cell_global_id = false;
    f_sfn_subfn = false;
    f_sib_mask = false;
    f_pdu_id_offset = false;
    f_sfn_has_4th = false;
    f_msg_data_len = false;
    f_msg_data = false;
    f_sfn_subfn_raw = false;
    f_pdu_id = false;
    f_arfcn_offset = false;
    f_header_size = false;
    f_sib_mask_offset = false;
    f_sfn = false;
    f_arfcn = false;
    f_msg_length = false;
    f_subframe = false;
    f_sfn_shift = false;
    f_sfn_subfn_b2 = false;
    f_has_ncgi = false;
    f_sfn_stamped = false;
    f_sfn_subfn_b3 = false;
    _read();
}

void diag_0xb821_t::_read() {
    m_version = m__io->read_u4le();
    m_rrc_release = m__io->read_u1();
    m_rrc_rel_min = m__io->read_u1();
    m_bearer_id = m__io->read_u1();
    m_pci = m__io->read_u2le();
}

diag_0xb821_t::~diag_0xb821_t() {
    _clean_up();
}

void diag_0xb821_t::_clean_up() {
    if (f_cell_global_id && !n_cell_global_id) {
    }
    if (f_sfn_subfn) {
    }
    if (f_sib_mask) {
    }
    if (f_msg_data) {
    }
    if (f_pdu_id) {
    }
    if (f_arfcn) {
    }
    if (f_msg_length) {
    }
    if (f_sfn_subfn_b2) {
    }
    if (f_sfn_subfn_b3) {
    }
}

int8_t diag_0xb821_t::msg_len_offset() {
    if (f_msg_len_offset)
        return m_msg_len_offset;
    m_msg_len_offset = ((has_ncgi()) ? (29) : (((version() >= 12) ? (21) : (22))));
    f_msg_len_offset = true;
    return m_msg_len_offset;
}

int8_t diag_0xb821_t::sfn_offset() {
    if (f_sfn_offset)
        return m_sfn_offset;
    m_sfn_offset = ((has_ncgi()) ? (21) : (13));
    f_sfn_offset = true;
    return m_sfn_offset;
}

uint64_t diag_0xb821_t::cell_global_id() {
    if (f_cell_global_id)
        return m_cell_global_id;
    n_cell_global_id = true;
    if (has_ncgi()) {
        n_cell_global_id = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(9);
        m_cell_global_id = m__io->read_u8le();
        m__io->seek(_pos);
        f_cell_global_id = true;
    }
    return m_cell_global_id;
}

uint16_t diag_0xb821_t::sfn_subfn() {
    if (f_sfn_subfn)
        return m_sfn_subfn;
    std::streampos _pos = m__io->pos();
    m__io->seek(sfn_offset());
    m_sfn_subfn = m__io->read_u2le();
    m__io->seek(_pos);
    f_sfn_subfn = true;
    return m_sfn_subfn;
}

uint32_t diag_0xb821_t::sib_mask() {
    if (f_sib_mask)
        return m_sib_mask;
    std::streampos _pos = m__io->pos();
    m__io->seek(sib_mask_offset());
    m_sib_mask = m__io->read_u4le();
    m__io->seek(_pos);
    f_sib_mask = true;
    return m_sib_mask;
}

int8_t diag_0xb821_t::pdu_id_offset() {
    if (f_pdu_id_offset)
        return m_pdu_id_offset;
    m_pdu_id_offset = ((has_ncgi()) ? (24) : (((version() >= 12) ? (16) : (17))));
    f_pdu_id_offset = true;
    return m_pdu_id_offset;
}

bool diag_0xb821_t::sfn_has_4th() {
    if (f_sfn_has_4th)
        return m_sfn_has_4th;
    m_sfn_has_4th =  ((!(has_ncgi())) && (version() < 12)) ;
    f_sfn_has_4th = true;
    return m_sfn_has_4th;
}

uint16_t diag_0xb821_t::msg_data_len() {
    if (f_msg_data_len)
        return m_msg_data_len;
    m_msg_data_len = (( ((msg_length() > 0) && ((header_size() + msg_length()) <= _io()->size())) ) ? (msg_length()) : (0));
    f_msg_data_len = true;
    return m_msg_data_len;
}

std::string diag_0xb821_t::msg_data() {
    if (f_msg_data)
        return m_msg_data;
    std::streampos _pos = m__io->pos();
    m__io->seek(header_size());
    m_msg_data = m__io->read_bytes(msg_data_len());
    m__io->seek(_pos);
    f_msg_data = true;
    return m_msg_data;
}

int32_t diag_0xb821_t::sfn_subfn_raw() {
    if (f_sfn_subfn_raw)
        return m_sfn_subfn_raw;
    m_sfn_subfn_raw = ((sfn_subfn() + (sfn_subfn_b2() << 16)) + ((sfn_has_4th()) ? ((sfn_subfn_b3() << 24)) : (0)));
    f_sfn_subfn_raw = true;
    return m_sfn_subfn_raw;
}

uint8_t diag_0xb821_t::pdu_id() {
    if (f_pdu_id)
        return m_pdu_id;
    std::streampos _pos = m__io->pos();
    m__io->seek(pdu_id_offset());
    m_pdu_id = m__io->read_u1();
    m__io->seek(_pos);
    f_pdu_id = true;
    return m_pdu_id;
}

int8_t diag_0xb821_t::arfcn_offset() {
    if (f_arfcn_offset)
        return m_arfcn_offset;
    m_arfcn_offset = ((has_ncgi()) ? (17) : (9));
    f_arfcn_offset = true;
    return m_arfcn_offset;
}

int8_t diag_0xb821_t::header_size() {
    if (f_header_size)
        return m_header_size;
    m_header_size = (( ((version() == 23) || (version() == 26)) ) ? (35) : (((has_ncgi()) ? (31) : (((version() >= 12) ? (23) : (24))))));
    f_header_size = true;
    return m_header_size;
}

int8_t diag_0xb821_t::sib_mask_offset() {
    if (f_sib_mask_offset)
        return m_sib_mask_offset;
    m_sib_mask_offset = ((has_ncgi()) ? (25) : (((version() >= 12) ? (17) : (18))));
    f_sib_mask_offset = true;
    return m_sib_mask_offset;
}

int32_t diag_0xb821_t::sfn() {
    if (f_sfn)
        return m_sfn;
    m_sfn = ((sfn_subfn_raw() >> sfn_shift()) & 1023);
    f_sfn = true;
    return m_sfn;
}

uint32_t diag_0xb821_t::arfcn() {
    if (f_arfcn)
        return m_arfcn;
    std::streampos _pos = m__io->pos();
    m__io->seek(arfcn_offset());
    m_arfcn = m__io->read_u4le();
    m__io->seek(_pos);
    f_arfcn = true;
    return m_arfcn;
}

uint16_t diag_0xb821_t::msg_length() {
    if (f_msg_length)
        return m_msg_length;
    std::streampos _pos = m__io->pos();
    m__io->seek(msg_len_offset());
    m_msg_length = m__io->read_u2le();
    m__io->seek(_pos);
    f_msg_length = true;
    return m_msg_length;
}

int32_t diag_0xb821_t::subframe() {
    if (f_subframe)
        return m_subframe;
    n_subframe = true;
    if (version() != 26) {
        n_subframe = false;
        m_subframe = ((sfn_subfn_raw() >> 3) & 15);
    }
    f_subframe = true;
    return m_subframe;
}

int8_t diag_0xb821_t::sfn_shift() {
    if (f_sfn_shift)
        return m_sfn_shift;
    m_sfn_shift = ((sfn_has_4th()) ? (16) : (9));
    f_sfn_shift = true;
    return m_sfn_shift;
}

uint8_t diag_0xb821_t::sfn_subfn_b2() {
    if (f_sfn_subfn_b2)
        return m_sfn_subfn_b2;
    std::streampos _pos = m__io->pos();
    m__io->seek((sfn_offset() + 2));
    m_sfn_subfn_b2 = m__io->read_u1();
    m__io->seek(_pos);
    f_sfn_subfn_b2 = true;
    return m_sfn_subfn_b2;
}

bool diag_0xb821_t::has_ncgi() {
    if (f_has_ncgi)
        return m_has_ncgi;
    m_has_ncgi = version() >= 17;
    f_has_ncgi = true;
    return m_has_ncgi;
}

bool diag_0xb821_t::sfn_stamped() {
    if (f_sfn_stamped)
        return m_sfn_stamped;
    m_sfn_stamped = (sfn_subfn_raw() & ((1 << (sfn_shift() + 10)) - 1)) != 0;
    f_sfn_stamped = true;
    return m_sfn_stamped;
}

uint8_t diag_0xb821_t::sfn_subfn_b3() {
    if (f_sfn_subfn_b3)
        return m_sfn_subfn_b3;
    std::streampos _pos = m__io->pos();
    m__io->seek((sfn_offset() + 3));
    m_sfn_subfn_b3 = m__io->read_u1();
    m__io->seek(_pos);
    f_sfn_subfn_b3 = true;
    return m_sfn_subfn_b3;
}
