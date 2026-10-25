// SPDX-License-Identifier: GPL-2.0-or-later
// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "diag_0xb0c0.h"

diag_0xb0c0_t::diag_0xb0c0_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, diag_0xb0c0_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    f_rrc_ver_minor = false;
    f_sfn_subfn = false;
    f_earfcn_u16 = false;
    f_sib_mask = false;
    f_nonv20_header_size = false;
    f_rrc_ver_major = false;
    f_msg_data_len = false;
    f_msg_data = false;
    f_msg_length_nonv20 = false;
    f_channel_type = false;
    f_nonv20_msglen_offset = false;
    f_header_size = false;
    f_subfn = false;
    f_ext = false;
    f_sfn = false;
    f_earfcn = false;
    f_msg_length = false;
    f_pci = false;
    f_nonv20_has_mask = false;
    f_nonv20_len_offset = false;
    f_channel_pos = false;
    f_radio_bearer_id = false;
    f_msg_length_v20 = false;
    f_narrow = false;
    f_nonv20_test_len = false;
    f_earfcn_u32 = false;
    f_pdu_number = false;
    _read();
}

void diag_0xb0c0_t::_read() {
    m_version = m__io->read_u1();
    m_rrc_release = m__io->read_u1();
}

diag_0xb0c0_t::~diag_0xb0c0_t() {
    _clean_up();
}

void diag_0xb0c0_t::_clean_up() {
    if (f_rrc_ver_minor && !n_rrc_ver_minor) {
    }
    if (f_sfn_subfn) {
    }
    if (f_earfcn_u16 && !n_earfcn_u16) {
    }
    if (f_sib_mask && !n_sib_mask) {
    }
    if (f_rrc_ver_major && !n_rrc_ver_major) {
    }
    if (f_msg_data) {
    }
    if (f_msg_length_nonv20 && !n_msg_length_nonv20) {
    }
    if (f_channel_type) {
    }
    if (f_pci) {
    }
    if (f_radio_bearer_id && !n_radio_bearer_id) {
    }
    if (f_msg_length_v20 && !n_msg_length_v20) {
    }
    if (f_nonv20_test_len && !n_nonv20_test_len) {
    }
    if (f_earfcn_u32 && !n_earfcn_u32) {
    }
}

uint8_t diag_0xb0c0_t::rrc_ver_minor() {
    if (f_rrc_ver_minor)
        return m_rrc_ver_minor;
    n_rrc_ver_minor = true;
    if (version() != 20) {
        n_rrc_ver_minor = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(3);
        m_rrc_ver_minor = m__io->read_u1();
        m__io->seek(_pos);
        f_rrc_ver_minor = true;
    }
    return m_rrc_ver_minor;
}

uint16_t diag_0xb0c0_t::sfn_subfn() {
    if (f_sfn_subfn)
        return m_sfn_subfn;
    std::streampos _pos = m__io->pos();
    m__io->seek(((narrow()) ? ((ext() + 2)) : ((ext() + 4))));
    m_sfn_subfn = m__io->read_u2le();
    m__io->seek(_pos);
    f_sfn_subfn = true;
    return m_sfn_subfn;
}

uint16_t diag_0xb0c0_t::earfcn_u16() {
    if (f_earfcn_u16)
        return m_earfcn_u16;
    n_earfcn_u16 = true;
    if (narrow()) {
        n_earfcn_u16 = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(ext());
        m_earfcn_u16 = m__io->read_u2le();
        m__io->seek(_pos);
        f_earfcn_u16 = true;
    }
    return m_earfcn_u16;
}

uint32_t diag_0xb0c0_t::sib_mask() {
    if (f_sib_mask)
        return m_sib_mask;
    n_sib_mask = true;
    if ( ((version() == 20) || (nonv20_has_mask())) ) {
        n_sib_mask = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(((version() == 20) ? (13) : (nonv20_len_offset())));
        m_sib_mask = m__io->read_u4le();
        m__io->seek(_pos);
        f_sib_mask = true;
    }
    return m_sib_mask;
}

int32_t diag_0xb0c0_t::nonv20_header_size() {
    if (f_nonv20_header_size)
        return m_nonv20_header_size;
    m_nonv20_header_size = (nonv20_msglen_offset() + 2);
    f_nonv20_header_size = true;
    return m_nonv20_header_size;
}

uint8_t diag_0xb0c0_t::rrc_ver_major() {
    if (f_rrc_ver_major)
        return m_rrc_ver_major;
    n_rrc_ver_major = true;
    if (version() != 20) {
        n_rrc_ver_major = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(2);
        m_rrc_ver_major = m__io->read_u1();
        m__io->seek(_pos);
        f_rrc_ver_major = true;
    }
    return m_rrc_ver_major;
}

uint16_t diag_0xb0c0_t::msg_data_len() {
    if (f_msg_data_len)
        return m_msg_data_len;
    m_msg_data_len = (( ((msg_length() > 0) && ((header_size() + msg_length()) <= _io()->size())) ) ? (msg_length()) : (0));
    f_msg_data_len = true;
    return m_msg_data_len;
}

std::string diag_0xb0c0_t::msg_data() {
    if (f_msg_data)
        return m_msg_data;
    std::streampos _pos = m__io->pos();
    m__io->seek(header_size());
    m_msg_data = m__io->read_bytes(msg_data_len());
    m__io->seek(_pos);
    f_msg_data = true;
    return m_msg_data;
}

uint16_t diag_0xb0c0_t::msg_length_nonv20() {
    if (f_msg_length_nonv20)
        return m_msg_length_nonv20;
    n_msg_length_nonv20 = true;
    if ( ((version() != 20) && ((nonv20_msglen_offset() + 2) <= _io()->size())) ) {
        n_msg_length_nonv20 = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(nonv20_msglen_offset());
        m_msg_length_nonv20 = m__io->read_u2le();
        m__io->seek(_pos);
        f_msg_length_nonv20 = true;
    }
    return m_msg_length_nonv20;
}

uint8_t diag_0xb0c0_t::channel_type() {
    if (f_channel_type)
        return m_channel_type;
    std::streampos _pos = m__io->pos();
    m__io->seek(channel_pos());
    m_channel_type = m__io->read_u1();
    m__io->seek(_pos);
    f_channel_type = true;
    return m_channel_type;
}

int32_t diag_0xb0c0_t::nonv20_msglen_offset() {
    if (f_nonv20_msglen_offset)
        return m_nonv20_msglen_offset;
    m_nonv20_msglen_offset = (nonv20_len_offset() + ((nonv20_has_mask()) ? (4) : (0)));
    f_nonv20_msglen_offset = true;
    return m_nonv20_msglen_offset;
}

int32_t diag_0xb0c0_t::header_size() {
    if (f_header_size)
        return m_header_size;
    m_header_size = ((version() == 20) ? (19) : ((nonv20_header_size() + ((version() == 30) ? (3) : (0)))));
    f_header_size = true;
    return m_header_size;
}

int32_t diag_0xb0c0_t::subfn() {
    if (f_subfn)
        return m_subfn;
    m_subfn = (sfn_subfn() & 15);
    f_subfn = true;
    return m_subfn;
}

int8_t diag_0xb0c0_t::ext() {
    if (f_ext)
        return m_ext;
    m_ext = ((version() >= 25) ? (8) : (6));
    f_ext = true;
    return m_ext;
}

int32_t diag_0xb0c0_t::sfn() {
    if (f_sfn)
        return m_sfn;
    m_sfn = ((sfn_subfn() >> 4) & 1023);
    f_sfn = true;
    return m_sfn;
}

uint32_t diag_0xb0c0_t::earfcn() {
    if (f_earfcn)
        return m_earfcn;
    m_earfcn = ((narrow()) ? (earfcn_u16()) : (earfcn_u32()));
    f_earfcn = true;
    return m_earfcn;
}

uint16_t diag_0xb0c0_t::msg_length() {
    if (f_msg_length)
        return m_msg_length;
    m_msg_length = ((version() == 20) ? (msg_length_v20()) : (msg_length_nonv20()));
    f_msg_length = true;
    return m_msg_length;
}

uint16_t diag_0xb0c0_t::pci() {
    if (f_pci)
        return m_pci;
    std::streampos _pos = m__io->pos();
    m__io->seek((ext() - 2));
    m_pci = m__io->read_u2le();
    m__io->seek(_pos);
    f_pci = true;
    return m_pci;
}

bool diag_0xb0c0_t::nonv20_has_mask() {
    if (f_nonv20_has_mask)
        return m_nonv20_has_mask;
    m_nonv20_has_mask =  ((version() != 20) && ((nonv20_len_offset() + 6) <= _io()->size()) && (nonv20_test_len() != ((_io()->size() - nonv20_len_offset()) - 2))) ;
    f_nonv20_has_mask = true;
    return m_nonv20_has_mask;
}

int32_t diag_0xb0c0_t::nonv20_len_offset() {
    if (f_nonv20_len_offset)
        return m_nonv20_len_offset;
    m_nonv20_len_offset = (channel_pos() + 1);
    f_nonv20_len_offset = true;
    return m_nonv20_len_offset;
}

int32_t diag_0xb0c0_t::channel_pos() {
    if (f_channel_pos)
        return m_channel_pos;
    m_channel_pos = ((version() == 20) ? (12) : (((version() < 8) ? ((ext() + 4)) : ((ext() + 6)))));
    f_channel_pos = true;
    return m_channel_pos;
}

uint8_t diag_0xb0c0_t::radio_bearer_id() {
    if (f_radio_bearer_id)
        return m_radio_bearer_id;
    n_radio_bearer_id = true;
    if (version() >= 25) {
        n_radio_bearer_id = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(5);
        m_radio_bearer_id = m__io->read_u1();
        m__io->seek(_pos);
        f_radio_bearer_id = true;
    }
    return m_radio_bearer_id;
}

uint16_t diag_0xb0c0_t::msg_length_v20() {
    if (f_msg_length_v20)
        return m_msg_length_v20;
    n_msg_length_v20 = true;
    if (version() == 20) {
        n_msg_length_v20 = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(17);
        m_msg_length_v20 = m__io->read_u2le();
        m__io->seek(_pos);
        f_msg_length_v20 = true;
    }
    return m_msg_length_v20;
}

bool diag_0xb0c0_t::narrow() {
    if (f_narrow)
        return m_narrow;
    m_narrow = version() < 8;
    f_narrow = true;
    return m_narrow;
}

uint16_t diag_0xb0c0_t::nonv20_test_len() {
    if (f_nonv20_test_len)
        return m_nonv20_test_len;
    n_nonv20_test_len = true;
    if ( ((version() != 20) && ((nonv20_len_offset() + 2) <= _io()->size())) ) {
        n_nonv20_test_len = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(nonv20_len_offset());
        m_nonv20_test_len = m__io->read_u2le();
        m__io->seek(_pos);
        f_nonv20_test_len = true;
    }
    return m_nonv20_test_len;
}

uint32_t diag_0xb0c0_t::earfcn_u32() {
    if (f_earfcn_u32)
        return m_earfcn_u32;
    n_earfcn_u32 = true;
    if (!(narrow())) {
        n_earfcn_u32 = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(ext());
        m_earfcn_u32 = m__io->read_u4le();
        m__io->seek(_pos);
        f_earfcn_u32 = true;
    }
    return m_earfcn_u32;
}

int8_t diag_0xb0c0_t::pdu_number() {
    if (f_pdu_number)
        return m_pdu_number;
    m_pdu_number = 0;
    f_pdu_number = true;
    return m_pdu_number;
}
