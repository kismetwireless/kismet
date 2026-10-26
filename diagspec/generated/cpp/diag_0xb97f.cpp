// SPDX-License-Identifier: GPL-2.0-or-later
// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "diag_0xb97f.h"

diag_0xb97f_t::diag_0xb97f_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, diag_0xb97f_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    m_carriers = nullptr;
    f_config_word = false;
    f_serving_pci = false;
    f_nr_arfcn = false;
    f_cfg_off = false;
    f_num_cc = false;
    f_companion_off = false;
    f_frame_number = false;
    f_num_cells_companion = false;
    f_rec_hdr = false;
    f_is_v7 = false;
    f_num_cells = false;
    f_num_cells_off = false;
    f_carriers = false;
    f_meas_tail = false;
    f_timing_offset = false;
    _read();
}

void diag_0xb97f_t::_read() {
    m_version = m__io->read_u2le();
    m_sub_version = m__io->read_u2le();
}

diag_0xb97f_t::~diag_0xb97f_t() {
    _clean_up();
}

void diag_0xb97f_t::_clean_up() {
    if (f_config_word) {
    }
    if (f_serving_pci) {
    }
    if (f_nr_arfcn) {
    }
    if (f_frame_number) {
    }
    if (f_num_cells_companion) {
    }
    if (f_num_cells) {
    }
    if (f_carriers) {
    }
    if (f_meas_tail) {
    }
    if (f_timing_offset) {
    }
}

diag_0xb97f_t::cc_block_t::cc_block_t(uint16_t p_ver, kaitai::kstream* p__io, diag_0xb97f_t* p__parent, diag_0xb97f_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    m_ver = p_ver;
    m_cells = nullptr;
    f_beam_extra = false;
    f_num_cells_companion = false;
    f_is_v7 = false;
    f_cell_size = false;
    f_num_cells = false;
    f_cc_meas = false;
    _read();
}

void diag_0xb97f_t::cc_block_t::_read() {
    m_nr_arfcn = m__io->read_u4le();
    m_id_byte4 = m__io->read_u1();
    m_id_byte5 = m__io->read_u1();
    m_serving_pci = m__io->read_u2le();
    m_flags = m__io->read_u4le();
    m_serving_rsrp_raw = m__io->read_s4le();
    m_serving_rsrp_b_raw = m__io->read_s4le();
    m_meas_tail = m__io->read_bytes((cc_meas() - 8));
    m_cells = std::unique_ptr<std::vector<std::unique_ptr<nr_cell_t>>>(new std::vector<std::unique_ptr<nr_cell_t>>());
    const int l_cells = num_cells();
    for (int i = 0; i < l_cells; i++) {
        m_cells->push_back(std::move(std::unique_ptr<nr_cell_t>(new nr_cell_t(cell_size(), beam_extra(), m__io, this, m__root))));
    }
}

diag_0xb97f_t::cc_block_t::~cc_block_t() {
    _clean_up();
}

void diag_0xb97f_t::cc_block_t::_clean_up() {
}

int8_t diag_0xb97f_t::cc_block_t::beam_extra() {
    if (f_beam_extra)
        return m_beam_extra;
    m_beam_extra = ((ver() == 0) ? (84) : (0));
    f_beam_extra = true;
    return m_beam_extra;
}

uint8_t diag_0xb97f_t::cc_block_t::num_cells_companion() {
    if (f_num_cells_companion)
        return m_num_cells_companion;
    m_num_cells_companion = ((is_v7()) ? (id_byte5()) : (id_byte4()));
    f_num_cells_companion = true;
    return m_num_cells_companion;
}

bool diag_0xb97f_t::cc_block_t::is_v7() {
    if (f_is_v7)
        return m_is_v7;
    m_is_v7 = ver() == 7;
    f_is_v7 = true;
    return m_is_v7;
}

int8_t diag_0xb97f_t::cc_block_t::cell_size() {
    if (f_cell_size)
        return m_cell_size;
    m_cell_size = (( ((ver() == 0) || (ver() == 10)) ) ? (100) : (60));
    f_cell_size = true;
    return m_cell_size;
}

uint8_t diag_0xb97f_t::cc_block_t::num_cells() {
    if (f_num_cells)
        return m_num_cells;
    m_num_cells = ((is_v7()) ? (id_byte4()) : (id_byte5()));
    f_num_cells = true;
    return m_num_cells;
}

int8_t diag_0xb97f_t::cc_block_t::cc_meas() {
    if (f_cc_meas)
        return m_cc_meas;
    m_cc_meas = ((ver() == 0) ? (28) : (20));
    f_cc_meas = true;
    return m_cc_meas;
}

diag_0xb97f_t::nr_cell_t::nr_cell_t(uint16_t p_cell_size, uint16_t p_beam_extra, kaitai::kstream* p__io, diag_0xb97f_t::cc_block_t* p__parent, diag_0xb97f_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    m_cell_size = p_cell_size;
    m_beam_extra = p_beam_extra;
    m_beam_words = nullptr;
    _read();
}

void diag_0xb97f_t::nr_cell_t::_read() {
    m_pci = m__io->read_u2le();
    m_pbch_sfn = m__io->read_u2le();
    m_num_beams = m__io->read_u4le();
    m_rsrp_raw = m__io->read_s4le();
    m_rsrq_raw = m__io->read_s4le();
    m_beam_words = std::unique_ptr<std::vector<int32_t>>(new std::vector<int32_t>());
    const int l_beam_words = ((num_beams() == 0) ? (0) : ((((cell_size() - 16) / 4) + ((num_beams() > 1) ? ((((num_beams() - 1) * beam_extra()) / 4)) : (0)))));
    for (int i = 0; i < l_beam_words; i++) {
        m_beam_words->push_back(std::move(m__io->read_s4le()));
    }
}

diag_0xb97f_t::nr_cell_t::~nr_cell_t() {
    _clean_up();
}

void diag_0xb97f_t::nr_cell_t::_clean_up() {
}

uint32_t diag_0xb97f_t::config_word() {
    if (f_config_word)
        return m_config_word;
    std::streampos _pos = m__io->pos();
    m__io->seek(cfg_off());
    m_config_word = m__io->read_u4le();
    m__io->seek(_pos);
    f_config_word = true;
    return m_config_word;
}

uint16_t diag_0xb97f_t::serving_pci() {
    if (f_serving_pci)
        return m_serving_pci;
    std::streampos _pos = m__io->pos();
    m__io->seek((rec_hdr() + 6));
    m_serving_pci = m__io->read_u2le();
    m__io->seek(_pos);
    f_serving_pci = true;
    return m_serving_pci;
}

uint32_t diag_0xb97f_t::nr_arfcn() {
    if (f_nr_arfcn)
        return m_nr_arfcn;
    std::streampos _pos = m__io->pos();
    m__io->seek(rec_hdr());
    m_nr_arfcn = m__io->read_u4le();
    m__io->seek(_pos);
    f_nr_arfcn = true;
    return m_nr_arfcn;
}

int8_t diag_0xb97f_t::cfg_off() {
    if (f_cfg_off)
        return m_cfg_off;
    m_cfg_off = ((is_v7()) ? (4) : (8));
    f_cfg_off = true;
    return m_cfg_off;
}

int32_t diag_0xb97f_t::num_cc() {
    if (f_num_cc)
        return m_num_cc;
    m_num_cc = (config_word() & 255);
    f_num_cc = true;
    return m_num_cc;
}

int8_t diag_0xb97f_t::companion_off() {
    if (f_companion_off)
        return m_companion_off;
    m_companion_off = ((is_v7()) ? (5) : (4));
    f_companion_off = true;
    return m_companion_off;
}

uint32_t diag_0xb97f_t::frame_number() {
    if (f_frame_number)
        return m_frame_number;
    std::streampos _pos = m__io->pos();
    m__io->seek((cfg_off() + 4));
    m_frame_number = m__io->read_u4le();
    m__io->seek(_pos);
    f_frame_number = true;
    return m_frame_number;
}

uint8_t diag_0xb97f_t::num_cells_companion() {
    if (f_num_cells_companion)
        return m_num_cells_companion;
    std::streampos _pos = m__io->pos();
    m__io->seek((rec_hdr() + companion_off()));
    m_num_cells_companion = m__io->read_u1();
    m__io->seek(_pos);
    f_num_cells_companion = true;
    return m_num_cells_companion;
}

int8_t diag_0xb97f_t::rec_hdr() {
    if (f_rec_hdr)
        return m_rec_hdr;
    m_rec_hdr = ((is_v7()) ? (16) : (20));
    f_rec_hdr = true;
    return m_rec_hdr;
}

bool diag_0xb97f_t::is_v7() {
    if (f_is_v7)
        return m_is_v7;
    m_is_v7 = version() == 7;
    f_is_v7 = true;
    return m_is_v7;
}

uint8_t diag_0xb97f_t::num_cells() {
    if (f_num_cells)
        return m_num_cells;
    std::streampos _pos = m__io->pos();
    m__io->seek((rec_hdr() + num_cells_off()));
    m_num_cells = m__io->read_u1();
    m__io->seek(_pos);
    f_num_cells = true;
    return m_num_cells;
}

int8_t diag_0xb97f_t::num_cells_off() {
    if (f_num_cells_off)
        return m_num_cells_off;
    m_num_cells_off = ((is_v7()) ? (4) : (5));
    f_num_cells_off = true;
    return m_num_cells_off;
}

std::vector<std::unique_ptr<diag_0xb97f_t::cc_block_t>>* diag_0xb97f_t::carriers() {
    if (f_carriers)
        return m_carriers.get();
    std::streampos _pos = m__io->pos();
    m__io->seek(rec_hdr());
    m_carriers = std::unique_ptr<std::vector<std::unique_ptr<cc_block_t>>>(new std::vector<std::unique_ptr<cc_block_t>>());
    const int l_carriers = num_cc();
    for (int i = 0; i < l_carriers; i++) {
        m_carriers->push_back(std::move(std::unique_ptr<cc_block_t>(new cc_block_t(version(), m__io, this, m__root))));
    }
    m__io->seek(_pos);
    f_carriers = true;
    return m_carriers.get();
}

std::string diag_0xb97f_t::meas_tail() {
    if (f_meas_tail)
        return m_meas_tail;
    std::streampos _pos = m__io->pos();
    m__io->seek(((rec_hdr() + 12) + 8));
    m_meas_tail = m__io->read_bytes((((version() == 0) ? (28) : (20)) - 8));
    m__io->seek(_pos);
    f_meas_tail = true;
    return m_meas_tail;
}

int32_t diag_0xb97f_t::timing_offset() {
    if (f_timing_offset)
        return m_timing_offset;
    std::streampos _pos = m__io->pos();
    m__io->seek((cfg_off() + 8));
    m_timing_offset = m__io->read_s4le();
    m__io->seek(_pos);
    f_timing_offset = true;
    return m_timing_offset;
}
