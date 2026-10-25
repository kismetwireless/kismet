// SPDX-License-Identifier: GPL-2.0-or-later
// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "diag_0xb195.h"

diag_0xb195_t::diag_0xb195_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, diag_0xb195_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    m_subpackets = nullptr;
    f_resp_idx = false;
    f_resp = false;
    f_earfcn = false;
    f_num_cells = false;
    _read();
}

void diag_0xb195_t::_read() {
    m_version = m__io->read_u1();
    m_num_subpackets = m__io->read_u1();
    m_counter = m__io->read_u2le();
    m_subpackets = std::unique_ptr<std::vector<std::unique_ptr<subpacket_t>>>(new std::vector<std::unique_ptr<subpacket_t>>());
    const int l_subpackets = num_subpackets();
    for (int i = 0; i < l_subpackets; i++) {
        m_subpackets->push_back(std::move(std::unique_ptr<subpacket_t>(new subpacket_t(m__io, this, m__root))));
    }
}

diag_0xb195_t::~diag_0xb195_t() {
    _clean_up();
}

void diag_0xb195_t::_clean_up() {
}

diag_0xb195_t::subpacket_t::subpacket_t(kaitai::kstream* p__io, diag_0xb195_t* p__parent, diag_0xb195_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    m__io__raw_body = nullptr;
    _read();
}

void diag_0xb195_t::subpacket_t::_read() {
    m_sp_id = m__io->read_u1();
    m_sp_ver = m__io->read_u1();
    m_sp_size = m__io->read_u2le();
    n_body = true;
    switch (sp_id()) {
    case 31: {
        n_body = false;
        m__raw_body = m__io->read_bytes((sp_size() - 4));
        m__io__raw_body = std::unique_ptr<kaitai::kstream>(new kaitai::kstream(m__raw_body));
        m_body = std::unique_ptr<response_body_t>(new response_body_t(m__io__raw_body.get(), this, m__root));
        break;
    }
    default: {
        m__raw_body = m__io->read_bytes((sp_size() - 4));
        break;
    }
    }
}

diag_0xb195_t::subpacket_t::~subpacket_t() {
    _clean_up();
}

void diag_0xb195_t::subpacket_t::_clean_up() {
    if (!n_body) {
    }
}

diag_0xb195_t::response_body_t::response_body_t(kaitai::kstream* p__io, diag_0xb195_t::subpacket_t* p__parent, diag_0xb195_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    m_cells = nullptr;
    m__raw_cells = nullptr;
    m__io__raw_cells = nullptr;
    f_earfcn_u16 = false;
    f_hdr_size = false;
    f_body_cells = false;
    f_num_cells_word = false;
    f_is_short_hdr = false;
    f_earfcn_raw = false;
    f_earfcn = false;
    f_sf_counter = false;
    f_cells = false;
    f_num_cells = false;
    _read();
}

void diag_0xb195_t::response_body_t::_read() {
}

diag_0xb195_t::response_body_t::~response_body_t() {
    _clean_up();
}

void diag_0xb195_t::response_body_t::_clean_up() {
    if (f_earfcn_u16 && !n_earfcn_u16) {
    }
    if (f_num_cells_word) {
    }
    if (f_earfcn_raw && !n_earfcn_raw) {
    }
    if (f_sf_counter && !n_sf_counter) {
    }
    if (f_cells) {
    }
}

uint16_t diag_0xb195_t::response_body_t::earfcn_u16() {
    if (f_earfcn_u16)
        return m_earfcn_u16;
    n_earfcn_u16 = true;
    if (is_short_hdr()) {
        n_earfcn_u16 = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(0);
        m_earfcn_u16 = m__io->read_u2le();
        m__io->seek(_pos);
        f_earfcn_u16 = true;
    }
    return m_earfcn_u16;
}

int8_t diag_0xb195_t::response_body_t::hdr_size() {
    if (f_hdr_size)
        return m_hdr_size;
    m_hdr_size = ((is_short_hdr()) ? (4) : (8));
    f_hdr_size = true;
    return m_hdr_size;
}

int32_t diag_0xb195_t::response_body_t::body_cells() {
    if (f_body_cells)
        return m_body_cells;
    m_body_cells = ((_io()->size() - hdr_size()) / 52);
    f_body_cells = true;
    return m_body_cells;
}

uint16_t diag_0xb195_t::response_body_t::num_cells_word() {
    if (f_num_cells_word)
        return m_num_cells_word;
    std::streampos _pos = m__io->pos();
    m__io->seek(((is_short_hdr()) ? (2) : (4)));
    m_num_cells_word = m__io->read_u2le();
    m__io->seek(_pos);
    f_num_cells_word = true;
    return m_num_cells_word;
}

bool diag_0xb195_t::response_body_t::is_short_hdr() {
    if (f_is_short_hdr)
        return m_is_short_hdr;
    m_is_short_hdr = _parent()->sp_ver() == 3;
    f_is_short_hdr = true;
    return m_is_short_hdr;
}

uint32_t diag_0xb195_t::response_body_t::earfcn_raw() {
    if (f_earfcn_raw)
        return m_earfcn_raw;
    n_earfcn_raw = true;
    if (!(is_short_hdr())) {
        n_earfcn_raw = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(0);
        m_earfcn_raw = m__io->read_u4le();
        m__io->seek(_pos);
        f_earfcn_raw = true;
    }
    return m_earfcn_raw;
}

int32_t diag_0xb195_t::response_body_t::earfcn() {
    if (f_earfcn)
        return m_earfcn;
    m_earfcn = ((is_short_hdr()) ? (earfcn_u16()) : ((earfcn_raw() & 262143)));
    f_earfcn = true;
    return m_earfcn;
}

uint16_t diag_0xb195_t::response_body_t::sf_counter() {
    if (f_sf_counter)
        return m_sf_counter;
    n_sf_counter = true;
    if (!(is_short_hdr())) {
        n_sf_counter = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(6);
        m_sf_counter = m__io->read_u2le();
        m__io->seek(_pos);
        f_sf_counter = true;
    }
    return m_sf_counter;
}

std::vector<std::unique_ptr<diag_0xb195_t::response_cell_t>>* diag_0xb195_t::response_body_t::cells() {
    if (f_cells)
        return m_cells.get();
    std::streampos _pos = m__io->pos();
    m__io->seek(hdr_size());
    m__raw_cells = std::unique_ptr<std::vector<std::string>>(new std::vector<std::string>());
    m__io__raw_cells = std::unique_ptr<std::vector<std::unique_ptr<kaitai::kstream>>>(new std::vector<std::unique_ptr<kaitai::kstream>>());
    m_cells = std::unique_ptr<std::vector<std::unique_ptr<response_cell_t>>>(new std::vector<std::unique_ptr<response_cell_t>>());
    const int l_cells = num_cells();
    for (int i = 0; i < l_cells; i++) {
        m__raw_cells->push_back(std::move(m__io->read_bytes(52)));
        kaitai::kstream* io__raw_cells = new kaitai::kstream(m__raw_cells->at(m__raw_cells->size() - 1));
        m__io__raw_cells->emplace_back(io__raw_cells);
        m_cells->push_back(std::move(std::unique_ptr<response_cell_t>(new response_cell_t(io__raw_cells, this, m__root))));
    }
    m__io->seek(_pos);
    f_cells = true;
    return m_cells.get();
}

int32_t diag_0xb195_t::response_body_t::num_cells() {
    if (f_num_cells)
        return m_num_cells;
    m_num_cells = (((num_cells_word() & 127) < body_cells()) ? ((num_cells_word() & 127)) : (body_cells()));
    f_num_cells = true;
    return m_num_cells;
}

diag_0xb195_t::response_cell_t::response_cell_t(kaitai::kstream* p__io, diag_0xb195_t::response_body_t* p__parent, diag_0xb195_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    f_pci = false;
    _read();
}

void diag_0xb195_t::response_cell_t::_read() {
    m_pci_raw = m__io->read_u4le();
    m_energy0 = m__io->read_u4le();
    m_energy1 = m__io->read_u4le();
    m_energy2 = m__io->read_u4le();
    m_energy_wide0 = m__io->read_u4le();
    m_energy_wide1 = m__io->read_u4le();
    m_meas_index = m__io->read_u2le();
    m_reserved0 = m__io->read_u2le();
    m_energy_filt = m__io->read_u4le();
    m_reserved1 = m__io->read_u4le();
    m_aux0 = m__io->read_u2le();
    m_aux1 = m__io->read_u2le();
    m_timing0 = m__io->read_u4le();
    m_timing1 = m__io->read_u4le();
    m_reserved2 = m__io->read_u4le();
}

diag_0xb195_t::response_cell_t::~response_cell_t() {
    _clean_up();
}

void diag_0xb195_t::response_cell_t::_clean_up() {
}

int32_t diag_0xb195_t::response_cell_t::pci() {
    if (f_pci)
        return m_pci;
    m_pci = (pci_raw() & 511);
    f_pci = true;
    return m_pci;
}

int32_t diag_0xb195_t::resp_idx() {
    if (f_resp_idx)
        return m_resp_idx;
    m_resp_idx = ((subpackets()->at(0)->sp_id() == 31) ? (0) : ((num_subpackets() - 1)));
    f_resp_idx = true;
    return m_resp_idx;
}

diag_0xb195_t::response_body_t* diag_0xb195_t::resp() {
    if (f_resp)
        return m_resp;
    m_resp = static_cast<diag_0xb195_t::response_body_t*>(subpackets()->at(resp_idx())->body());
    f_resp = true;
    return m_resp;
}

int32_t diag_0xb195_t::earfcn() {
    if (f_earfcn)
        return m_earfcn;
    m_earfcn = resp()->earfcn();
    f_earfcn = true;
    return m_earfcn;
}

int32_t diag_0xb195_t::num_cells() {
    if (f_num_cells)
        return m_num_cells;
    m_num_cells = resp()->num_cells();
    f_num_cells = true;
    return m_num_cells;
}
