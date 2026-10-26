// SPDX-License-Identifier: GPL-2.0-or-later
// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "diag_0xb192.h"

diag_0xb192_t::diag_0xb192_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, diag_0xb192_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    m_subpackets = nullptr;
    f_resp_idx = false;
    f_resp = false;
    f_sp_version = false;
    f_earfcn = false;
    f_num_cells = false;
    _read();
}

void diag_0xb192_t::_read() {
    m_version = m__io->read_u1();
    m_num_subpackets = m__io->read_u1();
    m_counter = m__io->read_u2le();
    m_subpackets = std::unique_ptr<std::vector<std::unique_ptr<subpacket_t>>>(new std::vector<std::unique_ptr<subpacket_t>>());
    const int l_subpackets = num_subpackets();
    for (int i = 0; i < l_subpackets; i++) {
        m_subpackets->push_back(std::move(std::unique_ptr<subpacket_t>(new subpacket_t(m__io, this, m__root))));
    }
}

diag_0xb192_t::~diag_0xb192_t() {
    _clean_up();
}

void diag_0xb192_t::_clean_up() {
}

diag_0xb192_t::response_body_t::response_body_t(kaitai::kstream* p__io, diag_0xb192_t::subpacket_t* p__parent, diag_0xb192_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    m_cells = nullptr;
    f_is_legacy = false;
    f_earfcn = false;
    f_num_cells = false;
    f_n_cells = false;
    f_cells_fit = false;
    _read();
}

void diag_0xb192_t::response_body_t::_read() {
    switch (_parent()->sp_ver()) {
    case 2: {
        m_hdr = std::unique_ptr<resp_hdr_legacy_t>(new resp_hdr_legacy_t(m__io, this, m__root));
        break;
    }
    default: {
        m_hdr = std::unique_ptr<resp_hdr_modern_t>(new resp_hdr_modern_t(m__io, this, m__root));
        break;
    }
    }
    m_cells = std::unique_ptr<std::vector<std::unique_ptr<response_cell_t>>>(new std::vector<std::unique_ptr<response_cell_t>>());
    const int l_cells = n_cells();
    for (int i = 0; i < l_cells; i++) {
        m_cells->push_back(std::move(std::unique_ptr<response_cell_t>(new response_cell_t(m__io, this, m__root))));
    }
}

diag_0xb192_t::response_body_t::~response_body_t() {
    _clean_up();
}

void diag_0xb192_t::response_body_t::_clean_up() {
}

bool diag_0xb192_t::response_body_t::is_legacy() {
    if (f_is_legacy)
        return m_is_legacy;
    m_is_legacy = _parent()->sp_ver() == 2;
    f_is_legacy = true;
    return m_is_legacy;
}

int32_t diag_0xb192_t::response_body_t::earfcn() {
    if (f_earfcn)
        return m_earfcn;
    m_earfcn = ((is_legacy()) ? (static_cast<diag_0xb192_t::resp_hdr_legacy_t*>(hdr())->earfcn()) : ((static_cast<diag_0xb192_t::resp_hdr_modern_t*>(hdr())->earfcn_raw() & 262143)));
    f_earfcn = true;
    return m_earfcn;
}

uint16_t diag_0xb192_t::response_body_t::num_cells() {
    if (f_num_cells)
        return m_num_cells;
    m_num_cells = ((is_legacy()) ? (static_cast<diag_0xb192_t::resp_hdr_legacy_t*>(hdr())->num_cells()) : (static_cast<diag_0xb192_t::resp_hdr_modern_t*>(hdr())->num_cells()));
    f_num_cells = true;
    return m_num_cells;
}

int32_t diag_0xb192_t::response_body_t::n_cells() {
    if (f_n_cells)
        return m_n_cells;
    m_n_cells = ((num_cells() < cells_fit()) ? (num_cells()) : (cells_fit()));
    f_n_cells = true;
    return m_n_cells;
}

int32_t diag_0xb192_t::response_body_t::cells_fit() {
    if (f_cells_fit)
        return m_cells_fit;
    m_cells_fit = ((_io()->size() - ((is_legacy()) ? (4) : (8))) / 52);
    f_cells_fit = true;
    return m_cells_fit;
}

diag_0xb192_t::request_body_t::request_body_t(kaitai::kstream* p__io, diag_0xb192_t::subpacket_t* p__parent, diag_0xb192_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    m_cells = nullptr;
    f_is_legacy = false;
    f_n_cells = false;
    _read();
}

void diag_0xb192_t::request_body_t::_read() {
    switch (_parent()->sp_ver()) {
    case 1: {
        m_hdr = std::unique_ptr<req_hdr_legacy_t>(new req_hdr_legacy_t(m__io, this, m__root));
        break;
    }
    default: {
        m_hdr = std::unique_ptr<req_hdr_modern_t>(new req_hdr_modern_t(m__io, this, m__root));
        break;
    }
    }
    m_cells = std::unique_ptr<std::vector<std::unique_ptr<request_cell_t>>>(new std::vector<std::unique_ptr<request_cell_t>>());
    const int l_cells = n_cells();
    for (int i = 0; i < l_cells; i++) {
        m_cells->push_back(std::move(std::unique_ptr<request_cell_t>(new request_cell_t(m__io, this, m__root))));
    }
}

diag_0xb192_t::request_body_t::~request_body_t() {
    _clean_up();
}

void diag_0xb192_t::request_body_t::_clean_up() {
}

bool diag_0xb192_t::request_body_t::is_legacy() {
    if (f_is_legacy)
        return m_is_legacy;
    m_is_legacy = _parent()->sp_ver() == 1;
    f_is_legacy = true;
    return m_is_legacy;
}

int32_t diag_0xb192_t::request_body_t::n_cells() {
    if (f_n_cells)
        return m_n_cells;
    m_n_cells = ((_io()->size() - ((is_legacy()) ? (4) : (8))) / 16);
    f_n_cells = true;
    return m_n_cells;
}

diag_0xb192_t::resp_hdr_modern_t::resp_hdr_modern_t(kaitai::kstream* p__io, diag_0xb192_t::response_body_t* p__parent, diag_0xb192_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    _read();
}

void diag_0xb192_t::resp_hdr_modern_t::_read() {
    m_earfcn_raw = m__io->read_u4le();
    m_num_cells = m__io->read_u2le();
    m_reserved = m__io->read_u2le();
}

diag_0xb192_t::resp_hdr_modern_t::~resp_hdr_modern_t() {
    _clean_up();
}

void diag_0xb192_t::resp_hdr_modern_t::_clean_up() {
}

diag_0xb192_t::subpacket_t::subpacket_t(kaitai::kstream* p__io, diag_0xb192_t* p__parent, diag_0xb192_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    m__io__raw_body = nullptr;
    _read();
}

void diag_0xb192_t::subpacket_t::_read() {
    m_sp_id = m__io->read_u1();
    m_sp_ver = m__io->read_u1();
    m_sp_size = m__io->read_u2le();
    n_body = true;
    switch (sp_id()) {
    case 26: {
        n_body = false;
        m__raw_body = m__io->read_bytes((sp_size() - 4));
        m__io__raw_body = std::unique_ptr<kaitai::kstream>(new kaitai::kstream(m__raw_body));
        m_body = std::unique_ptr<request_body_t>(new request_body_t(m__io__raw_body.get(), this, m__root));
        break;
    }
    case 27: {
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

diag_0xb192_t::subpacket_t::~subpacket_t() {
    _clean_up();
}

void diag_0xb192_t::subpacket_t::_clean_up() {
    if (!n_body) {
    }
}

diag_0xb192_t::req_hdr_legacy_t::req_hdr_legacy_t(kaitai::kstream* p__io, diag_0xb192_t::request_body_t* p__parent, diag_0xb192_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    _read();
}

void diag_0xb192_t::req_hdr_legacy_t::_read() {
    m_earfcn = m__io->read_u2le();
    m_flags = m__io->read_u2le();
}

diag_0xb192_t::req_hdr_legacy_t::~req_hdr_legacy_t() {
    _clean_up();
}

void diag_0xb192_t::req_hdr_legacy_t::_clean_up() {
}

diag_0xb192_t::req_hdr_modern_t::req_hdr_modern_t(kaitai::kstream* p__io, diag_0xb192_t::request_body_t* p__parent, diag_0xb192_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    _read();
}

void diag_0xb192_t::req_hdr_modern_t::_read() {
    m_earfcn_raw = m__io->read_u4le();
    m_num_cells_flag = m__io->read_u2le();
    m_reserved = m__io->read_u2le();
}

diag_0xb192_t::req_hdr_modern_t::~req_hdr_modern_t() {
    _clean_up();
}

void diag_0xb192_t::req_hdr_modern_t::_clean_up() {
}

diag_0xb192_t::response_cell_t::response_cell_t(kaitai::kstream* p__io, diag_0xb192_t::response_body_t* p__parent, diag_0xb192_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    f_pci = false;
    _read();
}

void diag_0xb192_t::response_cell_t::_read() {
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

diag_0xb192_t::response_cell_t::~response_cell_t() {
    _clean_up();
}

void diag_0xb192_t::response_cell_t::_clean_up() {
}

int32_t diag_0xb192_t::response_cell_t::pci() {
    if (f_pci)
        return m_pci;
    m_pci = (pci_raw() & 511);
    f_pci = true;
    return m_pci;
}

diag_0xb192_t::request_cell_t::request_cell_t(kaitai::kstream* p__io, diag_0xb192_t::request_body_t* p__parent, diag_0xb192_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    f_pci = false;
    _read();
}

void diag_0xb192_t::request_cell_t::_read() {
    m_pci_raw = m__io->read_u4le();
    m_timing0 = m__io->read_u4le();
    m_timing1 = m__io->read_u4le();
    m_reserved = m__io->read_u4le();
}

diag_0xb192_t::request_cell_t::~request_cell_t() {
    _clean_up();
}

void diag_0xb192_t::request_cell_t::_clean_up() {
}

int32_t diag_0xb192_t::request_cell_t::pci() {
    if (f_pci)
        return m_pci;
    m_pci = (pci_raw() & 511);
    f_pci = true;
    return m_pci;
}

diag_0xb192_t::resp_hdr_legacy_t::resp_hdr_legacy_t(kaitai::kstream* p__io, diag_0xb192_t::response_body_t* p__parent, diag_0xb192_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    _read();
}

void diag_0xb192_t::resp_hdr_legacy_t::_read() {
    m_earfcn = m__io->read_u2le();
    m_num_cells = m__io->read_u2le();
}

diag_0xb192_t::resp_hdr_legacy_t::~resp_hdr_legacy_t() {
    _clean_up();
}

void diag_0xb192_t::resp_hdr_legacy_t::_clean_up() {
}

int32_t diag_0xb192_t::resp_idx() {
    if (f_resp_idx)
        return m_resp_idx;
    m_resp_idx = ((subpackets()->at(0)->sp_id() == 27) ? (0) : ((num_subpackets() - 1)));
    f_resp_idx = true;
    return m_resp_idx;
}

diag_0xb192_t::response_body_t* diag_0xb192_t::resp() {
    if (f_resp)
        return m_resp;
    m_resp = static_cast<diag_0xb192_t::response_body_t*>(subpackets()->at(resp_idx())->body());
    f_resp = true;
    return m_resp;
}

uint8_t diag_0xb192_t::sp_version() {
    if (f_sp_version)
        return m_sp_version;
    m_sp_version = subpackets()->at(resp_idx())->sp_ver();
    f_sp_version = true;
    return m_sp_version;
}

int32_t diag_0xb192_t::earfcn() {
    if (f_earfcn)
        return m_earfcn;
    m_earfcn = resp()->earfcn();
    f_earfcn = true;
    return m_earfcn;
}

uint16_t diag_0xb192_t::num_cells() {
    if (f_num_cells)
        return m_num_cells;
    m_num_cells = resp()->num_cells();
    f_num_cells = true;
    return m_num_cells;
}
