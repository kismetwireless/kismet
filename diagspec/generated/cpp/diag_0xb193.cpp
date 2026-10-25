// SPDX-License-Identifier: GPL-2.0-or-later
// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "diag_0xb193.h"

diag_0xb193_t::diag_0xb193_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, diag_0xb193_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    m_body = nullptr;
    m__io__raw_body = nullptr;
    f_earfcn = false;
    _read();
}

void diag_0xb193_t::_read() {
    m_version = m__io->read_u1();
    m_num_subpackets = m__io->read_u1();
    m_counter = m__io->read_u2le();
    m_sp_id = m__io->read_u1();
    m_subpacket_version = m__io->read_u1();
    m_subpacket_size = m__io->read_u2le();
    m__raw_body = m__io->read_bytes_full();
    m__io__raw_body = std::unique_ptr<kaitai::kstream>(new kaitai::kstream(m__raw_body));
    m_body = std::unique_ptr<serving_body_t>(new serving_body_t(m__io__raw_body.get(), this, m__root));
}

diag_0xb193_t::~diag_0xb193_t() {
    _clean_up();
}

void diag_0xb193_t::_clean_up() {
}

diag_0xb193_t::serving_body_t::serving_body_t(kaitai::kstream* p__io, diag_0xb193_t* p__parent, diag_0xb193_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    m_cells = nullptr;
    f_is_v3_family = false;
    f_is_v18 = false;
    f_earfcn_u16 = false;
    f_is_fixed_slots = false;
    f_v18_pci_raw = false;
    f_slots_fit = false;
    f_earfcn_raw = false;
    f_earfcn = false;
    f_cells = false;
    f_num_cells = false;
    f_cell_base = false;
    f_v18_pci = false;
    f_v3_pci = false;
    f_is_inline_serving = false;
    f_cell_stride = false;
    f_cell_count = false;
    _read();
}

void diag_0xb193_t::serving_body_t::_read() {
}

diag_0xb193_t::serving_body_t::~serving_body_t() {
    _clean_up();
}

void diag_0xb193_t::serving_body_t::_clean_up() {
    if (f_earfcn_u16 && !n_earfcn_u16) {
    }
    if (f_v18_pci_raw && !n_v18_pci_raw) {
    }
    if (f_earfcn_raw && !n_earfcn_raw) {
    }
    if (f_cells && !n_cells) {
    }
    if (f_num_cells && !n_num_cells) {
    }
    if (f_v3_pci && !n_v3_pci) {
    }
}

bool diag_0xb193_t::serving_body_t::is_v3_family() {
    if (f_is_v3_family)
        return m_is_v3_family;
    m_is_v3_family =  ((_parent()->subpacket_version() == 3) || (_parent()->subpacket_version() == 6)) ;
    f_is_v3_family = true;
    return m_is_v3_family;
}

bool diag_0xb193_t::serving_body_t::is_v18() {
    if (f_is_v18)
        return m_is_v18;
    m_is_v18 = _parent()->subpacket_version() == 18;
    f_is_v18 = true;
    return m_is_v18;
}

uint16_t diag_0xb193_t::serving_body_t::earfcn_u16() {
    if (f_earfcn_u16)
        return m_earfcn_u16;
    n_earfcn_u16 = true;
    if (is_v3_family()) {
        n_earfcn_u16 = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(0);
        m_earfcn_u16 = m__io->read_u2le();
        m__io->seek(_pos);
        f_earfcn_u16 = true;
    }
    return m_earfcn_u16;
}

bool diag_0xb193_t::serving_body_t::is_fixed_slots() {
    if (f_is_fixed_slots)
        return m_is_fixed_slots;
    m_is_fixed_slots = _parent()->subpacket_version() == 40;
    f_is_fixed_slots = true;
    return m_is_fixed_slots;
}

uint32_t diag_0xb193_t::serving_body_t::v18_pci_raw() {
    if (f_v18_pci_raw)
        return m_v18_pci_raw;
    n_v18_pci_raw = true;
    if (is_v18()) {
        n_v18_pci_raw = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(4);
        m_v18_pci_raw = m__io->read_u4le();
        m__io->seek(_pos);
        f_v18_pci_raw = true;
    }
    return m_v18_pci_raw;
}

int32_t diag_0xb193_t::serving_body_t::slots_fit() {
    if (f_slots_fit)
        return m_slots_fit;
    n_slots_fit = true;
    if ( ((!(is_inline_serving())) && (cell_count() > 0) && (_io()->size() > cell_base()) && (cell_stride() >= 4)) ) {
        n_slots_fit = false;
        m_slots_fit = ((_io()->size() - cell_base()) / cell_stride());
    }
    f_slots_fit = true;
    return m_slots_fit;
}

uint32_t diag_0xb193_t::serving_body_t::earfcn_raw() {
    if (f_earfcn_raw)
        return m_earfcn_raw;
    n_earfcn_raw = true;
    if (!(is_v3_family())) {
        n_earfcn_raw = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(0);
        m_earfcn_raw = m__io->read_u4le();
        m__io->seek(_pos);
        f_earfcn_raw = true;
    }
    return m_earfcn_raw;
}

int32_t diag_0xb193_t::serving_body_t::earfcn() {
    if (f_earfcn)
        return m_earfcn;
    m_earfcn = ((is_v3_family()) ? (earfcn_u16()) : ((earfcn_raw() & 262143)));
    f_earfcn = true;
    return m_earfcn;
}

std::vector<std::string>* diag_0xb193_t::serving_body_t::cells() {
    if (f_cells)
        return m_cells.get();
    n_cells = true;
    if ( ((!(is_inline_serving())) && (cell_count() > 0) && (_io()->size() > cell_base()) && (cell_stride() >= 4)) ) {
        n_cells = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(cell_base());
        m_cells = std::unique_ptr<std::vector<std::string>>(new std::vector<std::string>());
        const int l_cells = ((cell_count() < slots_fit()) ? (cell_count()) : (slots_fit()));
        for (int i = 0; i < l_cells; i++) {
            m_cells->push_back(std::move(m__io->read_bytes(cell_stride())));
        }
        m__io->seek(_pos);
        f_cells = true;
    }
    return m_cells.get();
}

uint16_t diag_0xb193_t::serving_body_t::num_cells() {
    if (f_num_cells)
        return m_num_cells;
    n_num_cells = true;
    if (!(is_inline_serving())) {
        n_num_cells = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(4);
        m_num_cells = m__io->read_u2le();
        m__io->seek(_pos);
        f_num_cells = true;
    }
    return m_num_cells;
}

int8_t diag_0xb193_t::serving_body_t::cell_base() {
    if (f_cell_base)
        return m_cell_base;
    m_cell_base = ((_parent()->subpacket_version() == 48) ? (12) : (8));
    f_cell_base = true;
    return m_cell_base;
}

int32_t diag_0xb193_t::serving_body_t::v18_pci() {
    if (f_v18_pci)
        return m_v18_pci;
    n_v18_pci = true;
    if (is_v18()) {
        n_v18_pci = false;
        m_v18_pci = (v18_pci_raw() & 511);
    }
    f_v18_pci = true;
    return m_v18_pci;
}

uint16_t diag_0xb193_t::serving_body_t::v3_pci() {
    if (f_v3_pci)
        return m_v3_pci;
    n_v3_pci = true;
    if (is_v3_family()) {
        n_v3_pci = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(2);
        m_v3_pci = m__io->read_u2le();
        m__io->seek(_pos);
        f_v3_pci = true;
    }
    return m_v3_pci;
}

bool diag_0xb193_t::serving_body_t::is_inline_serving() {
    if (f_is_inline_serving)
        return m_is_inline_serving;
    m_is_inline_serving =  ((is_v3_family()) || (is_v18())) ;
    f_is_inline_serving = true;
    return m_is_inline_serving;
}

int32_t diag_0xb193_t::serving_body_t::cell_stride() {
    if (f_cell_stride)
        return m_cell_stride;
    n_cell_stride = true;
    if ( ((!(is_inline_serving())) && (cell_count() > 0) && (_io()->size() > cell_base())) ) {
        n_cell_stride = false;
        m_cell_stride = ((is_fixed_slots()) ? (132) : (((_io()->size() - cell_base()) / cell_count())));
    }
    f_cell_stride = true;
    return m_cell_stride;
}

int32_t diag_0xb193_t::serving_body_t::cell_count() {
    if (f_cell_count)
        return m_cell_count;
    n_cell_count = true;
    if (!(is_inline_serving())) {
        n_cell_count = false;
        m_cell_count = ((_parent()->subpacket_version() == 60) ? ((num_cells() & 7)) : (num_cells()));
    }
    f_cell_count = true;
    return m_cell_count;
}

int32_t diag_0xb193_t::earfcn() {
    if (f_earfcn)
        return m_earfcn;
    m_earfcn = body()->earfcn();
    f_earfcn = true;
    return m_earfcn;
}
