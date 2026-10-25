// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "kaitai/kaitaistruct.h"
#include <stdint.h>
#include <memory>
#include <vector>

#if KAITAI_STRUCT_VERSION < 9000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.9 or later is required"
#endif

class diag_0xb193_t : public kaitai::kstruct {

public:
    class serving_body_t;

    diag_0xb193_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = nullptr, diag_0xb193_t* p__root = nullptr);

private:
    void _read();
    void _clean_up();

public:
    ~diag_0xb193_t();

    class serving_body_t : public kaitai::kstruct {

    public:

        serving_body_t(kaitai::kstream* p__io, diag_0xb193_t* p__parent = nullptr, diag_0xb193_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~serving_body_t();

    private:
        bool f_is_v3_family;
        bool m_is_v3_family;

    public:
        bool is_v3_family();

    private:
        bool f_is_v18;
        bool m_is_v18;

    public:
        bool is_v18();

    private:
        bool f_earfcn_u16;
        uint16_t m_earfcn_u16;
        bool n_earfcn_u16;

    public:
        bool _is_null_earfcn_u16() { earfcn_u16(); return n_earfcn_u16; };

    private:

    public:
        uint16_t earfcn_u16();

    private:
        bool f_is_fixed_slots;
        bool m_is_fixed_slots;

    public:
        bool is_fixed_slots();

    private:
        bool f_v18_pci_raw;
        uint32_t m_v18_pci_raw;
        bool n_v18_pci_raw;

    public:
        bool _is_null_v18_pci_raw() { v18_pci_raw(); return n_v18_pci_raw; };

    private:

    public:
        uint32_t v18_pci_raw();

    private:
        bool f_slots_fit;
        int32_t m_slots_fit;
        bool n_slots_fit;

    public:
        bool _is_null_slots_fit() { slots_fit(); return n_slots_fit; };

    private:

    public:
        int32_t slots_fit();

    private:
        bool f_earfcn_raw;
        uint32_t m_earfcn_raw;
        bool n_earfcn_raw;

    public:
        bool _is_null_earfcn_raw() { earfcn_raw(); return n_earfcn_raw; };

    private:

    public:
        uint32_t earfcn_raw();

    private:
        bool f_earfcn;
        int32_t m_earfcn;

    public:
        int32_t earfcn();

    private:
        bool f_cells;
        std::unique_ptr<std::vector<std::string>> m_cells;
        bool n_cells;

    public:
        bool _is_null_cells() { cells(); return n_cells; };

    private:

    public:
        std::vector<std::string>* cells();

    private:
        bool f_num_cells;
        uint16_t m_num_cells;
        bool n_num_cells;

    public:
        bool _is_null_num_cells() { num_cells(); return n_num_cells; };

    private:

    public:
        uint16_t num_cells();

    private:
        bool f_cell_base;
        int8_t m_cell_base;

    public:
        int8_t cell_base();

    private:
        bool f_v18_pci;
        int32_t m_v18_pci;
        bool n_v18_pci;

    public:
        bool _is_null_v18_pci() { v18_pci(); return n_v18_pci; };

    private:

    public:
        int32_t v18_pci();

    private:
        bool f_v3_pci;
        uint16_t m_v3_pci;
        bool n_v3_pci;

    public:
        bool _is_null_v3_pci() { v3_pci(); return n_v3_pci; };

    private:

    public:
        uint16_t v3_pci();

    private:
        bool f_is_inline_serving;
        bool m_is_inline_serving;

    public:
        bool is_inline_serving();

    private:
        bool f_cell_stride;
        int32_t m_cell_stride;
        bool n_cell_stride;

    public:
        bool _is_null_cell_stride() { cell_stride(); return n_cell_stride; };

    private:

    public:
        int32_t cell_stride();

    private:
        bool f_cell_count;
        int32_t m_cell_count;
        bool n_cell_count;

    public:
        bool _is_null_cell_count() { cell_count(); return n_cell_count; };

    private:

    public:
        int32_t cell_count();

    private:
        diag_0xb193_t* m__root;
        diag_0xb193_t* m__parent;

    public:
        diag_0xb193_t* _root() const { return m__root; }
        diag_0xb193_t* _parent() const { return m__parent; }
    };

private:
    bool f_earfcn;
    int32_t m_earfcn;

public:
    int32_t earfcn();

private:
    uint8_t m_version;
    uint8_t m_num_subpackets;
    uint16_t m_counter;
    uint8_t m_sp_id;
    uint8_t m_subpacket_version;
    uint16_t m_subpacket_size;
    std::unique_ptr<serving_body_t> m_body;
    diag_0xb193_t* m__root;
    kaitai::kstruct* m__parent;
    std::string m__raw_body;
    std::unique_ptr<kaitai::kstream> m__io__raw_body;

public:
    uint8_t version() const { return m_version; }
    uint8_t num_subpackets() const { return m_num_subpackets; }
    uint16_t counter() const { return m_counter; }
    uint8_t sp_id() const { return m_sp_id; }
    uint8_t subpacket_version() const { return m_subpacket_version; }
    uint16_t subpacket_size() const { return m_subpacket_size; }
    serving_body_t* body() const { return m_body.get(); }
    diag_0xb193_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
    std::string _raw_body() const { return m__raw_body; }
    kaitai::kstream* _io__raw_body() const { return m__io__raw_body.get(); }
};
