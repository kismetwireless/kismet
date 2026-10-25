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

class diag_0xb195_t : public kaitai::kstruct {

public:
    class subpacket_t;
    class response_body_t;
    class response_cell_t;

    diag_0xb195_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = nullptr, diag_0xb195_t* p__root = nullptr);

private:
    void _read();
    void _clean_up();

public:
    ~diag_0xb195_t();

    class subpacket_t : public kaitai::kstruct {

    public:

        subpacket_t(kaitai::kstream* p__io, diag_0xb195_t* p__parent = nullptr, diag_0xb195_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~subpacket_t();

    private:
        uint8_t m_sp_id;
        uint8_t m_sp_ver;
        uint16_t m_sp_size;
        std::unique_ptr<response_body_t> m_body;
        bool n_body;

    public:
        bool _is_null_body() { body(); return n_body; };

    private:
        diag_0xb195_t* m__root;
        diag_0xb195_t* m__parent;
        std::string m__raw_body;
        std::unique_ptr<kaitai::kstream> m__io__raw_body;

    public:
        uint8_t sp_id() const { return m_sp_id; }
        uint8_t sp_ver() const { return m_sp_ver; }
        uint16_t sp_size() const { return m_sp_size; }
        response_body_t* body() const { return m_body.get(); }
        diag_0xb195_t* _root() const { return m__root; }
        diag_0xb195_t* _parent() const { return m__parent; }
        std::string _raw_body() const { return m__raw_body; }
        kaitai::kstream* _io__raw_body() const { return m__io__raw_body.get(); }
    };

    class response_body_t : public kaitai::kstruct {

    public:

        response_body_t(kaitai::kstream* p__io, diag_0xb195_t::subpacket_t* p__parent = nullptr, diag_0xb195_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~response_body_t();

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
        bool f_hdr_size;
        int8_t m_hdr_size;

    public:
        int8_t hdr_size();

    private:
        bool f_body_cells;
        int32_t m_body_cells;

    public:
        int32_t body_cells();

    private:
        bool f_num_cells_word;
        uint16_t m_num_cells_word;

    public:
        uint16_t num_cells_word();

    private:
        bool f_is_short_hdr;
        bool m_is_short_hdr;

    public:
        bool is_short_hdr();

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
        bool f_sf_counter;
        uint16_t m_sf_counter;
        bool n_sf_counter;

    public:
        bool _is_null_sf_counter() { sf_counter(); return n_sf_counter; };

    private:

    public:
        uint16_t sf_counter();

    private:
        bool f_cells;
        std::unique_ptr<std::vector<std::unique_ptr<response_cell_t>>> m_cells;

    public:
        std::vector<std::unique_ptr<response_cell_t>>* cells();

    private:
        bool f_num_cells;
        int32_t m_num_cells;

    public:
        int32_t num_cells();

    private:
        diag_0xb195_t* m__root;
        diag_0xb195_t::subpacket_t* m__parent;
        std::unique_ptr<std::vector<std::string>> m__raw_cells;
        std::unique_ptr<std::vector<std::unique_ptr<kaitai::kstream>>> m__io__raw_cells;

    public:
        diag_0xb195_t* _root() const { return m__root; }
        diag_0xb195_t::subpacket_t* _parent() const { return m__parent; }
        std::vector<std::string>* _raw_cells() const { return m__raw_cells.get(); }
        std::vector<std::unique_ptr<kaitai::kstream>>* _io__raw_cells() const { return m__io__raw_cells.get(); }
    };

    class response_cell_t : public kaitai::kstruct {

    public:

        response_cell_t(kaitai::kstream* p__io, diag_0xb195_t::response_body_t* p__parent = nullptr, diag_0xb195_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~response_cell_t();

    private:
        bool f_pci;
        int32_t m_pci;

    public:
        int32_t pci();

    private:
        uint32_t m_pci_raw;
        uint32_t m_energy0;
        uint32_t m_energy1;
        uint32_t m_energy2;
        uint32_t m_energy_wide0;
        uint32_t m_energy_wide1;
        uint16_t m_meas_index;
        uint16_t m_reserved0;
        uint32_t m_energy_filt;
        uint32_t m_reserved1;
        uint16_t m_aux0;
        uint16_t m_aux1;
        uint32_t m_timing0;
        uint32_t m_timing1;
        uint32_t m_reserved2;
        diag_0xb195_t* m__root;
        diag_0xb195_t::response_body_t* m__parent;

    public:
        uint32_t pci_raw() const { return m_pci_raw; }
        uint32_t energy0() const { return m_energy0; }
        uint32_t energy1() const { return m_energy1; }
        uint32_t energy2() const { return m_energy2; }
        uint32_t energy_wide0() const { return m_energy_wide0; }
        uint32_t energy_wide1() const { return m_energy_wide1; }
        uint16_t meas_index() const { return m_meas_index; }
        uint16_t reserved0() const { return m_reserved0; }
        uint32_t energy_filt() const { return m_energy_filt; }
        uint32_t reserved1() const { return m_reserved1; }
        uint16_t aux0() const { return m_aux0; }
        uint16_t aux1() const { return m_aux1; }
        uint32_t timing0() const { return m_timing0; }
        uint32_t timing1() const { return m_timing1; }
        uint32_t reserved2() const { return m_reserved2; }
        diag_0xb195_t* _root() const { return m__root; }
        diag_0xb195_t::response_body_t* _parent() const { return m__parent; }
    };

private:
    bool f_resp_idx;
    int32_t m_resp_idx;

public:
    int32_t resp_idx();

private:
    bool f_resp;
    diag_0xb195_t::response_body_t* m_resp;

public:
    diag_0xb195_t::response_body_t* resp();

private:
    bool f_earfcn;
    int32_t m_earfcn;

public:
    int32_t earfcn();

private:
    bool f_num_cells;
    int32_t m_num_cells;

public:
    int32_t num_cells();

private:
    uint8_t m_version;
    uint8_t m_num_subpackets;
    uint16_t m_counter;
    std::unique_ptr<std::vector<std::unique_ptr<subpacket_t>>> m_subpackets;
    diag_0xb195_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t version() const { return m_version; }
    uint8_t num_subpackets() const { return m_num_subpackets; }
    uint16_t counter() const { return m_counter; }
    std::vector<std::unique_ptr<subpacket_t>>* subpackets() const { return m_subpackets.get(); }
    diag_0xb195_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};
