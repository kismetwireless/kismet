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

class diag_0xb192_t : public kaitai::kstruct {

public:
    class response_body_t;
    class request_body_t;
    class resp_hdr_modern_t;
    class subpacket_t;
    class req_hdr_legacy_t;
    class req_hdr_modern_t;
    class response_cell_t;
    class request_cell_t;
    class resp_hdr_legacy_t;

    diag_0xb192_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = nullptr, diag_0xb192_t* p__root = nullptr);

private:
    void _read();
    void _clean_up();

public:
    ~diag_0xb192_t();

    class response_body_t : public kaitai::kstruct {

    public:

        response_body_t(kaitai::kstream* p__io, diag_0xb192_t::subpacket_t* p__parent = nullptr, diag_0xb192_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~response_body_t();

    private:
        bool f_is_legacy;
        bool m_is_legacy;

    public:
        bool is_legacy();

    private:
        bool f_earfcn;
        int32_t m_earfcn;

    public:
        int32_t earfcn();

    private:
        bool f_num_cells;
        uint16_t m_num_cells;

    public:
        uint16_t num_cells();

    private:
        bool f_n_cells;
        int32_t m_n_cells;

    public:
        int32_t n_cells();

    private:
        bool f_cells_fit;
        int32_t m_cells_fit;

    public:
        int32_t cells_fit();

    private:
        std::unique_ptr<kaitai::kstruct> m_hdr;
        std::unique_ptr<std::vector<std::unique_ptr<response_cell_t>>> m_cells;
        diag_0xb192_t* m__root;
        diag_0xb192_t::subpacket_t* m__parent;

    public:
        kaitai::kstruct* hdr() const { return m_hdr.get(); }
        std::vector<std::unique_ptr<response_cell_t>>* cells() const { return m_cells.get(); }
        diag_0xb192_t* _root() const { return m__root; }
        diag_0xb192_t::subpacket_t* _parent() const { return m__parent; }
    };

    class request_body_t : public kaitai::kstruct {

    public:

        request_body_t(kaitai::kstream* p__io, diag_0xb192_t::subpacket_t* p__parent = nullptr, diag_0xb192_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~request_body_t();

    private:
        bool f_is_legacy;
        bool m_is_legacy;

    public:
        bool is_legacy();

    private:
        bool f_n_cells;
        int32_t m_n_cells;

    public:
        int32_t n_cells();

    private:
        std::unique_ptr<kaitai::kstruct> m_hdr;
        std::unique_ptr<std::vector<std::unique_ptr<request_cell_t>>> m_cells;
        diag_0xb192_t* m__root;
        diag_0xb192_t::subpacket_t* m__parent;

    public:
        kaitai::kstruct* hdr() const { return m_hdr.get(); }
        std::vector<std::unique_ptr<request_cell_t>>* cells() const { return m_cells.get(); }
        diag_0xb192_t* _root() const { return m__root; }
        diag_0xb192_t::subpacket_t* _parent() const { return m__parent; }
    };

    class resp_hdr_modern_t : public kaitai::kstruct {

    public:

        resp_hdr_modern_t(kaitai::kstream* p__io, diag_0xb192_t::response_body_t* p__parent = nullptr, diag_0xb192_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~resp_hdr_modern_t();

    private:
        uint32_t m_earfcn_raw;
        uint16_t m_num_cells;
        uint16_t m_reserved;
        diag_0xb192_t* m__root;
        diag_0xb192_t::response_body_t* m__parent;

    public:
        uint32_t earfcn_raw() const { return m_earfcn_raw; }
        uint16_t num_cells() const { return m_num_cells; }
        uint16_t reserved() const { return m_reserved; }
        diag_0xb192_t* _root() const { return m__root; }
        diag_0xb192_t::response_body_t* _parent() const { return m__parent; }
    };

    class subpacket_t : public kaitai::kstruct {

    public:

        subpacket_t(kaitai::kstream* p__io, diag_0xb192_t* p__parent = nullptr, diag_0xb192_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~subpacket_t();

    private:
        uint8_t m_sp_id;
        uint8_t m_sp_ver;
        uint16_t m_sp_size;
        std::unique_ptr<kaitai::kstruct> m_body;
        bool n_body;

    public:
        bool _is_null_body() { body(); return n_body; };

    private:
        diag_0xb192_t* m__root;
        diag_0xb192_t* m__parent;
        std::string m__raw_body;
        std::unique_ptr<kaitai::kstream> m__io__raw_body;

    public:
        uint8_t sp_id() const { return m_sp_id; }
        uint8_t sp_ver() const { return m_sp_ver; }
        uint16_t sp_size() const { return m_sp_size; }
        kaitai::kstruct* body() const { return m_body.get(); }
        diag_0xb192_t* _root() const { return m__root; }
        diag_0xb192_t* _parent() const { return m__parent; }
        std::string _raw_body() const { return m__raw_body; }
        kaitai::kstream* _io__raw_body() const { return m__io__raw_body.get(); }
    };

    class req_hdr_legacy_t : public kaitai::kstruct {

    public:

        req_hdr_legacy_t(kaitai::kstream* p__io, diag_0xb192_t::request_body_t* p__parent = nullptr, diag_0xb192_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~req_hdr_legacy_t();

    private:
        uint16_t m_earfcn;
        uint16_t m_flags;
        diag_0xb192_t* m__root;
        diag_0xb192_t::request_body_t* m__parent;

    public:
        uint16_t earfcn() const { return m_earfcn; }
        uint16_t flags() const { return m_flags; }
        diag_0xb192_t* _root() const { return m__root; }
        diag_0xb192_t::request_body_t* _parent() const { return m__parent; }
    };

    class req_hdr_modern_t : public kaitai::kstruct {

    public:

        req_hdr_modern_t(kaitai::kstream* p__io, diag_0xb192_t::request_body_t* p__parent = nullptr, diag_0xb192_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~req_hdr_modern_t();

    private:
        uint32_t m_earfcn_raw;
        uint16_t m_num_cells_flag;
        uint16_t m_reserved;
        diag_0xb192_t* m__root;
        diag_0xb192_t::request_body_t* m__parent;

    public:
        uint32_t earfcn_raw() const { return m_earfcn_raw; }
        uint16_t num_cells_flag() const { return m_num_cells_flag; }
        uint16_t reserved() const { return m_reserved; }
        diag_0xb192_t* _root() const { return m__root; }
        diag_0xb192_t::request_body_t* _parent() const { return m__parent; }
    };

    class response_cell_t : public kaitai::kstruct {

    public:

        response_cell_t(kaitai::kstream* p__io, diag_0xb192_t::response_body_t* p__parent = nullptr, diag_0xb192_t* p__root = nullptr);

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
        diag_0xb192_t* m__root;
        diag_0xb192_t::response_body_t* m__parent;

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
        diag_0xb192_t* _root() const { return m__root; }
        diag_0xb192_t::response_body_t* _parent() const { return m__parent; }
    };

    class request_cell_t : public kaitai::kstruct {

    public:

        request_cell_t(kaitai::kstream* p__io, diag_0xb192_t::request_body_t* p__parent = nullptr, diag_0xb192_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~request_cell_t();

    private:
        bool f_pci;
        int32_t m_pci;

    public:
        int32_t pci();

    private:
        uint32_t m_pci_raw;
        uint32_t m_timing0;
        uint32_t m_timing1;
        uint32_t m_reserved;
        diag_0xb192_t* m__root;
        diag_0xb192_t::request_body_t* m__parent;

    public:
        uint32_t pci_raw() const { return m_pci_raw; }
        uint32_t timing0() const { return m_timing0; }
        uint32_t timing1() const { return m_timing1; }
        uint32_t reserved() const { return m_reserved; }
        diag_0xb192_t* _root() const { return m__root; }
        diag_0xb192_t::request_body_t* _parent() const { return m__parent; }
    };

    class resp_hdr_legacy_t : public kaitai::kstruct {

    public:

        resp_hdr_legacy_t(kaitai::kstream* p__io, diag_0xb192_t::response_body_t* p__parent = nullptr, diag_0xb192_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~resp_hdr_legacy_t();

    private:
        uint16_t m_earfcn;
        uint16_t m_num_cells;
        diag_0xb192_t* m__root;
        diag_0xb192_t::response_body_t* m__parent;

    public:
        uint16_t earfcn() const { return m_earfcn; }
        uint16_t num_cells() const { return m_num_cells; }
        diag_0xb192_t* _root() const { return m__root; }
        diag_0xb192_t::response_body_t* _parent() const { return m__parent; }
    };

private:
    bool f_resp_idx;
    int32_t m_resp_idx;

public:
    int32_t resp_idx();

private:
    bool f_resp;
    diag_0xb192_t::response_body_t* m_resp;

public:
    diag_0xb192_t::response_body_t* resp();

private:
    bool f_sp_version;
    uint8_t m_sp_version;

public:
    uint8_t sp_version();

private:
    bool f_earfcn;
    int32_t m_earfcn;

public:
    int32_t earfcn();

private:
    bool f_num_cells;
    uint16_t m_num_cells;

public:
    uint16_t num_cells();

private:
    uint8_t m_version;
    uint8_t m_num_subpackets;
    uint16_t m_counter;
    std::unique_ptr<std::vector<std::unique_ptr<subpacket_t>>> m_subpackets;
    diag_0xb192_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint8_t version() const { return m_version; }
    uint8_t num_subpackets() const { return m_num_subpackets; }
    uint16_t counter() const { return m_counter; }
    std::vector<std::unique_ptr<subpacket_t>>* subpackets() const { return m_subpackets.get(); }
    diag_0xb192_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};
