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

class diag_0xb97f_t : public kaitai::kstruct {

public:
    class cc_block_t;
    class nr_cell_t;

    diag_0xb97f_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = nullptr, diag_0xb97f_t* p__root = nullptr);

private:
    void _read();
    void _clean_up();

public:
    ~diag_0xb97f_t();

    class cc_block_t : public kaitai::kstruct {

    public:

        cc_block_t(uint16_t p_ver, kaitai::kstream* p__io, diag_0xb97f_t* p__parent = nullptr, diag_0xb97f_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~cc_block_t();

    private:
        bool f_beam_extra;
        int8_t m_beam_extra;

    public:
        int8_t beam_extra();

    private:
        bool f_num_cells_companion;
        uint8_t m_num_cells_companion;

    public:
        uint8_t num_cells_companion();

    private:
        bool f_is_v7;
        bool m_is_v7;

    public:
        bool is_v7();

    private:
        bool f_cell_size;
        int8_t m_cell_size;

    public:
        int8_t cell_size();

    private:
        bool f_num_cells;
        uint8_t m_num_cells;

    public:
        uint8_t num_cells();

    private:
        bool f_cc_meas;
        int8_t m_cc_meas;

    public:
        int8_t cc_meas();

    private:
        uint32_t m_nr_arfcn;
        uint8_t m_id_byte4;
        uint8_t m_id_byte5;
        uint16_t m_serving_pci;
        uint32_t m_flags;
        int32_t m_serving_rsrp_raw;
        int32_t m_serving_rsrp_b_raw;
        std::string m_meas_tail;
        std::unique_ptr<std::vector<std::unique_ptr<nr_cell_t>>> m_cells;
        uint16_t m_ver;
        diag_0xb97f_t* m__root;
        diag_0xb97f_t* m__parent;

    public:
        uint32_t nr_arfcn() const { return m_nr_arfcn; }
        uint8_t id_byte4() const { return m_id_byte4; }
        uint8_t id_byte5() const { return m_id_byte5; }
        uint16_t serving_pci() const { return m_serving_pci; }
        uint32_t flags() const { return m_flags; }
        int32_t serving_rsrp_raw() const { return m_serving_rsrp_raw; }
        int32_t serving_rsrp_b_raw() const { return m_serving_rsrp_b_raw; }
        std::string meas_tail() const { return m_meas_tail; }
        std::vector<std::unique_ptr<nr_cell_t>>* cells() const { return m_cells.get(); }
        uint16_t ver() const { return m_ver; }
        diag_0xb97f_t* _root() const { return m__root; }
        diag_0xb97f_t* _parent() const { return m__parent; }
    };

    class nr_cell_t : public kaitai::kstruct {

    public:

        nr_cell_t(uint16_t p_cell_size, uint16_t p_beam_extra, kaitai::kstream* p__io, diag_0xb97f_t::cc_block_t* p__parent = nullptr, diag_0xb97f_t* p__root = nullptr);

    private:
        void _read();
        void _clean_up();

    public:
        ~nr_cell_t();

    private:
        uint16_t m_pci;
        uint16_t m_pbch_sfn;
        uint32_t m_num_beams;
        int32_t m_rsrp_raw;
        int32_t m_rsrq_raw;
        std::unique_ptr<std::vector<int32_t>> m_beam_words;
        uint16_t m_cell_size;
        uint16_t m_beam_extra;
        diag_0xb97f_t* m__root;
        diag_0xb97f_t::cc_block_t* m__parent;

    public:
        uint16_t pci() const { return m_pci; }
        uint16_t pbch_sfn() const { return m_pbch_sfn; }
        uint32_t num_beams() const { return m_num_beams; }
        int32_t rsrp_raw() const { return m_rsrp_raw; }
        int32_t rsrq_raw() const { return m_rsrq_raw; }
        std::vector<int32_t>* beam_words() const { return m_beam_words.get(); }
        uint16_t cell_size() const { return m_cell_size; }
        uint16_t beam_extra() const { return m_beam_extra; }
        diag_0xb97f_t* _root() const { return m__root; }
        diag_0xb97f_t::cc_block_t* _parent() const { return m__parent; }
    };

private:
    bool f_config_word;
    uint32_t m_config_word;

public:
    uint32_t config_word();

private:
    bool f_serving_pci;
    uint16_t m_serving_pci;

public:
    uint16_t serving_pci();

private:
    bool f_nr_arfcn;
    uint32_t m_nr_arfcn;

public:
    uint32_t nr_arfcn();

private:
    bool f_cfg_off;
    int8_t m_cfg_off;

public:
    int8_t cfg_off();

private:
    bool f_num_cc;
    int32_t m_num_cc;

public:
    int32_t num_cc();

private:
    bool f_companion_off;
    int8_t m_companion_off;

public:
    int8_t companion_off();

private:
    bool f_frame_number;
    uint32_t m_frame_number;

public:
    uint32_t frame_number();

private:
    bool f_num_cells_companion;
    uint8_t m_num_cells_companion;

public:
    uint8_t num_cells_companion();

private:
    bool f_rec_hdr;
    int8_t m_rec_hdr;

public:
    int8_t rec_hdr();

private:
    bool f_is_v7;
    bool m_is_v7;

public:
    bool is_v7();

private:
    bool f_num_cells;
    uint8_t m_num_cells;

public:
    uint8_t num_cells();

private:
    bool f_num_cells_off;
    int8_t m_num_cells_off;

public:
    int8_t num_cells_off();

private:
    bool f_carriers;
    std::unique_ptr<std::vector<std::unique_ptr<cc_block_t>>> m_carriers;

public:
    std::vector<std::unique_ptr<cc_block_t>>* carriers();

private:
    bool f_meas_tail;
    std::string m_meas_tail;

public:
    std::string meas_tail();

private:
    bool f_timing_offset;
    int32_t m_timing_offset;

public:
    int32_t timing_offset();

private:
    uint16_t m_version;
    uint16_t m_sub_version;
    diag_0xb97f_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint16_t version() const { return m_version; }
    uint16_t sub_version() const { return m_sub_version; }
    diag_0xb97f_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};
