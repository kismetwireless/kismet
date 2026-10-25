// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "kaitai/kaitaistruct.h"
#include <stdint.h>
#include <memory>

#if KAITAI_STRUCT_VERSION < 9000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.9 or later is required"
#endif

class diag_0xb821_t : public kaitai::kstruct {

public:

    diag_0xb821_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = nullptr, diag_0xb821_t* p__root = nullptr);

private:
    void _read();
    void _clean_up();

public:
    ~diag_0xb821_t();

private:
    bool f_msg_len_offset;
    int8_t m_msg_len_offset;

public:
    int8_t msg_len_offset();

private:
    bool f_sfn_offset;
    int8_t m_sfn_offset;

public:
    int8_t sfn_offset();

private:
    bool f_cell_global_id;
    uint64_t m_cell_global_id;
    bool n_cell_global_id;

public:
    bool _is_null_cell_global_id() { cell_global_id(); return n_cell_global_id; };

private:

public:
    uint64_t cell_global_id();

private:
    bool f_sfn_subfn;
    uint16_t m_sfn_subfn;

public:
    uint16_t sfn_subfn();

private:
    bool f_sib_mask;
    uint32_t m_sib_mask;

public:
    uint32_t sib_mask();

private:
    bool f_pdu_id_offset;
    int8_t m_pdu_id_offset;

public:
    int8_t pdu_id_offset();

private:
    bool f_sfn_has_4th;
    bool m_sfn_has_4th;

public:
    bool sfn_has_4th();

private:
    bool f_msg_data_len;
    uint16_t m_msg_data_len;

public:
    uint16_t msg_data_len();

private:
    bool f_msg_data;
    std::string m_msg_data;

public:
    std::string msg_data();

private:
    bool f_sfn_subfn_raw;
    int32_t m_sfn_subfn_raw;

public:
    int32_t sfn_subfn_raw();

private:
    bool f_pdu_id;
    uint8_t m_pdu_id;

public:
    uint8_t pdu_id();

private:
    bool f_arfcn_offset;
    int8_t m_arfcn_offset;

public:
    int8_t arfcn_offset();

private:
    bool f_header_size;
    int8_t m_header_size;

public:
    int8_t header_size();

private:
    bool f_sib_mask_offset;
    int8_t m_sib_mask_offset;

public:
    int8_t sib_mask_offset();

private:
    bool f_sfn;
    int32_t m_sfn;

public:
    int32_t sfn();

private:
    bool f_arfcn;
    uint32_t m_arfcn;

public:
    uint32_t arfcn();

private:
    bool f_msg_length;
    uint16_t m_msg_length;

public:
    uint16_t msg_length();

private:
    bool f_subframe;
    int32_t m_subframe;
    bool n_subframe;

public:
    bool _is_null_subframe() { subframe(); return n_subframe; };

private:

public:
    int32_t subframe();

private:
    bool f_sfn_shift;
    int8_t m_sfn_shift;

public:
    int8_t sfn_shift();

private:
    bool f_sfn_subfn_b2;
    uint8_t m_sfn_subfn_b2;

public:
    uint8_t sfn_subfn_b2();

private:
    bool f_has_ncgi;
    bool m_has_ncgi;

public:
    bool has_ncgi();

private:
    bool f_sfn_stamped;
    bool m_sfn_stamped;

public:
    bool sfn_stamped();

private:
    bool f_sfn_subfn_b3;
    uint8_t m_sfn_subfn_b3;

public:
    uint8_t sfn_subfn_b3();

private:
    uint32_t m_version;
    uint8_t m_rrc_release;
    uint8_t m_rrc_rel_min;
    uint8_t m_bearer_id;
    uint16_t m_pci;
    diag_0xb821_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint32_t version() const { return m_version; }
    uint8_t rrc_release() const { return m_rrc_release; }
    uint8_t rrc_rel_min() const { return m_rrc_rel_min; }
    uint8_t bearer_id() const { return m_bearer_id; }
    uint16_t pci() const { return m_pci; }
    diag_0xb821_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};
