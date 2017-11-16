#ifndef DOT11_IE_192_VHT_OPERATION_H_
#define DOT11_IE_192_VHT_OPERATION_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_192_vht_operation_t : public kaitai::kstruct {

public:
    class mcs_map_t;

    enum channel_width_t {
        CHANNEL_WIDTH_CH_20_40 = 0,
        CHANNEL_WIDTH_CH_80 = 1,
        CHANNEL_WIDTH_CH_160 = 2,
        CHANNEL_WIDTH_CH_80_80 = 3
    };

    dot11_ie_192_vht_operation_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_192_vht_operation_t* p_root = 0);
    ~dot11_ie_192_vht_operation_t();

    class mcs_map_t : public kaitai::kstruct {

    public:

        mcs_map_t(kaitai::kstream* p_io, dot11_ie_192_vht_operation_t* p_parent = 0, dot11_ie_192_vht_operation_t* p_root = 0);
        ~mcs_map_t();

    private:
        uint64_t m_basic_4;
        uint64_t m_basic_3;
        uint64_t m_basic_2;
        uint64_t m_basic_1;
        uint64_t m_basic_8;
        uint64_t m_basic_7;
        uint64_t m_basic_6;
        uint64_t m_basic_5;
        dot11_ie_192_vht_operation_t* m__root;
        dot11_ie_192_vht_operation_t* m__parent;

    public:
        uint64_t basic_4() const { return m_basic_4; }
        uint64_t basic_3() const { return m_basic_3; }
        uint64_t basic_2() const { return m_basic_2; }
        uint64_t basic_1() const { return m_basic_1; }
        uint64_t basic_8() const { return m_basic_8; }
        uint64_t basic_7() const { return m_basic_7; }
        uint64_t basic_6() const { return m_basic_6; }
        uint64_t basic_5() const { return m_basic_5; }
        dot11_ie_192_vht_operation_t* _root() const { return m__root; }
        dot11_ie_192_vht_operation_t* _parent() const { return m__parent; }
    };

private:
    bool f_ie_num;
    uint8_t m_ie_num;

public:
    uint8_t ie_num();

private:
    channel_width_t m_channel_width;
    uint8_t m_center1;
    uint8_t m_center2;
    mcs_map_t* m_basic_mcs_map;
    dot11_ie_192_vht_operation_t* m__root;
    kaitai::kstruct* m__parent;

public:
    channel_width_t channel_width() const { return m_channel_width; }
    uint8_t center1() const { return m_center1; }
    uint8_t center2() const { return m_center2; }
    mcs_map_t* basic_mcs_map() const { return m_basic_mcs_map; }
    dot11_ie_192_vht_operation_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_192_VHT_OPERATION_H_
