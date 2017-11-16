#ifndef DOT11_IE_7_COUNTRY_H_
#define DOT11_IE_7_COUNTRY_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_7_country_t : public kaitai::kstruct {

public:
    class dot11_ie_country_triplet_t;

    dot11_ie_7_country_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_7_country_t* p_root = 0);
    ~dot11_ie_7_country_t();

    class dot11_ie_country_triplet_t : public kaitai::kstruct {

    public:

        dot11_ie_country_triplet_t(kaitai::kstream* p_io, dot11_ie_7_country_t* p_parent = 0, dot11_ie_7_country_t* p_root = 0);
        ~dot11_ie_country_triplet_t();

    private:
        uint8_t m_first_channel;
        uint8_t m_num_channels;
        uint8_t m_max_power;
        dot11_ie_7_country_t* m__root;
        dot11_ie_7_country_t* m__parent;

    public:
        uint8_t first_channel() const { return m_first_channel; }
        uint8_t num_channels() const { return m_num_channels; }
        uint8_t max_power() const { return m_max_power; }
        dot11_ie_7_country_t* _root() const { return m__root; }
        dot11_ie_7_country_t* _parent() const { return m__parent; }
    };

private:
    bool f_ie_num;
    int8_t m_ie_num;

public:
    int8_t ie_num();

private:
    std::string m_country_code;
    uint8_t m_environment;
    std::vector<dot11_ie_country_triplet_t*>* m_country_list;
    dot11_ie_7_country_t* m__root;
    kaitai::kstruct* m__parent;

public:
    std::string country_code() const { return m_country_code; }
    uint8_t environment() const { return m_environment; }
    std::vector<dot11_ie_country_triplet_t*>* country_list() const { return m_country_list; }
    dot11_ie_7_country_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_7_COUNTRY_H_
