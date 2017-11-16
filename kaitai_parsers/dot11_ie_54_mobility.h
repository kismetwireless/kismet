#ifndef DOT11_IE_54_MOBILITY_H_
#define DOT11_IE_54_MOBILITY_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_54_mobility_t : public kaitai::kstruct {

public:
    class mobility_policy_t;

    dot11_ie_54_mobility_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_54_mobility_t* p_root = 0);
    ~dot11_ie_54_mobility_t();

    class mobility_policy_t : public kaitai::kstruct {

    public:

        mobility_policy_t(kaitai::kstream* p_io, dot11_ie_54_mobility_t* p_parent = 0, dot11_ie_54_mobility_t* p_root = 0);
        ~mobility_policy_t();

    private:
        bool m_fast_bss_over_ds;
        bool m_resource_request_capbability;
        uint64_t m_reserved;
        dot11_ie_54_mobility_t* m__root;
        dot11_ie_54_mobility_t* m__parent;

    public:
        bool fast_bss_over_ds() const { return m_fast_bss_over_ds; }
        bool resource_request_capbability() const { return m_resource_request_capbability; }
        uint64_t reserved() const { return m_reserved; }
        dot11_ie_54_mobility_t* _root() const { return m__root; }
        dot11_ie_54_mobility_t* _parent() const { return m__parent; }
    };

private:
    bool f_ie_num;
    int8_t m_ie_num;

public:
    int8_t ie_num();

private:
    uint16_t m_mobility_domain;
    mobility_policy_t* m_ft_policy;
    dot11_ie_54_mobility_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint16_t mobility_domain() const { return m_mobility_domain; }
    mobility_policy_t* ft_policy() const { return m_ft_policy; }
    dot11_ie_54_mobility_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_54_MOBILITY_H_
