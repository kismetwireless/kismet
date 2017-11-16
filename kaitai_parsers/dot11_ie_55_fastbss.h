#ifndef DOT11_IE_55_FASTBSS_H_
#define DOT11_IE_55_FASTBSS_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class dot11_ie_55_fastbss_t : public kaitai::kstruct {

public:
    class fastbss_subelement_t;
    class fastbss_sub_pmk_r1_keyholder_t;
    class fastbss_sub_data_t;
    class fastbss_sub_gtk_t;
    class fastbss_sub_pmk_r0_khid_t;
    class fastbss_sub_gtk_keyinfo_t;
    class fastbss_mic_control_t;

    dot11_ie_55_fastbss_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_55_fastbss_t* p_root = 0);
    ~dot11_ie_55_fastbss_t();

    class fastbss_subelement_t : public kaitai::kstruct {

    public:

        fastbss_subelement_t(kaitai::kstream* p_io, dot11_ie_55_fastbss_t* p_parent = 0, dot11_ie_55_fastbss_t* p_root = 0);
        ~fastbss_subelement_t();

    private:
        uint8_t m_sub_id;
        uint8_t m_sub_length;
        kaitai::kstruct* m_sub_data;
        dot11_ie_55_fastbss_t* m__root;
        dot11_ie_55_fastbss_t* m__parent;
        std::string m__raw_sub_data;
        kaitai::kstream* m__io__raw_sub_data;

    public:
        uint8_t sub_id() const { return m_sub_id; }
        uint8_t sub_length() const { return m_sub_length; }
        kaitai::kstruct* sub_data() const { return m_sub_data; }
        dot11_ie_55_fastbss_t* _root() const { return m__root; }
        dot11_ie_55_fastbss_t* _parent() const { return m__parent; }
        std::string _raw_sub_data() const { return m__raw_sub_data; }
        kaitai::kstream* _io__raw_sub_data() const { return m__io__raw_sub_data; }
    };

    class fastbss_sub_pmk_r1_keyholder_t : public kaitai::kstruct {

    public:

        fastbss_sub_pmk_r1_keyholder_t(kaitai::kstream* p_io, dot11_ie_55_fastbss_t::fastbss_subelement_t* p_parent = 0, dot11_ie_55_fastbss_t* p_root = 0);
        ~fastbss_sub_pmk_r1_keyholder_t();

    private:
        std::string m_keyholder_id;
        dot11_ie_55_fastbss_t* m__root;
        dot11_ie_55_fastbss_t::fastbss_subelement_t* m__parent;

    public:
        std::string keyholder_id() const { return m_keyholder_id; }
        dot11_ie_55_fastbss_t* _root() const { return m__root; }
        dot11_ie_55_fastbss_t::fastbss_subelement_t* _parent() const { return m__parent; }
    };

    class fastbss_sub_data_t : public kaitai::kstruct {

    public:

        fastbss_sub_data_t(kaitai::kstream* p_io, dot11_ie_55_fastbss_t::fastbss_subelement_t* p_parent = 0, dot11_ie_55_fastbss_t* p_root = 0);
        ~fastbss_sub_data_t();

    private:
        std::string m_data;
        dot11_ie_55_fastbss_t* m__root;
        dot11_ie_55_fastbss_t::fastbss_subelement_t* m__parent;

    public:
        std::string data() const { return m_data; }
        dot11_ie_55_fastbss_t* _root() const { return m__root; }
        dot11_ie_55_fastbss_t::fastbss_subelement_t* _parent() const { return m__parent; }
    };

    class fastbss_sub_gtk_t : public kaitai::kstruct {

    public:

        fastbss_sub_gtk_t(kaitai::kstream* p_io, dot11_ie_55_fastbss_t::fastbss_subelement_t* p_parent = 0, dot11_ie_55_fastbss_t* p_root = 0);
        ~fastbss_sub_gtk_t();

    private:
        fastbss_sub_gtk_keyinfo_t* m_gtk_keyinfo;
        uint8_t m_gtk_keylen;
        std::string m_gtk_rsc;
        std::string m_gtk_gtk;
        dot11_ie_55_fastbss_t* m__root;
        dot11_ie_55_fastbss_t::fastbss_subelement_t* m__parent;

    public:
        fastbss_sub_gtk_keyinfo_t* gtk_keyinfo() const { return m_gtk_keyinfo; }
        uint8_t gtk_keylen() const { return m_gtk_keylen; }
        std::string gtk_rsc() const { return m_gtk_rsc; }
        std::string gtk_gtk() const { return m_gtk_gtk; }
        dot11_ie_55_fastbss_t* _root() const { return m__root; }
        dot11_ie_55_fastbss_t::fastbss_subelement_t* _parent() const { return m__parent; }
    };

    class fastbss_sub_pmk_r0_khid_t : public kaitai::kstruct {

    public:

        fastbss_sub_pmk_r0_khid_t(kaitai::kstream* p_io, dot11_ie_55_fastbss_t::fastbss_subelement_t* p_parent = 0, dot11_ie_55_fastbss_t* p_root = 0);
        ~fastbss_sub_pmk_r0_khid_t();

    private:
        std::string m_keyholder_id;
        dot11_ie_55_fastbss_t* m__root;
        dot11_ie_55_fastbss_t::fastbss_subelement_t* m__parent;

    public:
        std::string keyholder_id() const { return m_keyholder_id; }
        dot11_ie_55_fastbss_t* _root() const { return m__root; }
        dot11_ie_55_fastbss_t::fastbss_subelement_t* _parent() const { return m__parent; }
    };

    class fastbss_sub_gtk_keyinfo_t : public kaitai::kstruct {

    public:

        fastbss_sub_gtk_keyinfo_t(kaitai::kstream* p_io, dot11_ie_55_fastbss_t::fastbss_sub_gtk_t* p_parent = 0, dot11_ie_55_fastbss_t* p_root = 0);
        ~fastbss_sub_gtk_keyinfo_t();

    private:
        uint64_t m_keyinfo_reserved;
        uint64_t m_keyinfo_keyid;
        dot11_ie_55_fastbss_t* m__root;
        dot11_ie_55_fastbss_t::fastbss_sub_gtk_t* m__parent;

    public:
        uint64_t keyinfo_reserved() const { return m_keyinfo_reserved; }
        uint64_t keyinfo_keyid() const { return m_keyinfo_keyid; }
        dot11_ie_55_fastbss_t* _root() const { return m__root; }
        dot11_ie_55_fastbss_t::fastbss_sub_gtk_t* _parent() const { return m__parent; }
    };

    class fastbss_mic_control_t : public kaitai::kstruct {

    public:

        fastbss_mic_control_t(kaitai::kstream* p_io, dot11_ie_55_fastbss_t* p_parent = 0, dot11_ie_55_fastbss_t* p_root = 0);
        ~fastbss_mic_control_t();

    private:
        uint8_t m_reserved;
        uint8_t m_element_count;
        dot11_ie_55_fastbss_t* m__root;
        dot11_ie_55_fastbss_t* m__parent;

    public:
        uint8_t reserved() const { return m_reserved; }
        uint8_t element_count() const { return m_element_count; }
        dot11_ie_55_fastbss_t* _root() const { return m__root; }
        dot11_ie_55_fastbss_t* _parent() const { return m__parent; }
    };

private:
    fastbss_mic_control_t* m_mic_control;
    std::string m_mic;
    std::string m_anonce;
    std::string m_snonce;
    std::vector<fastbss_subelement_t*>* m_subelements;
    dot11_ie_55_fastbss_t* m__root;
    kaitai::kstruct* m__parent;

public:
    fastbss_mic_control_t* mic_control() const { return m_mic_control; }
    std::string mic() const { return m_mic; }
    std::string anonce() const { return m_anonce; }
    std::string snonce() const { return m_snonce; }
    std::vector<fastbss_subelement_t*>* subelements() const { return m_subelements; }
    dot11_ie_55_fastbss_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_55_FASTBSS_H_
