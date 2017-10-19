#ifndef DOT11_IE_H_
#define DOT11_IE_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include <kaitai/kaitaistruct.h>
#include <kaitai/kaitaistream.h>

#include <stdint.h>
#include <vector>
#include <sstream>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif
class dot11_ie_221_vendor_t;
class dot11_ie_7_country_t;
class dot11_ie_11_qbss_t;

class dot11_ie_t : public kaitai::kstruct {

public:
    class dot11_ie_data_t;
    class dot11_ie_tim_t;
    class dot11_ie_basicrates_t;
    class dot11_ie_tim_bitmap_t;
    class dot11_ie_extendedrates_t;
    class dot11_ie_ds_channel_t;
    class dot11_ie_ssid_t;
    class dot11_ie_cisco_ccx1_ckip_t;
    class ieee_80211_tag_t;

    dot11_ie_t(kaitai::kstream* p_io, kaitai::kstruct* p_parent = 0, dot11_ie_t* p_root = 0);
    ~dot11_ie_t();

    class dot11_ie_data_t : public kaitai::kstruct {

    public:

        dot11_ie_data_t(kaitai::kstream* p_io, dot11_ie_t::ieee_80211_tag_t* p_parent = 0, dot11_ie_t* p_root = 0);
        ~dot11_ie_data_t();

    private:
        std::string m_data;
        dot11_ie_t* m__root;
        dot11_ie_t::ieee_80211_tag_t* m__parent;

    public:
        std::string data() const { return m_data; }
        dot11_ie_t* _root() const { return m__root; }
        dot11_ie_t::ieee_80211_tag_t* _parent() const { return m__parent; }
    };

    class dot11_ie_tim_t : public kaitai::kstruct {

    public:

        dot11_ie_tim_t(kaitai::kstream* p_io, dot11_ie_t::ieee_80211_tag_t* p_parent = 0, dot11_ie_t* p_root = 0);
        ~dot11_ie_tim_t();

    private:
        uint8_t m_dtim_count;
        uint8_t m_dtim_period;
        dot11_ie_tim_bitmap_t* m_bitmap_control;
        uint8_t m_pv_bitmap;
        dot11_ie_t* m__root;
        dot11_ie_t::ieee_80211_tag_t* m__parent;

    public:
        uint8_t dtim_count() const { return m_dtim_count; }
        uint8_t dtim_period() const { return m_dtim_period; }
        dot11_ie_tim_bitmap_t* bitmap_control() const { return m_bitmap_control; }
        uint8_t pv_bitmap() const { return m_pv_bitmap; }
        dot11_ie_t* _root() const { return m__root; }
        dot11_ie_t::ieee_80211_tag_t* _parent() const { return m__parent; }
    };

    class dot11_ie_basicrates_t : public kaitai::kstruct {

    public:

        dot11_ie_basicrates_t(kaitai::kstream* p_io, dot11_ie_t::ieee_80211_tag_t* p_parent = 0, dot11_ie_t* p_root = 0);
        ~dot11_ie_basicrates_t();

    private:
        std::vector<uint8_t>* m_basic_rate;
        dot11_ie_t* m__root;
        dot11_ie_t::ieee_80211_tag_t* m__parent;

    public:
        std::vector<uint8_t>* basic_rate() const { return m_basic_rate; }
        dot11_ie_t* _root() const { return m__root; }
        dot11_ie_t::ieee_80211_tag_t* _parent() const { return m__parent; }
    };

    class dot11_ie_tim_bitmap_t : public kaitai::kstruct {

    public:

        dot11_ie_tim_bitmap_t(kaitai::kstream* p_io, dot11_ie_t::dot11_ie_tim_t* p_parent = 0, dot11_ie_t* p_root = 0);
        ~dot11_ie_tim_bitmap_t();

    private:
        uint64_t m_bitmap_offset;
        bool m_multicast;
        dot11_ie_t* m__root;
        dot11_ie_t::dot11_ie_tim_t* m__parent;

    public:
        uint64_t bitmap_offset() const { return m_bitmap_offset; }
        bool multicast() const { return m_multicast; }
        dot11_ie_t* _root() const { return m__root; }
        dot11_ie_t::dot11_ie_tim_t* _parent() const { return m__parent; }
    };

    class dot11_ie_extendedrates_t : public kaitai::kstruct {

    public:

        dot11_ie_extendedrates_t(kaitai::kstream* p_io, dot11_ie_t::ieee_80211_tag_t* p_parent = 0, dot11_ie_t* p_root = 0);
        ~dot11_ie_extendedrates_t();

    private:
        std::vector<uint8_t>* m_extended_rate;
        dot11_ie_t* m__root;
        dot11_ie_t::ieee_80211_tag_t* m__parent;

    public:
        std::vector<uint8_t>* extended_rate() const { return m_extended_rate; }
        dot11_ie_t* _root() const { return m__root; }
        dot11_ie_t::ieee_80211_tag_t* _parent() const { return m__parent; }
    };

    class dot11_ie_ds_channel_t : public kaitai::kstruct {

    public:

        dot11_ie_ds_channel_t(kaitai::kstream* p_io, dot11_ie_t::ieee_80211_tag_t* p_parent = 0, dot11_ie_t* p_root = 0);
        ~dot11_ie_ds_channel_t();

    private:
        uint8_t m_current_channel;
        dot11_ie_t* m__root;
        dot11_ie_t::ieee_80211_tag_t* m__parent;

    public:
        uint8_t current_channel() const { return m_current_channel; }
        dot11_ie_t* _root() const { return m__root; }
        dot11_ie_t::ieee_80211_tag_t* _parent() const { return m__parent; }
    };

    class dot11_ie_ssid_t : public kaitai::kstruct {

    public:

        dot11_ie_ssid_t(kaitai::kstream* p_io, dot11_ie_t::ieee_80211_tag_t* p_parent = 0, dot11_ie_t* p_root = 0);
        ~dot11_ie_ssid_t();

    private:
        std::string m_ssid;
        dot11_ie_t* m__root;
        dot11_ie_t::ieee_80211_tag_t* m__parent;

    public:
        std::string ssid() const { return m_ssid; }
        dot11_ie_t* _root() const { return m__root; }
        dot11_ie_t::ieee_80211_tag_t* _parent() const { return m__parent; }
    };

    class dot11_ie_cisco_ccx1_ckip_t : public kaitai::kstruct {

    public:

        dot11_ie_cisco_ccx1_ckip_t(kaitai::kstream* p_io, dot11_ie_t::ieee_80211_tag_t* p_parent = 0, dot11_ie_t* p_root = 0);
        ~dot11_ie_cisco_ccx1_ckip_t();

    private:
        std::string m_ccx1_unk1;
        std::string m_ap_name;
        uint8_t m_station_count;
        std::string m_ccx1_unk2;
        dot11_ie_t* m__root;
        dot11_ie_t::ieee_80211_tag_t* m__parent;

    public:
        std::string ccx1_unk1() const { return m_ccx1_unk1; }
        std::string ap_name() const { return m_ap_name; }
        uint8_t station_count() const { return m_station_count; }
        std::string ccx1_unk2() const { return m_ccx1_unk2; }
        dot11_ie_t* _root() const { return m__root; }
        dot11_ie_t::ieee_80211_tag_t* _parent() const { return m__parent; }
    };

    class ieee_80211_tag_t : public kaitai::kstruct {

    public:

        ieee_80211_tag_t(kaitai::kstream* p_io, dot11_ie_t* p_parent = 0, dot11_ie_t* p_root = 0);
        ~ieee_80211_tag_t();

    private:
        uint8_t m_tag_num;
        uint8_t m_tag_length;
        kaitai::kstruct* m_tag_data;
        dot11_ie_t* m__root;
        dot11_ie_t* m__parent;
        std::string m__raw_tag_data;
        kaitai::kstream* m__io__raw_tag_data;

    public:
        uint8_t tag_num() const { return m_tag_num; }
        uint8_t tag_length() const { return m_tag_length; }
        kaitai::kstruct* tag_data() const { return m_tag_data; }
        dot11_ie_t* _root() const { return m__root; }
        dot11_ie_t* _parent() const { return m__parent; }
        std::string _raw_tag_data() const { return m__raw_tag_data; }
        kaitai::kstream* _io__raw_tag_data() const { return m__io__raw_tag_data; }
    };

private:
    std::vector<ieee_80211_tag_t*>* m_tag;
    dot11_ie_t* m__root;
    kaitai::kstruct* m__parent;

public:
    std::vector<ieee_80211_tag_t*>* tag() const { return m_tag; }
    dot11_ie_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // DOT11_IE_H_
