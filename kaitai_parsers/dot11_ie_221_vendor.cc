// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_221_vendor.h"

#include <iostream>
#include <fstream>

dot11_ie_221_vendor_t::dot11_ie_221_vendor_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_221_vendor_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_ie_num = false;
    f_vendor_oui_extract = false;
    f_vendor_oui_int = false;
    f_vendor_oui_type = false;
    m_vendor_oui = m__io->read_bytes(3);
    m_vendor_tag = new ieee_221_vendor_tag_t(m__io, this, m__root);
}

dot11_ie_221_vendor_t::~dot11_ie_221_vendor_t() {
    delete m_vendor_tag;
    if (f_vendor_oui_extract) {
        delete m_vendor_oui_extract;
    }
}

dot11_ie_221_vendor_t::vendor_oui_bytes_t::vendor_oui_bytes_t(kaitai::kstream *p_io, dot11_ie_221_vendor_t *p_parent, dot11_ie_221_vendor_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_oui1 = m__io->read_u1();
    m_oui2 = m__io->read_u1();
    m_oui3 = m__io->read_u1();
}

dot11_ie_221_vendor_t::vendor_oui_bytes_t::~vendor_oui_bytes_t() {
}

dot11_ie_221_vendor_t::ieee_221_vendor_tag_t::ieee_221_vendor_tag_t(kaitai::kstream *p_io, dot11_ie_221_vendor_t *p_parent, dot11_ie_221_vendor_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_vendor_data = m__io->read_bytes_full();
}

dot11_ie_221_vendor_t::ieee_221_vendor_tag_t::~ieee_221_vendor_tag_t() {
}

uint8_t dot11_ie_221_vendor_t::ie_num() {
    if (f_ie_num)
        return m_ie_num;
    m_ie_num = 221;
    f_ie_num = true;
    return m_ie_num;
}

dot11_ie_221_vendor_t::vendor_oui_bytes_t* dot11_ie_221_vendor_t::vendor_oui_extract() {
    if (f_vendor_oui_extract)
        return m_vendor_oui_extract;
    std::streampos _pos = m__io->pos();
    m__io->seek(0);
    m_vendor_oui_extract = new vendor_oui_bytes_t(m__io, this, m__root);
    m__io->seek(_pos);
    f_vendor_oui_extract = true;
    return m_vendor_oui_extract;
}

int32_t dot11_ie_221_vendor_t::vendor_oui_int() {
    if (f_vendor_oui_int)
        return m_vendor_oui_int;
    m_vendor_oui_int = (((vendor_oui_extract()->oui1() << 16) + (vendor_oui_extract()->oui2() << 8)) + vendor_oui_extract()->oui3());
    f_vendor_oui_int = true;
    return m_vendor_oui_int;
}

uint8_t dot11_ie_221_vendor_t::vendor_oui_type() {
    if (f_vendor_oui_type)
        return m_vendor_oui_type;
    std::streampos _pos = m__io->pos();
    m__io->seek(3);
    m_vendor_oui_type = m__io->read_u1();
    m__io->seek(_pos);
    f_vendor_oui_type = true;
    return m_vendor_oui_type;
}
