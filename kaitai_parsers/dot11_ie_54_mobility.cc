// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "dot11_ie_54_mobility.h"

#include <iostream>
#include <fstream>

dot11_ie_54_mobility_t::dot11_ie_54_mobility_t(kaitai::kstream *p_io, kaitai::kstruct *p_parent, dot11_ie_54_mobility_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = this;
    f_ie_num = false;
    m_mobility_domain = m__io->read_u2le();
    m_ft_policy = new mobility_policy_t(m__io, this, m__root);
}

dot11_ie_54_mobility_t::~dot11_ie_54_mobility_t() {
    delete m_ft_policy;
}

dot11_ie_54_mobility_t::mobility_policy_t::mobility_policy_t(kaitai::kstream *p_io, dot11_ie_54_mobility_t *p_parent, dot11_ie_54_mobility_t *p_root) : kaitai::kstruct(p_io) {
    m__parent = p_parent;
    m__root = p_root;
    m_fast_bss_over_ds = m__io->read_bits_int(1);
    m_resource_request_capbability = m__io->read_bits_int(1);
    m_reserved = m__io->read_bits_int(6);
}

dot11_ie_54_mobility_t::mobility_policy_t::~mobility_policy_t() {
}

int8_t dot11_ie_54_mobility_t::ie_num() {
    if (f_ie_num)
        return m_ie_num;
    m_ie_num = 54;
    f_ie_num = true;
    return m_ie_num;
}
