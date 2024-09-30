/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __DOT11_IE_221_MS_WPS_H__
#define __DOT11_IE_221_MS_WPS_H__

/* dot11 ie 221 vendor WPS
 *
 * 802.11 WPS control
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_221_ms_wps {
public:
    class wps_de_sub_element;

    typedef std::vector<std::shared_ptr<wps_de_sub_element> > shared_wps_de_sub_element_vector;

    dot11_ie_221_ms_wps() { }
    ~dot11_ie_221_ms_wps() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 uint8_t vendor_subtype() const {
        return m_vendor_subtype;
    }

    std::shared_ptr<shared_wps_de_sub_element_vector> wps_elements() const {
        return m_wps_elements;
    }

    constexpr17 static uint32_t ms_wps_oui() {
        return 0x0050f2;
    }

    constexpr17 static uint8_t ms_wps_subtype() {
        return 0x04;
    }

    void reset() {
        m_vendor_subtype = 0;
        m_wps_elements.reset();
    }

protected:
    uint8_t m_vendor_subtype;
    std::shared_ptr<shared_wps_de_sub_element_vector> m_wps_elements;

public:
    class wps_de_sub_element {
    public:
        class wps_de_sub_common;
        class wps_de_sub_string;
        class wps_de_sub_rfband;
        class wps_de_sub_state;
        class wps_de_sub_uuid_e;
        class wps_de_sub_vendor_extension;
        class wps_de_sub_version;
        class wps_de_sub_primary_type;
        class wps_de_sub_ap_setup;
        class wps_de_sub_config_methods;
        class wps_de_sub_generic;

        enum wps_de_type_e {
            wps_de_config_methods = 0x1008,
            wps_de_device_name = 0x1011,
            wps_de_manuf = 0x1021,
            wps_de_model = 0x1023,
            wps_de_model_num = 0x1024,
            wps_de_rfbands = 0x103c,
            wps_de_serial = 0x1042,
            wps_de_state = 0x1044,
            wps_de_uuid_e = 0x1047,
            wps_de_vendor_extension = 0x1049,
            wps_de_version = 0x104a,
            wps_de_primary_type = 0x1054,
            wps_de_ap_setup = 0x1057
        };


        wps_de_sub_element() {};
        ~wps_de_sub_element() {};

        void parse(kaitai::kstream& p_io);

        constexpr17 wps_de_type_e wps_de_type() const {
            return (wps_de_type_e) m_wps_de_type;
        }

        constexpr17 uint16_t wps_de_len() const {
            return m_wps_de_len;
        }

        constexpr17 const std::string& wps_de_content() const {
            return m_wps_de_content;
        }

        std::shared_ptr<wps_de_sub_common> sub_element() const {
            return m_sub_element;
        }

        std::shared_ptr<wps_de_sub_string> sub_element_as_string() const {
            return std::static_pointer_cast<wps_de_sub_string>(sub_element());
        }

        std::shared_ptr<wps_de_sub_string> sub_element_name() const {
            if (wps_de_type() == wps_de_device_name)
                return sub_element_as_string();
            return NULL;
        }

        std::shared_ptr<wps_de_sub_string> sub_element_manuf() const {
            if (wps_de_type() == wps_de_manuf)
                return sub_element_as_string();
            return NULL;
        }

        std::shared_ptr<wps_de_sub_string> sub_element_model() const {
            if (wps_de_type() == wps_de_model)
                return sub_element_as_string();
            return NULL;
        }

        std::shared_ptr<wps_de_sub_string> sub_element_model_num() const {
            if (wps_de_type() == wps_de_model_num)
                return sub_element_as_string();
            return NULL;
        }

        std::shared_ptr<wps_de_sub_rfband> sub_element_rfbands() const {
            if (wps_de_type() == wps_de_rfbands)
                return std::static_pointer_cast<wps_de_sub_rfband>(sub_element());
            return NULL;
        }

        std::shared_ptr<wps_de_sub_string> sub_element_serial() const {
            if (wps_de_type() == wps_de_serial)
                return sub_element_as_string();
            return NULL;
        }

       std::shared_ptr<wps_de_sub_version> sub_element_version() const {
            if (wps_de_type() == wps_de_version)
                return std::static_pointer_cast<wps_de_sub_version>(sub_element());
            return NULL;
        }

        std::shared_ptr<wps_de_sub_state> sub_element_state() const {
            if (wps_de_type() == wps_de_state)
                return std::static_pointer_cast<wps_de_sub_state>(sub_element());
            return NULL;
        }

        std::shared_ptr<wps_de_sub_ap_setup> sub_element_ap_setup() const {
            if (wps_de_type() == wps_de_ap_setup)
                return std::static_pointer_cast<wps_de_sub_ap_setup>(sub_element());
            return NULL;
        }

        std::shared_ptr<wps_de_sub_config_methods> sub_element_config_methods() const {
            if (wps_de_type() == wps_de_config_methods)
                return std::static_pointer_cast<wps_de_sub_config_methods>(sub_element());
            return NULL;
        }

        std::shared_ptr<wps_de_sub_uuid_e> sub_element_uuid_e() const {
            if (wps_de_type() == wps_de_uuid_e)
                return std::static_pointer_cast<wps_de_sub_uuid_e>(sub_element());
            return NULL;
        }

        void reset() {
            m_wps_de_type = 0;
            m_wps_de_len = 0;
            m_wps_de_content = "";
            m_sub_element.reset();
        }

    protected:
        uint16_t m_wps_de_type;
        uint16_t m_wps_de_len;
        std::string m_wps_de_content;
        std::shared_ptr<wps_de_sub_common> m_sub_element;

    public:
        class wps_de_sub_common {
        public:
            wps_de_sub_common() { };
            virtual ~wps_de_sub_common() { };

            virtual void parse(const std::string& data) { }

            virtual void reset() = 0;
        };

        class wps_de_sub_string : public wps_de_sub_common {
        public:
            wps_de_sub_string() { }
            virtual ~wps_de_sub_string() { }

            virtual void parse(const std::string& data) override;

            constexpr const std::string& str() const {
                return m_str;
            }

            virtual void reset() override {
                m_str = "";
            }

        protected:
            std::string m_str;
        };

        class wps_de_sub_rfband : public wps_de_sub_common {
        public:
            wps_de_sub_rfband() { }
            virtual ~wps_de_sub_rfband() { }

            virtual void parse(const std::string& data) override;

            constexpr17 uint8_t rfband() const {
                return m_rfband;
            }

            constexpr17 unsigned int rfband_2p4ghz() const {
                return rfband() & 0x1;
            }

            constexpr17 unsigned int rfband_5ghz() const {
                return rfband() & 0x2;
            }

            virtual void reset() override {
                m_rfband = 0;
            }

        protected:
            uint8_t m_rfband;
        };

        class wps_de_sub_state : public wps_de_sub_common {
        public:
            wps_de_sub_state() { }
            virtual ~wps_de_sub_state() { }

            virtual void parse(const std::string& data) override;

            constexpr17 uint8_t state() const {
                return m_state;
            }

            constexpr17 unsigned int wps_state_configured() const {
                return state() & 0x2;
            }

            virtual void reset() override {
                m_state = 0;
            }

        protected:
            uint8_t m_state;
        };

        class wps_de_sub_uuid_e : public wps_de_sub_common {
        public:
            wps_de_sub_uuid_e() { }
            virtual ~wps_de_sub_uuid_e() { }

            virtual void parse(const std::string& data) override;

            constexpr17 const std::string& str() const {
                return m_uuid;
            }

            virtual void reset() override {
                m_uuid = "";
            }

        protected:
            std::string m_uuid;
        };

        class wps_de_sub_primary_type : public wps_de_sub_common {
        public:
            wps_de_sub_primary_type() { }
            virtual ~wps_de_sub_primary_type() { }

            virtual void parse(const std::string& data) override;

            constexpr17 uint16_t category() const {
                return m_category;
            }

            constexpr17 uint32_t typedata() const {
                return m_typedata;
            }

            constexpr17 uint16_t subcategory() const {
                return m_subcategory;
            }

            virtual void reset() override {
                m_category = 0;
                m_typedata = 0;
                m_subcategory = 0;
            }

        protected:
            uint16_t m_category;
            uint32_t m_typedata;
            uint16_t m_subcategory;
        };

        class wps_de_sub_vendor_extension : public wps_de_sub_common {
        public:
            wps_de_sub_vendor_extension() { }
            virtual ~wps_de_sub_vendor_extension() { }

            virtual void parse(const std::string& data) override;

            std::string vendor_id() const {
                return m_vendor_id;
            }

            constexpr17 uint8_t wfa_sub_id() const {
                return m_wfa_sub_id;
            }

            constexpr17 uint8_t wfa_sub_len() const {
                return m_wfa_sub_len;
            }

            std::string wfa_sub_data() const {
                return m_wfa_sub_data;
            }

            virtual void reset() override {
                m_vendor_id = "";
                m_wfa_sub_id = 0;
                m_wfa_sub_len = 0;
                m_wfa_sub_data = "";
            }

        protected:
            std::string m_vendor_id;
            uint8_t m_wfa_sub_id;
            uint8_t m_wfa_sub_len;
            std::string m_wfa_sub_data;
        };

        class wps_de_sub_version : public wps_de_sub_common {
        public:
            wps_de_sub_version() { }
            virtual ~wps_de_sub_version() { }

            virtual void parse(const std::string& data) override;

            constexpr17 uint8_t version() const {
                return m_version;
            }

            void reset() override {
                m_version = 0;
            }

        protected:
            uint8_t m_version;
        };

        class wps_de_sub_ap_setup : public wps_de_sub_common {
        public:
            wps_de_sub_ap_setup() { }
            virtual ~wps_de_sub_ap_setup() { }

            virtual void parse(const std::string& data) override;

            constexpr17 uint8_t ap_setup_locked() const {
                return m_ap_setup_locked;
            }

            void reset() override {
                m_ap_setup_locked = 0;
            }

        protected:
            uint8_t m_ap_setup_locked;
        };

        class wps_de_sub_config_methods : public wps_de_sub_common {
        public:
            wps_de_sub_config_methods() { }
            virtual ~wps_de_sub_config_methods() { }

            virtual void parse(const std::string& data) override;

            constexpr17 uint16_t wps_config_methods() const {
                return m_config_methods;
            }

            void reset() override {
                m_config_methods = 0;
            }

        protected:
            uint16_t m_config_methods;
        };

        class wps_de_sub_generic : public wps_de_sub_common {
        public:
            wps_de_sub_generic() { }
            virtual ~wps_de_sub_generic() { }

            virtual void parse(const std::string& data) override;

            constexpr17 const std::string& wps_de_data() const {
                return m_wps_de_data;
            }

            void reset() override {
                m_wps_de_data = "";
            }

        protected:
            std::string m_wps_de_data;
        };

    };

};


#endif

