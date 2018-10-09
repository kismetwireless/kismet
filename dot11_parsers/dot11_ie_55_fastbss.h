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

#ifndef __DOT11_IE_55_FASTBSS_H__
#define __DOT11_IE_55_FASTBSS_H__

/* dot11 ie 55 fastbss
 *
 * Fast-roaming
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_55_fastbss {
public:
    class sub_mic_control;
    class sub_element;
    typedef std::vector<std::shared_ptr<sub_element> > shared_sub_element_vector;

    dot11_ie_55_fastbss() { }
    ~dot11_ie_55_fastbss() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    std::shared_ptr<sub_mic_control> mic_control() const {
        return m_mic_control;
    }

    std::string mic() const {
        return m_mic;
    }

    std::string anonce() const {
        return m_anonce;
    }

    std::string snonce() const {
        return m_snonce;
    }

    std::shared_ptr<shared_sub_element_vector> subelements() const {
        return m_subelements;
    }

protected:
    std::shared_ptr<sub_mic_control> m_mic_control;
    std::string m_mic;
    std::string m_anonce;
    std::string m_snonce;
    std::shared_ptr<shared_sub_element_vector> m_subelements;

public:
    class sub_mic_control {
    public:
        sub_mic_control() { }
        ~sub_mic_control() { }

        void parse(std::shared_ptr<kaitai::kstream> p_io);

        constexpr17 uint8_t element_count() const {
            return m_element_count;
        }

    protected:
        uint8_t m_reserved;
        uint8_t m_element_count;
    };

    class sub_element {
    public:
        class sub_element_data;
        class sub_element_data_pmk_r1_keyholder;
        class sub_element_data_pmk_r0_kh_id;
        class sub_element_data_gtk;
        class sub_element_data_generic;

        enum sub_type {
            sub_pmk_r1_keyholder = 1,
            sub_pmk_gtk = 2,
            sub_pmk_r0_kh_id = 3
        };


        sub_element() { }
        ~sub_element() { }

        void parse(std::shared_ptr<kaitai::kstream> p_io);

        constexpr17 sub_type sub_id() const {
            return (sub_type) m_sub_id;
        }

        constexpr17 uint8_t sub_len() const {
            return m_sub_len;
        }

        std::shared_ptr<sub_element_data> sub_data() const {
            return m_sub_data;
        }

        std::shared_ptr<sub_element_data_pmk_r1_keyholder> sub_data_pmk_r1_keyholder() const {
            if (sub_id() == sub_pmk_r1_keyholder)
                return std::static_pointer_cast<sub_element_data_pmk_r1_keyholder>(sub_data());
            return NULL;
        }

        std::shared_ptr<sub_element_data_gtk> sub_data_pmk_gtk() const {
            if (sub_id() == sub_pmk_gtk)
                return std::static_pointer_cast<sub_element_data_gtk>(sub_data());
            return NULL;
        }

        std::shared_ptr<sub_element_data_pmk_r0_kh_id> sub_data_pmk_r0_kh_id() const {
            if (sub_id() == sub_pmk_r0_kh_id)
                return std::static_pointer_cast<sub_element_data_pmk_r0_kh_id>(sub_data());
            return NULL;
        }

        std::shared_ptr<sub_element_data_generic> sub_data_generic() const {
            return std::static_pointer_cast<sub_element_data_generic>(sub_data());
        }

    protected:
        uint8_t m_sub_id;
        uint8_t m_sub_len;
        std::string m_raw_sub_data;
        std::shared_ptr<kaitai::kstream> m_raw_sub_data_stream;
        std::shared_ptr<sub_element_data> m_sub_data;

    public:
        class sub_element_data {
        public:
            sub_element_data() { };
            virtual ~sub_element_data() { };

            virtual void parse(std::shared_ptr<kaitai::kstream> p_io) { };
        };

        class sub_element_data_pmk_r1_keyholder : public sub_element_data {
        public:
            sub_element_data_pmk_r1_keyholder() { }
            virtual ~sub_element_data_pmk_r1_keyholder() { }

            virtual void parse(std::shared_ptr<kaitai::kstream> p_io);

            std::string keyholder_id() const {
                return m_keyholder_id;
            }

        protected:
            std::string m_keyholder_id;
        };

        class sub_element_data_pmk_r0_kh_id : public sub_element_data {
        public:
            sub_element_data_pmk_r0_kh_id() { };
            virtual ~sub_element_data_pmk_r0_kh_id() { };

            virtual void parse(std::shared_ptr<kaitai::kstream> p_io);

            std::string keyholder_id() const {
                return m_keyholder_id;
            }

        protected:
            std::string m_keyholder_id;
        };

        class sub_element_data_gtk : public sub_element_data {
        public:
            class sub_element_data_gtk_sub_keyinfo;

            sub_element_data_gtk() { }
            virtual ~sub_element_data_gtk() { }

            void parse(std::shared_ptr<kaitai::kstream> p_io);

        protected:
            std::shared_ptr<sub_element_data_gtk_sub_keyinfo> m_gtk_keyinfo;
            uint8_t m_keylen;
            std::string m_gtk_rsc;
            std::string m_gtk_gtk;

        public:
            class sub_element_data_gtk_sub_keyinfo {
            public:
                sub_element_data_gtk_sub_keyinfo() { }
                ~sub_element_data_gtk_sub_keyinfo() { }

                void parse(std::shared_ptr<kaitai::kstream> p_io);

                constexpr17 uint16_t keyinfo() const {
                    return m_keyinfo;
                }

                constexpr17 unsigned int keyid() const {
                    return keyinfo() & 0x04;
                }
            protected:
                uint16_t m_keyinfo;
            };
        };

        class sub_element_data_generic : public sub_element_data {
        public:
            sub_element_data_generic() { }
            virtual ~sub_element_data_generic() { }

            virtual void parse(std::shared_ptr<kaitai::kstream> p_io);

            std::string data() const {
                return m_data;
            }

        protected:
            std::string m_data;
        };

    };
};


#endif 
