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

#ifndef __DOT11_WPA_EAP_H__
#define __DOT11_WPA_EAP_H__

/* dot11 WPA EAP frames
 *
 * dot1x EAP keying
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_wpa_eap {
public:
    class dot1x_common;
    class dot1x_eap_packet;
    class dot1x_key;

    enum dot1x_type_e {
        dot1x_type_eap_packet = 0x00,
        dot1x_type_eap_key = 0x03
    };

    dot11_wpa_eap() { }
    ~dot11_wpa_eap() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 uint8_t dot1x_version() const {
        return m_dot1x_version;
    }

    constexpr17 dot1x_type_e dot1x_type() const {
        return (dot1x_type_e) m_dot1x_type;
    }

    constexpr17 uint16_t dot1x_len() const {
        return m_dot1x_len;
    }

    constexpr const std::string& dot1x_data() const {
        return m_dot1x_data;
    }

    std::shared_ptr<dot1x_common> dot1x_content() const {
        return m_dot1x_content;
    }

    std::shared_ptr<dot1x_eap_packet> dot1x_content_eap_packet() const {
        if (dot1x_type() == dot1x_type_eap_packet) 
            return std::static_pointer_cast<dot1x_eap_packet>(dot1x_content());
        return nullptr;
    }

    std::shared_ptr<dot1x_key> dot1x_content_key() const {
        if (dot1x_type() == dot1x_type_eap_key)
            return std::static_pointer_cast<dot1x_key>(dot1x_content());
        return nullptr;
    }

protected:
    uint8_t m_dot1x_version;
    uint8_t m_dot1x_type;
    uint16_t m_dot1x_len;
    std::string m_dot1x_data;
    std::shared_ptr<dot1x_common> m_dot1x_content;

public:
    class dot1x_common {
    public:
        dot1x_common() {}
        virtual ~dot1x_common() {}
    };

    class dot1x_key : public dot1x_common {
    public:
        class dot1x_key_common;
        class eapol_key_rsn;

        enum dot1x_key_type_e {
            dot1x_key_type_eapol_rsn = 0x02
        };

        dot1x_key() {}
        virtual ~dot1x_key() { }

        void parse(std::shared_ptr<kaitai::kstream> p_io);
		void parse(const std::string& data);

        constexpr17 dot1x_key_type_e key_descriptor_type() const {
            return (dot1x_key_type_e) m_key_descriptor_type;
        }

        constexpr17 const std::string& key_content_data() const {
            return m_key_content_data;
        }

        std::shared_ptr<dot1x_key_common> key_content() const {
            return m_key_content;
        }

        std::shared_ptr<eapol_key_rsn> key_content_eapolrsn() const {
            if (key_descriptor_type() == dot1x_key_type_eapol_rsn)
                return std::static_pointer_cast<eapol_key_rsn>(key_content());
            return nullptr;
        }

    protected:
        uint8_t m_key_descriptor_type;
        std::string m_key_content_data;
        std::shared_ptr<dot1x_key_common> m_key_content;

    public:
        class dot1x_key_common {
        public:
            dot1x_key_common() {}
            virtual ~dot1x_key_common() {}
        };

        class eapol_key_rsn : public dot1x_key_common {
        public:
            eapol_key_rsn() {}
            virtual ~eapol_key_rsn() {}

            void parse(std::shared_ptr<kaitai::kstream> p_io);
			void parse(const std::string& data);

            constexpr17 uint16_t key_info() const {
                return m_key_info;
            }

            constexpr17 uint16_t key_len() const {
                return m_key_len;
            }

            constexpr17 uint64_t replay_counter() const {
                return m_replay_counter;
            }

            constexpr17 const std::string& wpa_key_nonce() const {
                return m_wpa_key_nonce;
            } 

            constexpr17 const std::string& wpa_key_iv() const {
                return m_wpa_key_iv;
            }

            constexpr17 const std::string& wpa_key_rsc() const {
                return m_wpa_key_rsc;
            }

            constexpr17 const std::string& wpa_key_id() const {
                return m_wpa_key_id;
            }

            constexpr17 const std::string& wpa_key_mic() const {
                return m_wpa_key_mic;
            }

            constexpr17 uint16_t wpa_key_data_len() const {
                return m_wpa_key_data_len;
            }

            constexpr17 const std::string& wpa_key_data() const {
                return m_wpa_key_data;
            }

            enum eapol_key_descriptor_version {
                eapol_key_rc4_md5 = 0x01,
                eapol_key_aes_sha1 = 0x02,
                eapol_key_aes_cmac = 0x03,
            };

            constexpr17 unsigned int key_info_descriptor_version() const {
                return key_info() & 0x7;
            }

            constexpr17 unsigned int key_info_pairwise_key() const {
                return key_info() & 0x8;
            }

            constexpr17 unsigned int key_info_key_index() const {
                return key_info() & 0x30;
            }

            constexpr17 unsigned int key_info_install() const {
                return key_info() & 0x40;
            }

            constexpr17 unsigned int key_info_key_ack() const {
                return key_info() & 0x80;
            }

            constexpr17 unsigned int key_info_key_mic() const {
                return key_info() & 0x100;
            }

            constexpr17 unsigned int key_info_secure() const {
                return key_info() & 0x200;
            }

            constexpr17 unsigned int key_info_error() const {
                return key_info() & 0x400;
            }

            constexpr17 unsigned int key_info_request() const {
                return key_info() & 0x800;
            }

            constexpr17 unsigned int key_info_encrypted_key_data() const {
                return key_info() & 0x1000;
            }

        protected:
            uint16_t m_key_info;
            uint16_t m_key_len;
            uint64_t m_replay_counter;
            std::string m_wpa_key_nonce;
            std::string m_wpa_key_iv;
            std::string m_wpa_key_rsc;
            std::string m_wpa_key_id;
            std::string m_wpa_key_mic;
            uint16_t m_wpa_key_data_len;
            std::string m_wpa_key_data;
        };

    };

    class dot1x_eap_packet : public dot1x_common {
    public:
        class eapol_content_common;
        class eapol_extended_wpa_wps;

        enum eapol_type_e {
            eapol_type_request = 0x1,
            eapol_type_response = 0x2
        };

        enum eapol_expanded_type_e {
            eapol_expanded_wfa_wps = 0xFE
        };

        dot1x_eap_packet() {}
        virtual ~dot1x_eap_packet() {}

        void parse(std::shared_ptr<kaitai::kstream> p_io);
		void parse(const std::string& data);

        constexpr17 eapol_type_e eapol_type() const {
            return (eapol_type_e) m_eapol_type;
        }

        constexpr17 uint8_t eapol_id() const {
            return m_eapol_id;
        }

        constexpr17 uint16_t eapol_len() const {
            return m_eapol_len;
        }

        constexpr17 eapol_expanded_type_e eapol_expanded_type() const {
            return (eapol_expanded_type_e) m_eapol_expanded_type;
        }

        constexpr17 const std::string& eapol_content_data() const {
            return m_eapol_content_data;
        }

        std::shared_ptr<eapol_content_common> eapol_content() const {
            return m_eapol_content;
        }

        std::shared_ptr<eapol_extended_wpa_wps> eapol_content_wpa_wps() const {
            if (eapol_expanded_type() == eapol_expanded_wfa_wps) 
                return std::static_pointer_cast<eapol_extended_wpa_wps>(eapol_content());
            return NULL;
        }

    protected:
        uint8_t m_eapol_type;
        uint8_t m_eapol_id;
        uint16_t m_eapol_len;
        uint8_t m_eapol_expanded_type;
        std::string m_eapol_content_data;
        std::shared_ptr<eapol_content_common> m_eapol_content;

    public:
        class eapol_content_common {
        public:
            eapol_content_common() { }
            virtual ~eapol_content_common() { }
        };

        class eapol_extended_wpa_wps : public eapol_content_common {
        public:
            class eapol_wpa_field;
            typedef std::vector<std::shared_ptr<eapol_wpa_field> > shared_eapol_wpa_field_vector;

            enum eapol_wpa_field_vendortype_e {
                eapol_wpa_field_vendortype_simpleconfig = 0x1
            };

            enum eapol_wpa_field_opcode_e {
                eapol_wpa_field_opcode_wsc_msg = 0x04
            };

            eapol_extended_wpa_wps() {}
            virtual ~eapol_extended_wpa_wps() { }

            void parse(std::shared_ptr<kaitai::kstream> p_io);
			void parse(const std::string& data);

            std::string vendor_id() const {
                return m_vendor_id;
            }

            constexpr17 eapol_wpa_field_vendortype_e vendor_type() const {
                return (eapol_wpa_field_vendortype_e) m_vendor_type;
            }

            constexpr17 eapol_wpa_field_opcode_e opcode() const {
                return (eapol_wpa_field_opcode_e) m_opcode;
            }

            constexpr17 uint8_t flags() const {
                return m_flags;
            }

            std::shared_ptr<shared_eapol_wpa_field_vector> fields() const {
                return m_fields;
            }

        protected:
            std::string m_vendor_id;
            uint32_t m_vendor_type;
            uint8_t m_opcode;
            uint8_t m_flags;
            std::shared_ptr<shared_eapol_wpa_field_vector> m_fields;

        public:
            class eapol_wpa_field {
            public:
                class eapol_field_common;
                class eapol_field_version;
                class eapol_field_message_type;
                class eapol_field_uuid;
                class eapol_field_auth_type_flags;
                class eapol_field_encryption_type_flags;
                class eapol_field_connection_type_flags;
                class eapol_field_config_methods;

                enum eapol_wpa_field_type_e {
                    wpa_field_type_auth_flags = 0x1004,
                    wpa_field_type_authenticator = 0x1005,
                    wpa_field_type_connection_flags = 0x100d,
                    wpa_field_type_config_methods = 0x1008,
                    wpa_field_type_encryption_flags = 0x1010,
                    wpa_field_type_wpa_e_hash1 = 0x1014,
                    wpa_field_type_wpa_e_hash2 = 0x1015,
                    wpa_field_type_wpa_e_nonce = 0x101a,
                    wpa_field_type_wpa_mac_address = 0x1020,
                    wpa_field_type_wpa_manufacturer = 0x1021,
                    wpa_field_type_wpa_message_type = 0x1022,
                    wpa_field_type_wpa_model_name = 0x1023,
                    wpa_field_type_wpa_model_number = 0x1024,
                    wpa_field_type_wpa_public_key = 0x1032,
                    wpa_field_type_wpa_registrar_nonce = 0x1039,
                    wpa_field_type_wpa_serial_number = 0x1042,
                    wpa_field_type_wpa_uuid = 0x1047,
                    wpa_field_type_vendor_extension = 0x1049,
                    wpa_field_type_version = 0x104a
                };

                eapol_wpa_field() { }
                ~eapol_wpa_field() { }

                void parse(kaitai::kstream& p_io);

                constexpr17 eapol_wpa_field_type_e type() const {
                    return (eapol_wpa_field_type_e) m_type;
                }

                constexpr17 uint16_t len() const {
                    return m_len;
                }

                constexpr17 const std::string& content_data() const {
                    return m_content_data;
                }

                std::shared_ptr<eapol_field_common> content() const {
                    return m_content;
                }

                std::shared_ptr<eapol_field_version> content_version() const {
                    if (type() == wpa_field_type_version)
                        return std::static_pointer_cast<eapol_field_version>(content());
                    return NULL;
                }

                std::shared_ptr<eapol_field_message_type> content_message_type() const {
                    if (type() == wpa_field_type_wpa_message_type)
                        return std::static_pointer_cast<eapol_field_message_type>(content());
                    return NULL;
                }

                std::shared_ptr<eapol_field_uuid> content_uuid() const {
                    if (type() == wpa_field_type_wpa_uuid) 
                        return std::static_pointer_cast<eapol_field_uuid>(content());
                    return NULL;
                }

                std::shared_ptr<eapol_field_auth_type_flags> content_auth_type_flags() const {
                    if (type() == wpa_field_type_auth_flags) 
                        return std::static_pointer_cast<eapol_field_auth_type_flags>(content());
                    return NULL;
                }

                std::shared_ptr<eapol_field_encryption_type_flags> content_encryption_type_flags() const {
                    if (type() == wpa_field_type_encryption_flags)
                        return std::static_pointer_cast<eapol_field_encryption_type_flags>(content());
                    return NULL;
                }

                std::shared_ptr<eapol_field_connection_type_flags> content_connection_type_flags() const {
                    if (type() == wpa_field_type_connection_flags)
                        return std::static_pointer_cast<eapol_field_connection_type_flags>(content());
                    return NULL;
                }

                std::shared_ptr<eapol_field_config_methods> content_config_methods() const {
                    if (type() == wpa_field_type_connection_flags)
                        return std::static_pointer_cast<eapol_field_config_methods>(content());
                    return NULL;
                }

            protected:
                uint16_t m_type;
                uint16_t m_len;
                std::string m_content_data;
                std::shared_ptr<eapol_field_common> m_content;

            public:
                class eapol_field_common {
                public:
                    eapol_field_common() { }
                    virtual ~eapol_field_common() { }
                };

                class eapol_field_version : public eapol_field_common {
                public:
                    eapol_field_version() { }
                    virtual ~eapol_field_version() { }

                    void parse(const std::string& data);

                    uint8_t version() {
                        return m_version;
                    }

                protected:
                    uint8_t m_version;
                };

                class eapol_field_message_type : public eapol_field_common {
                public:
                    enum messagetype_e {
                        eapol_messagetype_m1 = 0x04,
                        eapol_messagetype_m2 = 0x05,
                        eapol_messagetype_m2d = 0x06,
                        eapol_messagetype_m3 = 0x07,
                        eapol_messagetype_m4 = 0x08,
                        eapol_messagetype_wsc_nack = 0x0e
                    };

                    eapol_field_message_type() {}
                    virtual ~eapol_field_message_type() {}

                    void parse(std::shared_ptr<kaitai::kstream> p_io);
					void parse(const std::string& data);

                    constexpr17 messagetype_e messagetype() const {
                        return (messagetype_e) m_messagetype;
                    }

                protected:
                    uint8_t m_messagetype;
                };

                class eapol_field_uuid : public eapol_field_common {
                public:
                    eapol_field_uuid() {}
                    virtual ~eapol_field_uuid() {}

                    void parse(std::shared_ptr<kaitai::kstream> p_io);
					void parse(const std::string& data);

                    std::string uuid() const {
                        return m_uuid;
                    }

                protected:
                    std::string m_uuid;
                };

                class eapol_field_auth_type_flags : public eapol_field_common {
                public:
                    eapol_field_auth_type_flags() {}
                    virtual ~eapol_field_auth_type_flags() {}

                    void parse(std::shared_ptr<kaitai::kstream> p_io);
					void parse(const std::string& data);

                    constexpr17 uint16_t flags() const {
                        return m_flags;
                    }

                    constexpr17 unsigned int flag_open() const {
                        return flags() & 0x01;
                    }

                    constexpr17 unsigned int flag_wep() const {
                        return flags() & 0x02;
                    }

                    constexpr17 unsigned int flag_tkip() const {
                        return flags() & 0x04;
                    }

                    constexpr17 unsigned int flag_aes() const {
                        return flags() & 0x08;
                    }

                protected:
                    uint16_t m_flags;
                };

                class eapol_field_encryption_type_flags : public eapol_field_common {
                public:
                    eapol_field_encryption_type_flags() {}
                    virtual ~eapol_field_encryption_type_flags() {}

                    void parse(std::shared_ptr<kaitai::kstream> p_io);
					void parse(const std::string& data);

                    constexpr17 uint16_t flags() const {
                        return m_flags;
                    }

                    constexpr17 unsigned int flag_open() const {
                        return flags() & 0x01;
                    }

                    constexpr17 unsigned int flag_wep() const {
                        return flags() & 0x02;
                    }

                    constexpr17 unsigned int flag_tkip() const {
                        return flags() & 0x04;
                    }

                    constexpr17 unsigned int flag_aes() const {
                        return flags() & 0x08;
                    }

                protected:
                    uint16_t m_flags;
                };

                class eapol_field_connection_type_flags : public eapol_field_common {
                public:
                    eapol_field_connection_type_flags() {}
                    virtual ~eapol_field_connection_type_flags() {}

                    void parse(std::shared_ptr<kaitai::kstream> p_io);
					void parse(const std::string& data);

                    constexpr17 uint8_t flags() const {
                        return m_flags;
                    }

                    constexpr17 unsigned int flag_ess() const {
                        return flags() & 0x01;
                    }

                    constexpr17 unsigned int flag_ibss() const {
                        return flags() & 0x02;
                    }

                protected:
                    uint8_t m_flags;
                };

                class eapol_field_config_methods : public eapol_field_common {
                public:
                    eapol_field_config_methods() {}
                    virtual ~eapol_field_config_methods() {}

                    void parse(std::shared_ptr<kaitai::kstream> p_io);
					void parse(const std::string& data);

                    constexpr17 uint16_t flags() const {
                        return m_flags;
                    }

                    constexpr17 unsigned int flag_usb() const {
                        return flags() & 0x01;
                    }

                    constexpr17 unsigned int flag_ethernet() const {
                        return flags() & 0x02;
                    }

                    constexpr17 unsigned int flag_label() const {
                        return flags() & 0x04;
                    }

                    constexpr17 unsigned int flag_display() const {
                        return flags() & 0x08;
                    }

                    constexpr17 unsigned int flag_external_nfc() const {
                        return flags() & 0x10;
                    }

                    constexpr17 unsigned int flag_internal_nfc() const {
                        return flags() & 0x20;
                    }

                    constexpr17 unsigned int flag_nfc_interface() const {
                        return flags() & 0x40;
                    }

                    constexpr17 unsigned int flag_push_button() const {
                        return flags() & 0x80;
                    }

                    constexpr17 unsigned int flag_keypad() const {
                        return flags() & 0x100;
                    } 

                    constexpr17 unsigned int flag_virtual_button() const {
                        return flags() & 0x200;
                    }

                    constexpr17 unsigned int flag_physical_button() const {
                        return flags() & 0x400;
                    }

                    constexpr17 unsigned int flag_virtual_display() const {
                        return flags() & 0x1000;
                    }

                    constexpr17 unsigned int flag_physical_display() const {
                        return flags() & 0x2000;
                    }

                protected:
                    uint16_t m_flags;
                };
            };

        };


    };

};


#endif

