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

    uint8_t dot1x_version() {
        return m_dot1x_version;
    }

    dot1x_type_e dot1x_type() {
        return (dot1x_type_e) m_dot1x_type;
    }

    uint16_t dot1x_len() {
        return m_dot1x_len;
    }

    std::string dot1x_data() {
        return m_dot1x_data;
    }

    std::shared_ptr<kaitai::kstream> dot1x_data_stream() {
        return m_dot1x_data_stream;
    }

    std::shared_ptr<dot1x_common> dot1x_content() {
        return m_dot1x_content;
    }

    std::shared_ptr<dot1x_eap_packet> dot1x_content_eap_packet() {
        if (dot1x_type() == dot1x_type_eap_packet) 
            return std::static_pointer_cast<dot1x_eap_packet>(dot1x_content());
        return NULL;
    }

    std::shared_ptr<dot1x_key> dot1x_content_key() {
        if (dot1x_type() == dot1x_type_eap_key)
            return std::static_pointer_cast<dot1x_key>(dot1x_content());
        return NULL;
    }

protected:
    uint8_t m_dot1x_version;
    uint8_t m_dot1x_type;
    uint16_t m_dot1x_len;
    std::string m_dot1x_data;
    std::shared_ptr<kaitai::kstream> m_dot1x_data_stream;
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

        dot1x_key_type_e key_descriptor_type() {
            return (dot1x_key_type_e) m_key_descriptor_type;
        }

        std::string key_content_data() {
            return m_key_content_data;
        }

        std::shared_ptr<kaitai::kstream> key_content_data_stream() {
            return m_key_content_data_stream;
        }

        std::shared_ptr<dot1x_key_common> key_content() {
            return m_key_content;
        }

        std::shared_ptr<eapol_key_rsn> key_content_eapolrsn() {
            if (key_descriptor_type() == dot1x_key_type_eapol_rsn)
                return std::static_pointer_cast<eapol_key_rsn>(key_content());
            return NULL;
        }

    protected:
        uint8_t m_key_descriptor_type;
        std::string m_key_content_data;
        std::shared_ptr<kaitai::kstream> m_key_content_data_stream;
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

            uint16_t key_info() {
                return m_key_info;
            }

            uint16_t key_len() {
                return m_key_len;
            }

            uint64_t replay_counter() {
                return m_replay_counter;
            }

            std::string wpa_key_nonce() {
                return m_wpa_key_nonce;
            } 

            std::string wpa_key_iv() {
                return m_wpa_key_iv;
            }

            std::string wpa_key_rsc() {
                return m_wpa_key_rsc;
            }
            std::string wpa_key_id() {
                return m_wpa_key_id;
            }

            std::string wpa_key_mic() {
                return m_wpa_key_mic;
            }

            uint16_t wpa_key_data_len() {
                return m_wpa_key_data_len;
            }

            std::string wpa_key_data() {
                return m_wpa_key_data;
            }

            unsigned int key_info_descriptor_version() {
                return key_info() & 0x7;
            }

            unsigned int key_info_pairwise_key() {
                return key_info() & 0x8;
            }

            unsigned int key_info_key_index() {
                return key_info() & 0x30;
            }

            unsigned int key_info_install() {
                return key_info() & 0x40;
            }

            unsigned int key_info_key_ack() {
                return key_info() & 0x80;
            }

            unsigned int key_info_key_mic() {
                return key_info() & 0x100;
            }

            unsigned int key_info_secure() {
                return key_info() & 0x200;
            }

            unsigned int key_info_error() {
                return key_info() & 0x400;
            }

            unsigned int key_info_request() {
                return key_info() & 0x800;
            }

            unsigned int key_info_encrypted_key_data() {
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

        eapol_type_e eapol_type() {
            return (eapol_type_e) m_eapol_type;
        }

        uint8_t eapol_id() {
            return m_eapol_id;
        }

        uint16_t eapol_len() {
            return m_eapol_len;
        }

        eapol_expanded_type_e eapol_expanded_type() { 
            return (eapol_expanded_type_e) m_eapol_expanded_type;
        }

        std::string eapol_content_data() {
            return m_eapol_content_data;
        }

        std::shared_ptr<kaitai::kstream> p_io() {
            return m_eapol_content_data_stream;
        }

        std::shared_ptr<eapol_content_common> eapol_content() {
            return m_eapol_content;
        }

        std::shared_ptr<eapol_extended_wpa_wps> eapol_content_wpa_wps() {
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
        std::shared_ptr<kaitai::kstream> m_eapol_content_data_stream;
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

            std::string vendor_id() {
                return m_vendor_id;
            }

            eapol_wpa_field_vendortype_e vendor_type() {
                return (eapol_wpa_field_vendortype_e) m_vendor_type;
            }

            eapol_wpa_field_opcode_e opcode() {
                return (eapol_wpa_field_opcode_e) m_opcode;
            }

            uint8_t flags() {
                return m_flags;
            }

            std::shared_ptr<shared_eapol_wpa_field_vector> fields() {
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

                void parse(std::shared_ptr<kaitai::kstream> p_io);

                eapol_wpa_field_type_e type() {
                    return (eapol_wpa_field_type_e) m_type;
                }

                uint16_t len() {
                    return m_len;
                }

                std::string content_data() {
                    return m_content_data;
                }

                std::shared_ptr<kaitai::kstream> content_data_stream() {
                    return m_content_data_stream;
                }

                std::shared_ptr<eapol_field_common> content() {
                    return m_content;
                }

                std::shared_ptr<eapol_field_version> content_version() {
                    if (type() == wpa_field_type_version)
                        return std::static_pointer_cast<eapol_field_version>(content());
                    return NULL;
                }

                std::shared_ptr<eapol_field_message_type> content_message_type() {
                    if (type() == wpa_field_type_wpa_message_type)
                        return std::static_pointer_cast<eapol_field_message_type>(content());
                    return NULL;
                }

                std::shared_ptr<eapol_field_uuid> content_uuid() {
                    if (type() == wpa_field_type_wpa_uuid) 
                        return std::static_pointer_cast<eapol_field_uuid>(content());
                    return NULL;
                }

                std::shared_ptr<eapol_field_auth_type_flags> content_auth_type_flags() {
                    if (type() == wpa_field_type_auth_flags) 
                        return std::static_pointer_cast<eapol_field_auth_type_flags>(content());
                    return NULL;
                }

                std::shared_ptr<eapol_field_encryption_type_flags> content_encryption_type_flags() {
                    if (type() == wpa_field_type_encryption_flags)
                        return std::static_pointer_cast<eapol_field_encryption_type_flags>(content());
                    return NULL;
                }

                std::shared_ptr<eapol_field_connection_type_flags> content_connection_type_flags() {
                    if (type() == wpa_field_type_connection_flags)
                        return std::static_pointer_cast<eapol_field_connection_type_flags>(content());
                    return NULL;
                }

                std::shared_ptr<eapol_field_config_methods> content_config_methods() {
                    if (type() == wpa_field_type_connection_flags)
                        return std::static_pointer_cast<eapol_field_config_methods>(content());
                    return NULL;
                }

            protected:
                uint16_t m_type;
                uint16_t m_len;
                std::string m_content_data;
                std::shared_ptr<kaitai::kstream> m_content_data_stream;
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

                    void parse(std::shared_ptr<kaitai::kstream> p_io);

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

                    messagetype_e messagetype() {
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

                    std::string uuid() {
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

                    uint16_t flags() {
                        return m_flags;
                    }

                    unsigned int flag_open() {
                        return flags() & 0x01;
                    }

                    unsigned int flag_wep() {
                        return flags() & 0x02;
                    }

                    unsigned int flag_tkip() {
                        return flags() & 0x04;
                    }

                    unsigned int flag_aes() {
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

                    uint16_t flags() {
                        return m_flags;
                    }

                    unsigned int flag_open() {
                        return flags() & 0x01;
                    }

                    unsigned int flag_wep() {
                        return flags() & 0x02;
                    }

                    unsigned int flag_tkip() {
                        return flags() & 0x04;
                    }

                    unsigned int flag_aes() {
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

                    uint8_t flags() {
                        return m_flags;
                    }

                    unsigned int flag_ess() {
                        return flags() & 0x01;
                    }

                    unsigned int flag_ibss() {
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

                    uint16_t flags() {
                        return m_flags;
                    }

                    unsigned int flag_usb() {
                        return flags() & 0x01;
                    }

                    unsigned int flag_ethernet() {
                        return flags() & 0x02;
                    }

                    unsigned int flag_label() {
                        return flags() & 0x04;
                    }

                    unsigned int flag_display() {
                        return flags() & 0x08;
                    }

                    unsigned int flag_external_nfc() {
                        return flags() & 0x10;
                    }

                    unsigned int flag_internal_nfc() {
                        return flags() & 0x20;
                    }

                    unsigned int flag_nfc_interface() {
                        return flags() & 0x40;
                    }

                    unsigned int flag_push_button() {
                        return flags() & 0x80;
                    }

                    unsigned int flag_keypad() {
                        return flags() & 0x100;
                    } 

                    unsigned int flag_virtual_button() {
                        return flags() & 0x200;
                    }

                    unsigned int flag_physical_button() {
                        return flags() & 0x400;
                    }

                    unsigned int flag_virtual_display() {
                        return flags() & 0x1000;
                    }

                    unsigned int flag_physical_display() {
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

