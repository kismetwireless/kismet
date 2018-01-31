meta:
  id: wpaeap
  endian: be
  
seq:
  - id: dot1x_version
    type: u1
  - id: dot1x_type
    type: u1
    enum: dot1x_type_enum
  - id: dot1x_length
    type: u2
  - id: dot1x_content
    type:
      switch-on: dot1x_type
      cases:
        'dot1x_type_enum::eap_packet': dot1x_eapol
        'dot1x_type_enum::key': dot1x_key
    
            
types:
  dot1x_key:
    seq:
      - id: key_descriptor_type
        type: u1
        enum: dot1x_key_type_enum
      - id: key_content
        type:
          switch-on: key_descriptor_type
          cases:
            'dot1x_key_type_enum::eapol_rsn_key': eapol_rsn_key
  
  eapol_rsn_key:
    seq:
      - id: key_information
        type: eapol_rsn_key_info
      - id: key_length
        type: u2
      - id: replay_counter
        type: u8
      - id: wpa_key_nonce
        size: 32
      - id: key_iv
        size: 16
      - id: wpa_key_rsc
        size: 8
      - id: wpa_key_id
        size: 8
      - id: wpa_key_mic
        size: 16
      - id: wpa_key_data_length
        type: u2
      - id: wpa_key_data
        size: wpa_key_data_length
        
  eapol_rsn_key_info:
    seq:
      - id: unused
        type: b3
      - id: encrypted_key_data
        type: b1
      - id: request
        type: b1
      - id: error
        type: b1
      - id: secure
        type: b1
      - id: key_mic
        type: b1
      - id: key_ack
        type: b1
      - id: install
        type: b1
      - id: key_index
        type: b2
      - id: pairwise_key
        type: b1
      - id: key_descriptor_version
        type: b3
        enum: key_descriptor_version_enum
  
  dot1x_eapol:
    seq:
      - id: eapol_type
        type: u1
        enum: eapol_type_enum
      - id: eapol_id
        type: u1
      - id: eapol_length
        type: u2
      - id: eapol_expanded_type
        type: u1
        enum: eapol_expanded_type_enum
      - id: content
        type:
          switch-on: eapol_expanded_type
          cases:
            'eapol_expanded_type_enum::wfa_wps': eapol_extended_wpa_wps

  eapol_extended_wpa_wps:
    seq:
      - id: vendor_id
        contents: [0x00, 0x37, 0x2a]
      - id: vendor_type
        type: u4
        enum: eapol_wfa_vendortype_enum
      - id: opcode
        type: u1
        enum: eapol_wfa_opcode
      - id: flags
        type: u1
      - id: fields
        type: eapol_field
        repeat: eos

  eapol_field:
    seq:
      - id: type
        type: u2
        enum: eapol_field_type_enum
      - id: field_length
        type: u2
      - id: content
        size: field_length
        type:
          switch-on: type
          cases:
            'eapol_field_type_enum::version': eapol_field_version
            'eapol_field_type_enum::message_type': eapol_field_messagetype
            'eapol_field_type_enum::uuid': eapol_field_uuid
            'eapol_field_type_enum::auth_type_flags': eapol_field_auth_type_flags
            'eapol_field_type_enum::encryption_type_flags': eapol_field_encryption_type_flags
            'eapol_field_type_enum::connection_type_flags': eapol_field_connection_type_flags
            'eapol_field_type_enum::config_methods': eapol_field_config_methods
        
  eapol_field_version:
    seq:
      - id: version
        type: u1
        
  eapol_field_messagetype:
    seq:
      - id: messagetype
        type: u1
        enum: eapol_messagetype_enum
  
  eapol_field_uuid:
    seq:
      - id: uuid
        size: 16
        
  eapol_field_macaddress:
    seq:
      - id: macaddress
        size: 6
        
  eapol_field_auth_type_flags:
    seq:
      - id: unused
        type: b10
      - id: wpa2psk
        type: b1
      - id: wpa2
        type: b1
      - id: wpa
        type: b1
      - id: shared
        type: b1
      - id: wpapsk
        type: b1
      - id: open
        type: b1
  
  eapol_field_encryption_type_flags:
    seq:
      - id: unused
        type: b12
      - id: aes
        type: b1
      - id: tkip
        type: b1
      - id: wep
        type: b1
      - id: none
        type: b1
        
  eapol_field_connection_type_flags:
    seq:
      - id: unused
        type: b6
      - id: ibss
        type: b1
      - id: ess
        type: b1
  
  eapol_field_config_methods:
    seq:
      - id: unused
        type: b1
      - id: physical_display
        type: b1
      - id: virtual_display
        type: b1
      - id: unused2
        type: b2
      - id: physical_button
        type: b1
      - id: virtual_button
        type: b1
      - id: keypad
        type: b1
      - id: push_button
        type: b1
      - id: nfc_interface
        type: b1
      - id: internal_nfc
        type: b1
      - id: external_nfc
        type: b1
      - id: display
        type: b1
      - id: label
        type: b1
      - id: ethernet
        type: b1
      - id: usb
        type: b1
        

enums:
  dot1x_type_enum:
    0x00: eap_packet
    0x03: key
    
  dot1x_key_type_enum:
    0x02: eapol_rsn_key
    
  key_descriptor_version_enum:
    0x01: rc4_hmac_md5
    0x02: aes_hmac_sha1
    0x03: aes_hmac_aes128_cmac
    
  eapol_type_enum:
    0x01: request
    0x02: response

  eapol_expanded_type_enum:
    0xFE: wfa_wps
    
  eapol_wfa_vendortype_enum:
    0x00000001: simpleconfig
    
  eapol_wfa_opcode:
    0x04: wsc_msg
    
  eapol_field_type_enum:
    0x1004: auth_type_flags
    0x1005: authenticator
    0x100d: connection_type_flags
    0x1008: config_methods
    0x1010: encryption_type_flags
    0x1014: e_hash1
    0x1015: e_hash2
    0x101a: e_nonce
    0x1020: mac_address
    0x1021: manufacturer
    0x1022: message_type
    0x1023: model_name
    0x1024: model_number
    0x1032: public_key
    0x1039: regstrar_nonce
    0x1042: serial_number
    0x1047: uuid
    0x1049: vendor_extension
    0x104a: version
    
  eapol_messagetype_enum:
    0x04: m1
    0x04: m2
    0x07: m3
    0x08: m4
    0x0e: wsc_nack
