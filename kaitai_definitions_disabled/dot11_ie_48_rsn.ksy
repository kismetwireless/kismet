meta:
  id: dot11_ie_48_rsn
  file-extension: dot11_ie_48_rsn

doc: |
  IE tag 48 defines the 802.11i RSN (Robust Security Network) settings
  
seq:
  - id: rsn_version
    type: u2le
  - id: group_cipher
    type: rsn_cipher
  - id: pairwise_count
    type: u2le
  - id: pairwise_ciphers
    type: rsn_cipher
    repeat: expr
    repeat-expr: pairwise_count
  - id: akm_count
    type: u2le
  - id: akm_ciphers
    type: rsn_management
    repeat: expr
    repeat-expr: akm_count
    
types:
  rsn_cipher:
    seq:
      - id: cipher_suite_oui
        size: 3
      - id: cipher_type
        type: u1
        enum: rsn_cipher_types
        
  rsn_management:
    seq:
      - id: management_suite_oui
        size: 3
      - id: management_type
        type: u1
        enum: rsn_management_types
    
enums:
  rsn_cipher_types:
    0: rsn_none
    1: rsn_wep_40
    2: rsn_tkip
    3: rsn_aes_ocb
    4: rsn_aes_ccm
    5: rsn_wep_104
    6: rsn_bip
    7: rsn_no_group
    8: rsn_gcmp
    
  rsn_management_types:
    0: mgmt_none
    1: mgmt_wpa
    2: mgmt_psk
    3: mgmt_ft_dot1x
    4: mgmt_ft_psk
    5: mgmt_wpa_sha256
    6: mgmt_psk_sha256
    7: mgmt_tdls_tpk
    
