meta:
  id: dot11_ie_221_wfa_wpa
  file-extension: dot11_ie_221_wfa_wpa
  
seq:
  - id: vendor_subtype
    type: u1
  - id: wpa_version
    type: u2le
  - id: multicast_cipher
    type: wpa_v1_cipher
  - id: unicast_count
    type: u2le
  - id: unicast_ciphers
    type: wpa_v1_cipher
    repeat: expr
    repeat-expr: unicast_count
  - id: akm_count
    type: u2le
  - id: akm_ciphers
    type: wpa_v1_cipher
    repeat: expr
    repeat-expr: akm_count
  
types:
  wpa_v1_cipher:
    seq:
      - id: oui
        size: 3
      - id: cipher_type
        type: u1
        
enums:
  wfa_wpa_cipher:
    0: none
    1: wep_40
    2: tkip
    3: aes_ocb
    4: aes_ccm
    5: wep_104
    6: bip
    7: no_group

  wfa_wpa_mgmt:
    0: none
    1: wpa
    2: psk
    3: ft_dot1x
    4: ft_psk
    5: wpa_sha256
    6: psk_sha256
    7: tdls_tpk

