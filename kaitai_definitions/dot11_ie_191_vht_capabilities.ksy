meta:
  id: dot11_ie_191_vht_capabilities
  file-extension: dot11_ie_191_vht_capabilities

seq:
  - id: vht_capabilities
    type: u4le
  - id: rx_mcs_map
    type: u2le
  - id: rx_mcs_set
    type: u2le
  - id: tx_mcs_map
    type: u2le
  - id: tx_mcs_set
    type: u2le
  
instances:
  vht_cap_160mhz_supported:
    value: "(vht_capabilities & 0xC)"
  vht_cap_80mhz_shortgi:
    value: "(vht_capabilities & 0x20)"
  vht_cap_160mhz_shortgi:
    value: "(vht_capabilities & 0x40)"
    
  rx_mcs_s1:
    value: "(rx_mcs_map & 0x3)"
  rx_mcs_s2:
    value: "(rx_mcs_map & 0xC) >> 2"
  rx_mcs_s3:
    value: "(rx_mcs_map & 0x30) >> 4"
  rx_mcs_s4:
    value: "(rx_mcs_map & 0xC0) >> 6"
  rx_mcs_s5:
    value: "(rx_mcs_map & 0x300) >> 8"
  rx_mcs_s6:
    value: "(rx_mcs_map & 0xC00) >> 10"
  rx_mcs_s7:
    value: "(rx_mcs_map & 0x3000) >> 12"
  rx_mcs_s8:
    value: "(rx_mcs_map & 0xC000) >> 14"
    
  tx_mcs_s1:
    value: "(tx_mcs_map & 0x3)"
  tx_mcs_s2:
    value: "(tx_mcs_map & 0xC) >> 2"
  tx_mcs_s3:
    value: "(tx_mcs_map & 0x30) >> 4"
  tx_mcs_s4:
    value: "(tx_mcs_map & 0xC0) >> 6"
  tx_mcs_s5:
    value: "(tx_mcs_map & 0x300) >> 8"
  tx_mcs_s6:
    value: "(tx_mcs_map & 0xC00) >> 10"
  tx_mcs_s7:
    value: "(tx_mcs_map & 0x3000) >> 12"
  tx_mcs_s8:
    value: "(tx_mcs_map & 0xC000) >> 14"
