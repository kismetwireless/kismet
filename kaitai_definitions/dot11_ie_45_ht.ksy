meta:
  id: dot11_ie_45_ht
  file-extension: dot11_ie_45_ht

seq:
  - id: ht_capabilities
    type: u2le
  - id: ampdu
    type: u1
  - id: mcs
    type: rx_mcs
  - id: ht_extended_caps
    type: u2be
  - id: txbf_caps
    type: u4be
  - id: asel_caps
    type: u1
    
types:
  rx_mcs:
    seq:
      - id: rx_mcs
        size: 10
      - id: supported_data_rate
        type: u2le
      - id: txflags
        type: u4be

instances:
  ht_cap_ldpc:
    value: "ht_capabilities & 0x01"
  ht_cap_40mhz_channel:
    value: "ht_capabilities & 0x02"
  ht_cap_sm_powersave:
    value: "ht_capabilities & 0x0C"
  ht_cap_greenfield:
    value: "ht_capabilities & 0x10"
  ht_cap_20mhz_shortgi:
    value: "ht_capabilities & 0x20"
  ht_cap_40mhz_shortgi:
    value: "ht_capabilities & 0x40"
  ht_cap_tx_stbc:
    value: "ht_capabilities & 0x80"
  ht_cap_rx_stbc:
    value: "ht_capabilities & 0x300"
  ht_cap_delayed_block_ack:
    value: "ht_capabilities & 0x400"
  ht_cap_max_amsdu_len:
    value: "ht_capabilities & 0x800"
  ht_cap_dss_40mhz:
    value: "ht_capabilities & 0x1000"
  ht_cap_psmp_intolerant:
    value: "ht_capabilities & 0x2000"
  ht_cap_40mhz_intolerant:
    value: "ht_capabilities & 0x4000"
  ht_cap_lsig_txop:
    value: "ht_capabilities & 0x8000"

      
