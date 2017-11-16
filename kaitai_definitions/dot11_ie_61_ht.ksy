meta:
  id: dot11_ie_61_ht
  file-extension: dot11_ie_61_ht

seq:
  - id: primary_channel
    type: u1
  - id: info_subset_1
    type: ht_info_subset_1
  - id: info_subset_2
    type: ht_info_subset_2
  - id: info_subset_3
    type: ht_info_subset_3
  - id: rx_coding_scheme
    type: u2le

instances:
  ie_num:
    value: 61
  
types:
  ht_info_subset_1:
    seq:
      - id: ssi
        type: b3
      - id: psmp_only
        type: b1
      - id: rifs
        type: b1
      - id: channel_width
        type: b1
      - id: secondary_offset
        type: b2
        enum: secondary_offset_type
        
  ht_info_subset_2:
    seq:
      - id: reserved0
        type: b3
      - id: non_ht_present
        type: b1
      - id: tx_burst_limit
        type: b1
      - id: non_greenfield_present
        type: b1
      - id: operating_mode
        type: b2
      - id: reserved1
        type: b8
        
  ht_info_subset_3:
    seq:
      - id: dual_cts_required
        type: b1
      - id: dual_beacon_tx
        type: b1
      - id: reserved0
        type: b6
      - id: reserved1
        type: b4
      - id: pco_phase
        type: b1
      - id: pco_phase_enabled
        type: b1
      - id: lsig_txop_protection
        type: b1
      - id: beacon_id
        type: b1

enums:
  secondary_offset_type:
    0x00: no_secondary
    0x01: secondary_above
    0x02: reserved
    0x03: secondary_below
    
