meta:
  id: dot11_ie_192_vht_operation
  file-extension: dot11_ie_192_vht_operation

seq:
  - id: channel_width
    type: u1
    enum: channel_width
  - id: center1
    type: u1
  - id: center2
    type: u1
  - id: basic_mcs_map
    type: mcs_map

enums:
  channel_width:
    0x00: ch_20_40
    0x01: ch_80
    0x02: ch_160
    0x03: ch_80_80
    
types:
  mcs_map:
    seq:
      - id: basic_4
        type: b2
      - id: basic_3
        type: b2
      - id: basic_2
        type: b2
      - id: basic_1
        type: b2
      - id: basic_8
        type: b2
      - id: basic_7
        type: b2
      - id: basic_6
        type: b2
      - id: basic_5
        type: b2