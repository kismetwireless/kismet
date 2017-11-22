meta:
  id: dot11_ie_61_ht
  file-extension: dot11_ie_61_ht

seq:
  - id: primary_channel
    type: u1
  - id: info_subset_1
    type: u1
  - id: info_subset_2
    type: u2be
  - id: info_subset_3
    type: u2be
  - id: rx_coding_scheme
    type: u2le

instances:
  ht_info_chan_offset:
    value: "info_subset_1 & 0x03"
  ht_info_chan_offset_none:
    value: "(info_subset_1 & 0x03) == 0x00"
  ht_info_chan_offset_above:
    value: "(info_subset_1 & 0x03) == 0x01"
  ht_info_chan_offset_below:
    value: "(info_subset_1 & 0x03) == 0x03"
  ht_info_chanwidth:
    value: "info_subset_1 & 0x04"
  ht_info_rifs:
    value: "info_subset_1 & 0x08"
  ht_info_psmp_station:
    value: "info_subset_1 & 0x10"
  ht_info_shortest_psmp:
    value: "(info_subset_1 & 0xe0) >> 5"
  

