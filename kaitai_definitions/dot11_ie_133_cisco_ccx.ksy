meta:
  id: dot11_ie_133_cisco_ccx
  file-extension: dot11_ie_133_cisco_ccx
  endian: be

seq:
  - id: ccx1_unk1
    size: 10
  - id: ap_name
    type: strz
    encoding: ASCII
    size: 16
  - id: station_count
    type: u1
  - id: ccx1_unk2
    size: 3

