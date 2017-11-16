meta:
  id: dot11_ie_52_rmm_neighbor
  file-extension: dot11_ie_52_rmm_neighbor

seq:
  - id: bssid
    size: 6
  - id: bssid_info
    type: u4le
  - id: operating_class
    type: u1
  - id: channel_number
    type: u1
  - id: phy_type
    type: u1
    
instances:
  bssid_reachability:
    value: "bssid_info & 0x03"
  bssid_security:
    value: "bssid_info & 0x04"
  bssid_keyscope:
    value: "bssid_info & 0x08"
  bssid_capability:
    value: "(bssid_info & 0x3F0) >> 4"
  bssid_mobility_domain:
    value: "(bssid_info & 0x400)"
  bssid_ht:
    value: "(bssid_info & 0x800)"
  
    
types:
  bssid_info_bits:
    seq:
      - id: reachability
        type: b2
      - id: security
        type: b1
      - id: key_scope
        type: b1
      - id: capability
        type: b6
        
    