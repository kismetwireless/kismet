meta:
  id: dot11_action
  file-extension: dot11_action
  
doc: |
  IEEE802.11 action frames; they look a lot like management frames
  but with a custom frame control header.
  
  Some of the IE tag parsing overlaps with existing IE tag parsers
  
seq:
  - id: category_code
    type: u1
    enum: category_code_type
  - id: action_frame
    size-eos: true
    type:
      switch-on: category_code
      cases:
        'category_code_type::radio_measurement': action_rmm
        
types:
  action_rmm:
    seq:
      - id: rmm_action_code
        type: u1
        enum: rmm_action_type
      - id: dialog_token
        type: u1
      - id: tags
        type: ie_tag
        repeat: eos

  ie_tag:
    seq:
      - id: ie
        type: u1
      - id: ie_len
        type: u1
      - id: ie_data
        size: ie_len
    
enums:
  category_code_type:
    0: spectrum_management
    1: qos
    2: dls
    3: block_ack
    4: public
    5: radio_measurement
    6: fastbss
    7: ht
    8: sa_query
    9: public_protected
    10: wnm
    11: unprotected_wnm
    12: tlds
    13: mesh
    14: multihop
    15: self_protected
    16: dmg
    17: mgmt_notification
    18: fast_session_transfer
    19: robust_av_streaming
    20: unprotected_dmg
    21: vht
    126: vendor_specific_protected
    127: vendor_specific
    
  rmm_action_type:
    0: measurement_req
    1: measurement_report
    2: link_measurement_req
    3: link_measurement_report
    4: neighbor_req
    5: neighbor_report
    
