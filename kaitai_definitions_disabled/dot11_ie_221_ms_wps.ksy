meta:
  id: dot11_ie_221_ms_wps
  file-extension: dot11_ie_221_ms_wps
  
seq:
  - id: vendor_subtype
    type: u1

  - id: wps_element
    type: wps_de_element
    repeat: eos

instances:
  ms_wps_oui:
    value: 0x0050f2
  ms_wps_subtype:
    value: 0x04

types:
  wps_de_element:
    seq:
      - id: wps_de_type
        type: u2be
        enum: wps_de_types
      - id: wps_de_length
        type: u2be
      - id: wps_de_content
        size: wps_de_length
        
#        type:
#          switch-on: wps_de_type
#          cases:
#            'wps_de_types::device_name': wps_de_rawstr
#            'wps_de_types::manuf': wps_de_rawstr
#            'wps_de_types::model': wps_de_rawstr
#            'wps_de_types::model_num': wps_de_rawstr
#            'wps_de_types::rfbands': wps_de_rfband
#            'wps_de_types::serial': wps_de_rawstr
#            'wps_de_types::state': wps_de_state
#            'wps_de_types::uuid_e': wps_de_uuid_e
#            'wps_de_types::vendor_extension': wps_de_vendor_extension
#            'wps_de_types::version': wps_de_version
#            'wps_de_types::primary_type': wps_de_primary_type
#            'wps_de_types::ap_setup': wps_de_ap_setup
#            _: wps_de_generic
           
    enums:
      wps_de_types:
        0x1011: device_name
        0x1021: manuf
        0x1023: model
        0x1024: model_num
        0x103c: rfbands
        0x1042: serial
        0x1044: state
        0x1047: uuid_e
        0x1049: vendor_extension
        0x104a: version
        0x1054: primary_type
        0x1057: ap_setup
 
  wps_de_rawstr:
    seq:
      - id: raw_str
        type: str
        encoding: "ASCII"
        size-eos: true

  wps_de_rfband:
    seq:
      - id: reserved1
        type: b6
      - id: rf_band_5ghz
        type: b1
      - id: rf_band_24ghz
        type: b1
  
  wps_de_state:
    seq:
      - id: state
        type: u1
    
    instances:
      wps_state_configured:
        value: 0x2
  
  wps_de_uuid_e:
    seq:
      - id: uuid_e
        size-eos: true

  wps_de_primary_type:
    seq:
      - id: category
        type: u2le
      - id: typedata
        type: u4le
      - id: subcategory
        type: u2le
        
  wps_de_vendor_extension:
    seq:
      - id: vendor_id
        size: 3
      - id: wfa_sub_id
        type: u1
      - id: wfa_sub_len
        type: u1
      - id: wfa_sub_data
        size: wfa_sub_len
        
    instances:
      wfa_sub_version:
        value: 0
        
  wps_de_version:
    seq:
      - id: version
        type: u1
        
  wps_de_ap_setup:
    seq:
      - id: ap_setup_locked
        type: u1
  
  wps_de_generic:
    seq:
      - id: wps_de_data
        size-eos: true

  vendor_data_generic:
    seq:
      - id: vendor_data
        size-eos: true


