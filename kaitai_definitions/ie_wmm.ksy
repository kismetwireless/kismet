meta:
  id: ie_wmm
  endian: be
  
seq:
  - id: tag_number
    type: u1
  - id: tag_length
    type: u1
  - id: wmm_oui
    contents: [0x00, 0x50, 0xf2]
  
  # For proper demod this needs to be broken out further
  - id: wmm_type
    type: u1
  - id: wme_subtype
    type: u1
  - id: wme_version
    type: u1
  
    
    
    
    
    