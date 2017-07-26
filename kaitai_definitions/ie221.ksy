meta:
  id: ie221
  endian: be
  
seq:
  - id: tag_number
    type: u1
  - id: tag_length
    type: u1
    
  # Hardcode the MS OUI used for WMM/WME
  - id: wmm_oui
    contents: [0x00, 0x50, 0xf2]

  # Vendor specific OUI
  - id: vendor_type
    contents: u1
    
  # This should be broken out for future code but for now we 
  # just check the headers and length
    
    
    
    
    
