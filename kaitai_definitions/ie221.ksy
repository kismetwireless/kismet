meta:
  id: ie221
  endian: be
  
seq:
    # We're called inside the IE tag
    #- id: tag_number
    #type: u1

  - id: tag_length
    type: u1
    
  # Hardcode the MS OUI used for WMM/WME
  - id: vendor_oui
    size: 3

  # Vendor specific OUI
  - id: vendor_type
    type: u1
    
  # This should be broken out for future code but for now we 
  # just check the headers and length
    
    
    
    
    
