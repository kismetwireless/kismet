# Top-level breakout for 221 vendor-specific tags, the actual tag is
# determined by the vendor OUI

meta:
  id: dot11_ie_221_vendor
  endian: be
    
seq:
  # Our substream starts inside the IE tag, after the tagno and length
  - id: vendor_oui
    size: 3

  # Switch on the vendor OUI as an integer value to break out to specific
  # 221 subpacket types
  - id: vendor_content
    type:
      switch-on: vendor_oui_int
      cases:
        _: ieee_221_vendor_tag
    
instances:
  # 4-byte integer representations of the 3-byte OUI
  vendor_oui_foo:
    value: 0x12345600

  # Absolute position of the 3 OUI bytes, pos 0 relative to the start of our stream
  vendor_oui_extract:
    type: vendor_oui_bytes
    pos: 0

  # Hack to convert the 3-byte OUI value to an integer we can use in a switch
  # statement; we can't easily 
  vendor_oui_int:
    value: (vendor_oui_extract.oui1 << 8) + (vendor_oui_extract.oui2 << 16) + (vendor_oui_extract.oui3 << 24)
    
types:
  vendor_oui_bytes:
    seq:
      - id: oui1
        type: u1
      - id: oui2
        type: u1
      - id: oui3
        type: u1
  
  # Generic tag
  ieee_221_vendor_tag:
    seq:
      - id: vendor_type
        type: u1
      - id: vendor_data
        size-eos: true
    
    
