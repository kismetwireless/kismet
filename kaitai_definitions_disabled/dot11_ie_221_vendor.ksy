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
  - id: vendor_tag
    type: ieee_221_vendor_tag
    
instances:
  # Use an absolute position at the start of the stream to get the vendor oui
  vendor_oui_extract:
    type: vendor_oui_bytes
    pos: 0

  # Bitshift it into a predictable int
  vendor_oui_int:
    value: (vendor_oui_extract.oui1 << 16) + (vendor_oui_extract.oui2 << 8) + (vendor_oui_extract.oui3)

  # Extract the vendor type without consuming it
  vendor_oui_type:
    type: u1
    pos: 3

types:
  # Break the OUI into bytes which we assemble into an int
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
      - id: vendor_data
        size-eos: true
    
