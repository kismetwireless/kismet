# 802.11d country
 
meta:
  id: dot11_ie_7_country
  file-extension: dot11_ie_7_country
  
seq:
  - id: country_code
    size: 2
  - id: environment
    type: u1
  - id: country_list
    type: dot11_ie_country_triplet
    repeat: eos

types:
  dot11_ie_country_triplet:
    seq:
      - id: first_channel
        type: u1
      - id: num_channels
        type: u1
      - id: max_power
        type: u1

