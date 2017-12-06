# Highest-level decoder for 802.11 IE fields, simply breaks into
# tag+length

meta:
  id: dot11_ie
  endian: be
  
seq:
  - id: tags
    type: ieee_80211_tag
    repeat: eos
    
types:
  ieee_80211_tag:
    seq:
      - id: tag_num
        type: u1
      - id: tag_length
        type: u1
      - id: tag_data
        size: tag_length
