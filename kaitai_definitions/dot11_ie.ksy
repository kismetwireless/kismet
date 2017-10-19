# Parser for IEEE 80211 IE tag sets, combines multiple parsers into one
# decoder phase and creates generic entries for tags it doesn't currently
# decode

meta:
  id: dot11_ie
  endian: be
  
  imports:
    - dot11_ie_7_country
    - dot11_ie_11_qbss
    - dot11_ie_54_mobility
    - dot11_ie_55_fastbss
    - dot11_ie_221_vendor
  
seq:
  - id: tag
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
        type:
          switch-on: tag_num
          cases:
            0: dot11_ie_ssid
            1: dot11_ie_basicrates
            3: dot11_ie_ds_channel
            5: dot11_ie_tim
            7: dot11_ie_7_country
            11: dot11_ie_11_qbss
            50: dot11_ie_extendedrates
            133: dot11_ie_cisco_ccx1_ckip
            221: dot11_ie_221_vendor
            _: dot11_ie_data

  # IE 0, SSID
  dot11_ie_ssid:
    seq:
      - id: ssid
        size-eos: true
        
  # IE 01, basic data rates
  dot11_ie_basicrates:
    seq:
      - id: basic_rate
        type: u1
        repeat: eos

  # IE 03, basic channel
  dot11_ie_ds_channel:
    seq:
      - id: current_channel
        type: u1

  # IE 05, TIM traffic indication map
  dot11_ie_tim:
    seq:
      - id: dtim_count
        type: u1
      - id: dtim_period
        type: u1
      - id: bitmap_control
        type: dot11_ie_tim_bitmap
      - id: pv_bitmap
        type: u1

  # DTIM bitmap
  dot11_ie_tim_bitmap:
    seq:
      - id: bitmap_offset
        type: b7
      - id: multicast
        type: b1

  # IE 50, extended data rates
  dot11_ie_extendedrates:
    seq:
      - id: extended_rate
        type: u1
        repeat: eos
        
  # IE 133, Cisco CCX1 CKIP
  dot11_ie_cisco_ccx1_ckip:
    seq:
      - id: ccx1_unk1
        size: 10
      - id: ap_name
        type: strz
        encoding: ASCII
        size: 16
      - id: station_count
        type: u1
      - id: ccx1_unk2
        size: 3

  # Generic data
  dot11_ie_data:
    seq:
      - id: data
        size-eos: true

