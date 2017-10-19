meta:
  id: dot11_ie_55_fastbss
  file-extension: dot11_ie_55_fastbss
  endian: be

seq:
  - id: mic_control
    type: fastbss_mic_control
  - id: mic
    size: 16
  - id: anonce
    size: 32
  - id: snonce
    size: 32
  - id: subelements
    type: fastbss_subelement
    repeat: eos
  
types:
  fastbss_mic_control:
    seq:
      - id: reserved
        type: u1
      - id: element_count
        type: u1
  
  fastbss_subelement:
    seq:
      - id: sub_id
        type: u1
      - id: sub_length
        type: u1
      - id: sub_data
        size: sub_length
        type:
          switch-on: sub_id
          cases:
            1: fastbss_sub_pmk_r1_keyholder
            2: fastbss_sub_gtk
            3: fastbss_sub_pmk_r0_khid
            _: fastbss_sub_data
        

  
  fastbss_sub_pmk_r1_keyholder:
    seq:
      - id: keyholder_id
        size-eos: true
        
  fastbss_sub_pmk_r0_khid:
    seq:
      - id: keyholder_id
        type: strz
        encoding: ASCII
        size-eos: true

  fastbss_sub_gtk:
    seq:
      - id: gtk_keyinfo
        type: fastbss_sub_gtk_keyinfo
      - id: gtk_keylen
        type: u1
      - id: gtk_rsc
        size: 8
      - id: gtk_gtk
        # Auto-derive the gtk key length from our substream size
        size-eos: true
        
  fastbss_sub_gtk_keyinfo:
    seq:
      - id: keyinfo_reserved
        type: b14
      - id: keyinfo_keyid
        type: b2

  fastbss_sub_data:
    seq:
      - id: data
        size-eos: true
