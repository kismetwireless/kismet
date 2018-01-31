meta:
  id: dot11_ie_54_mobility
  file-extension: dot11_ie_54_mobility
  
seq:
  - id: mobility_domain
    type: u2le
  - id: ft_policy
    type: mobility_policy
    
types:
  mobility_policy:
    seq:
      - id: fast_bss_over_ds
        type: b1
      - id: resource_request_capbability
        type: b1
      - id: reserved
        type: b6
