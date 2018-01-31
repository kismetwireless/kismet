meta:
  id: dot11_ie_48_rsn_partial
  file-extension: dot11_ie_48_rsn_partial

doc: |
  Implementation of the basic stub version of a RSN IE tag, used for
  WIDS sensing of insane pairwise counts
  
seq:
  - id: rsn_version
    type: u2le
  - id: group_cipher
    size: 4
  - id: pairwise_count
    type: u2le
    
