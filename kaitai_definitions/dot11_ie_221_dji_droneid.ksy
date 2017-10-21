# Drone ID (DJI Telemetry) sub-packets
# Embedded in Wi-Fi beacon frames as IE221 tags under the OUI 26:32:12
#

meta:
  id: dot11_ie_221_dji_droneid
  endian: le
doc: |
  Drone ID is a standard packet addition proposed by DJI which includes
  drone identification and telemetry information.  For Wi-Fi drones, 
  this is put in an IE tag in the standard IEEE802.11 beacon frames,
  under the OUI 26:32:12.

  Two packet types can be sent; packets with a subcommand of 0x10
  include flight telemetry and location, while packets with a subcommand
  of 0x11 include user-entered information about the drone and
  the flight.

  The DroneID format was decoded by
    Freek van Tienen <freek.v.tienen@gmail.com>
    and
    Jan Dumon <jan@crossbar.net>

  and more details on the packet internals can be found at
  https://github.com/fvantienen

seq:
  # Grafted into the tree immediately after the OUI field, first field is
  # the 221 Vendor-Specific Type
  - id: vendor_type
    type: u1
  - id: unk1
    type: u1
  - id: unk2
    type: u1
  - id: subcommand
    type: u1
  - id: record
    type:
      switch-on: subcommand
      cases:
        0x10: flight_reg_info
        # Temporarily disabled
        # 0x11: flight_purpose

instances:
    dot11_ie_221_dji_droneid_oui:
        value: 0x12372600

types:
  # Flight purpose record - user entered data
  flight_purpose:
    seq:
      - id: serialnumber
        type: strz
        encoding: ASCII
        size: 16
        
      - id: len
        type: u8
      
      # Droneid sets a length but has a fixed size
      - id: drone_id
        type: strz
        encoding: ASCII
        size: 10
        
      - id: purpose_len
        type: u8
      
      # Purpose sets a length but has a fixed size
      - id: purpose
        type: strz
        encoding: ASCII
        size: 100

  # Flight telemetry data
  flight_reg_info:
    seq:
      # DJI DroneID flight reg info
      - id: version
        type: u1
      - id: seq
        type: u2
      - id: state_info
        type: state
      - id: serialnumber
        type: strz
        encoding: ASCII
        size: 16
      - id: raw_lon
        type: s4le
      - id: raw_lat
        type: s4le
      - id: altitude
        type: s2
      - id: height
        type: s2
      - id: v_north
        type: s2
      - id: v_east
        type: s2
      - id: v_up
        type: s2
      - id: raw_pitch
        type: s2
      - id: raw_roll
        type: s2
      - id: raw_yaw
        type: s2
      - id: raw_home_lon
        type: s4
      - id: raw_home_lat
        type: s4
      - id: product_type
        type: u1
      - id: uuid_len
        type: u1
      - id: uuid
        size: 20
    
    instances:
      # Convert from float and radians in one op
      lon:
        value: raw_lon / 174533.0
    
      lat:
        value: raw_lat / 174533.0
    
      home_lon:
        value: raw_home_lon / 174533.0
    
      home_lat:
        value: raw_home_lat / 174533.0
        
      pitch:
        value: ((raw_pitch) / 100.0) / 57.296
      
      roll:
        value: ((raw_roll) / 100.0) / 57.296
      
      yaw:
        value: ((raw_yaw) / 100.0) / 57.296

  state:
    seq:
      # 16-bit field in little-endian
    
      # 7 - guess
      - id: unk_alt_valid
        type: b1
      # 6 - guess
      - id: unk_gps_valid
        type: b1
      # 5 - Drone in the air
      - id: in_air
        type: b1
      # 4 - Props on
      - id: motor_on
        type: b1
      # 3 - uuid is configured
      - id: uuid_set
        type: b1
      # 2 - home lat/lon valid
      - id: homepoint_set
        type: b1
      # 1 - inverse - set true when private mode is disabled
      # If false, we cannot see lat/lon/etc
      - id: private_disabled
        type: b1
      # 0 - Serial # is valid
      - id: serial_valid
        type: b1
        
      # 15
      - id: unk15
        type: b1
      # 14
      - id: unk14
        type: b1
      # 13
      - id: unk13
        type: b1
      # 12
      - id: unk12
        type: b1
      # 11
      - id: unk11
        type: b1
      # 10 - Guess that v_up is valid
      - id: unk_velocity_z_valid
        type: b1
      # 9 - Guess that v_east / v_north valid
      - id: unk_velocity_x_valid
        type: b1
      # 8 - Guess that height valid
      - id: unk_height_valid
        type: b1
        
