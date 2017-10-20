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
  - id: droneid_unk1
    type: u1
  - id: droneid_unk2
    type: u1
  - id: droneid_subcommand
    type: u1
  - id: droneid_record
    type:
      switch-on: droneid_subcommand
      cases:
        0x10: droneid_flight_reg_info
        # Temporarily disabled
        # 0x11: droneid_flight_purpose

types:
  # Flight purpose record - user entered data
  droneid_flight_purpose:
    seq:
      - id: droneid_serialnumber
        type: strz
        encoding: ASCII
        size: 16
        
      - id: droneid_len
        type: u8
      
      # Droneid sets a length but has a fixed size
      - id: droneid
        type: strz
        encoding: ASCII
        size: 10
        
      - id: droneid_purpose_len
        type: u8
      
      # Purpose sets a length but has a fixed size
      - id: droneid_purpose
        type: strz
        encoding: ASCII
        size: 100

  # Flight telemetry data
  droneid_flight_reg_info:
    seq:
      # DJI DroneID flight reg info
      - id: droneid_version
        type: u1
      - id: droneid_seq
        type: u2
      - id: droneid_state_info
        type: droneid_state
      - id: droneid_serialnumber
        type: strz
        encoding: ASCII
        size: 16
      - id: droneid_raw_lon
        type: s4le
      - id: droneid_raw_lat
        type: s4le
      - id: droneid_altitude
        type: s2
      - id: droneid_height
        type: s2
      - id: droneid_v_north
        type: s2
      - id: droneid_v_east
        type: s2
      - id: droneid_v_up
        type: s2
      - id: droneid_raw_pitch
        type: s2
      - id: droneid_raw_roll
        type: s2
      - id: droneid_raw_yaw
        type: s2
      - id: droneid_raw_home_lon
        type: s4
      - id: droneid_raw_home_lat
        type: s4
      - id: droneid_product_type
        type: u1
      - id: droneid_uuid_len
        type: u1
      - id: droneid_uuid
        size: 20
    
    instances:
      # Convert from float and radians in one op
      droneid_lon:
        value: droneid_raw_lon / 174533.0
    
      droneid_lat:
        value: droneid_raw_lat / 174533.0
    
      droneid_home_lon:
        value: droneid_raw_home_lon / 174533.0
    
      droneid_home_lat:
        value: droneid_raw_home_lat / 174533.0
        
      droneid_pitch:
        value: ((droneid_raw_pitch) / 100.0) / 57.296
      
      droneid_roll:
        value: ((droneid_raw_roll) / 100.0) / 57.296
      
      droneid_yaw:
        value: ((droneid_raw_yaw) / 100.0) / 57.296

  droneid_state:
    seq:
      # 16-bit field in little-endian
    
      # 7 - guess
      - id: droneid_state_unk_alt_valid
        type: b1
      # 6 - guess
      - id: droneid_state_unk_gps_valid
        type: b1
      # 5 - Drone in the air
      - id: droneid_state_in_air
        type: b1
      # 4 - Props on
      - id: droneid_state_motor_on
        type: b1
      # 3 - uuid is configured
      - id: droneid_state_uuid_set
        type: b1
      # 2 - home lat/lon valid
      - id: droneid_state_homepoint_set
        type: b1
      # 1 - inverse - set true when private mode is disabled
      # If false, we cannot see lat/lon/etc
      - id: droneid_state_private_disabled
        type: b1
      # 0 - Serial # is valid
      - id: droneid_state_serial_valid
        type: b1
        
      # 15
      - id: droneid_state_unk15
        type: b1
      # 14
      - id: droneid_state_unk14
        type: b1
      # 13
      - id: droneid_state_unk13
        type: b1
      # 12
      - id: droneid_state_unk12
        type: b1
      # 11
      - id: droneid_state_unk11
        type: b1
      # 10 - Guess that v_up is valid
      - id: droneid_state_unk_velocity_y_valid
        type: b1
      # 9 - Guess that v_east / v_north valid
      - id: droneid_state_unk_velocity_x_valid
        type: b1
      # 8 - Guess that height valid
      - id: droneid_state_unk_height_valid
        type: b1
        
