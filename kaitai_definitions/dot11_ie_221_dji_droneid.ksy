# Drone ID (DJI Telemetry) sub-packets
# Embedded in Wi-Fi beacon frames as IE221 tags under the OUI 26:37:12
#

meta:
  id: dot11_ie_221_dji_droneid
  endian: le
doc: |
  Drone ID is a standard packet addition proposed by DJI which includes
  drone identification and telemetry information.  For Wi-Fi drones, 
  this is put in an IE tag in the standard IEEE802.11 beacon frames,
  under the OUI 26:37:12.

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
    size-eos: true

instances:
    dot11_ie_221_dji_droneid_oui:
        value: 0x12372600

    subcommand_flight_reg_info:
        value: "(subcommand == 0x10)"
    subcommand_flight_purpose:
        value: "(subcommand == 0x11)"

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
      
      # Purpose sets a length but has a fixed size; current DJI firmware
      # seems to generate invalid frames which have a truncated purpose, 
      # map to eos
      - id: purpose
        type: strz
        encoding: ASCII
        size-eos: true

  # Flight telemetry data
  flight_reg_info:
    seq:
      # DJI DroneID flight reg info
      - id: version
        type: u1
      - id: seq
        type: u2le
      - id: state_info
        type: u2le
      - id: serialnumber
        type: strz
        encoding: ASCII
        size: 16
      - id: raw_lon
        type: s4le
      - id: raw_lat
        type: s4le
      - id: altitude
        type: s2le
      - id: height
        type: s2le
      - id: v_north
        type: s2le
      - id: v_east
        type: s2le
      - id: v_up
        type: s2le
      - id: raw_pitch
        type: s2le
      - id: raw_roll
        type: s2le
      - id: raw_yaw
        type: s2le
      - id: raw_home_lon
        type: s4le
      - id: raw_home_lat
        type: s4le
      - id: product_type
        type: u1
      - id: uuid_len
        type: u1
      - id: uuid
        size: 20
    
    instances:
      state_serial_valid:
        doc: Serial is valid
        value: "(state_info & 0x01)"

      state_user_private_disabled:
        doc: private mode disabled (set to 1)
        value: "(state_info & 0x02)"

      state_homepoint_set:
        doc: firmware unclear; could be conflated with uuid bit
        value: "(state_info & 0x04)"

      state_uuid_set:
        doc: firmware unclear; could be conflated with homepoint bit
        value: "(state_info & 0x08)"

      state_motor_on:
        value: "(state_info & 0x10)"

      state_in_air:
        value: "(state_info & 0x20)"

      state_gps_valid:
        doc: Guessed; GPS fields may be valid?
        value: "(state_info & 0x40)"

      state_alt_valid:
        doc: Guessed; Altitude GPS record valid?
        value: "(state_info & 0x80)"

      state_height_valid:
        doc: Guessed; Height-over-ground valid?
        value: "(state_info & 0x100)"

      state_horiz_valid:
        doc: Guessed; Horizontal velocity valid?
        value: "(state_info & 0x200)"

      state_vup_valid:
        doc: Guessed; V_up velocity valid?
        value: "(state_info & 0x400)"

      state_pitchroll_valid:
        doc: Guessed; pitch/roll/yaw valid?
        value: "(state_info & 0x800)"

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
