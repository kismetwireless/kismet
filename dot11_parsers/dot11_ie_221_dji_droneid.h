/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __DOT11_IE_221_DJI_DRONEID_H__
#define __DOT11_IE_221_DJI_DRONEID_H__

/* dot11 ie 221 Vendor: DJI DroneID
 * 
 * Drone ID is a standard packet addition proposed by DJI which includes
 * drone identification and telemetry information.  For Wi-Fi drones, 
 * this is put in an IE tag in the standard IEEE802.11 beacon frames,
 * under the OUI 26:37:12.
 *
 * Two packet types can be sent; packets with a subcommand of 0x10
 * include flight telemetry and location, while packets with a subcommand
 * of 0x11 include user-entered information about the drone and
 * the flight.
 *
 * The DroneID format was decoded by
 * Freek van Tienen <freek.v.tienen@gmail.com>
 * and
 * Jan Dumon <jan@crossbar.net>
 *
 * and more details on the packet internals can be found at
 * https://github.com/fvantienen
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_221_dji_droneid {
public:
    class dji_subcommand_common;
    class dji_subcommand_flight_reg;
    class dji_subcommand_flight_purpose;

    enum e_dji_subcommand_type {
        subcommand_unknwon = 0,
        subcommand_flightreg = 0x10,
        subcommand_flightpurpose = 0x11
    };

    dot11_ie_221_dji_droneid() { }
    ~dot11_ie_221_dji_droneid() { }

    constexpr17 static unsigned int vendor_oui() {
        return 0x263712;
    }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    constexpr17 uint8_t vendor_type() const {
        return m_vendor_type;
    }

    constexpr17 uint8_t unk1() const {
        return m_unk1;
    }

    constexpr17 uint8_t unk2() const {
        return m_unk2;
    }

    constexpr17 e_dji_subcommand_type subcommand() const {
        return (e_dji_subcommand_type) m_subcommand;
    }

    std::string raw_record_data() const {
        return m_raw_record_data;
    }

    std::shared_ptr<dji_subcommand_common> record() const {
        return m_record;
    }

    std::shared_ptr<dji_subcommand_flight_reg> flight_reg_record() const {
        if (subcommand() == subcommand_flightreg)
            return std::static_pointer_cast<dji_subcommand_flight_reg>(m_record);
        return NULL;
    }

    std::shared_ptr<dji_subcommand_flight_purpose> flight_purpose_record() const {
        if (subcommand() == subcommand_flightpurpose)
            return std::static_pointer_cast<dji_subcommand_flight_purpose>(m_record);
        return NULL;
    }

    void reset() {
        m_vendor_type = 0;
        m_unk1 = 0;
        m_unk2 = 0;
        m_subcommand = 0;
        m_raw_record_data = "";
        m_raw_record_data_stream.reset();
        m_record.reset();
    }

protected:
    uint8_t m_vendor_type;
    uint8_t m_unk1;
    uint8_t m_unk2;
    uint8_t m_subcommand;
    std::string m_raw_record_data;
    std::shared_ptr<kaitai::kstream> m_raw_record_data_stream;
    std::shared_ptr<dji_subcommand_common> m_record;

public:
    class dji_subcommand_common {
    public:
        dji_subcommand_common() { }
        virtual ~dji_subcommand_common() { }

        virtual void parse(std::shared_ptr<kaitai::kstream> p_io __attribute__((unused))) { }
    };

    class dji_subcommand_flight_reg : public dji_subcommand_common {
    public:
        dji_subcommand_flight_reg() { }
        virtual ~dji_subcommand_flight_reg() { }

        virtual void parse(std::shared_ptr<kaitai::kstream> p_io);

        uint8_t version() {
            return m_version;
        }

        uint16_t seq() {
            return m_seq;
        }

        uint16_t state_info() {
            return m_state_info;
        }

        std::string serialnumber() {
            return m_serialnumber;
        }

        int32_t raw_lon() {
            return m_raw_lon;
        }

        int32_t raw_lat() {
            return m_raw_lat;
        }

        int16_t altitude() {
            return m_altitude;
        }

        int16_t height() {
            return m_height;
        }

        int16_t v_north() {
            return m_v_north;
        }

        int16_t v_east() {
            return m_v_east;
        }

        int16_t v_up() {
            return m_v_up;
        }

        int16_t raw_pitch() {
            return m_raw_pitch;
        }

        int16_t raw_roll() {
            return m_raw_roll;
        }

        int16_t raw_yaw() {
            return m_raw_yaw;
        }

        int32_t raw_home_lon() {
            return m_raw_home_lon;
        }

        int32_t raw_home_lat() {
            return m_raw_home_lat;
        }

        uint8_t product_type() {
            return m_product_type;
        }

        uint8_t uuid_len() {
            return m_uuid_len;
        }

        std::string uuid() {
            return m_uuid;
        }

        unsigned int state_serial_valid() {
            return state_info() & 0x01;
        }

        unsigned int state_user_privacy_enabled() {
            return (state_info() & 0x02) == 0;
        }

        unsigned int state_homepoint_set() {
            return state_info() & 0x04;
        }

        unsigned int state_uuid_set() {
            return state_info() & 0x08;
        }

        unsigned int state_motor_on() {
            return state_info() & 0x10;
        }

        unsigned int state_in_air() {
            return state_info() & 0x20;
        }

        unsigned int state_gps_valid() {
            return state_info() & 0x40;
        }

        unsigned int state_alt_valid() {
            return state_info() & 0x80;
        }

        unsigned int state_height_valid() {
            return state_info() & 0x100;
        }

        unsigned int state_horiz_valid() {
            return state_info() & 0x200;
        }

        unsigned int state_vup_valid() {
            return state_info() & 0x400;
        }

        unsigned int state_pitchroll_valid() {
            return state_info() & 0x800;
        }

        float lon() {
            return (float) raw_lon() / 174533.0f;
        }

        float lat() {
            return (float) raw_lat() / 174533.0f;
        }

        float home_lon() {
            return (float) raw_home_lon() / 174533.0f;
        }

        float home_lat() {
            return (float) raw_home_lat() / 174533.0f;
        }

        float pitch() {
            return ((float) raw_pitch() / 100.0f) / 57.296f;
        }

        float roll() {
            return ((float) raw_roll() / 100.0f) / 57.296f;
        }

        float yaw() {
            return ((float) raw_yaw() / 100.0f) / 57.296f;
        }

        void reset() {
            m_version = 0;
            m_seq = 0;
            m_state_info = 0;
            m_serialnumber = "";
            m_raw_lon = 0;
            m_raw_lat = 0;
            m_altitude = 0;
            m_height = 0;
            m_v_north = 0;
            m_v_east = 0;
            m_v_up = 0;
            m_raw_pitch = 0;
            m_raw_roll = 0;
            m_raw_yaw = 0;
            m_raw_home_lon = 0;
            m_raw_home_lat = 0;
            m_product_type = 0;
            m_uuid_len = 0;
            m_uuid = "";
        }

    protected:
        uint8_t m_version;
        uint16_t m_seq;
        uint16_t m_state_info;
        std::string m_serialnumber;
        int32_t m_raw_lon;
        int32_t m_raw_lat;
        int16_t m_altitude;
        int16_t m_height;
        int16_t m_v_north;
        int16_t m_v_east;
        int16_t m_v_up;
        int16_t m_raw_pitch;
        int16_t m_raw_roll;
        int16_t m_raw_yaw;
        int32_t m_raw_home_lon;
        int32_t m_raw_home_lat;
        uint8_t m_product_type;
        uint8_t m_uuid_len;
        std::string m_uuid;
    };

    class dji_subcommand_flight_purpose : public dji_subcommand_common {
    public:
        dji_subcommand_flight_purpose() { }
        virtual ~dji_subcommand_flight_purpose() { }

        virtual void parse(std::shared_ptr<kaitai::kstream> p_io);

        std::string serialnumber() {
            return m_serialnumber;
        }

        uint8_t drone_id_len() {
            return m_drone_id_len;
        }

        std::string drone_id() {
            return m_drone_id;
        }

        uint8_t purpose_len() {
            return m_purpose_len;
        }

        std::string purpose() {
            return m_purpose;
        }

        void reset() {
            m_serialnumber = "";
            m_drone_id_len = 0;
            m_drone_id = "";
            m_purpose_len = 0;
            m_purpose = "";
        }

    protected:
        std::string m_serialnumber;
        uint8_t m_drone_id_len;
        std::string m_drone_id;
        uint8_t m_purpose_len;
        std::string m_purpose;
    };

};


#endif

