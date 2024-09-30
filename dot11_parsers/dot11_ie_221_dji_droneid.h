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

#include "fmt.h"
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
	void parse(const std::string& data);

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

    constexpr17 const std::string& raw_record_data() const {
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
        m_record.reset();
    }

protected:
    uint8_t m_vendor_type;
    uint8_t m_unk1;
    uint8_t m_unk2;
    uint8_t m_subcommand;
    std::string m_raw_record_data;
    std::shared_ptr<dji_subcommand_common> m_record;

public:
    class dji_subcommand_common {
    public:
        dji_subcommand_common() { }
        virtual ~dji_subcommand_common() { }

        virtual void parse(const std::string& data __attribute__((unused))) { }
    };

    class dji_subcommand_flight_reg : public dji_subcommand_common {
    public:
        dji_subcommand_flight_reg() { }
        virtual ~dji_subcommand_flight_reg() { }

        virtual void parse(const std::string& data);

        const uint8_t version() const {
            return m_version;
        }

        const uint16_t seq() const {
            return m_seq;
        }

        const uint16_t state_info() const {
            return m_state_info;
        }

        constexpr17 const std::string& serialnumber() const {
            return m_serialnumber;
        }

        const int32_t raw_lon() const {
            return m_raw_lon;
        }

        const int32_t raw_lat() const {
            return m_raw_lat;
        }

        const int16_t altitude() const {
            return m_altitude;
        }

        const int16_t height() const {
            return m_height;
        }

        const int16_t v_north() const {
            return m_v_north;
        }

        const int16_t v_east() const {
            return m_v_east;
        }

        const int16_t v_up() const {
            return m_v_up;
        }

        const int16_t raw_pitch() const {
            return m_raw_pitch;
        }

        const int16_t raw_roll() const {
            return m_raw_roll;
        }

        const int16_t raw_yaw() const {
            return m_raw_yaw;
        }

        const int32_t raw_home_lon() const {
            return m_raw_home_lon;
        }

        const int32_t raw_home_lat() const {
            return m_raw_home_lat;
        }

        const int32_t raw_app_lon() const {
            return m_raw_app_lon;
        }

        const int32_t raw_app_lat() const {
            return m_raw_app_lat;
        }

        const uint8_t product_type() const {
            return m_product_type;
        }

        const std::string product_type_str() {
            switch (product_type()) {
                case 1:
                    return "Instpire 1";
                case 2:
                case 3:
                    return "Phantom 3 Series";
                case 4: 
                    return "Phandom 3 Std";
                case 5:
                    return "M100";
                case 6:
                    return "ACEONE";
                case 7:
                    return "WKM";
                case 8:
                    return "NAZA";
                case 9:
                    return "A2";
                case 10:
                    return "A3";
                case 11:
                    return "Phantom 4";
                case 12:
                    return "MG1";
                case 14:
                    return "M600";
                case 15:
                    return "Phantom 3 4k";
                case 16:
                    return "Mavic Pro";
                case 17:
                    return "Inspire 2";
                case 18:
                    return "Phantom 4 Pro";
                case 20:
                    return "N2";
                case 21:
                    return "Spark";
                case 23:
                    return "M600 Pro";
                case 24:
                    return "Mavic Air";
                case 25:
                    return "M200";
                case 26:
                    return "Phantom 4 Series";
                case 27:
                    return "Phantom 4 Adv";
                case 28:
                    return "M210";
                case 30:
                    return "M210RTK";
                case 31:
                    return "A3_AG";
                case 32:
                    return "MG2";
                case 34:
                    return "MG1A";
                case 35:
                    return "Phantom 4 RTK";
                case 36:
                    return "Phantom 4 Pro V2.0";
                case 38:
                    return "MG1P";
                case 40:
                    return "MV1P-RTK";
                case 41:
                    return "Mavic 2";
                case 44:
                    return "M200 V2 Series";
                case 51:
                    return "Mavic 2 Enterprise";
                case 53:
                    return "Mavic Mini";
                case 58:
                    return "Mavic Air 2";
                case 59:
                    return "P4M";
                case 60:
                    return "M300 RTK";
                case 61:
                    return "DJI FPV";
                case 63:
                    return "Mini 2";
                case 64:
                    return "AGRAS T10";
                case 65:
                    return "AGRAS T30";
                case 66:
                    return "Air 2S";
                case 68:
                    return "Mavic 3";
                case 69:
                    return "Mavic 2 Enterprise Advanced";
                case 70:
                    return "Mini SE";
                default:
                    return fmt::format("Unknown ({})", product_type());
            }
        }

        const uint8_t uuid_len() const {
            return m_uuid_len;
        }

        const std::string uuid() const {
            return m_uuid;
        }

        const unsigned int state_serial_valid() const {
            return state_info() & 0x01;
        }

        const unsigned int state_user_privacy_enabled() const {
            return (state_info() & 0x02) == 0;
        }

        const unsigned int state_homepoint_set() const {
            return state_info() & 0x04;
        }

        const unsigned int state_uuid_set() const {
            return state_info() & 0x08;
        }

        const unsigned int state_motor_on() const {
            return state_info() & 0x10;
        }

        const unsigned int state_in_air() const {
            return state_info() & 0x20;
        }

        const unsigned int state_gps_valid() const {
            return state_info() & 0x40;
        }

        const unsigned int state_alt_valid() const {
            return state_info() & 0x80;
        }

        const unsigned int state_height_valid() const {
            return state_info() & 0x100;
        }

        const unsigned int state_horiz_valid() const {
            return state_info() & 0x200;
        }

        const unsigned int state_vup_valid() const {
            return state_info() & 0x400;
        }

        const unsigned int state_pitchroll_valid() const {
            return state_info() & 0x800;
        }

        const float lon() const {
            return (float) raw_lon() / 174533.0f;
        }

        const float lat() const {
            return (float) raw_lat() / 174533.0f;
        }

        const float home_lon() const {
            return (float) raw_home_lon() / 174533.0f;
        }

        const float home_lat() const {
            return (float) raw_home_lat() / 174533.0f;
        }

        const float app_lon() const {
            return (float) raw_app_lon() / 174533.0f;
        }

        const float app_lat() const {
            return (float) raw_app_lat() / 174533.0f;
        }

        const uint64_t gps_time() const {
            return m_gps_time;
        }

        const float pitch() const {
            return ((float) raw_pitch() / 100.0f) / 57.296f;
        }

        const float roll() const {
            return ((float) raw_roll() / 100.0f) / 57.296f;
        }

        const float yaw() const {
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
            m_gps_time = 0;
            m_raw_app_lon = 0;
            m_raw_app_lat = 0;
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

        // V2 additional fields
        uint64_t m_gps_time;
        int32_t m_raw_app_lon;
        int32_t m_raw_app_lat;
    };

    class dji_subcommand_flight_purpose : public dji_subcommand_common {
    public:
        dji_subcommand_flight_purpose() { }
        virtual ~dji_subcommand_flight_purpose() { }

        virtual void parse(const std::string& data);

        constexpr17 const std::string& serialnumber() {
            return m_serialnumber;
        }

        uint8_t drone_id_len() {
            return m_drone_id_len;
        }

        constexpr17 const std::string& drone_id() {
            return m_drone_id;
        }

        uint8_t purpose_len() {
            return m_purpose_len;
        }

        constexpr17 const std::string& purpose() {
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

