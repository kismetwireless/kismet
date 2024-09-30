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

#include "globalregistry.h"
#include "util.h"

#include "dot11_ie_221_dji_droneid.h"

void dot11_ie_221_dji_droneid::parse(std::shared_ptr<kaitai::kstream> p_io) {
    m_vendor_type = p_io->read_u1();
    m_unk1 = p_io->read_u1();
    m_unk2 = p_io->read_u1();
    m_subcommand = p_io->read_u1();

    m_raw_record_data = p_io->read_bytes_full();

    if (subcommand() == subcommand_flightreg) {
        auto fr = Globalreg::new_from_pool<dji_subcommand_flight_reg>();
        fr->parse(raw_record_data());
        m_record = fr;
    } else if (subcommand() == subcommand_flightpurpose) {
        auto fp = Globalreg::new_from_pool<dji_subcommand_flight_purpose>();
        fp->parse(raw_record_data());
        m_record = fp;
    }
}

void dot11_ie_221_dji_droneid::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_vendor_type = p_io.read_u1();
    m_unk1 = p_io.read_u1();
    m_unk2 = p_io.read_u1();
    m_subcommand = p_io.read_u1();

    m_raw_record_data = p_io.read_bytes_full();

    if (subcommand() == subcommand_flightreg) {
        auto fr = Globalreg::new_from_pool<dji_subcommand_flight_reg>();
        fr->parse(raw_record_data());
        m_record = fr;
    } else if (subcommand() == subcommand_flightpurpose) {
        auto fp = Globalreg::new_from_pool<dji_subcommand_flight_purpose>();
        fp->parse(raw_record_data());
        m_record = fp;
    }
}

void dot11_ie_221_dji_droneid::dji_subcommand_flight_reg::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_version = p_io.read_u1();

    /* None of the decodes seem proper and there is no way to validate any of the additional data, 
     * including if height/altitude is swapped, so decode the little we CAN reliably read from
     * whatever they seem to be sending
     */

    m_seq = p_io.read_u2le();
    m_state_info = p_io.read_u2le();
    m_serialnumber = p_io.read_bytes(16);
    m_raw_lon = p_io.read_s4le();
    m_raw_lat = p_io.read_s4le();

    /*
    switch (m_version) {
        case 1:
            m_seq = p_io->read_u2le();
            m_state_info = p_io->read_u2le();
            m_serialnumber = p_io->read_bytes(16);
            m_raw_lon = p_io->read_s4le();
            m_raw_lat = p_io->read_s4le();
            m_altitude = p_io->read_s2le();
            m_height = p_io->read_s2le();
            m_v_north = p_io->read_s2le();
            m_v_east = p_io->read_s2le();
            m_v_up = p_io->read_s2le();
            m_raw_pitch = p_io->read_s2le();
            m_raw_roll = p_io->read_s2le();
            m_raw_yaw = p_io->read_s2le();
            m_raw_home_lon = p_io->read_s4le();
            m_raw_home_lat = p_io->read_s4le();
            m_product_type = p_io->read_u1();
            m_uuid_len = p_io->read_u1();
            m_uuid = p_io->read_bytes(uuid_len());
            break;
        case 2:
            m_seq = p_io->read_u2le();
            m_state_info = p_io->read_u2le();
            m_serialnumber = p_io->read_bytes(16);
            m_raw_lon = p_io->read_s4le();
            m_raw_lat = p_io->read_s4le();
            // Height is from barometric actual height, altitude is height since
            // takeoff
            m_height = p_io->read_s2le() / 10;
            m_altitude = p_io->read_s2le();

            m_v_north = p_io->read_s2le();
            m_v_east = p_io->read_s2le();
            m_v_up = p_io->read_s2le();
            m_raw_yaw = p_io->read_s2le();

            // V2 gps time
            m_gps_time = p_io->read_u8le();
            m_raw_app_lat = p_io->read_s4le();
            m_raw_app_lon = p_io->read_s4le();
            m_raw_home_lon = p_io->read_s4le();
            m_raw_home_lat = p_io->read_s4le();

            m_product_type = p_io->read_u1();
            m_uuid_len = p_io->read_u1();
            m_uuid = p_io->read_bytes(uuid_len());
    }
    */
}

void dot11_ie_221_dji_droneid::dji_subcommand_flight_purpose::parse(const std::string& data) {
	membuf d_membuf(data.data(), data.data() + data.length());
	std::istream is(&d_membuf);
	kaitai::kstream p_io(&is);

    m_serialnumber = p_io.read_bytes(16);
    m_drone_id_len = p_io.read_u1();
    // Fixed size but obey the length field
    m_drone_id = p_io.read_bytes(10).substr(0, drone_id_len());
    // Length field, but DJI also mis-transmits this due to a sw bug, so we use 'the rest of
    // the buffer' instead of the 100 bytes or so it's supposed to be, then adjust
    // for the length specified
    m_purpose_len = p_io.read_u1();
    m_purpose = p_io.read_bytes_full().substr(0, purpose_len());
}

