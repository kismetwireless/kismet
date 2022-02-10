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

#include "config.h"

#include <time.h>

#include <stdexcept>

#include "gpsnmea_v2.h"
#include "gpstracker.h"
#include "messagebus.h"
#include "util.h"

struct kis_gps_nmea_v2_soft_fail : public std::exception {
    const char * what () const throw () {
        return "Unparseable NMEA data";
    }
};

void kis_gps_nmea_v2::start_read() {
    // Pass through to virtualized function to initiate read on socket/serial port/whatever
    start_read_impl();
}

void kis_gps_nmea_v2::handle_read(const boost::system::error_code& ec, std::size_t sz) {
    kis_unique_lock<kis_mutex> lk(gps_mutex, std::defer_lock, "handle_read");

    if (stopped)
        return;

    if (ec) {
        // Return from aborted errors cleanly
        if (ec.value() == boost::asio::error::operation_aborted)
            return;

        _MSG_ERROR("(GPS) Error reading NMEA data: {}", ec.message());
        close_impl();
        return;
    }

    if (in_buf.size() == 0) {
        _MSG_ERROR("(GPS) Error reading NMEA data: No data available");
        close_impl();
        return;
    }

    // Pull the buffer
    std::string line;
    std::istream is(&in_buf);
    std::getline(is, line);

    // Ignore blank lines from gpsd
    if (line.empty()) {
        return start_read();
    }

    auto new_location = packetchain->new_packet_component<kis_gps_packinfo>();

    // If it's been < 1 second since the last time, inherit it
    struct timeval now;
    struct timeval tdiff;

    gettimeofday(&now, NULL);

    subtract_timeval(&gps_location->tv, &now, &tdiff);

    if (now.tv_sec < 1)
        new_location->set(gps_location);

    bool set_lat_lon;
    bool set_alt;
    bool set_speed;
    bool set_fix;

    set_lat_lon = false;
    set_alt = false;
    set_speed = false;
    set_fix = false;

    for (unsigned int x = 0; x < line.length(); x++) {
        if (line[x] < 0x32 || line[x] > 0x7A) {
            if (!warned_about_binary) {
                warned_about_binary = true;
                _MSG_ERROR("NMEA GPS {} appears to be reporting binary data, not NMEA.  If this "
                        "is a binary-only GPS unit, you will need to use gpsd and configure Kismet "
                        "for gpsd mode.", get_gps_name());
            }
        }
    }

    if (line.length() < 4) {
        return start_read();
    }

    // $GPGGA,012527.000,4142.6918,N,07355.8711,W,1,07,1.2,57.8,M,-34.0,M,,0000*57

    std::vector<std::string> gpstoks = str_tokenize(line, ",");

    try {
        if (gpstoks.size() == 0)
            throw kis_gps_nmea_v2_soft_fail();

        if (gpstoks[0] == "$GPGGA") {
            int tint;
            double tdouble;

            if (gpstoks.size() < 15)
                throw kis_gps_nmea_v2_soft_fail();

            // Parse the basic gps coordinate string
            // $GPGGA,time,lat,NS,lon,EW,quality,#sats,hdop,alt,M,geopos,M,dgps1,dgps2,checksum

            if (sscanf(gpstoks[2].c_str(), "%2d%lf", &tint, &tdouble) != 2)
                throw kis_gps_nmea_v2_soft_fail();

            new_location->lat = (double) tint + (tdouble / 60);
            if (gpstoks[3] == "S")
                new_location->lat *= -1;

            if (sscanf(gpstoks[4].c_str(), "%3d%lf", &tint, &tdouble) != 2)
                throw kis_gps_nmea_v2_soft_fail();

            new_location->lon = (double) tint + (tdouble / 60);
            if (gpstoks[5] == "W")
                new_location->lon *= -1;

            set_lat_lon = true;
            if (new_location->fix < 2)
                new_location->fix = 2;

            if (sscanf(gpstoks[9].c_str(), "%lf", &tdouble) != 1)
                throw kis_gps_nmea_v2_soft_fail();

            new_location->alt = tdouble;
            set_alt = true;
            if (new_location->fix < 3)
                new_location->fix = 3;
            set_fix = true;

            // printf("debug - %f, %f alt %f\n", in_lat, in_lon, in_alt);
        } else if (gpstoks[0] == "$GPRMC") {
            // recommended minimum
            // $GPRMC,time,valid,lat,lathemi,lon,lonhemi,speed-knots,bearing,utc,,checksum
            int tint;
            double tdouble;

            if (gpstoks.size() < 12)
                throw kis_gps_nmea_v2_soft_fail();

            if (gpstoks[2] == "A") {
                // Kluge - if we have a 3d fix, we're getting another sentence
                // which contains better information, so we don't override it. 
                // If we < a 2d fix, we up it to 2d.
                if (new_location->fix < 2)
                    new_location->fix = 2;
                set_fix = true;
            } else {
                throw kis_gps_nmea_v2_soft_fail();
            }

            if (sscanf(gpstoks[3].c_str(), "%2d%lf", &tint, &tdouble) != 2)
                throw kis_gps_nmea_v2_soft_fail();

            new_location->lat = (double) tint + (tdouble / 60);
            if (gpstoks[4] == "S")
                new_location->lat *= -1;

            if (sscanf(gpstoks[5].c_str(), "%3d%lf", &tint, &tdouble) != 2)
                throw kis_gps_nmea_v2_soft_fail();

            new_location->lon = (double) tint + (tdouble / 60);
            if (gpstoks[6] == "W")
                new_location->lon *= -1;

            if (new_location->fix < 2)
                new_location->fix = 2;
            set_fix = true;

            if (sscanf(gpstoks[7].c_str(), "%lf", &tdouble) != 1) 
                throw kis_gps_nmea_v2_soft_fail();

            new_location->speed = tdouble;
            set_speed = true;

            // This sentence doesn't have altitude, so don't set it.  If another
            // sentence in this same block sets it we'll use that.
        } else if (gpstoks[0] == "$GPVTG") {
            // Travel made good, also a source of speed
            // $GPVTG,,T,,M,0.00,N,0.0,K,A*13
            double tdouble;

            if (gpstoks.size() < 10) 
                throw kis_gps_nmea_v2_soft_fail();

            // Only use VTG if we didn't get our speed from another sentence
            // in this series
            if (set_speed == 0) {
                if (sscanf(gpstoks[7].c_str(), "%lf", &tdouble) != 1) 
                    throw kis_gps_nmea_v2_soft_fail();

                new_location->speed = tdouble;
                set_speed = 1;
            }

        } else if (line.substr(0, 6) == "$GPGSV") {
            // Satellites in view
            // TODO figure out if we can use this data and so something smarter with it
            // $GPGSV,3,1,09,22,80,170,40,14,58,305,19,01,46,291,,18,44,140,33*7B
            // $GPGSV,3,2,09,05,39,105,31,12,34,088,32,30,31,137,31,09,26,047,34*72
            // $GPGSV,3,3,09,31,26,222,31*46
            //
            // # of sentences for data
            // sentence #
            // # of sats in view
            //
            // sat #
            // elevation
            // azimuth
            // snr

#if 0
            vector<string> svvec = str_tokenize(inptok[it], ",");
            GPSCore::sat_pos sp;

            gps_connected = 1;

            if (svvec.size() < 6) {
                continue;
            }

            // If we're on the last sentence, move the new vec to the transmitted one
            if (svvec[1] == svvec[2]) {
                sat_pos_map = sat_pos_map_tmp;
                sat_pos_map_tmp.clear();
            }

            unsigned int pos = 4;
            while (pos + 4 < svvec.size()) {
                if (sscanf(svvec[pos++].c_str(), "%d", &sp.prn) != 1) 
                    break;
                if (sscanf(svvec[pos++].c_str(), "%d", &sp.elevation) != 1)
                    break;
                if (sscanf(svvec[pos++].c_str(), "%d", &sp.azimuth) != 1)
                    break;
                if (sscanf(svvec[pos++].c_str(), "%d", &sp.snr) != 1)
                    sp.snr = 0;

                sat_pos_map_tmp[sp.prn] = sp;
            }
#endif
        }
    } catch (const kis_gps_nmea_v2_soft_fail& e) {
        boost::asio::dispatch(strand_,
                [self = shared_from_this()]() {
                    self->start_read();
                });
        return;
    }

    lk.lock();

    set_int_gps_data_time(time(0));

    if (set_alt || set_speed || set_lat_lon || set_fix) {
        set_int_gps_signal_time(time(0));

        ever_seen_gps = true;

        gettimeofday(&(new_location->tv), NULL);

        new_location->gpsuuid = get_gps_uuid();
        new_location->gpsname = get_gps_name();

        if (time(0) - last_heading_time > 5 &&
                gps_location != nullptr && gps_location->fix >= 2) {
            new_location->heading = 
                gps_calc_heading(new_location->lat, new_location->lon, 
                        gps_location->lat, gps_location->lon);
            last_heading_time = new_location->tv.tv_sec;
        }

        gps_last_location = gps_location;
        gps_location = new_location;

        // Sync w/ the tracked fields
        update_locations();
    }

    last_data_time = time(0);

    lk.unlock();

    boost::asio::dispatch(strand_,
            [self = shared_from_this()]() {
                self->start_read();
            });
    return;
}

