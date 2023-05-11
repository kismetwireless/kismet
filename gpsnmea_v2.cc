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
    bool set_heading;
    bool set_fix;

    set_lat_lon = false;
    set_alt = false;
    set_speed = false;
    set_heading = false;
    set_fix = false;

    for (unsigned int x = 0; x < line.length(); x++) {
        if ( (line[x] < 0x20 || line[x] > 0x7F) && line[x] != 0x0d) {
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

    std::vector<std::string> gpstoks = str_tokenize(line, ",");
    try {
        if (gpstoks.size() == 0) {
            throw kis_gps_nmea_v2_soft_fail();
        } else {
            // The NMEA sentence should be the last 3 characters of the first string in gpstoks
            // NMEA sentences can be rerferenced at: https://gpsd.io/NMEA.html
            std::string nmea_sentence = gpstoks[0].substr(3);

            if (nmea_sentence == "GGA") {
            /*
                NMEA GGA standard referenced from https://gpsd.io/NMEA.html#_gga_global_positioning_system_fix_data
                Example:
                $GNGGA,001043.00,4404.14036,N,12118.85961,W,1,12,0.98,1113.0,M,-21.3,M*47
                $--GGA,hhmmss.ss,ddmm.mm,a,ddmm.mm,a,x,xx,x.x,x.x,M,x.x,M,x.x,xxxx*hh<CR><LF>
                Field Number:
                    0.  Talker ID + GGA
                    1.  UTC of this position report, hh is hours, mm is minutes, ss.ss is seconds.
                    2.  Latitude, dd is degrees, mm.mm is minutes
                    3.  N or S (North or South)
                    4.  Longitude, dd is degrees, mm.mm is minutes
                    5.  E or W (East or West)
                    6.  GPS Quality Indicator (non null)
                        0 - fix not available,
                        1 - GPS fix,
                        2 - Differential GPS fix (values above 2 are 2.3 features)
                        3 = PPS fix
                        4 = Real Time Kinematic
                        5 = Float RTK
                        6 = estimated (dead reckoning)
                        7 = Manual input mode
                        8 = Simulation mode
                    7.  Number of satellites in use, 00 - 12
                    8.  Horizontal Dilution of precision (meters)
                    9.  Antenna Altitude above/below mean-sea-level (geoid) (in meters)
                    10. Units of antenna altitude, meters
                    11. Geoidal separation, the difference between the WGS-84 earth ellipsoid and mean-sea-level (geoid), "-" means mean-sea-level below ellipsoid
                    12. Units of geoidal separation, meters
                    13. Age of differential GPS data, time in seconds since last SC104 type 1 or 9 update, null field when DGPS is not used
                    14. Differential reference station ID, 0000-1023
                    15. Checksum
                    The number of digits past the decimal point for Time, Latitude and Longitude is model dependent.
            */
                int tint;
                double tdouble;

                // GGA does not set speed or heading directly, so inherit it from previous data
                if (gps_location != nullptr) {
                    new_location->speed = gps_location->speed;
                    new_location->heading = gps_location->heading;
                }

                if (gpstoks.size() < 15)
                    throw kis_gps_nmea_v2_soft_fail();

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

            } else if (nmea_sentence == "RMC") {
            /*
                NMEA RMC standard referenced from: https://gpsd.io/NMEA.html#_rmc_recommended_minimum_navigation_information
                Example: $GNRMC,001031.00,A,4404.13993,N,12118.86023,W,0.146,,100117,,,A*7B
                $--RMC,hhmmss.ss,A,ddmm.mm,a,dddmm.mm,a,x.x,x.x,xxxx,x.x,a*hh<CR><LF>
                NMEA 2.3:
                $--RMC,hhmmss.ss,A,ddmm.mm,a,dddmm.mm,a,x.x,x.x,xxxx,x.x,a,m*hh<CR><LF>
                NMEA 4.1:
                $--RMC,hhmmss.ss,A,ddmm.mm,a,dddmm.mm,a,x.x,x.x,xxxx,x.x,a,m,s*hh<CR><LF>
                Field Number:
                    0.  Talker ID + RMC
                    1.  UTC of position fix, hh is hours, mm is minutes, ss.ss is seconds.
                    2.  Status, A = Valid, V = Warning
                    3.  Latitude, dd is degrees. mm.mm is minutes.
                    4.  N or S
                    5.  Longitude, ddd is degrees. mm.mm is minutes.
                    6.  E or W
                    7.  Speed over ground, knots
                    8.  Track made good, degrees true
                    9.  Date, ddmmyy
                    10. Magnetic Variation, degrees
                    11. E or W
                    12. FAA mode indicator (NMEA 2.3 and later)
                    13. Nav Status (NMEA 4.1 and later) A=autonomous, D=differential, E=Estimated, M=Manual input mode N=not valid, S=Simulator, V = Valid
                    14. Checksum
            */
                int tint;
                double tdouble;

                // RMC does not set heading directly, so we will inherit the current heading
                if (gps_location != nullptr) {
                    new_location->heading = gps_location->heading;
                }

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
            } else if (nmea_sentence == "VTG") {
                /*
                    NMEA VTG standard referenced from: https://gpsd.io/NMEA.html#_vtg_track_made_good_and_ground_speed
                    Example: $GPVTG,220.86,T,,M,2.550,N,4.724,K,A*34
                    $--VTG,x.x,T,x.x,M,x.x,N,x.x,K*hh<CR><LF>
                    NMEA 2.3:
                    $--VTG,x.x,T,x.x,M,x.x,N,x.x,K,m*hh<CR><LF>
                    Field Number:
                        0.  Talker ID + VTG
                        1.  Course over ground, degrees True
                        2.  T = True
                        3.  Course over ground, degrees Magnetic
                        4.  M = Magnetic
                        5.  Speed over ground, knots
                        6.  N = Knots
                        7.  Speed over ground, km/hr
                        8.  K = Kilometers Per Hour
                        9.  FAA mode indicator (NMEA 2.3 and later)
                        10. Checksum
                */

                // Copy the previous location data to this location because VTG does not contain lat/lon/alt
                // Otherwise update_location() will overwrite the lat/lon values with 0
                if (gps_location != nullptr) {
                    new_location->set(gps_location);
                    /*
                       new_location->lat = gps_location->lat;
                       new_location->lon = gps_location->lon;
                       new_location->alt = gps_location->alt;
                       */
                }

                double tdouble;

                if (gpstoks.size() < 10) 
                    throw kis_gps_nmea_v2_soft_fail();

                // Only use VTG if we didn't get our speed from another sentence in this series
                if (set_speed == false && (sscanf(gpstoks[7].c_str(), "%lf", &tdouble) == 1) ) {
                    new_location->speed = tdouble;
                    set_speed = true;
                }

                // Set the true and mag heading from the VTG sentence if it is available, otherwise it will be calculated
                if ((sscanf(gpstoks[1].c_str(), "%lf", &tdouble) == 1 )) {
                    new_location->heading = tdouble;
                    last_heading_time = new_location->tv.tv_sec;
                    set_heading = true;
                }
                if ((sscanf(gpstoks[3].c_str(), "%lf", &tdouble) == 1 )) {
                    new_location->magheading = tdouble;
                    last_heading_time = new_location->tv.tv_sec;
                    set_heading = true;
                }

            } else if (nmea_sentence == "GSV") {
            /*
                NMEA GSV standard referenced from: https://gpsd.io/NMEA.html#_gsv_satellites_in_view
                These sentences describe the sky position of a UPS satellite in view. Typically they’re shipped in a group of 2 or 3
                Example: 
                $GPGSV,3,1,11,03,03,111,00,04,15,270,00,06,01,010,00,13,06,292,00*74 
                $GPGSV,3,2,11,14,25,170,00,16,57,208,39,18,67,296,40,19,40,246,00*74 
                $GPGSV,3,3,11,22,42,067,42,24,14,311,43,27,05,244,00,,,,*4D

                $--GSV,x,x,x,x,x,x,x,...*hh<CR><LF>

                Field Number:
                    0.  Talker ID + GSV
                    1.  Total number of GSV sentences to be transmitted in this group
                    2.  Sentence number, 1-9 of this GSV message within current group
                    3.  Total number of satellites in view (leading zeros sent)
                    4.  Satellite ID or PRN number (leading zeros sent)
                    5.  Elevation in degrees (-90 to 90) (leading zeros sent)
                    6.  Azimuth in degrees to true north (000 to 359) (leading zeros sent)
                    7.  SNR in dB (00-99) (leading zeros sent) more satellite info quadruples like 4-7 n-1) Signal ID (NMEA 4.11) n) checksum
            */

                // Not currently handled, in the future could be used for a graphical plot of
                // the satellite position

            }

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

    if (set_alt || set_speed || set_heading || set_lat_lon || set_fix) {
        set_int_gps_signal_time(time(0));

        ever_seen_gps = true;

        gettimeofday(&(new_location->tv), NULL);

        new_location->gpsuuid = get_gps_uuid();
        new_location->gpsname = get_gps_name();

        if (time(0) - last_heading_time > 5 &&
                gps_location != nullptr && gps_location->fix >= 2 
                && set_heading == false) {
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

