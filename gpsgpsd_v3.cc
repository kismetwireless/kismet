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

#include "gpsgpsd_v3.h"
#include "gpstracker.h"
#include "messagebus.h"
#include "timetracker.h"
#include "util.h"

kis_gps_gpsd_v3::kis_gps_gpsd_v3(shared_gps_builder in_builder) : 
    kis_gps(in_builder),
    resolver{Globalreg::globalreg->io},
    socket{Globalreg::globalreg->io},
    strand_{Globalreg::globalreg->io} {

    // Defer making buffers until open, because we might be used to make a 
    // builder instance

    last_heading_time = time(0);

    poll_mode = 0;
    si_units = 0;
    si_raw = 0;

    last_data_time = time(0);

    auto timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>("TIMETRACKER");

    error_reconnect_timer = 
        timetracker->register_timer(SERVER_TIMESLICES_SEC * 10, NULL, 1,
                [this](int) -> int {
                kis_lock_guard<kis_mutex> lk(gps_mutex, "error timer");

                if (socket.is_open())
                    return 1;

                if (!get_gps_reconnect())
                    return 1;

                open_gps(get_gps_definition());

                return 1;
                });

    data_timeout_timer =
        timetracker->register_timer(SERVER_TIMESLICES_SEC * 10, NULL, 1,
                [this](int) -> int {
                kis_lock_guard<kis_mutex> lk(gps_mutex, "data timer");

                if (socket.is_open() && time(0) - last_data_time > 30) {
                    close();

                    if (get_gps_reconnect()) {
                        _MSG_ERROR("(GPS) No usable data from gpsd in over 30 seconds, reconnecting...");
                        open_gps(get_gps_definition());
                    } else {
                        _MSG_ERROR("(GPS) No usable data from gpsd in over 30 seconds, disconnecting");
                    }
                }

                return 1;
                });

}

kis_gps_gpsd_v3::~kis_gps_gpsd_v3() {
    close();

    auto timetracker = Globalreg::fetch_global_as<time_tracker>("TIMETRACKER");
    if (timetracker != nullptr) {
        timetracker->remove_timer(error_reconnect_timer);
        timetracker->remove_timer(data_timeout_timer);
    }
}

void kis_gps_gpsd_v3::close() {
    kis_lock_guard<kis_mutex> lk(gps_mutex, "close");

    stopped = true;
    set_int_device_connected(false);

    if (socket.is_open()) {
        try {
            socket.cancel();
            socket.close();
        } catch (const std::exception& e) {
            // Ignore failures to close the socket, so long as its closed
            ;
        }
    }

}

void kis_gps_gpsd_v3::start_connect(std::shared_ptr<kis_gps_gpsd_v3> ref,
        const boost::system::error_code& error, tcp::resolver::iterator endpoints) {

    if (stopped)
        return;

    if (error) {
        _MSG_ERROR("(GPS) Could not resolve gpsd address {}:{} - {}", host, port, error.message());
        stopped = true;
        set_int_device_connected(false);
    } else if (endpoints == tcp::resolver::iterator()) {
        _MSG_ERROR("(GPS) Could not connect to gpsd {}:{}", host, port);
        stopped = true;
        set_int_device_connected(false);
    } else {
        boost::asio::async_connect(socket, endpoints,
                boost::asio::bind_executor(strand_, 
                [this, ref](const boost::system::error_code& ec, tcp::resolver::iterator endpoint) {
                    handle_connect(ref, ec, endpoint);
                }));
    }
}

void kis_gps_gpsd_v3::handle_connect(std::shared_ptr<kis_gps_gpsd_v3> ref,
        const boost::system::error_code& error, tcp::resolver::iterator endpoint) {

    if (stopped) {
        return;
    }

    if (error) {
        if (endpoint == tcp::resolver::iterator())
            _MSG_ERROR("(GPS) Could not connect to gpsd {}:{} - {}", host, port, error.message());
        else
            _MSG_ERROR("(GPS) Could not connect to gpsd {} - {}", endpoint->endpoint(), error.message());
        close();
        return;
    }

    _MSG_INFO("(GPS) Connected to gpsd server {}", endpoint->endpoint());

    stopped = false;
    set_int_device_connected(true);

    start_read(ref);
}

void kis_gps_gpsd_v3::write_gpsd(std::shared_ptr<kis_gps_gpsd_v3> ref, const std::string& data) {
    if (stopped)
        return;

    auto buf = std::make_shared<std::string>(data);

    boost::asio::post(strand_,
        [this, buf]() {
            out_bufs.push_back(buf);

            if (out_bufs.size() > 1)
                return;

            write_impl();
            });

        /*
    boost::asio::async_write(socket, boost::asio::buffer(data),
            [this](const boost::system::error_code& error, std::size_t) {
                if (error) {
                    if (error.value() == boost::asio::error::operation_aborted)
                        return;

                    _MSG_ERROR("(GPS) Error writing GPSD command: {}", error.message());
                    close();
                }
            }); */
}

void kis_gps_gpsd_v3::write_impl() {
    auto buf = out_bufs.front();

    if (socket.is_open()) {
        boost::asio::async_write(socket, boost::asio::buffer(buf->data(), buf->size()),
                boost::asio::bind_executor(strand_, 
                    [this](const boost::system::error_code& ec, std::size_t) {
                        out_bufs.pop_front();

                        if (ec) {
                            if (ec.value() == boost::asio::error::operation_aborted)
                                return;

                            _MSG_ERROR("(GPS) Error writing GPSD command: {}", ec.message());
                            return close();
                        }

                        if (out_bufs.size())
                            return write_impl();
                    }));
    }
}

void kis_gps_gpsd_v3::start_read(std::shared_ptr<kis_gps_gpsd_v3> ref) {
    boost::asio::async_read_until(socket, in_buf, '\n',
            boost::asio::bind_executor(strand_, 
                [this, ref](const boost::system::error_code& error, std::size_t t) {
                handle_read(ref, error, t);
            }));
}

void kis_gps_gpsd_v3::handle_read(std::shared_ptr<kis_gps_gpsd_v3> ref,
        const boost::system::error_code& error, std::size_t t) {
    kis_unique_lock<kis_mutex> lk(gps_mutex, std::defer_lock, "handle_read");

    if (stopped)
        return;

    if (error) {
        // Return from aborted errors cleanly
        if (error.value() == boost::asio::error::operation_aborted)
            return;

        _MSG_ERROR("(GPS) Error reading from GPSD connection {}:{} - {}", host, port, error.message());
        return close();
    }

    // Pull the buffer
    std::string line;
    std::istream is(&in_buf);
    std::getline(is, line);

    // Ignore blank lines from gpsd
    if (line.empty()) {
        start_read(ref);
        return;
    }

    // Aggregate into a new location; then copy into the main location
    // depending on what we found.  Locations can come in multiple sentences
    // so if we're within a second of the previous one we can aggregate them
    std::unique_ptr<kis_gps_packinfo> new_location(new kis_gps_packinfo);
    bool set_lat_lon;
    bool set_alt;
    bool set_speed;
    bool set_fix;
    bool set_heading;
    bool set_error;

    set_lat_lon = false;
    set_alt = false;
    set_speed = false;
    set_fix = false;
    set_heading = false;

    // We don't know what we're going to get from GPSD.  If it starts with 
    // { then it probably is json, try to parse it
    if (line[0] == '{') {
        Json::Value json;

        try {
            std::stringstream ss(line);
            ss >> json;

            std::string msg_class = json["class"].asString();

            if (msg_class == "VERSION") {
                std::string version  = munge_to_printable(json["release"].asString());

                _MSG_INFO("(GPS) Connected to a JSON-enabled GPSD ({}), enabling JSON mode", version);

                // Set JSON mode
                poll_mode = 10;
                // We get speed in meters/sec
                si_units = 1;

                write_gpsd(ref, "?WATCH={\"json\":true};\n");
            } else if (msg_class == "TPV") {
                if (json.isMember("mode")) {
                    new_location->fix = json["mode"].asInt();
                    set_fix = true;
                }

                // If we have a valid alt, use it
                if (set_fix && new_location->fix > 2) {
                    if (json.isMember("alt")) {
                        new_location->alt = json["alt"].asDouble();
                        set_alt = true;
                    }
                } 

                if (json.isMember("epx")) {
                    new_location->error_x = json["epx"].asDouble();
                    set_error = true;
                }

                if (json.isMember("epy")) {
                    new_location->error_y = json["epy"].asDouble();
                    set_error = true;
                }

                if (json.isMember("epv")) {
                    new_location->error_v = json["epv"].asDouble();
                    set_error = true;
                }

                if (set_fix && new_location->fix >= 2) {
                    // If we have LAT and LON, use them
                    if (json.isMember("lat") && json.isMember("lon")) {
                        new_location->lat = json["lat"].asDouble();
                        new_location->lon = json["lon"].asDouble();

                        set_lat_lon = true;
                    }

                    if (json.isMember("track")) {
                        new_location->heading = json["track"].asDouble();
                        set_heading = true;
                    }

                    if (json.isMember("speed")) {
                        new_location->speed = json["speed"].asDouble();
                        set_speed = true;

                        // GPSD JSON reports in meters/second, convert to kph
                        new_location->speed *= 3.6;
                    }
                }
#if 0
            } else if (msg_class == "SKY") {
                GPSCore::sat_pos sp;
                struct JSON_value *v = NULL, *s = NULL;

                gps_connected = 1;

                v = JSON_dict_get_value(json, "satellites", err);

                if (err.length() == 0 && v != NULL) {
                    sat_pos_map.clear();

                    if (v->value.tok_type == JSON_arrstart) {
                        for (unsigned int z = 0; z < v->value_array.size(); z++) {
                            float prn, ele, az, snr;
                            int valid = 1;

                            s = v->value_array[z];

                            // If we're not a dictionary in the sat array, skip
                            if (s->value.tok_type != JSON_start) {
                                continue;
                            }

                            prn = JSON_dict_get_number(s, "PRN", err);
                            if (err.length() != 0) 
                                valid = 0;

                            ele = JSON_dict_get_number(s, "el", err);
                            if (err.length() != 0)
                                valid = 0;

                            az = JSON_dict_get_number(s, "az", err);
                            if (err.length() != 0)
                                valid = 0;

                            snr = JSON_dict_get_number(s, "ss", err);
                            if (err.length() != 0)
                                valid = 0;

                            if (valid) {
                                sp.prn = prn;
                                sp.elevation = ele;
                                sp.azimuth = az;
                                sp.snr = snr;

                                sat_pos_map[prn] = sp;
                            }
                        }

                    }

                }
#endif
            }

        } catch (std::exception& e) {
            _MSG_ERROR("(GPS) Received an invalid JSON record from GPSD {}:{} - '{}'", host, port, e.what());
            return close();
        }
    } else if (poll_mode == 0 && line == "GPSD") {
        // Look for a really old gpsd which doesn't do anything intelligent
        // with the L (version) command.  Only do this once, if we've already
        // figured out a poll mode then there's not much point in hammering
        // the server.  Force us into watch mode.

        poll_mode = 1;

        write_gpsd(ref, "L\n");
    } else if (poll_mode < 10 && line.substr(0, 15) == "GPSD,L=2 1.0-25") {
        // Maemo ships a broken,broken GPS which doesn't parse NMEA correctly
        // and results in no alt or fix in watcher or polling modes, so we
        // have to detect this version and kick it into debug R=1 mode
        // and do NMEA ourselves.

        write_gpsd(ref, "R=1\n");

        // Use raw for position
        si_raw = 1;
    } else if (poll_mode < 10 && line.substr(0, 7) == "GPSD,L=") {
        // Look for the version response
        std::vector<std::string> lvec = str_tokenize(line, " ");
        int gma, gmi;

        if (lvec.size() < 3) {
            poll_mode = 1;
        } else if (sscanf(lvec[1].c_str(), "%d.%d", &gma, &gmi) != 2) {
            poll_mode = 1;
        } else {
            if (gma < 2 || (gma == 2 && gmi < 34)) {
                poll_mode = 1;
            }
            // Since GPSD r2368 'O' gives the speed as m/s instead of knots
            if (gma > 2 || (gma == 2 && gmi >= 31)) {
                si_units = 1;
            }
        }

        // Don't use raw for position
        si_raw = 0;

        // If we're still in poll mode 0, write the watcher command.
        // This has been merged into one command because gpsd apparently
        // silently drops the second command sent too quickly
        write_gpsd(ref, "J=1,W=1,R=1\n");
        write_gpsd(ref, "PAVM\n");

    } else if (poll_mode < 10 && line.substr(0, 7) == "GPSD,P=") {
        // pollable_poll lines
        std::vector<std::string> pollvec = str_tokenize(line, ",");

        if (pollvec.size() < 5) {
            start_read(ref);
            return;
        }

        if (pollvec[1].substr(0, 2) == "P=" && sscanf(pollvec[1].c_str(), "P=%lf %lf", 
                    &(new_location->lat), &(new_location->lon)) != 2) {
            start_read(ref);
            return;
        }

        if (pollvec[4].substr(0, 2) == "M=" && sscanf(pollvec[4].c_str(), "M=%d", &(new_location->fix)) != 1) {
            start_read(ref);
            return;
        }

        if (pollvec[2].substr(0, 2) == "A=" && sscanf(pollvec[2].c_str(), "A=%lf", &(new_location->alt)) != 1)
            set_alt = false;
        else
            set_alt = true;

        if (pollvec[3].substr(0, 2) == "V=" && sscanf(pollvec[3].c_str(), "V=%lf", &(new_location->speed)) != 1) {
            set_speed = false;
        } else  {
            set_speed = true;

            // Convert from knots to kph - unclear if truly knots still but lets hope; this is only in
            // an ancient gpsd
            new_location->speed *= 1.852;
        }

        if (set_alt && new_location->fix < 3)
            new_location->fix = 3;

        if (!set_alt && new_location->fix < 2)
            new_location->fix = 2;

        set_heading = false;
        set_fix = true;
        set_lat_lon = true;

    } else if (poll_mode < 10 && line.substr(0, 7) == "GPSD,O=") {
        // Look for O= watch lines
        std::vector<std::string> ggavec = str_tokenize(line, " ");

        if (ggavec.size() < 15) {
            start_read(ref);
            return;
        }

        // Total fail if we can't get lat/lon/mode
        if (sscanf(ggavec[3].c_str(), "%lf", &(new_location->lat)) != 1) {
            start_read(ref);
            return;
        }

        if (sscanf(ggavec[4].c_str(), "%lf", &(new_location->lon)) != 1) {
            start_read(ref);
            return;
        }

        if (sscanf(ggavec[14].c_str(), "%d", &(new_location->fix)) != 1) {
            start_read(ref);
            return;
        }

        if (sscanf(ggavec[5].c_str(), "%lf", &(new_location->alt)) != 1)
            set_alt = false;
        else
            set_alt = true;

        if (sscanf(ggavec[8].c_str(), "%lf", &(new_location->heading)) != 1)
            set_heading = false;
        else
            set_heading = true;

        if (sscanf(ggavec[9].c_str(), "%lf", &(new_location->speed)) != 1) {
            set_speed = false;
        } else {
            set_speed = true;

            // Convert from knots to kph
            new_location->speed *= 1.852;
        }

        if (set_alt && new_location->fix < 3)
            new_location->fix = 3;

        if (!set_alt && new_location->fix < 2)
            new_location->fix = 2;


        set_fix = true;
        set_lat_lon = true;
    } else if (poll_mode < 10 && si_raw && line.substr(0, 6) == "$GPGSA") {
        std::vector<std::string> savec = str_tokenize(line, ",");

        if (savec.size() != 18) {
            start_read(ref);
            return;
        }

        if (sscanf(savec[2].c_str(), "%d", &(new_location->fix)) != 1) {
            start_read(ref);
            return;
        }

        set_fix = true;
    } else if (si_raw && line.substr(0, 6) == "$GPVTG") {
        std::vector<std::string> vtvec = str_tokenize(line, ",");

        if (vtvec.size() != 10) {
            start_read(ref);
            return;
        }

        if (sscanf(vtvec[7].c_str(), "%lf", &(new_location->speed)) != 1) {
            start_read(ref);
            return;
        }

        // Convert from knots to kph
        new_location->speed *= 1.852;

        set_speed = true;
    } else if (poll_mode < 10 && si_raw && line.substr(0, 6) == "$GPGGA") {
        std::vector<std::string> gavec = str_tokenize(line, ",");
        int tint;
        float tfloat;

        if (gavec.size() != 15) {
            start_read(ref);
            return;
        }

        if (sscanf(gavec[2].c_str(), "%2d%f", &tint, &tfloat) != 2) {
            start_read(ref);
            return;
        }

        new_location->lat = (float) tint + (tfloat / 60);
        if (gavec[3] == "S")
            new_location->lat *= -1;

        if (sscanf(gavec[4].c_str(), "%3d%f", &tint, &tfloat) != 2) {
            start_read(ref);
            return;
        }

        new_location->lon = (float) tint + (tfloat / 60);
        if (gavec[5] == "W")
            new_location->lon *= -1;

        if (sscanf(gavec[9].c_str(), "%f", &tfloat) != 1) {
            start_read(ref);
            return;
        }

        new_location->alt = tfloat;

        if (new_location->fix < 3)
            new_location->fix = 3;

        set_fix = 3;
        set_alt = true;
        set_lat_lon = true;

    } else {
        start_read(ref);
        return;
    }

    // If we've gotten this far in the parser, we've gotten usable data, even if it's not
    // actionable data (ie status w/ no valid signal is OK, but mangled unparsable nonsense isn't.)
    
    lk.lock();

    last_data_time = time(0);

    set_int_gps_data_time(last_data_time);

    if (set_alt || set_speed || set_lat_lon || set_fix || set_heading) {
        set_int_gps_signal_time(last_data_time);

        if (gps_location != NULL) {
            // Copy the current location to the last one
            if (gps_last_location != NULL)
                delete gps_last_location;
            gps_last_location = new kis_gps_packinfo(gps_location);
        } else {
            gps_location = new kis_gps_packinfo();
        }

        // Copy whatever we know about the new location into the current
        if (set_lat_lon) {
            gps_location->lat = new_location->lat;
            gps_location->lon = new_location->lon;
        }

        if (set_alt)
            gps_location->alt = new_location->alt;

        if (set_speed) {
            gps_location->speed = new_location->speed;
        }

        if (set_fix) {
            gps_location->fix = new_location->fix;
        }

        if (set_heading) {
            gps_location->heading = new_location->heading;
        }

        if (set_error) {
            gps_location->error_x = new_location->error_x;
            gps_location->error_y = new_location->error_y;
            gps_location->error_v = new_location->error_v;
        }

        gettimeofday(&(gps_location->tv), NULL);

        if (!set_heading && time(0) - last_heading_time > 5 &&
                gps_last_location->fix >= 2) {
            gps_location->heading = 
                gps_calc_heading(gps_location->lat, gps_location->lon, 
                        gps_last_location->lat, gps_last_location->lon);
            last_heading_time = gps_location->tv.tv_sec;
        }
    }

    // Sync w/ the tracked fields
    update_locations();

    lk.unlock();

    // Initiate another read
    return start_read(ref);
}

bool kis_gps_gpsd_v3::open_gps(std::string in_opts) {
    kis_unique_lock<kis_mutex> lk(gps_mutex, "gps_gpsd_v3 open_gps");

    if (!kis_gps::open_gps(in_opts))
        return false;

    // Disconnect the client if it still exists
    if (socket.is_open()) { 
        try {
            socket.cancel();
            socket.close();
        } catch (const std::exception& e) {
            ;
        }

        strand_.post([this]() {
            out_bufs.clear();
            });
    }

    std::string proto_host;
    std::string proto_port;

    proto_host = fetch_opt("host", source_definition_opts);
    proto_port = fetch_opt("port", source_definition_opts);

    if (proto_host == "") {
        _MSG("(GPS) Expected a host= option for gpsd, none found.", MSGFLAG_ERROR);
        return -1;
    }

    if (proto_port == "") {
        proto_port = "2947";
        _MSG_INFO("(GPS) Defaulting to port 2947 for GPSD, set the port= option if "
                "your gpsd is on a different port");
    }

    host = proto_host;
    port = proto_port;

    // Reset the time counter
    last_data_time = time(0);

    // We're not stopped
    stopped = false;

    _MSG_INFO("(GPS) Connecting to GPSD on {}:{}", host, port);

    lk.unlock();

    resolver.async_resolve(tcp::resolver::query(host.c_str(), port.c_str()),
            boost::asio::bind_executor(strand_, 
            [this](const boost::system::error_code& error, tcp::resolver::iterator endp) {
                start_connect(shared_from_this(), error, endp);
            }));

    return 1;
}

bool kis_gps_gpsd_v3::get_location_valid() {
    kis_lock_guard<kis_mutex> lk(gps_mutex, "gps_gpsd_v3 get_location_valid");

    if (!get_device_connected()) {
        return false;
    }

    if (gps_location == NULL) {
        return false;
    }

    if (gps_location->fix < 2) {
        return false;
    }

    // If a location is older than 10 seconds, it's no good anymore
    if (time(0) - gps_location->tv.tv_sec > 10) {
        return false;
    }

    return true;
}

