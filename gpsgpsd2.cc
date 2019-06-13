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

#include "gpsgpsd2.h"
#include "util.h"
#include "time.h"
#include "gpstracker.h"
#include "kismet_json.h"
#include "pollabletracker.h"
#include "timetracker.h"

GPSGpsdV2::GPSGpsdV2(SharedGpsBuilder in_builder) : 
    KisGps(in_builder),
    tcpinterface {
        [this](size_t in_amt) { 
            BufferAvailable(in_amt);
        },
        [this](std::string in_err) {
            BufferError(in_err);
        }
    } {

    // Defer making buffers until open, because we might be used to make a 
    // builder instance

    tcphandler = NULL;

    last_heading_time = time(0);

    poll_mode = 0;
    si_units = 0;
    si_raw = 0;

    last_data_time = time(0);

    pollabletracker = 
        Globalreg::FetchMandatoryGlobalAs<PollableTracker>("POLLABLETRACKER");

    auto timetracker = Globalreg::FetchMandatoryGlobalAs<Timetracker>("TIMETRACKER");

    error_reconnect_timer = 
        timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 10, NULL, 1,
                [this](int) -> int {
                {
                    local_shared_locker l(&gps_mutex);

                    if (tcpclient != nullptr && tcpclient->FetchConnected())
                        return 1;
                }

                open_gps(get_gps_definition());
                return 1;

                });

    data_timeout_timer =
        timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 10, NULL, 1,
                [this](int) -> int {

                {
                    local_shared_locker l(&gps_mutex);

                    if (tcpclient == nullptr || (tcpclient != nullptr && !tcpclient->FetchConnected()))
                        return 1;
                }

                if (time(0) - last_data_time > 30) {
                    _MSG_ERROR("GPSDv2 didn't get data from gpsd in over 30 seconds, reconnecting "
                            "to GPSD server.");

                tcpclient->Disconnect();
                set_int_device_connected(false);
                }

                return 1;
                });

}

GPSGpsdV2::~GPSGpsdV2() {
    if (tcpclient != nullptr)
        pollabletracker->RemovePollable(tcpclient);

    tcpclient.reset();

    if (tcphandler != nullptr)
        tcphandler->RemoveReadBufferInterface();

    tcphandler.reset();

    auto timetracker = Globalreg::FetchGlobalAs<Timetracker>("TIMETRACKER");
    if (timetracker != nullptr) {
        timetracker->RemoveTimer(error_reconnect_timer);
        timetracker->RemoveTimer(data_timeout_timer);
    }
}

bool GPSGpsdV2::open_gps(std::string in_opts) {
    local_locker lock(&gps_mutex);

    if (!KisGps::open_gps(in_opts))
        return false;

    set_int_device_connected(false);

    // Disconnect the client if it still exists
    if (tcpclient != nullptr) {
        tcpclient->Disconnect();
    }

    // Clear the buffers
    if (tcphandler != nullptr) {
        tcphandler->ClearReadBuffer();
        tcphandler->ClearWriteBuffer();
    }

    std::string proto_host;
    std::string proto_port_s;
    unsigned int proto_port;

    proto_host = FetchOpt("host", source_definition_opts);
    proto_port_s = FetchOpt("port", source_definition_opts);

    if (proto_host == "") {
        _MSG("GPSGpsdV2 expected host= option, none found.", MSGFLAG_ERROR);
        return -1;
    }

    if (proto_port_s != "") {
        if (sscanf(proto_port_s.c_str(), "%u", &proto_port) != 1) {
            _MSG("GPSGpsdV2 expected port in port= option.", MSGFLAG_ERROR);
            return -1;
        }
    } else {
        proto_port = 2947;
        _MSG("GPSGpsdV2 defaulting to port 2947, set the port= option if "
                "your gpsd is on a different port", MSGFLAG_INFO);
    }

    // Do the first time setup
    if (tcphandler == nullptr) {
        // GPSD network connection writes data as well as reading, but most of it is
        // inbound data
        tcphandler = std::make_shared<BufferHandler<RingbufV2>>(4096, 512);
        // Set the read handler to our function interface
        tcphandler->SetReadBufferInterface(&tcpinterface);
    }

    if (tcpclient == nullptr) {
        // Link it to a tcp connection
        tcpclient = std::make_shared<TcpClientV2>(Globalreg::globalreg, tcphandler);
        pollabletracker->RegisterPollable(std::static_pointer_cast<Pollable>(tcpclient));
    }

    host = proto_host;
    port = proto_port;

    // Reset the time counter
    last_data_time = time(0);

    // We're not connected until we get data
    set_int_device_connected(0);

    // Connect
    tcpclient->Connect(proto_host, proto_port);

    return 1;
}

bool GPSGpsdV2::get_location_valid() {
    local_shared_locker lock(&gps_mutex);

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

void GPSGpsdV2::BufferAvailable(size_t in_amt) {
    local_locker lock(&gps_mutex);

    size_t buf_sz;
    char *buf;

    // We defer logging that we saw new data until we see a complete record, in case 
    // one of the weird failure conditions of GPSD is to send a partial record

    if (tcphandler->GetReadBufferAvailable() == 0) {
        _MSG_ERROR("GPSDv2 read buffer filled without getting a valid record; "
                "disconnecting and reconnecting.");
        tcpclient->Disconnect();
        set_int_device_connected(false);
        return;
    }

    // Use data availability as the connected status since tcp poll is currently
    // hidden from us
    {
        if (!get_device_connected()) {
            _MSG_INFO("GPSGPSD connected to GPSD server on {}:{}", host, port);
            set_int_device_connected(true);
        }
    }

    // Peek at all the data we have available
    buf_sz = tcphandler->PeekReadBufferData((void **) &buf, 
            tcphandler->GetReadBufferAvailable());

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

    std::vector<std::string> inptok = StrTokenize(std::string(buf, buf_sz), "\n", 0);
    tcphandler->PeekFreeReadBufferData(buf);

    if (inptok.size() < 1) {
        return;
    }

    set_lat_lon = false;
    set_alt = false;
    set_speed = false;
    set_fix = false;
    set_heading = false;

    for (unsigned int it = 0; it < inptok.size(); it++) {
        // Consume the data from the ringbuffer
        tcphandler->ConsumeReadBufferData(inptok[it].length() + 1);

        // We don't know what we're going to get from GPSD.  If it starts with 
        // { then it probably is json, try to parse it
        if (inptok[it][0] == '{') {
            Json::Value json;

            try {
                std::stringstream ss(inptok[it]);
                ss >> json;

                std::string msg_class = json["class"].asString();

                if (msg_class == "VERSION") {
                    std::string version  = MungeToPrintable(json["release"].asString());

                    _MSG("GPSGpsdV2 connected to a JSON-enabled GPSD version " +
                            version + ", turning on JSON mode", MSGFLAG_INFO);

                    // Set JSON mode
                    poll_mode = 10;
                    // We get speed in meters/sec
                    si_units = 1;

                    // Send a JSON message that we want future communication in JSON
                    std::string json_msg = "?WATCH={\"json\":true};\n";

                    if (tcphandler->PutWriteBufferData((void *) json_msg.c_str(), 
                                json_msg.length(), true) < json_msg.length()) {
                        _MSG("GPSGpsdV2 could not not write JSON enable command",
                                MSGFLAG_ERROR);
                    }
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
                _MSG_ERROR("GPSGPSDv2 got an invalid JSON record from GPSD: '{}'", e.what());

                tcpclient->Disconnect();
                set_int_device_connected(false);

                continue;
            }
        } else if (poll_mode == 0 && inptok[it] == "GPSD") {
            // Look for a really old gpsd which doesn't do anything intelligent
            // with the L (version) command.  Only do this once, if we've already
            // figured out a poll mode then there's not much point in hammering
            // the server.  Force us into watch mode.

            poll_mode = 1;

            std::string init_cmd = "L\n";
            if (tcphandler->PutWriteBufferData((void *) init_cmd.c_str(), 
                        init_cmd.length(), true) < init_cmd.length()) {
                _MSG("GPSGpsdV2 could not not write NMEA enable command",
                        MSGFLAG_ERROR);
            }

            continue;
        } else if (poll_mode < 10 && inptok[it].substr(0, 15) == "GPSD,L=2 1.0-25") {
            // Maemo ships a broken,broken GPS which doesn't parse NMEA correctly
            // and results in no alt or fix in watcher or polling modes, so we
            // have to detect this version and kick it into debug R=1 mode
            // and do NMEA ourselves.
            std::string cmd = "R=1\n";
            if (tcphandler->PutWriteBufferData((void *) cmd.c_str(), 
                        cmd.length(), true) < cmd.length()) {
                _MSG("GPSGpsdV2 could not not write NMEA enable command",
                        MSGFLAG_ERROR);
            }

            // Use raw for position
            si_raw = 1;
        } else if (poll_mode < 10 && inptok[it].substr(0, 7) == "GPSD,L=") {
            // Look for the version response
            std::vector<std::string> lvec = StrTokenize(inptok[it], " ");
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
            std::string watch_cmd = "J=1,W=1,R=1\n";
            if (tcphandler->PutWriteBufferData((void *) watch_cmd.c_str(), 
                        watch_cmd.length(), true) < watch_cmd.length()) {
                _MSG("GPSGpsdV2 could not not write GPSD watch command",
                        MSGFLAG_ERROR);
            }

            // Go into poll mode
            std::string poll_cmd = "PAVM\n";
            if (tcphandler->PutWriteBufferData((void *) poll_cmd.c_str(), 
                        poll_cmd.length(), true) < poll_cmd.length()) {
                _MSG("GPSGpsdV2 could not not write GPSD watch command",
                        MSGFLAG_ERROR);
            }


        } else if (poll_mode < 10 && inptok[it].substr(0, 7) == "GPSD,P=") {
            // Poll lines
            std::vector<std::string> pollvec = StrTokenize(inptok[it], ",");

            if (pollvec.size() < 5) {
                continue;
            }

            if (pollvec[1].substr(0, 2) == "P=" && sscanf(pollvec[1].c_str(), "P=%lf %lf", 
                        &(new_location->lat), &(new_location->lon)) != 2) {
                continue;
            }

            if (pollvec[4].substr(0, 2) == "M=" && sscanf(pollvec[4].c_str(), "M=%d", &(new_location->fix)) != 1) {
                continue;
            }

            if (pollvec[2].substr(0, 2) == "A=" && sscanf(pollvec[2].c_str(), "A=%lf", &(new_location->alt)) != 1)
                set_alt = false;
            else
                set_alt = true;

            if (pollvec[3].substr(0, 2) == "V=" && sscanf(pollvec[3].c_str(), "V=%lf", &(new_location->speed)) != 1)
                set_speed = false;
            else 
                set_speed = true;

            if (set_alt && new_location->fix < 3)
                new_location->fix = 3;

            if (!set_alt && new_location->fix < 2)
                new_location->fix = 2;

            set_heading = false;
            set_fix = true;
            set_lat_lon = true;

        } else if (poll_mode < 10 && inptok[it].substr(0, 7) == "GPSD,O=") {
            // Look for O= watch lines
            std::vector<std::string> ggavec = StrTokenize(inptok[it], " ");

            if (ggavec.size() < 15) {
                continue;
            }

            // Total fail if we can't get lat/lon/mode
            if (sscanf(ggavec[3].c_str(), "%lf", &(new_location->lat)) != 1)
                continue;

            if (sscanf(ggavec[4].c_str(), "%lf", &(new_location->lon)) != 1)
                continue;

            if (sscanf(ggavec[14].c_str(), "%d", &(new_location->fix)) != 1)
                continue;

            if (sscanf(ggavec[5].c_str(), "%lf", &(new_location->alt)) != 1)
                set_alt = false;
            else
                set_alt = true;

#if 0
            if (sscanf(ggavec[6].c_str(), "%f", &in_hdop) != 1) 
                use_dop = 0;

            if (sscanf(ggavec[7].c_str(), "%f", &in_vdop) != 1)
                use_dop = 0;
#endif

            if (sscanf(ggavec[8].c_str(), "%lf", &(new_location->heading)) != 1)
                set_heading = false;
            else
                set_heading = true;

            if (sscanf(ggavec[9].c_str(), "%lf", &(new_location->speed)) != 1)
                set_speed = false;
            else
                set_speed = true;

#if 0
            if (si_units == 0)
                in_spd *= 0.514; /* Speed in meters/sec from knots */
#endif

            if (set_alt && new_location->fix < 3)
                new_location->fix = 3;

            if (!set_alt && new_location->fix < 2)
                new_location->fix = 2;


            set_fix = true;
            set_lat_lon = true;
        } else if (poll_mode < 10 && si_raw && inptok[it].substr(0, 6) == "$GPGSA") {
            std::vector<std::string> savec = StrTokenize(inptok[it], ",");

            if (savec.size() != 18)
                continue;

            if (sscanf(savec[2].c_str(), "%d", &(new_location->fix)) != 1)
                continue;

            set_fix = true;
        } else if (si_raw && inptok[it].substr(0, 6) == "$GPVTG") {
            std::vector<std::string> vtvec = StrTokenize(inptok[it], ",");

            if (vtvec.size() != 10)
                continue;

            if (sscanf(vtvec[7].c_str(), "%lf", &(new_location->speed)) != 1)
                continue;

            set_speed = true;
        } else if (poll_mode < 10 && si_raw && inptok[it].substr(0, 6) == "$GPGGA") {
            std::vector<std::string> gavec = StrTokenize(inptok[it], ",");
            int tint;
            float tfloat;

            if (gavec.size() != 15)
                continue;

            if (sscanf(gavec[2].c_str(), "%2d%f", &tint, &tfloat) != 2)
                continue;
            new_location->lat = (float) tint + (tfloat / 60);
            if (gavec[3] == "S")
                new_location->lat *= -1;

            if (sscanf(gavec[4].c_str(), "%3d%f", &tint, &tfloat) != 2)
                continue;
            new_location->lon = (float) tint + (tfloat / 60);
            if (gavec[5] == "W")
                new_location->lon *= -1;

            if (sscanf(gavec[9].c_str(), "%f", &tfloat) != 1)
                continue;
            new_location->alt = tfloat;

            if (new_location->fix < 3)
                new_location->fix = 3;

            set_fix = 3;
            set_alt = true;
            set_lat_lon = true;
#if 0
        } else if (poll_mode < 10 && inptok[it].substr(0, 6) == "$GPGSV") {
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

            gps_connected = 1;

            vector<string> svvec = StrTokenize(inptok[it], ",");
            GPSCore::sat_pos sp;

            if (svvec.size() < 6)
                continue;

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

            continue;
#endif
        } else {
            continue;
        }
    }

    // If we've gotten this far in the parser, we've gotten usable data, even if it's not
    // actionable data (ie status w/ no valid signal is OK, but mangled unparsable nonsense
    // isn't.)
    last_data_time = time(0);

    // fprintf(stderr, "gps set loc %d alt %d spd %d fix %d heading %d\n", set_lat_lon, set_alt, set_speed, set_fix, set_heading);

    if (set_alt || set_speed || set_lat_lon || set_fix || set_heading) {
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
            // NMEA reports speed in knots, convert
            gps_location->speed *= 0.514;
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
                GpsCalcHeading(gps_location->lat, gps_location->lon, 
                        gps_last_location->lat, gps_last_location->lon);
            last_heading_time = gps_location->tv.tv_sec;
        }
    }

    // Sync w/ the tracked fields
    update_locations();
}

void GPSGpsdV2::BufferError(std::string in_error) {
    local_locker lock(&gps_mutex);

    set_int_device_connected(false);

    // Delete any existing interface before we parse options
    if (tcpclient != NULL) {
        pollabletracker->RemovePollable(tcpclient);
        tcpclient.reset();
    }

    _MSG("GPS device '" + get_gps_name() + "' encountered a network error: " + in_error,
            MSGFLAG_ERROR);

}


