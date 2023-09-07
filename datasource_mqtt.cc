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
#include "kis_datasource.h"
#include "datasource_mqtt.h"
#include "alertracker.h"

#ifdef HAVE_LIBMOSQUITTO

kis_datasource_mqtt::kis_datasource_mqtt(shared_datasource_builder in_builder) :
    kis_datasource(in_builder) {

    mosquitto_ = nullptr;
    thread_started_ = false;
    mqtt_connected_ = false;
    set_int_source_hardware("mqtt");
}

kis_datasource_mqtt::~kis_datasource_mqtt() {
    close_source();
}

// Override probing to handle locally
void kis_datasource_mqtt::probe_interface(std::string in_definition, unsigned int in_transaction, 
        probe_callback_t in_cb) {

    // Populate our local info about the interface
    if (!parse_source_definition(in_definition)) {
        if (in_cb != nullptr) {
            in_cb(in_transaction, false, "invalid source definition");
        }

        return;
    }

    if (get_source_interface() == "mqtt") {
        if (in_cb != nullptr) {
            in_cb(in_transaction, true, "");
        }

        return;
    }

    if (in_cb != nullptr) {
        in_cb(in_transaction, false, "");
    }

    return;
}

// Override normal source error handling since we have no external component, we let mosquitto handle
// reconnecting.
void kis_datasource_mqtt::handle_source_error(void) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource_mqtt handle_source_error");

    if (get_source_running()) {
        auto alrt = fmt::format("Source {} ({}) has encountered an error ({}).  The MQTT service "
                "will attempt to automatically reconnect.", get_source_name(), get_source_uuid(),
                get_source_error_reason());

        std::shared_ptr<alert_tracker> alertracker =
            Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");
        alertracker->raise_one_shot("SOURCEERROR", "SYSTEM", kis_alert_severity::critical, alrt, -1);

        _MSG(alrt, MSGFLAG_ERROR);
    } else {
        auto alrt = fmt::format("Source {} ({}) has encountered an error and can not be started ({}). ",
                get_source_name(), get_source_uuid(), get_source_error_reason());

        std::shared_ptr<alert_tracker> alertracker =
            Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");
        alertracker->raise_one_shot("SOURCEERROR", "SYSTEM", kis_alert_severity::critical, alrt, -1);

        _MSG(alrt, MSGFLAG_ERROR);
    }

    set_int_source_running(false);
    return;
}

void kis_datasource_mqtt::open_interface(std::string in_definition, unsigned int in_transaction,
        open_callback_t in_cb) {

    // Some copypasta from the datasource common code, but we need to process all our options and
    // connect to mqtt ourselves, but we don't actually connect to any datasources; instead we 
    // spawn a mqtt handler thread per datasource & asyncrhronously process packets from that.

    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock, "datasource_mqtt open_interface");
    lock.lock();

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    set_int_source_definition(in_definition);

    // Populate our local info about the interface
    if (!parse_source_definition(in_definition)) {
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "Malformed source config");
            lock.lock();
        }

        return;
    }

    if (has_definition_opt("host")) {
        host_ = get_definition_opt("host");
    } else {
        set_int_source_running(0);
        set_int_source_error(1);
        set_int_source_error_reason("Missing 'host' option");

        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "Missing 'host' option in mqtt source definition");
            return;
        }
    }

    if (has_definition_opt("port")) {
        try {
            port_ = string_to_uint(get_definition_opt("port"));
        } catch (...) {
            set_int_source_running(0);
            set_int_source_error(1);
            set_int_source_error_reason("Invalid 'port' option");
            if (in_cb != NULL) {
                lock.unlock();
                in_cb(in_transaction, false, "Invalid 'port' option in mqtt source definition, expected port number");
                return;
            }
        }
    } else {
        port_ = 1883;
    }

    if (has_definition_opt("topic")) {
        topic_ = get_definition_opt("topic");
        set_int_source_cap_interface(topic_);
    } else {
        set_int_source_running(0);
        set_int_source_error(1);
        set_int_source_error_reason("Missing 'topic' option");

        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "Missing 'topic' option in mqtt source definition");
            return;
        }
    }

    if (has_definition_opt("mapping")) {
        json_type_ = get_definition_opt("mapping");
    } else {
        set_int_source_running(0);
        set_int_source_error(1);
        set_int_source_error_reason("Missing 'mapping' option");
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "Missing 'mapping' option in mqtt source definition, this is required");
            return;
        }

    }

    if (get_source_uuid().error && !local_uuid) {
        uuid nuuid;

        nuuid.generate_time_uuid((uint8_t *) "\x00\x00\x00\x00\x00\x00");

        set_source_uuid(nuuid);
        set_source_key(adler32_checksum(nuuid.uuid_to_string()));
    }

    if (has_definition_opt("identity")) {
        identity_ = get_definition_opt("identity");
    } else {
        identity_ = fmt::format("kismet-{}", get_source_uuid());
    }

    if (has_definition_opt("channel")) {
        channel_ = get_definition_opt("channel");
    }

    if (has_definition_opt("frequency")) {
        try {
            freq_khz_ = human_to_freq_khz(get_definition_opt("frequency"));
        } catch (...) {
            set_int_source_running(0);
            set_int_source_error(1);
            set_int_source_error_reason("Invalid 'frequency' option");
            if (in_cb != NULL) {
                lock.unlock();
                in_cb(in_transaction, false, "Invalid 'frequency' option in mqtt source definition, expected number");
                return;
            }
        }
    } else {
        freq_khz_ = 0;
    }


    user_ = get_definition_opt("user");
    password_ = get_definition_opt("password");

    tls_ = get_definition_opt_bool("tls", false);
    tls_psk_ = get_definition_opt("tls_psk");
    tls_ca_path_ = get_definition_opt("tls_ca_dir");
    tls_ca_file_ = get_definition_opt("tls_ca_file");
    tls_certfile_ = get_definition_opt("tls_certfile");
    tls_keyfile_ = get_definition_opt("tls_keyfile");
    tls_keyfile_pw_ = get_definition_opt("tls_keyfile_pw");

    if (tls_ && tls_ca_file_.length() == 0 && tls_ca_path_.length() == 0) {
        _MSG_INFO("MQTT source {} ({}) no CA file or path provided, guessing system default "
                "of /etc/ssl/certs.", get_source_name(), get_source_uuid());
        tls_ca_path_ = "/etc/ssl/certs";
    }

    if (tls_psk_.length() || tls_ca_path_.length() || tls_ca_file_.length() || 
            tls_certfile_.length()) {
        tls_ = true;
    }

    if (tls_psk_.length() != 0 && tls_certfile_.length() != 0) {
        set_int_source_running(0);
        set_int_source_error(1);
        set_int_source_error_reason("Can not combine 'tls_psk' and 'tls_certfile' mqtt options");
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "Can not combine 'tls_psk' and 'tls_certfile' mqtt options");
            return;
        }
    }

    if (tls_certfile_.length() == 0 && tls_keyfile_.length() != 0) {
        set_int_source_running(0);
        set_int_source_error(1);
        set_int_source_error_reason("'tls_keyfile' requires 'tls_certfile' mqtt option");
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "'tls_keyfile' option requires a 'tls_certfile' mqtt option");
            return;
        }
    }

    if (user_.length() != 0 && password_.length() == 0) {
        set_int_source_running(0);
        set_int_source_error(1);
        set_int_source_error_reason("'user' requires 'password' mqtt option");
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "'user' option requires a 'password' mqtt option");
            return;
        }
    }

    if (user_.length() != 0 && !tls_) {
        set_int_source_running(0);
        set_int_source_error(1);
        set_int_source_error_reason("MQTT logins require TLS");
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "MQTT logins require TLS");
            return;
        }
    }


    if (has_definition_opt("metagps")) {
        auto gpstracker = Globalreg::fetch_mandatory_global_as<gps_tracker>();
        auto metaname = get_definition_opt("metagps");

        auto gps = gpstracker->find_gps_by_name(metaname);
        if (gps != nullptr) {
            set_device_gps(gps);
        } else {
            auto gpsdef = fmt::format("meta:name={}", metaname);
            set_device_gps(gpstracker->create_gps(gpsdef));
        }
    }

    if (mosquitto_ == nullptr) {
        mosquitto_ = mosquitto_new(identity_.c_str(), true, this);
    } else {
        mosquitto_disconnect(mosquitto_);
    }

    set_int_source_retry_attempts(0);
    set_int_source_error(0);

    // We don't use error timers
    if (error_timer_id > 0)
        timetracker->remove_timer(error_timer_id);

    // Remember the open callback to pass through ourselves to the opencb
    open_cb_ = in_cb;
    open_trans_id_ = in_transaction;

    mosquitto_connect_callback_set(mosquitto_, [](struct mosquitto *m, void *obj, int rc) -> void {
            auto ds = static_cast<kis_datasource_mqtt *>(obj);

            // _MSG_DEBUG("MQTT connect cb {} {}", ds->get_name(), rc);

            kis_unique_lock<kis_mutex> lock(ds->ext_mutex, std::defer_lock, "datasource_mqtt mqtt_conn_cb");
            lock.lock();

            if (rc == 0) {
                ds->set_int_source_running(true);
                ds->set_int_source_error(false);

                _MSG_INFO("MQTT source {} ({}) connected to server at {}:{}",
                        ds->get_source_name(), ds->get_source_uuid(), ds->host_, ds->port_);

                if (ds->open_cb_ != nullptr) {
                    lock.unlock();
                    ds->open_cb_(ds->open_trans_id_, true, "MQTT connected");
                    lock.lock();

                    ds->open_cb_ = nullptr;
    
                    if (ds->error_timer_id > 0)
                        ds->timetracker->remove_timer(ds->error_timer_id);
                }

                mosquitto_subscribe(ds->mosquitto_, NULL, ds->topic_.c_str(), 0);
            } else {
                ds->set_int_source_running(false);
                ds->set_int_source_error(true);
                ds->set_int_source_error_reason(std::string(mosquitto_strerror(rc)));

                _MSG_ERROR("MQTT source {} ({}) failed to connect to server at {}:{}: {}",
                        ds->get_source_name(), ds->get_source_uuid(), ds->host_, ds->port_,
                        mosquitto_strerror(rc));

                if (ds->open_cb_ != nullptr) {
                    lock.unlock();
                    ds->open_cb_(ds->open_trans_id_, false, std::string(std::string(mosquitto_strerror(rc))));
                    lock.lock();

                    ds->open_cb_ = nullptr;
                    ds->handle_source_error();
                }
            }

        });

    mosquitto_disconnect_callback_set(mosquitto_, [](struct mosquitto *m, void *obj, int rc) -> void {
            auto ds = static_cast<kis_datasource_mqtt *>(obj);

            kis_unique_lock<kis_mutex> lock(ds->ext_mutex, std::defer_lock, "datasource_mqtt mqtt_disconn_cb");
            lock.lock();

            ds->set_int_source_running(0);
            ds->set_int_source_error_reason(std::string(mosquitto_strerror(rc)));

            _MSG_ERROR("MQTT source {} ({}) lost connection to server at {}:{}: {}",
                    ds->get_source_name(), ds->get_source_uuid(), ds->host_, ds->port_,
                    mosquitto_strerror(rc));

            ds->handle_source_error();
        });

    mosquitto_message_callback_set(mosquitto_, [](struct mosquitto *m, void *obj, const struct mosquitto_message *msg) {
            auto ds = static_cast<kis_datasource_mqtt *>(obj);

            //_MSG_DEBUG("MQTT {} {}", msg->topic, std::string((const char *) msg->payload, msg->payloadlen));
           
            /*
            bool match = false;
            mosquitto_topic_matches_sub(ds->topic_.c_str(), msg->topic, &match);

            if (!match) {
                return;
            }
            */

            auto packet = ds->packetchain->generate_packet();

            auto datasrcinfo = ds->packetchain->new_packet_component<packetchain_comp_datasource>();
            datasrcinfo->ref_source = ds;

            packet->insert(ds->pack_comp_datasrc, datasrcinfo);

            ds->inc_source_num_packets(1);
            ds->get_source_packet_rrd()->add_sample(1, Globalreg::globalreg->last_tv_sec);

            // Insert GPS data as soon as possible in the chain if there's no data
            // from the rest of the processing
            if (packet->fetch(ds->pack_comp_gps) == nullptr &&
                    packet->fetch(ds->pack_comp_no_gps) == nullptr) {
                // If we haven't acquired the gpstracker, do so
                if (ds->gpstracker == nullptr)
                    ds->gpstracker = Globalreg::fetch_mandatory_global_as<gps_tracker>();

                auto gpsloc = ds->gpstracker->get_best_location();

                if (gpsloc != nullptr) {
                    packet->insert(ds->pack_comp_gps, std::move(gpsloc));
                }

            }

            gettimeofday(&(packet->ts), NULL);

            if (ds->freq_khz_ != 0 || ds->channel_.length() != 0) {
                auto l1 = ds->packetchain->new_packet_component<kis_layer1_packinfo>();

                l1->freq_khz = ds->freq_khz_;
                l1->channel = ds->channel_;

                packet->insert(ds->pack_comp_l1_agg, l1);
            }

            auto jsoninfo = ds->packetchain->new_packet_component<kis_json_packinfo>();
            jsoninfo->type = ds->json_type_;
            jsoninfo->json_string = std::string((const char *) msg->payload, msg->payloadlen);

            packet->insert(ds->pack_comp_json, jsoninfo);

            // Inject the packet into the packetchain if we have one
            ds->packetchain->process_packet(packet);

        });

    if (get_definition_opt_bool("debug", false)) {
        mosquitto_log_callback_set(mosquitto_, 
                [](struct mosquitto *mosq, void *obj, int level, const char *str) {
                    _MSG_DEBUG("MQTT - {}", str);
                });
    }

    if (tls_) {
        auto rc = mosquitto_tls_set(mosquitto_, 
                tls_ca_file_.length() != 0 ? tls_ca_file_.c_str() : NULL,
                tls_ca_path_.length() != 0 ? tls_ca_path_.c_str() : NULL,
                tls_certfile_.length() != 0 ? tls_certfile_.c_str() : NULL,
                tls_keyfile_.length() != 0 ? tls_keyfile_.c_str() : NULL,
                [](char *buf, int size, int, void *obj) -> int {
                    // If no pw is supplied we'll fail opening as an incorrect pw which is fine
                    auto ds = static_cast<kis_datasource_mqtt *>(mosquitto_userdata((struct mosquitto *) obj));
                    kis_unique_lock<kis_mutex> lock(ds->ext_mutex, std::defer_lock, "datasource_mqtt tls");
                    lock.lock();
                    snprintf(buf, size, "%s", ds->tls_keyfile_pw_.c_str());
                    return ds->tls_keyfile_.length();
                });

        if (rc != MOSQ_ERR_SUCCESS) {
            set_int_source_running(0);
            set_int_source_error(1);
            set_int_source_error_reason("error configuring TLS");
            if (in_cb != NULL) {
                lock.unlock();
                in_cb(in_transaction, false, "error configuring TLS");
                return;
            }
        }
    }

    if (user_.length() != 0) {
        mosquitto_username_pw_set(mosquitto_, user_.c_str(), password_.c_str());
    }

    // Spawn background thread if needed for mqtt async
    if (!thread_started_) {
        auto rc = mosquitto_loop_start(mosquitto_);

        if (rc != MOSQ_ERR_SUCCESS) {
            set_int_source_running(0);
            set_int_source_error(1);
            set_int_source_error_reason("could not start mosquitto handler thread");
            if (in_cb != NULL) {
                lock.unlock();
                in_cb(in_transaction, false, "could not start mosquitto handler thread");
                return;
            }
        }

        thread_started_ = true;
    }

    if (mqtt_connected_) {
        mosquitto_reconnect_async(mosquitto_);
    } else {
        mosquitto_connect_async(mosquitto_, host_.c_str(), port_, 30);
    }

    return;
}

void kis_datasource_mqtt::close_source() {
    if (thread_started_) {
        mosquitto_loop_stop(mosquitto_, true);
        thread_started_ = false;
    }

    if (mosquitto_) {
        mosquitto_disconnect(mosquitto_);
        mosquitto_destroy(mosquitto_);
        mosquitto_ = nullptr;
    }
}

#else /* no libmosquitto */

kis_datasource_mqtt::kis_datasource_mqtt(shared_datasource_builder in_builder) :
    kis_datasource(in_builder) {

    set_int_source_hardware("mqtt");
}

kis_datasource_mqtt::~kis_datasource_mqtt() {

}

void kis_datasource_mqtt::open_interface(std::string in_definition, unsigned int in_transaction,
        open_callback_t in_cb) {
    set_int_source_definition(in_definition);

    if (in_cb != nullptr) {
        in_cb(in_transaction, false, "libmosquito MQTT support not compiled into Kismet");
    }

    return;
}

#endif

