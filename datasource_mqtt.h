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

#ifndef __DATASOURCE_MQTT_H__
#define __DATASOURCE_MQTT_H__

#include "config.h"

#include "kis_datasource.h"


#ifdef HAVE_LIBMOSQUITTO

#include <mosquitto.h>

class kis_datasource_mqtt : public kis_datasource {
public:
    kis_datasource_mqtt(shared_datasource_builder in_builder);
    virtual ~kis_datasource_mqtt();

protected:
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb) override;
    virtual void close_source() override;

    virtual void handle_source_error() override;

    virtual void probe_interface(std::string in_definition, unsigned int in_transaction, probe_callback_t in_cb) override;

    struct mosquitto *mosquitto_;
    bool thread_started_;
    bool mqtt_connected_;

    std::string json_type_;
    
    std::string host_;
    unsigned int port_;

    std::string identity_;
    std::string user_;
    std::string password_;

    bool tls_;
    std::string tls_psk_;
    std::string tls_ca_path_;
    std::string tls_ca_file_;
    std::string tls_certfile_;
    std::string tls_keyfile_;
    std::string tls_keyfile_pw_;

    std::string topic_;

    uint64_t freq_khz_;
    std::string channel_;

    open_callback_t open_cb_;
    unsigned int open_trans_id_;
};

#else /* ! HAVE_LIBMOSQUITTO */

// Stub implementation to show warnings, no implementation behind it
class kis_datasource_mqtt : public kis_datasource {
public:
    kis_datasource_mqtt(shared_datasource_builder in_builder);
    virtual ~kis_datasource_mqtt();

protected:
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb) override;
};

#endif

class datasource_mqtt_builder : public kis_datasource_builder {
public:
    datasource_mqtt_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_mqtt_builder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_mqtt_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~datasource_mqtt_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return std::make_shared<kis_datasource_mqtt>(in_sh_this);
    }

    virtual void initialize() override {
        set_source_type("mqtt");
        set_source_description("MQTT listener");

        set_probe_capable(true);
        set_list_capable(false);

        // We have no local or remote capture, we connect to mqtt directly
        set_local_capable(false);
        set_remote_capable(false);

        // Passive only
        set_passive_capable(true);

        // Incapable of tuning, we accept whatever mqtt gives us
        set_tune_capable(false);
        set_hop_capable(false);
    }

};

#endif /* __DATASOURCE_MQTT_H__ */
