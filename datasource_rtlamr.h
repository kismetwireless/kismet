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

#ifndef __DATASOURCE_RLTAMR_H__
#define __DATASOURCE_RLTAMR_H__

#include "config.h"

#include "kis_datasource.h"

class kis_datasource_rtlamr;
typedef std::shared_ptr<kis_datasource_rtlamr> shared_datasource_rtlamr;

class kis_datasource_rtlamr : public kis_datasource {
public:
    kis_datasource_rtlamr(shared_datasource_builder in_builder, bool in_mqtt);
    virtual ~kis_datasource_rtlamr();

protected:
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb) override;

};

class datasource_rtlamr_builder : public kis_datasource_builder {
public:
    datasource_rtlamr_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_rtlamr_builder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_rtlamr_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~datasource_rtlamr_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_rtlamr(new kis_datasource_rtlamr(in_sh_this, false));
    }

    virtual void initialize() override {
        set_source_type("rtlamr");
        set_source_description("rtl_amr USB SDR");

        set_probe_capable(true);
        set_list_capable(true);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(true);
    }
};

class DatasourceRtlamrMqttBuilder : public kis_datasource_builder {
public:
    DatasourceRtlamrMqttBuilder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceRtlamrMqttBuilder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceRtlamrMqttBuilder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~DatasourceRtlamrMqttBuilder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_rtlamr(new kis_datasource_rtlamr(in_sh_this, true));
    }

    virtual void initialize() override {
        set_source_type("rtlamrmqtt");
        set_source_description("rtl_amr MQTT feed");

        set_probe_capable(true);
        set_list_capable(false);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(true);
        set_hop_capable(false);
    }
};

#endif


