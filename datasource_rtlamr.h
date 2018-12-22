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

class KisDatasourceRtlamr;
typedef std::shared_ptr<KisDatasourceRtlamr> SharedDatasourceRtlamr;

class KisDatasourceRtlamr : public KisDatasource {
public:
    KisDatasourceRtlamr(SharedDatasourceBuilder in_builder, bool in_mqtt);
    virtual ~KisDatasourceRtlamr();

protected:
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb) override;

};

class DatasourceRtlamrBuilder : public KisDatasourceBuilder {
public:
    DatasourceRtlamrBuilder() :
        KisDatasourceBuilder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceRtlamrBuilder(int in_id) :
        KisDatasourceBuilder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceRtlamrBuilder(int in_id, std::shared_ptr<TrackerElementMap> e) :
        KisDatasourceBuilder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~DatasourceRtlamrBuilder() { }

    virtual SharedDatasource build_datasource(SharedDatasourceBuilder in_sh_this) override {
        return SharedDatasourceRtlamr(new KisDatasourceRtlamr(in_sh_this, false));
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

class DatasourceRtlamrMqttBuilder : public KisDatasourceBuilder {
public:
    DatasourceRtlamrMqttBuilder() :
        KisDatasourceBuilder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceRtlamrMqttBuilder(int in_id) :
        KisDatasourceBuilder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceRtlamrMqttBuilder(int in_id, std::shared_ptr<TrackerElementMap> e) :
        KisDatasourceBuilder(in_id, e) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~DatasourceRtlamrMqttBuilder() { }

    virtual SharedDatasource build_datasource(SharedDatasourceBuilder in_sh_this) override {
        return SharedDatasourceRtlamr(new KisDatasourceRtlamr(in_sh_this, true));
    }

    virtual void initialize() override {
        set_source_type("rtlamrmqtt");
        set_source_description("rtl_amr MQTT feed");

        set_probe_capable(true);
        set_list_capable(false);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(false);
    }
};

#endif


