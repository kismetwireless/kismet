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

#ifndef __DATASOURCE_RLTADSB_H__
#define __DATASOURCE_RLTADSB_H__

#include "config.h"

#include "kis_datasource.h"

class KisDatasourceRtladsb;
typedef std::shared_ptr<KisDatasourceRtladsb> SharedDatasourceRtladsb;

class KisDatasourceRtladsb : public KisDatasource {
public:
    KisDatasourceRtladsb(SharedDatasourceBuilder in_builder, bool in_mqtt);
    virtual ~KisDatasourceRtladsb();

protected:
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb) override;

};

class DatasourceRtladsbBuilder : public KisDatasourceBuilder {
public:
    DatasourceRtladsbBuilder() :
        KisDatasourceBuilder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceRtladsbBuilder(int in_id) :
        KisDatasourceBuilder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceRtladsbBuilder(int in_id, std::shared_ptr<TrackerElementMap> e) :
        KisDatasourceBuilder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~DatasourceRtladsbBuilder() { }

    virtual SharedDatasource build_datasource(SharedDatasourceBuilder in_sh_this) override {
        return SharedDatasourceRtladsb(new KisDatasourceRtladsb(in_sh_this, false));
    }

    virtual void initialize() override {
        set_source_type("rtladsb");
        set_source_description("rtl_adsb USB SDR");

        set_probe_capable(true);
        set_list_capable(true);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(true);
    }
};

class DatasourceRtladsbMqttBuilder : public KisDatasourceBuilder {
public:
    DatasourceRtladsbMqttBuilder() :
        KisDatasourceBuilder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceRtladsbMqttBuilder(int in_id) :
        KisDatasourceBuilder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceRtladsbMqttBuilder(int in_id, std::shared_ptr<TrackerElementMap> e) :
        KisDatasourceBuilder(in_id, e) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~DatasourceRtladsbMqttBuilder() { }

    virtual SharedDatasource build_datasource(SharedDatasourceBuilder in_sh_this) override {
        return SharedDatasourceRtladsb(new KisDatasourceRtladsb(in_sh_this, true));
    }

    virtual void initialize() override {
        set_source_type("rtladsbmqtt");
        set_source_description("rtl_adsb MQTT feed");

        set_probe_capable(true);
        set_list_capable(false);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(false);
    }
};

#endif


