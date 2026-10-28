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

#ifndef __DATASOURCE_RTLAIS_H__
#define __DATASOURCE_RTLAIS_H__

#include "config.h"

#include "kis_datasource.h"
#include "datasource_virtual.h"

class kis_datasource_rtlais;
typedef std::shared_ptr<kis_datasource_rtlais> shared_datasource_rtlais;

class kis_datasource_rtlais : public kis_datasource {
public:
    kis_datasource_rtlais(shared_datasource_builder in_builder);
    virtual ~kis_datasource_rtlais();

    // Both AIS channels are taken in at once, 288 ksps around 162MHz
    virtual bool channel_span(const std::string& in_channel, double& low_khz,
            double& high_khz) override {
        constexpr double center_khz = 162000;
        constexpr double half_khz = 288.0 / 2;
        if (channel_frequency_khz(in_channel) <= 0)
            return false;
        low_khz = center_khz - half_khz;
        high_khz = center_khz + half_khz;
        return true;
    }

protected:
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb) override;

};

class datasource_rtlais_builder : public kis_datasource_builder {
public:
    datasource_rtlais_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_rtlais_builder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_rtlais_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~datasource_rtlais_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return std::make_shared<kis_datasource_rtlais>(in_sh_this);
    }

    virtual void initialize() override {
        set_source_type("rtlais");
        set_source_description("rtl-sdr AIS USB SDR");

        set_probe_capable(true);
        set_list_capable(true);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(false);
        set_hop_capable(false);
    }
};

#endif


