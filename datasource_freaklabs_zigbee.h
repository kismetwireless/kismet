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

#ifndef __DATASOURCE_FREAKLABS_ZIGBEE_H__
#define __DATASOURCE_FREAKLABS_ZIGBEE_H__

#include "config.h"

#include "kis_datasource.h"

class KisDatasourceFreaklabsZigbee;
typedef std::shared_ptr<KisDatasourceFreaklabsZigbee> SharedDatasourceFreaklabsZigbee;

class KisDatasourceFreaklabsZigbee : public KisDatasource {
public:
    KisDatasourceFreaklabsZigbee(GlobalRegistry *in_globalreg, SharedDatasourceBuilder in_builder) :
        KisDatasource(in_globalreg, in_builder) { };
    virtual ~KisDatasourceFreaklabsZigbee() { };
};

class DatasourceFreaklabsZigbeeBuilder : public KisDatasourceBuilder {
public:
    DatasourceFreaklabsZigbeeBuilder(GlobalRegistry *in_globalreg, int in_id) :
        KisDatasourceBuilder(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceFreaklabsZigbeeBuilder(GlobalRegistry *in_globalreg, int in_id,
        SharedTrackerElement e) :
        KisDatasourceBuilder(in_globalreg, in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    DatasourceFreaklabsZigbeeBuilder(GlobalRegistry *in_globalreg) :
        KisDatasourceBuilder(in_globalreg, 0) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~DatasourceFreaklabsZigbeeBuilder() { }

    virtual SharedDatasource build_datasource(SharedDatasourceBuilder in_sh_this) {
        return SharedDatasourceFreaklabsZigbee(new KisDatasourceFreaklabsZigbee(globalreg, in_sh_this));
    }

    virtual void initialize() {
        set_source_type("freaklabszigbee");
        set_source_description("Freaklabs Zigbee adapter");

        set_probe_capable(true);
        set_list_capable(false);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(true);
    }
};

#endif

