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

#ifndef __DATASOURCE_CELL_QMI_H__
#define __DATASOURCE_CELL_QMI_H__

#include "config.h"

#include "kis_datasource.h"

/* A cellular modem's cells over QMI (capture_cell_qmi).  The helper sends
 * CellModem records, which the cellular phy reads as it does the AT and
 * DIAG sources'; nothing here needs to look inside them. */
class kis_datasource_cell_qmi : public kis_datasource {
public:
    kis_datasource_cell_qmi(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {
        std::string devpath = munge_to_printable(get_definition_opt("device"));
        if (devpath != "")
            set_int_source_cap_interface("cellqmi#" + devpath);
        else
            set_int_source_cap_interface("cellqmi");

        set_int_source_hardware("cellqmi");
        set_int_source_ipc_binary("kismet_cap_cell_qmi");
    }

    virtual ~kis_datasource_cell_qmi() { }
};

class datasource_cell_qmi_builder : public kis_datasource_builder {
public:
    datasource_cell_qmi_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(nullptr);
        initialize();
    }

    datasource_cell_qmi_builder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(nullptr);
        initialize();
    }

    datasource_cell_qmi_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~datasource_cell_qmi_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return std::make_shared<kis_datasource_cell_qmi>(in_sh_this);
    }

    virtual void initialize() override {
        set_source_type("cellqmi");
        set_source_description("Cellular modem cell survey over QMI");

        /* Probing and listing read node names and sysfs only; a node is
         * opened when the source is */
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
