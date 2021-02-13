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

#ifndef __DATASOURCE_VIRTUAL_H__
#define __DATASOURCE_VIRTUAL_H__

#include "config.h"

#include "globalregistry.h"
#include "kis_datasource.h"

class kis_datasource_virtual;
typedef std::shared_ptr<kis_datasource_virtual> shared_datasource_virtual;

// Virtual datasource with no capture binary; this is used to implement virtual functionality,
// like scanning reports from devices which aren't, themselves, data sources.  We make virtual
// datasources to provide something for seenby to look at
class kis_datasource_virtual : public kis_datasource {
public:
    kis_datasource_virtual(shared_datasource_builder in_builder) :
        kis_datasource(in_builder) {

        // We don't have a capture binary
        
        set_int_source_cap_interface("virtual");
        set_int_source_hardware("virtual");
    }

    virtual ~kis_datasource_virtual() { };

    // Shim the internal set commands for virtuals
    void set_virtual_hardware(const std::string& in_hw) {
        set_int_source_hardware(in_hw);
    }

    void open_virtual_interface() {
        set_int_source_running(true);
    }

    void close_virtual_interface() {
        set_int_source_running(false);
    }
    
};


class datasource_virtual_builder : public kis_datasource_builder, public lifetime_global {
public:
    static std::string global_name() { return "VIRTUALDATASOURCEBUILDER"; }

    static std::shared_ptr<datasource_virtual_builder> create_virtualbuilder() {
        std::shared_ptr<datasource_virtual_builder> builder(new datasource_virtual_builder());
        Globalreg::globalreg->register_lifetime_global(builder);
        Globalreg::globalreg->insert_global(global_name(), builder);
        return builder;
    }

protected:
    datasource_virtual_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_virtual_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_virtual_builder() :
        kis_datasource_builder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

public:
    virtual ~datasource_virtual_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return shared_datasource_virtual(new kis_datasource_virtual(in_sh_this));
    }

    virtual void initialize() override {
        set_source_type("virtual");
        set_source_description("Virtual datasource used by various non-packet data types.");

        set_probe_capable(false);
        set_list_capable(false);
        set_local_capable(false);
        set_remote_capable(false);
        set_passive_capable(true);
        set_tune_capable(true);
    }
};

#endif

