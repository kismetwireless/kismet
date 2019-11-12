
#ifndef __DATASOURCE_TI_CC2540_H__
#define __DATASOURCE_TI_CC2540_H__

#include "config.h"

#define HAVE_TI_CC2540_DATASOURCE

#include "kis_datasource.h"
#include "dlttracker.h"

class kis_datasource_TICC2540;
typedef std::shared_ptr<kis_datasource_TICC2540> shared_datasource_TICC2540;

class kis_datasource_TICC2540 : public kis_datasource {
public:
    kis_datasource_TICC2540(shared_datasource_builder in_builder,
            std::shared_ptr<kis_recursive_timed_mutex> mutex) :
        kis_datasource(in_builder, mutex) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_ti_cc2540");

        // Get and register a DLT
        auto dltt = 
            Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");

        set_int_source_override_linktype(dltt->register_linktype("TICC2540"));
    }

    virtual ~kis_datasource_TICC2540() { };
};


class datasource_TICC2540_builder : public kis_datasource_builder {
public:
    datasource_TICC2540_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_TICC2540_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_TICC2540_builder() :
        kis_datasource_builder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~datasource_TICC2540_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this,
            std::shared_ptr<kis_recursive_timed_mutex> mutex) override {
        return shared_datasource_TICC2540(new kis_datasource_TICC2540(in_sh_this, mutex));
    }

    virtual void initialize() override {
        // Set up our basic parameters for the linux wifi driver
        
        set_source_type("ticc2540");
        set_source_description("TI CC2540 with sniffer firmware");

        set_probe_capable(true);
        set_list_capable(true);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(true);
    }
};

#endif

