
#ifndef __DATASOURCE_NRF_51822__H__
#define __DATASOURCE_NRF_51822__H__

#include "config.h"

#define HAVE_NRF_51822_DATASOURCE

#include "kis_datasource.h"
#include "dlttracker.h"

class kis_datasource_NRF_51822;
typedef std::shared_ptr<kis_datasource_NRF_51822> shared_datasource_NRF_51822;

class kis_datasource_NRF_51822 : public kis_datasource {
public:
    kis_datasource_NRF_51822(shared_datasource_builder in_builder,
            std::shared_ptr<kis_recursive_timed_mutex> mutex) :
        kis_datasource(in_builder, mutex) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_nrf_51822");

        // Get and register a DLT
        auto dltt = 
            Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");

        set_int_source_override_linktype(dltt->register_linktype("NRF_51822"));
    }

    virtual ~kis_datasource_NRF_51822() { };
};


class datasource_NRF_51822_builder : public kis_datasource_builder {
public:
    datasource_NRF_51822_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_NRF_51822_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_NRF_51822_builder() :
        kis_datasource_builder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~datasource_NRF_51822_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this,
            std::shared_ptr<kis_recursive_timed_mutex> mutex) override {
        return shared_datasource_NRF_51822(new kis_datasource_NRF_51822(in_sh_this, mutex));
    }

    virtual void initialize() override {
        // Set up our basic parameters for the linux wifi driver
        
        set_source_type("nrf51822");
        set_source_description("nrf 51822 with sniffer firmware");

        set_probe_capable(false);
        set_list_capable(false);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(false);
    }
};

#endif

