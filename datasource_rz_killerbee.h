
#ifndef __DATASOURCE_RZ_KILLERBEE_H__
#define __DATASOURCE_RZ_KILLERBEE_H__

#include "config.h"

#define HAVE_RZ_KILLERBEE_DATASOURCE

#include "kis_datasource.h"
#include "dlttracker.h"

class kis_datasource_RZ_KILLERBEE;
typedef std::shared_ptr<kis_datasource_RZ_KILLERBEE> shared_datasource_RZ_KILLERBEE;

class kis_datasource_RZ_KILLERBEE : public kis_datasource {
public:
    kis_datasource_RZ_KILLERBEE(shared_datasource_builder in_builder,
            std::shared_ptr<kis_recursive_timed_mutex> mutex) :
        kis_datasource(in_builder, mutex) {

        // Set the capture binary
        set_int_source_ipc_binary("kismet_cap_rz_killerbee");

        // Get and register a DLT
        auto dltt = 
            Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");

        set_int_source_override_linktype(dltt->register_linktype("RZ_KILLERBEE"));
    }

    virtual ~kis_datasource_RZ_KILLERBEE() { };
};


class datasource_RZ_KILLERBEE_builder : public kis_datasource_builder {
public:
    datasource_RZ_KILLERBEE_builder(int in_id) :
        kis_datasource_builder(in_id) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_RZ_KILLERBEE_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    datasource_RZ_KILLERBEE_builder() :
        kis_datasource_builder() {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~datasource_RZ_KILLERBEE_builder() { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this,
            std::shared_ptr<kis_recursive_timed_mutex> mutex) override {
        return shared_datasource_RZ_KILLERBEE(new kis_datasource_RZ_KILLERBEE(in_sh_this, mutex));
    }

    virtual void initialize() override {
        // Set up our basic parameters for the linux wifi driver
        
        set_source_type("rz_killerbee");
        set_source_description("RZ Usb stick with Killerbee firmware");

        set_probe_capable(true);
        set_list_capable(true);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(true);
    }
};

#endif

