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

#ifndef __DATASOURCE_WIRED_H__
#define __DATASOURCE_WIRED_H__

#include "config.h"

#include "kis_datasource.h"

namespace wired_status {
struct report;
}

// Ethernet capture through kismet_cap_wired.  Frames arrive as DLT_EN10MB through
// the normal packet path; the helper's status record (kernel drops, offloads, link)
// is kept on the source instead of becoming a packet.
class kis_datasource_wired : public kis_datasource {
public:
    kis_datasource_wired(shared_datasource_builder in_builder);
    virtual ~kis_datasource_wired() { };

protected:
    virtual void handle_rx_jsonlayer_v3(std::shared_ptr<kis_packet> packet,
            mpack_node_t& root, mpack_tree_t *tree) override;
    void apply_status(std::string_view json);
    // data_mutex held
    void apply_status_locked(const wired_status::report& r);

    // Every close and error ends here; drops the status's warning with the interface
    virtual void close_external_impl() override;

    std::shared_ptr<tracker_element_uint64> kernel_received;
    std::shared_ptr<tracker_element_uint64> kernel_drops;
    std::shared_ptr<tracker_element_uint64> if_drops;
    std::shared_ptr<tracker_element_uint64> frames;
    std::shared_ptr<tracker_element_uint64> forwarded;
    std::shared_ptr<tracker_element_uint32> sample;
    std::shared_ptr<tracker_element_uint32> snaplen;
    std::shared_ptr<tracker_element_uint32> buffer_mb;
    std::shared_ptr<tracker_element_uint8> promisc;
    std::shared_ptr<tracker_element_uint8> remote_excluded;
    std::shared_ptr<tracker_element_string> carrier;
    std::shared_ptr<tracker_element_string> offloads;

    // The source warning the status record last set, so only that one is replaced or
    // cleared; under data_mutex, with the warning itself
    std::string status_warning;
};

class datasource_wired_builder : public kis_datasource_builder {
public:
    datasource_wired_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_wired_builder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    datasource_wired_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~datasource_wired_builder() override { }

    virtual shared_datasource build_datasource(shared_datasource_builder in_sh_this) override {
        return std::make_shared<kis_datasource_wired>(in_sh_this);
    }

    virtual void initialize() override {
        set_source_type("wired");
        set_source_description("Capture from Linux Ethernet interfaces");

#ifdef SYS_LINUX
        set_probe_capable(true);
        set_list_capable(true);
        set_local_capable(true);
#else
        set_probe_capable(false);
        set_list_capable(false);
        set_local_capable(false);
#endif

        // A Linux sensor can feed any server
        set_remote_capable(true);
        set_passive_capable(false);
        set_tune_capable(false);
        set_hop_capable(false);
    }
};

#endif
