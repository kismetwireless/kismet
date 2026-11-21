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

#include "config.h"

#include "datasource_wired.h"
#include "datasource_wired_status.h"

kis_datasource_wired::kis_datasource_wired(shared_datasource_builder in_builder) :
    kis_datasource(in_builder) {
    set_int_source_ipc_binary("kismet_cap_wired");

    // Base construction is complete, so insert() targets this source's own map
    auto et = Globalreg::globalreg->entrytracker;

    kernel_received = std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.wired.kernel_received",
                tracker_element_factory<tracker_element_uint64>(),
                "frames the kernel received for the capture since the source opened"));
    insert(kernel_received);
    kernel_drops = std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.wired.kernel_drops",
                tracker_element_factory<tracker_element_uint64>(),
                "frames the kernel dropped because the capture fell behind"));
    insert(kernel_drops);
    if_drops = std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.wired.if_drops",
                tracker_element_factory<tracker_element_uint64>(),
                "frames the interface or its driver dropped"));
    insert(if_drops);
    frames = std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.wired.frames",
                tracker_element_factory<tracker_element_uint64>(),
                "frames the helper captured, before sampling"));
    insert(frames);
    forwarded = std::make_shared<tracker_element_uint64>(
            et->register_field("kismet.datasource.wired.forwarded",
                tracker_element_factory<tracker_element_uint64>(),
                "frames the helper sent to the server"));
    insert(forwarded);
    sample = std::make_shared<tracker_element_uint32>(
            et->register_field("kismet.datasource.wired.sample",
                tracker_element_factory<tracker_element_uint32>(),
                "1 in this many frames is sent to the server"));
    insert(sample);
    snaplen = std::make_shared<tracker_element_uint32>(
            et->register_field("kismet.datasource.wired.snaplen",
                tracker_element_factory<tracker_element_uint32>(),
                "most bytes of each frame captured"));
    insert(snaplen);
    buffer_mb = std::make_shared<tracker_element_uint32>(
            et->register_field("kismet.datasource.wired.buffer_mb",
                tracker_element_factory<tracker_element_uint32>(),
                "kernel capture buffer, MB"));
    insert(buffer_mb);
    promisc = std::make_shared<tracker_element_uint8>(
            et->register_field("kismet.datasource.wired.promisc",
                tracker_element_factory<tracker_element_uint8>(),
                "interface in promiscuous mode"));
    insert(promisc);
    remote_excluded = std::make_shared<tracker_element_uint8>(
            et->register_field("kismet.datasource.wired.remote_excluded",
                tracker_element_factory<tracker_element_uint8>(),
                "a remote helper's own connection to the server is left out of the capture, "
                "and runs over the captured interface"));
    insert(remote_excluded);
    carrier = std::make_shared<tracker_element_string>(
            et->register_field("kismet.datasource.wired.carrier",
                tracker_element_factory<tracker_element_string>(),
                "link state: up, down, or empty when the helper can't tell"));
    insert(carrier);
    offloads = std::make_shared<tracker_element_string>(
            et->register_field("kismet.datasource.wired.offloads",
                tracker_element_factory<tracker_element_string>(),
                "NIC offloads which are on and change what the capture sees, comma separated; "
                "only rx-vlan-filter outside promiscuous mode raises the source warning"));
    insert(offloads);
}

void kis_datasource_wired::apply_status(std::string_view json) {
    wired_status::report r;

    if (!wired_status::parse(json, r))
        return;

    // The tracked fields are read under data_mutex (serialization), so they're
    // written under it like the base setters; called with ext_mutex held, and
    // ext_mutex -> data_mutex is the base class order
    kis_lock_guard<kis_mutex> lk(data_mutex, "kis_datasource_wired apply_status");

    apply_status_locked(r);

    auto w = wired_status::warning(offloads->get(), r.carrier, promisc->get() != 0);

    // A warning set elsewhere (the helper's own warning report) is left alone
    if (wired_status::take_warning(source_warning->get(), status_warning, w))
        source_warning->set(w);
}

void kis_datasource_wired::close_external_impl() {
    kis_datasource::close_external_impl();

    // Callers may hold ext_mutex (handle_error), and ext_mutex -> data_mutex is the
    // base class order
    kis_lock_guard<kis_mutex> lk(data_mutex, "kis_datasource_wired close_external_impl");

    if (wired_status::release_warning(source_warning->get(), status_warning))
        source_warning->set("");
}

void kis_datasource_wired::apply_status_locked(const wired_status::report& r) {
    if (r.kernel_received)
        kernel_received->set(*r.kernel_received);
    if (r.kernel_drops)
        kernel_drops->set(*r.kernel_drops);
    if (r.if_drops)
        if_drops->set(*r.if_drops);
    if (r.frames)
        frames->set(*r.frames);
    if (r.forwarded)
        forwarded->set(*r.forwarded);
    if (r.sample)
        sample->set(*r.sample);
    if (r.snaplen)
        snaplen->set(*r.snaplen);
    if (r.buffer_mb)
        buffer_mb->set(*r.buffer_mb);
    if (r.promisc)
        promisc->set(*r.promisc ? 1 : 0);
    if (r.remote_excluded)
        remote_excluded->set(*r.remote_excluded ? 1 : 0);

    // A record without the key means the helper can't tell, not that nothing changed.
    // Strings are only rewritten when they change, so a steady report doesn't
    // reallocate them every few seconds
    const std::string_view c = r.carrier ? (*r.carrier ? "up" : "down") : "";

    if (carrier->get() != c)
        carrier->set(std::string(c));

    if (r.offloads && offloads->get() != *r.offloads)
        offloads->set(*r.offloads);
}

void kis_datasource_wired::handle_rx_jsonlayer_v3(std::shared_ptr<kis_packet> packet,
        mpack_node_t& root, mpack_tree_t *tree) {
    if (mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_JSONBLOCK)) {
        auto jsonmap = mpack_node_map_uint(root, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_JSONBLOCK);

        if (mpack_tree_error(tree) == mpack_ok) {
            auto type_n = mpack_node_map_uint_optional(jsonmap,
                    KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_TYPE);

            if (!mpack_node_is_missing(type_n) && mpack_node_type(type_n) == mpack_type_str &&
                    std::string_view(mpack_node_str(type_n), mpack_node_data_len(type_n)) ==
                    wired_status::json_type) {
                auto json_n = mpack_node_map_uint_optional(jsonmap,
                        KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_JSON);

                if (!mpack_node_is_missing(json_n) && mpack_node_type(json_n) == mpack_type_str)
                    apply_status(std::string_view(mpack_node_str(json_n),
                                mpack_node_data_len(json_n)));

                // A status record, never a packet
                return;
            }
        }
    }

    kis_datasource::handle_rx_jsonlayer_v3(packet, root, tree);
}
