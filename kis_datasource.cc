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

#include "kis_datasource.h"
#include "endian_magic.h"
#include "configfile.h"
#include "datasourcetracker.h"
#include "entrytracker.h"
#include "alertracker.h"
#include "packetchain.h"
#include "timetracker.h"
#include <future>

// We never instantiate from a generic tracker component or from a stored
// record so we always re-allocate ourselves
kis_datasource::kis_datasource(shared_datasource_builder in_builder) :
    tracker_component(0),
    kis_external_interface() {

    next_transaction = 1;

    if (in_builder != nullptr)
        ext_mutex.set_name(fmt::format("kis_datasource({})", in_builder->get_source_type()));
    else
        ext_mutex.set_name(fmt::format("kis_datasource(base)"));

    data_mutex.set_name("kds_data");

    register_fields();
    reserve_fields(nullptr);

    if (in_builder != nullptr) {
        set_source_builder(in_builder);
        insert(in_builder);
    }

    timetracker =
        Globalreg::fetch_mandatory_global_as<time_tracker>("TIMETRACKER");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>("PACKETCHAIN");

    pack_comp_report = packetchain->register_packet_component("PACKETREPORT");
	pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_l1info = packetchain->register_packet_component("RADIODATA");
    pack_comp_l1_agg = packetchain->register_packet_component("RADIODATA_AGG");
    pack_comp_gps = packetchain->register_packet_component("GPS");
    pack_comp_no_gps = packetchain->register_packet_component("NOGPS");
	pack_comp_datasrc = packetchain->register_packet_component("KISDATASRC");
    pack_comp_json = packetchain->register_packet_component("JSON");
    pack_comp_protobuf = packetchain->register_packet_component("PROTOBUF");

    suppress_gps = false;

    error_timer_id = -1;
    ping_timer_id = -1;

    mode_probing = false;
    mode_listing = false;

    listed_interface_entry_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.datasourcetracker.listed_interface",
                tracker_element_factory<kis_datasource_interface>(),
                "automatically discovered available interface");

    last_pong = (time_t) Globalreg::globalreg->last_tv_sec;

    quiet_errors = 0;

    set_int_source_running(false);

    get_source_packet_rrd()->add_sample(0, Globalreg::globalreg->last_tv_sec);
    get_source_packet_size_rrd()->add_sample(0, Globalreg::globalreg->last_tv_sec);
}

kis_datasource::~kis_datasource() {
    // Cancel any timer
    timetracker->remove_timer(error_timer_id);
    timetracker->remove_timer(ping_timer_id);

    kis_unique_lock<kis_mutex> lk(ext_mutex, "~kisdatasource");
    cancel_all_commands("source deleted");
    command_ack_map.clear();
}

std::vector<std::string> kis_datasource::get_source_channels_vec_copy() {
    std::vector<std::string> ret;

    kis_unique_lock<kis_mutex> lock(ext_mutex, "datasource get channel vec copy");

    for (const auto& i : *source_channels_vec) {
        ret.push_back(i);
    }

    return ret;
}

void kis_datasource::list_interfaces(unsigned int in_transaction, list_callback_t in_cb) {
    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock, "datasource list_interfaces");
    lock.lock();

    set_source_name("list");
    set_int_source_interface("n/a");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    mode_listing = true;

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    // If we can't list interfaces according to our prototype, die
    // and call the cb instantly
    if (!get_source_builder()->get_list_capable()) {
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(std::static_pointer_cast<kis_datasource>(shared_from_this()), in_transaction,
                    std::vector<shared_interface>());
        }

        return;
    }

    // If we don't have our local binary, die and call cb instantly
    if (!kis_external_interface::check_ipc(get_source_ipc_binary())) {
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(std::static_pointer_cast<kis_datasource>(shared_from_this()), in_transaction,
                    std::vector<shared_interface>());
        }
        return;
    }

    // Quiet errors during launch since it's not a well-formed interface yet
    quiet_errors = 1;

    // Launch the IPC
    if (!launch_ipc()) {
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(std::static_pointer_cast<kis_datasource>(shared_from_this()),
                    in_transaction, std::vector<shared_interface>());
        }

        return;
    }

    send_list_interfaces(in_transaction, in_cb);
}

void kis_datasource::probe_interface(std::string in_definition, unsigned int in_transaction,
        probe_callback_t in_cb) {
    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock, "datasource probe_interface");
    lock.lock();

    set_source_name("probe");
    set_int_source_interface("n/a");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    mode_probing = true;

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    set_int_source_definition(in_definition);

    // If we can't probe interfaces according to our prototype, die
    // and call the cb instantly
    if (!get_source_builder()->get_probe_capable()) {
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "Driver not capable of probing");
            lock.lock();
        }
        return;
    }

    // If we don't have our local binary, die and call cb instantly
    if (!kis_external_interface::check_ipc(get_source_ipc_binary())) {
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "Capture tool not installed");
            lock.lock();
        }
        return;
    }

    // Populate our local info about the interface
    if (!parse_source_definition(in_definition)) {
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "Malformed source config");
            lock.lock();
        }

        return;
    }

    // Squelch errors from probe because they're not useful
    quiet_errors = true;

    lock.unlock();

    // Launch the IPC
    if (launch_ipc()) {
        // Create and send probe command
        send_probe_source(get_source_definition(), in_transaction, in_cb);
    } else {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "Failed to launch IPC to probe source");
        }
    }
}

void kis_datasource::open_interface(std::string in_definition, unsigned int in_transaction,
        open_callback_t in_cb) {
    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock, "datasource open_interface");
    lock.lock();

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    set_int_source_definition(in_definition);

    // Populate our local info about the interface
    if (!parse_source_definition(in_definition)) {
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "Malformed source config");
            lock.lock();
        }

        return;
    }

    if (has_definition_opt("metagps")) {
        auto gpstracker = Globalreg::fetch_mandatory_global_as<gps_tracker>();
        auto metaname = get_definition_opt("metagps");

        auto gps = gpstracker->find_gps_by_name(metaname);
        if (gps != nullptr) {
            set_device_gps(gps);
        } else {
            auto gpsdef = fmt::format("meta:name={}", metaname);
            set_device_gps(gpstracker->create_gps(gpsdef));
        }
    }


    if (get_source_builder()->get_passive_capable()) {
        if (get_source_uuid().error && !local_uuid) {
            uuid nuuid;

            nuuid.generate_time_uuid((uint8_t *) "\x00\x00\x00\x00\x00\x00");

            set_source_uuid(nuuid);
            set_source_key(adler32_checksum(nuuid.uuid_to_string()));
        }

        set_int_source_retry_attempts(0);

        set_int_source_running(1);
        set_int_source_error(0);

        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, true, "Source opened");
            lock.lock();
        }

        return;
    }

    // If we can't open local interfaces, die
    if (!get_source_builder()->get_local_capable()) {
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "Driver does not support direct capture");
            lock.lock();
        }

        return;
    }

    // If we don't have our local binary, die and call cb instantly
    if (!kis_external_interface::check_ipc(get_source_ipc_binary())) {
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "Capture tool not installed");
            lock.lock();
        }
        return;
    }

    // If we have an error callback that's going to try to re-open us, cancel it
    if (error_timer_id > 0)
        timetracker->remove_timer(error_timer_id);

    // Launch the IPC, outside of lock
    lock.unlock();

    if (!launch_ipc()) {
        return;
    }

    lock.lock();

    set_int_source_running(true);

    last_pong = (time_t) Globalreg::globalreg->last_tv_sec;

    // If we got here we're valid; start a PING timer
    timetracker->remove_timer(ping_timer_id);
    ping_timer_id = timetracker->register_timer(std::chrono::seconds(5), true, [this](int) -> int {
        // kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource ping_timer lambda");

        if (!get_source_running()) {
            ping_timer_id = -1;
            return 0;
        }

        send_ping();

        return 1;
    });

    // Create and send open command
    send_open_source(get_source_definition(), in_transaction, in_cb);
}

void kis_datasource::set_channel(std::string in_channel, unsigned int in_transaction,
        configure_callback_t in_cb) {
    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock, "datasource set_channel");
    lock.lock();

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    if (!get_source_builder()->get_tune_capable()) {
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "Driver not capable of changing channel");
            lock.lock();
        }
        return;
    }

    send_configure_channel(in_channel, in_transaction, in_cb);
}

void kis_datasource::set_channel_hop(double in_rate, std::vector<std::string> in_chans,
        bool in_shuffle, unsigned int in_offt, unsigned int in_transaction,
        configure_callback_t in_cb) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource set_channel_hop");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    if (!get_source_builder()->get_tune_capable()) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "Driver not capable of changing channel");
        }
        return;
    }

    if (!get_source_builder()->get_hop_capable()) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "Driver not capable of channel hopping");
        }
        return;
    }

    // Convert the std::vector to a channel vector
    auto vec = std::make_shared<tracker_element_vector_string>(source_hop_vec_id);

    for (const auto& i : in_chans) {
        vec->push_back(i);
    }

    // Call the common function that takes a sharedtrackerelement of channels
    set_channel_hop(in_rate, vec, in_shuffle, in_offt, in_transaction, in_cb);
}

void kis_datasource::set_channel_hop(double in_rate,
        std::shared_ptr<tracker_element_vector_string> in_chans,
        bool in_shuffle, unsigned int in_offt, unsigned int in_transaction,
        configure_callback_t in_cb) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource set_channel_hop");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    if (!get_source_builder()->get_tune_capable()) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "Driver not capable of changing channel");
        }
        return;
    }

    if (!get_source_builder()->get_hop_capable()) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "Driver not capable of channel hopping");
        }
        return;
    }

    // Generate the command and send it
    send_configure_channel_hop(in_rate, in_chans, in_shuffle, in_offt,
            in_transaction, in_cb);
}

void kis_datasource::set_channel_hop_rate(double in_rate, unsigned int in_transaction,
        configure_callback_t in_cb) {
    // Don't bother checking if we can set channel since we're just calling a function
    // that already checks that
    set_channel_hop(in_rate, get_source_hop_vec(), get_source_hop_shuffle(),
            get_source_hop_offset(), in_transaction, in_cb);
}

void kis_datasource::set_channel_hop_list(std::vector<std::string> in_chans,
        unsigned int in_transaction, configure_callback_t in_cb) {
    // Again don't bother, we're just an API shim
    set_channel_hop(get_source_hop_rate(), in_chans, get_source_hop_shuffle(),
            get_source_hop_offset(), in_transaction, in_cb);
}

void kis_datasource::connect_remote(std::string in_definition, kis_datasource* in_remote,
        bool in_tcp, configure_callback_t in_cb) {
    kis_unique_lock<kis_mutex> lk(ext_mutex, "datasource connect_remote");

    cancelled = false;

    // We can't reconnect failed interfaces that are remote
    set_int_source_retry(false);

    // We're remote
    set_int_source_remote(true);

    // Kill any error handlers
    if (error_timer_id > 0)
        timetracker->remove_timer(error_timer_id);

    // Reset the state
    set_int_source_running(true);
    set_int_source_definition(in_definition);
    set_int_source_error(false);

    // Populate our local info about the interface
    if (!parse_source_definition(in_definition)) {
        set_int_source_running(false);
        set_int_source_error(true);
        set_int_source_error_reason("Unable to parse interface definition of remote source");
        _MSG("Unable to parse interface definition", MSGFLAG_ERROR);

        if (in_cb)
            in_cb(0, false, "Unable to parse definition of remote source");

        return;
    }

    if (has_definition_opt("metagps")) {
        auto gpstracker = Globalreg::fetch_mandatory_global_as<gps_tracker>();
        auto metaname = get_definition_opt("metagps");

        auto gps = gpstracker->find_gps_by_name(metaname);
        if (gps != nullptr) {
            set_device_gps(gps);
        } else {
            auto gpsdef = fmt::format("meta:name={}", metaname);
            set_device_gps(gpstracker->create_gps(gpsdef));
        }
    }

    last_pong = (time_t) Globalreg::globalreg->last_tv_sec;

    if (ping_timer_id > 0)
        timetracker->remove_timer(ping_timer_id);

    ping_timer_id = timetracker->register_timer(std::chrono::seconds(5), true, [this](int) -> int {
        kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource ping_timer lambda");

        if (!get_source_running()) {
            ping_timer_id = -1;
            return 0;
        }

        if (Globalreg::globalreg->last_tv_sec - last_pong > 15) {
            ping_timer_id = -1;
            trigger_error("did not get a ping response from the capture");
            return 0;
        }

        send_ping();
        return 1;
    });

    // Unlock before attaching sockets
    lk.unlock();

    if (io_ != nullptr) {
        io_->stop();
    }

    // Inherit the incoming io mode
    io_ = in_remote->move_io(shared_from_this());

    // Inherit the incoming closure
    closure_cb = in_remote->move_closure_cb();

    // Send an opensource
    send_open_source(get_source_definition(), 0, in_cb);
}

void kis_datasource::disable_source() {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource disable_source");

    close_source();

    set_int_source_error(true);
    set_int_source_error_reason("Source disabled");

    set_int_source_retry(false);

    // cancel any timers
    if (error_timer_id > 0)
        timetracker->remove_timer(error_timer_id);

    error_timer_id = -1;
}

void kis_datasource::pause_source() {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource pause_source");

    if (!get_source_paused()) {
        auto evt = eventbus->get_eventbus_event(event_datasource_paused());
        evt->get_event_content()->insert(event_datasource_paused(), source_uuid);
        eventbus->publish(evt);
    }

    set_source_paused(true);
}

void kis_datasource::resume_source() {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource pause_source");

    if (get_source_paused()) {
        auto evt = eventbus->get_eventbus_event(event_datasource_resumed());
        evt->get_event_content()->insert(event_datasource_resumed(), source_uuid);
        eventbus->publish(evt);
    }

    set_source_paused(false);
}

void kis_datasource::handle_error(const std::string& in_error) {
    kis_unique_lock<kis_mutex> lk(ext_mutex, "datasource handle_error");

    if (!quiet_errors && in_error.length()) {
        _MSG_ERROR("Data source '{} / {}' ('{}') encountered an error: {}",
                get_source_name(), generate_source_definition(), get_source_interface(), in_error);
    }

    set_int_source_error(true);
    set_int_source_error_reason(in_error);

    set_int_source_running(false);

    auto evt = eventbus->get_eventbus_event(event_datasource_error());
    evt->get_event_content()->insert(event_datasource_error(), source_uuid);
    eventbus->publish(evt);

    lk.unlock();
    handle_source_error();
    cancel_all_commands(in_error);
    lk.lock();

    close_external();
}

void kis_datasource::close_source() {
	set_int_source_running(false);
    return close_external();
}

void kis_datasource::close_source_async(std::function<void (void)> in_callback) {
    if (io_ == nullptr || (io_ != nullptr && io_->strand().running_in_this_thread())) {
        close_external_impl();
        in_callback();
    } else {
        boost::asio::post(io_->strand(),
                std::packaged_task<void()>([this, in_callback]() mutable {
                    close_external_impl();
                    in_callback();
                }));
    }

}

void kis_datasource::close_external() {
    if (io_ == nullptr || (io_ != nullptr && io_->strand().running_in_this_thread())) {
        close_external_impl();
    } else {
        auto ft = boost::asio::post(io_->strand(),
                std::packaged_task<void()>([this]() mutable {
                    close_external_impl();
                }));
        // ft.wait();
    }
}

void kis_datasource::close_external_impl() {
    kis_unique_lock<kis_mutex> lk(ext_mutex, "datasource close_external");

    if (ping_timer_id > 0) {
        timetracker->remove_timer(ping_timer_id);
        ping_timer_id = -1;
    }

    set_int_source_running(false);

    lk.unlock();

    auto evt = eventbus->get_eventbus_event(event_datasource_closed());
    evt->get_event_content()->insert(event_datasource_closed(), source_uuid);
    eventbus->publish(evt);

    cancel_all_commands("source closed");

    kis_external_interface::close_external_impl();
}

void kis_datasource::set_device_gps(std::shared_ptr<kis_gps> in_gps) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource set_gps");
    device_gps = in_gps;
}

void kis_datasource::clear_device_gps() {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource clear_gps");
    device_gps.reset();
}

bool kis_datasource::has_definition_opt(const std::string& in_opt) {

    return source_definition_opts.find(str_lower(in_opt)) !=
            source_definition_opts.end();
}

std::string kis_datasource::get_definition_opt(std::string in_opt) {
    auto i = source_definition_opts.find(str_lower(in_opt));

    if (i == source_definition_opts.end())
        return override_default_option(in_opt);

    return i->second;
}

bool kis_datasource::get_definition_opt_bool(std::string in_opt, bool in_def) {
    auto i = source_definition_opts.find(str_lower(in_opt));
    std::string opt;

    if (i != source_definition_opts.end())
        opt = i->second;
    else
        opt = override_default_option(in_opt);

    return string_to_bool(opt, in_def);
}

double kis_datasource::get_definition_opt_double(std::string in_opt, double in_def) {
    auto i = source_definition_opts.find(str_lower(in_opt));
    std::string opt;

    if (i != source_definition_opts.end())
        opt = i->second;
    else
        return in_def;

    std::stringstream ss;
    ss << opt << std::endl;

    double d;
    ss >> d;

    return d;
}

bool kis_datasource::parse_source_definition(std::string in_definition) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource parse_interface");

    local_uuid = false;

    std::string interface;

    size_t cpos = in_definition.find(":");

    // Turn the rest into an opt vector
    std::vector<opt_pair> options;

    // If there's no ':' then there are no options
    if (cpos == std::string::npos) {
        set_int_source_interface(in_definition);
        set_source_name(in_definition);
    } else {
        // Slice the interface
        set_int_source_interface(in_definition.substr(0, cpos));

        // Blow up if we fail parsing
        if (string_to_opts(in_definition.substr(cpos + 1,
                        in_definition.size() - cpos - 1), ",", &options) < 0) {
            return false;
        }

        // Throw into a nice keyed dictionary so other elements of the DS can use it
        for (auto i = options.begin(); i != options.end(); ++i) {
            source_definition_opts[str_lower((*i).opt)] = (*i).val;
        }
    }

    // Append and override
    for (const auto& o : source_append_opts) {
        if (source_definition_opts.find(o.first) == source_definition_opts.end()) {
            source_definition_opts[o.first] = o.second;
        }
    }

    for (const auto& o : source_override_opts) {
        source_definition_opts[o.first] = o.second;
    }

    set_int_source_definition(generate_source_definition());

    // Set some basic options

    std::string namestr = get_definition_opt("name");

    if (namestr != "") {
        set_source_name(namestr);
    } else {
        set_source_name(get_source_interface());
    }

    std::string uuidstr = get_definition_opt("uuid");

    if (uuidstr != "") {
        uuid u(uuidstr);

        if (u.error) {
            _MSG("Invalid UUID for data source " + get_source_name() + "/" +
                    get_source_interface(), MSGFLAG_ERROR);
            return false;
        }

        set_source_uuid(u);
        local_uuid = true;
        set_source_key(adler32_checksum(u.uuid_to_string()));
    }

    auto datasourcetracker =
        Globalreg::fetch_mandatory_global_as<datasource_tracker>("DATASOURCETRACKER");

    set_int_source_retry(get_definition_opt_bool("retry",
                datasourcetracker->get_config_defaults()->get_retry_on_error()));

    clobber_timestamp = get_definition_opt_bool("timestamp",
            datasourcetracker->get_config_defaults()->get_remote_cap_timestamp());

    set_source_info_antenna_type(get_definition_opt("info_antenna_type"));
    set_source_info_antenna_gain(get_definition_opt_double("info_antenna_gain", 0.0f));
    set_source_info_antenna_orientation(get_definition_opt_double("info_antenna_orientation", 0.0f));
    set_source_info_antenna_beamwidth(get_definition_opt_double("info_antenna_beamwidth", 0.0f));
    set_source_info_amp_type(get_definition_opt("info_amp_type"));
    set_source_info_amp_gain(get_definition_opt_double("info_amp_gain", 0.0f));

    return true;
}

bool kis_datasource::append_source_definition(const std::string& in_key,
        const std::string& in_data) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource append_interface");

    source_append_opts[str_lower(in_key)] = in_data;

    return true;
}

void kis_datasource::update_source_definition(const std::string& in_key,
        const std::string& in_data) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource update_interface");
    source_override_opts[str_lower(in_key)] = in_data;
}

std::string kis_datasource::generate_source_definition() {
    std::stringstream ss;

    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource generate_interface");

    ss << get_source_interface();

    if (source_definition_opts.size()) {
        ss << ":";

        bool comma = false;

        for (const auto& o : source_definition_opts) {
            if (comma)
                ss << ",";
            comma = true;

            ss << o.first << "=" << o.second;
        }
    }

    return ss.str();
}


std::map<std::string, std::string> kis_datasource::get_config_overrides(const std::string& in_key) {
    std::map<std::string, std::string> ret;
    auto opts = Globalreg::globalreg->kismet_config->fetch_opt_vec(in_key);

    for (const auto& o : opts) {
        auto toks = str_tokenize(o, ",");

        if (toks.size() != 2)
            continue;

        ret[toks[0]] = toks[1];
    }

    return ret;
}

std::shared_ptr<kis_datasource::tracked_command> kis_datasource::get_command(uint32_t in_transaction) {
    kis_unique_lock<kis_mutex> lk(ext_mutex, "datasource get_command");
    auto i = command_ack_map.find(in_transaction);

    if (i == command_ack_map.end())
        return NULL;

    return i->second;
}

void kis_datasource::cancel_command(uint32_t in_transaction, std::string in_error) {
    kis_unique_lock<kis_mutex> lk(ext_mutex, "datasource cancel_command");

    auto i = command_ack_map.find(in_transaction);
    if (i != command_ack_map.end()) {
        std::shared_ptr<tracked_command> cmd = i->second;

        // Cancel any timers
        if (cmd->timer_id > -1) {
            timetracker->remove_timer(cmd->timer_id);
            cmd->timer_id = -1;
        }

        // fprintf(stderr, "debug - erasing from command ack via cancel %u\n", in_transaction);
        command_ack_map.erase(i);

        // Cancel any callbacks, zeroing them out as we call them so they
        // can't recurse through
        if (cmd->list_cb != NULL) {
            list_callback_t cb = cmd->list_cb;
            cmd->list_cb = NULL;
            lk.unlock();
            cb(std::static_pointer_cast<kis_datasource>(shared_from_this()),
                    cmd->transaction, std::vector<shared_interface>());
            lk.lock();
        } else if (cmd->probe_cb != NULL) {
            probe_callback_t cb = cmd->probe_cb;
            cmd->probe_cb = NULL;
            lk.unlock();
            cb(cmd->transaction, false, in_error);
            lk.lock();
        } else if (cmd->open_cb != NULL) {
            open_callback_t cb = cmd->open_cb;
            cmd->open_cb = NULL;
            lk.unlock();
            cb(cmd->transaction, false, in_error);
            lk.lock();
        } else if (cmd->configure_cb != NULL) {
            configure_callback_t cb = cmd->configure_cb;
            cmd->configure_cb = NULL;
            lk.unlock();
            cb(cmd->transaction, false, in_error);
            lk.lock();
        }
    }
}

void kis_datasource::cancel_all_commands(std::string in_error) {
    kis_unique_lock<kis_mutex> lk(ext_mutex, "datasource cancel_all_commands");

    // fprintf(stderr, "debug - cancel all commands\n");

    while (1) {
        auto i = command_ack_map.begin();

        if (i == command_ack_map.end())
            break;

        lk.unlock();
        cancel_command(i->first, in_error);
        lk.lock();
    }

    command_ack_map.clear();
}

void kis_datasource::handle_msg_proxy(const std::string& msg, const int type) {
    if (get_source_remote())
        _MSG(fmt::format("{} - {}", get_source_name(), msg), type);
    else
        _MSG(msg, type);
}

void kis_datasource::handle_rx_packet(std::shared_ptr<kis_packet> packet) {
    auto datasrcinfo = packetchain->new_packet_component<packetchain_comp_datasource>();
    datasrcinfo->ref_source = this;

    packet->insert(pack_comp_datasrc, datasrcinfo);

    inc_source_num_packets(1);
    get_source_packet_rrd()->add_sample(1, Globalreg::globalreg->last_tv_sec);

    // Insert GPS data as soon as possible in the chain if there's no data
    // from the rest of the processing
    if (packet->fetch(pack_comp_gps) == nullptr &&
            packet->fetch(pack_comp_no_gps) == nullptr) {
        auto gpsloc = gpstracker->get_best_location();

        if (gpsloc != nullptr) {
            packet->insert(pack_comp_gps, std::move(gpsloc));
        }

    }

    // Inject the packet into the packetchain if we have one
    packetchain->process_packet(packet);
}

unsigned int kis_datasource::send_configure_channel(const std::string& in_channel, unsigned int in_transaction,
        configure_callback_t in_cb) {
    if (protocol_version < 3) {
#ifdef HAVE_PROTOBUF_CPP
        return send_configure_channel_v2(in_channel, in_transaction, in_cb);
#else
        trigger_error("cannot use v2 protocol on this build");
        return 0;
#endif
    }

    if (protocol_version == 3) {
        return send_configure_channel_v3(in_channel, in_transaction, in_cb);
    }

    trigger_error(fmt::format(fmt::runtime("unknown protocol version {}"), protocol_version));
    return 0;
}

unsigned int kis_datasource::send_configure_channel_hop(double in_rate, std::shared_ptr<tracker_element_vector_string> in_chans,
        bool in_shuffle, unsigned int in_offt, unsigned int in_transaction,
        configure_callback_t in_cb) {
    if (protocol_version < 3) {
#ifdef HAVE_PROTOBUF_CPP
        return send_configure_channel_hop_v2(in_rate, in_chans, in_shuffle, in_offt, in_transaction, in_cb);
#else
        trigger_error("cannot use v2 protocol on this build");
        return 0;
#endif
    }

    if (protocol_version == 3) {
        return send_configure_channel_hop_v3(in_rate, in_chans, in_shuffle, in_offt, in_transaction, in_cb);
    }

    trigger_error(fmt::format(fmt::runtime("unknown protocol version {}"), protocol_version));
    return 0;
}

unsigned int kis_datasource::send_list_interfaces(unsigned int in_transaction, list_callback_t in_cb) {
    if (protocol_version < 3) {
#ifdef HAVE_PROTOBUF_CPP
        return send_list_interfaces_v2(in_transaction, in_cb);
#else
        trigger_error("cannot use v2 protocol on this build");
        return 0;
#endif
    }

    if (protocol_version == 3) {
        return send_list_interfaces_v3(in_transaction, in_cb);
    }

    trigger_error(fmt::format(fmt::runtime("unknown protocol version {}"), protocol_version));
    return 0;
}

unsigned int kis_datasource::send_open_source(const std::string& in_definition, unsigned int in_transaction,
        open_callback_t in_cb) {
    if (protocol_version < 3) {
#ifdef HAVE_PROTOBUF_CPP
        return send_open_source_v2(in_definition, in_transaction, in_cb);
#else
        trigger_error("cannot use v2 protocol on this build");
        return 0;
#endif
    }

    if (protocol_version == 3) {
        return send_open_source_v3(in_definition, in_transaction, in_cb);
    }

    trigger_error(fmt::format(fmt::runtime("unknown protocol version {}"), protocol_version));
    return 0;
}

unsigned int kis_datasource::send_probe_source(const std::string& in_definition, unsigned int in_transaction,
        probe_callback_t in_cb) {
    if (protocol_version < 3) {
#ifdef HAVE_PROTOBUF_CPP
        return send_open_probe_source_v2(in_definition, in_transaction, in_cb);
#else
        trigger_error("cannot use v2 protocol on this build");
        return 0;
#endif
    }

    if (protocol_version == 3) {
        return send_probe_source_v3(in_definition, in_transaction, in_cb);
    }

    trigger_error(fmt::format(fmt::runtime("unknown protocol version {}"), protocol_version));
    return 0;
}

bool kis_datasource::dispatch_rx_packet_v3(uint16_t command, uint16_t code,
        uint32_t seqno, const nonstd::string_view& content) {
    if (kis_external_interface::dispatch_rx_packet_v3(command, code, seqno, content)) {
        return true;
    }

    // v3 drops explicit error/warning reports and rolls them into the return codes of the
    // packet headers itself
    switch (command) {
        case KIS_EXTERNAL_V3_KDS_CONFIGUREREPORT:
            handle_packet_configure_report_v3(seqno, code, content);
            return true;
        case KIS_EXTERNAL_V3_KDS_PACKET:
            handle_packet_data_report_v3(seqno, code, content);
            return true;
        case KIS_EXTERNAL_V3_KDS_LISTREPORT:
            handle_packet_interfaces_report_v3(seqno, code, content);
            return true;
        case KIS_EXTERNAL_V3_KDS_OPENREPORT:
            handle_packet_opensource_report_v3(seqno, code, content);
            return true;
    }

    return false;
}

void kis_datasource::handle_packet_configure_report_v3(uint32_t seqno, uint16_t code,
        const nonstd::string_view& in_packet) {
    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock, "datasource handle_packet_configure_report_v3");
    lock.lock();

    /*
    KismetDatasource::ConfigureReport report;

    if (!report.ParseFromArray(in_content.data(), in_content.length())) {
        _MSG(std::string("Kismet datasource driver ") + get_source_builder()->get_source_type() +
                std::string(" could not parse the configure report, something is wrong with "
                    "the remote capture tool"), MSGFLAG_ERROR);
        trigger_error("Invalid KDSCONFIGUREREPORT");
        return;
    }

    std::string msg;

    if (report.has_message())
        msg = report.message().msgtext();

    if (report.has_warning())
        set_int_source_warning(munge_to_printable(report.warning()));

    if (report.has_channel()) {
        set_int_source_hopping(false);
        set_int_source_channel(report.channel().channel());
    } else if (report.has_hopping()) {
        if (report.hopping().has_rate())
            set_int_source_hopping(report.hopping().rate() != 0);
        else
            set_int_source_hopping(false);

        if (report.hopping().has_rate())
            set_int_source_hop_rate(report.hopping().rate());

        if (report.hopping().has_shuffle())
            set_int_source_hop_shuffle(report.hopping().shuffle());

        if (report.hopping().has_shuffle_skip())
            set_int_source_hop_shuffle_skip((report.hopping().shuffle_skip()));

        if (report.hopping().has_offset())
            set_int_source_hop_offset(report.hopping().offset());

        source_hop_vec->clear();

        for (auto c : report.hopping().channels()) {
            source_hop_vec->push_back(c);
        }
    }

    // Get the sequence number and look up our command
    uint32_t seq = report.success().seqno();
    auto ci = command_ack_map.find(seq);
    if (ci != command_ack_map.end()) {
        auto cb = ci->second->configure_cb;
        auto transaction = ci->second->transaction;

        command_ack_map.erase(ci);

        if (cb != nullptr) {
            lock.unlock();
            cb(transaction, report.success().success(), msg);
            lock.lock();
        }
    }

    if (!report.success().success()) {
        trigger_error(msg);
        set_int_source_error_reason(msg);
    }
    */
}

#ifdef HAVE_PROTOBUF_CPP
bool kis_datasource::dispatch_rx_packet_v2(const nonstd::string_view& command,
        uint32_t seqno, const nonstd::string_view& content) {
    // Handle all the default options first; ping, pong, message, etc are all
    // handled for us by the overhead of the KismetExternal protocol, we only need
    // to worry about our specific ones
    if (kis_external_interface::dispatch_rx_packet(command, seqno, content))
        return true;

    // Handle all the KisDataSource sub-protocols
    if (command.compare("KDSCONFIGUREREPORT") == 0) {
        handle_packet_configure_report_v2(seqno, content);
        return true;
    } else if (command.compare("KDSDATAREPORT") == 0) {
        handle_packet_data_report_v2(seqno, content);
        return true;
    } else if (command.compare("KDSERRORREPORT") == 0) {
        handle_packet_error_report_v2(seqno, content);
        return true;
    } else if (command.compare("KDSINTERFACESREPORT") == 0) {
        quiet_errors = true;
        handle_packet_interfaces_report_v2(seqno, content);
        return true;
    } else if (command.compare("KDSOPENSOURCEREPORT") == 0) {
        handle_packet_opensource_report_v2(seqno, content);
        return true;
    } else if (command.compare("KDSPROBESOURCEREPORT") == 0) {
        quiet_errors = true;
        handle_packet_probesource_report_v2(seqno, content);
        return true;
    } else if (command.compare("KDSWARNINGREPORT") == 0) {
        handle_packet_warning_report_v2(seqno, content);
        return true;
    }

    return false;
}

void kis_datasource::handle_packet_probesource_report_v2(uint32_t in_seqno,
        const nonstd::string_view& in_content) {
    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock,
            "datasource handle_packet_probesource_report");
    lock.lock();

    KismetDatasource::ProbeSourceReport report;

    if (!report.ParseFromArray(in_content.data(), in_content.length())) {
        _MSG_ERROR("Kismet datasource driver '{}' could not parse the probe report received "
                "from the capture tool, something is wrong with the capture binary '{}'",
                source_builder->get_source_type(), source_ipc_binary->get());
        trigger_error("Invalid KDSPROBESOURCEREPORT");
        return;
    }

    std::string msg;

    // Extract any message to send to the probe callback
    if (report.has_message()) {
        msg = report.message().msgtext();
    }

    if (report.has_channels()) {
        source_channels_vec->clear();

        for (int x = 0; x < report.channels().channels_size(); x++) {
            source_channels_vec->push_back(report.channels().channels(x));
        }
    }

    if (report.has_channel()) {
        set_int_source_channel(report.channel().channel());
    }

    if (report.has_hardware()) {
        set_int_source_hardware(report.hardware());
    }

    uint32_t seq = report.success().seqno();
    auto ci = command_ack_map.find(seq);

    if (ci != command_ack_map.end()) {
        auto cb = ci->second->probe_cb;
        auto transaction = ci->second->transaction;
        command_ack_map.erase(ci);

        if (cb != nullptr) {
            lock.unlock();
            cb(transaction, report.success().success(), msg);
        }
    }

}

void kis_datasource::handle_packet_opensource_report_v2(uint32_t in_seqno,
        const nonstd::string_view& in_content) {

    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock,
            "datasource handle_packet_opensource_report");
    lock.lock();

    KismetDatasource::OpenSourceReport report;

    if (!report.ParseFromArray(in_content.data(), in_content.length())) {
        _MSG(std::string("Kismet datasource driver ") + get_source_builder()->get_source_type() +
                std::string(" could not parse the open report, something is wrong with "
                    "the remote capture tool"), MSGFLAG_ERROR);
        trigger_error("Invalid KDSOPENSOURCEREPORT");
        return;
    }

    std::string msg;

    // Extract any message to send to the probe callback
    if (report.has_message()) {
        msg = report.message().msgtext();
    }

    if (report.has_uuid() && get_source_uuid() == 0) {
        // Don't clobber local UUID
        uuid u(report.uuid());
        set_source_uuid(u);
        set_source_key(adler32_checksum(u.uuid_to_string()));
    } else if (!local_uuid && get_source_uuid() == 0) {
        // Only generate a new UUID if we don't already have one
        uuid nuuid;
        nuuid.generate_time_uuid((uint8_t *) "\x00\x00\x00\x00\x00\x00");
        set_source_uuid(nuuid);
        set_source_key(adler32_checksum(nuuid.uuid_to_string()));
    }


    if (!report.success().success()) {
        trigger_error(msg);
        set_int_source_error_reason(msg);
    }

    if (report.has_channels()) {
        source_channels_vec->clear();

        for (int x = 0; x < report.channels().channels_size(); x++) {
            source_channels_vec->push_back(report.channels().channels(x));
        }
    }

    if (report.has_channel()) {
        set_int_source_channel(report.channel().channel());
    }

    if (report.has_hop_config()) {

        // Set the basics, if we got them we're being overridden by the remote
        // end; this might be a remote capture triggering remote-side options

        if (report.hop_config().has_rate())
            set_int_source_hop_rate(report.hop_config().rate());

        if (report.hop_config().has_shuffle())
            set_int_source_hop_shuffle(report.hop_config().shuffle());

        if (report.hop_config().has_shuffle_skip())
            set_int_source_hop_shuffle_skip(report.hop_config().shuffle_skip());

        if (report.hop_config().has_offset())
            set_int_source_hop_offset(report.hop_config().offset());
    }

    if (report.has_hardware()) {
        set_int_source_hardware(report.hardware());
    }

    // Only override the source level dlt if it hasn't been set
    if (report.has_dlt() && get_source_dlt() == 0) {
        set_int_source_dlt(report.dlt());
    }

    if (report.has_capture_interface()) {
        set_int_source_cap_interface(report.capture_interface());
    }

    // If we have a channels= option in the definition, override the
    // channels list, merge the custom channels list and the supplied channels
    // list.  Otherwise, copy the source list to the hop list.
    //
    // If we have a 'channel=' in the source definition that isn't in the list,
    // add it.
    //
    // If we have a 'add_channels=' in the source, use the provided list + that
    // for hop,
    //
    // If we have a 'block_channels=' in the source, use the list to mask
    // out any channels we think we support that are otherwise blocked

    source_hop_vec->clear();

    // Add the channel= to the channels list
    std::string def_chan = get_definition_opt("channel");
    if (def_chan != "") {
        bool append = true;
        for (const auto& sci : *source_hop_vec) {
            if (strcasecmp(sci.c_str(), def_chan.c_str()) == 0) {
                append = false;
                break;
            }
        }

        if (append) {
            source_channels_vec->push_back(def_chan);
        }
    }

    std::vector<std::string> def_vec = str_tokenize(get_definition_opt("channels"), ",");
    std::vector<std::string> add_vec = str_tokenize(get_definition_opt("add_channels"), ",");
    std::vector<std::string> block_vec = str_tokenize(get_definition_opt("block_channels"), ",");

    if (def_vec.size() != 0) {
        // If we override the channels, use our supplied list entirely, and we don't
        // care about the blocked channels
        for (auto dc : def_vec) {
            source_hop_vec->push_back(dc);

            // Do we need to add the custom channels to the list of channels the
            // source supports?
            bool append = true;
            for (const auto& sci : *source_channels_vec) {
                if (strcasecmp(sci.c_str(), dc.c_str()) == 0) {
                    append = false;
                    break;
                }
            }

            if (append)
                source_channels_vec->push_back(dc);
        }
    } else if (add_vec.size() != 0) {
        // Add all our existing channels, filtering for blocked channels
        for (const auto& c : *source_channels_vec) {
            bool skip = false;
            for (const auto& bchan : block_vec) {
                if (str_lower(c) == str_lower(bchan)) {
                    skip = true;
                    break;
                }
            }

            if (!skip)
                source_hop_vec->push_back(c);
        }

        for (auto ac : add_vec) {
            // Add any new channels from the add_vec, we don't filter blocked channels here
            bool append = true;
            for (const auto& sci : *source_channels_vec) {
                if (strcasecmp(sci.c_str(), ac.c_str()) == 0) {
                    append = false;
                    break;
                }
            }

            if (append) {
                source_hop_vec->push_back(ac);
                source_channels_vec->push_back(ac);
            }
        }

    } else {
        // Otherwise, or hop list is our channels list, filtering for blocks
        for (const auto& c : *source_channels_vec) {
            bool skip = false;
            for (const auto& bchan : block_vec) {
                if (str_lower(c) == str_lower(bchan)) {
                    skip = true;
                    break;
                }
            }

            if (!skip)
                source_hop_vec->push_back(c);
        }
    }

    if (report.success().success())
        set_int_source_retry_attempts(0);

    set_int_source_running(report.success().success());

    set_int_source_error(!report.success().success());

    uint32_t seq = report.success().seqno();
    auto ci = command_ack_map.find(seq);
    if (ci != command_ack_map.end()) {
        auto cb = ci->second->open_cb;
        auto transaction = ci->second->transaction;
        command_ack_map.erase(ci);

        if (cb != nullptr) {
            lock.unlock();
            cb(transaction, report.success().success(), msg);
            lock.lock();
        }
    }

}

void kis_datasource::handle_packet_interfaces_report_v2(uint32_t in_seqno,
        const nonstd::string_view& in_content) {
    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock, "datasource handle_packet_interfaces_report");
    lock.lock();

    listed_interfaces.clear();

    KismetDatasource::InterfacesReport report;

    if (!report.ParseFromArray(in_content.data(), in_content.length())) {
        _MSG(std::string("Kismet datasource driver ") + get_source_builder()->get_source_type() +
                std::string(" could not parse the interface report, something is wrong with "
                    "the remote capture tool"), MSGFLAG_ERROR);
        lock.unlock();
        trigger_error("Invalid KDSPROBESOURCEREPORT");
        return;
    }

    std::string msg;

    if (report.has_message()) {
        msg = report.message().msgtext();
    }

    for (auto rintf : report.interfaces()) {
        auto intf =
            std::make_shared<kis_datasource_interface>(listed_interface_entry_id);

        intf->populate(rintf.interface(), rintf.flags());
        intf->set_prototype(get_source_builder());

        if (rintf.has_hardware())
            intf->set_hardware(rintf.hardware());

        if (rintf.has_capinterface())
            intf->set_cap_interface(rintf.capinterface());

        listed_interfaces.push_back(intf);
    }

    // Quiet errors display for shutdown of pipe
    quiet_errors = true;

    lock.unlock();

    uint32_t seq = report.success().seqno();

    auto ci = command_ack_map.find(seq);
    if (ci != command_ack_map.end()) {
        auto cb = ci->second->list_cb;
        auto transaction = ci->second->transaction;
        command_ack_map.erase(ci);

        if (cb != nullptr) {
            cb(std::static_pointer_cast<kis_datasource>(shared_from_this()),
                    transaction, listed_interfaces);
        }
    }

}

void kis_datasource::handle_packet_error_report_v2(uint32_t in_seqno,
        const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource handle_packet_error_report");

    KismetDatasource::ErrorReport report;

    if (!report.ParseFromArray(in_content.data(), in_content.length())) {
        _MSG(std::string("Kismet datasource driver ") + get_source_builder()->get_source_type() +
                std::string(" could not parse the error report, something is wrong with "
                    "the remote capture tool"), MSGFLAG_ERROR);
        trigger_error("Invalid KDSERRORREPORT");
        return;
    }

    if (report.has_message())
        handle_msg_proxy(report.message().msgtext(), MSGFLAG_ERROR);

    if (!report.success().success()) {
        trigger_error("Fatal error from remote source");
    }
}

void kis_datasource::handle_packet_configure_report_v2(uint32_t in_seqno,
        const nonstd::string_view& in_content) {
    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock, "datasource handle_packet_configure_report");
    lock.lock();

    KismetDatasource::ConfigureReport report;

    if (!report.ParseFromArray(in_content.data(), in_content.length())) {
        _MSG(std::string("Kismet datasource driver ") + get_source_builder()->get_source_type() +
                std::string(" could not parse the configure report, something is wrong with "
                    "the remote capture tool"), MSGFLAG_ERROR);
        trigger_error("Invalid KDSCONFIGUREREPORT");
        return;
    }

    std::string msg;

    if (report.has_message())
        msg = report.message().msgtext();

    if (report.has_warning())
        set_int_source_warning(munge_to_printable(report.warning()));

    if (report.has_channel()) {
        set_int_source_hopping(false);
        set_int_source_channel(report.channel().channel());
    } else if (report.has_hopping()) {
        if (report.hopping().has_rate())
            set_int_source_hopping(report.hopping().rate() != 0);
        else
            set_int_source_hopping(false);

        if (report.hopping().has_rate())
            set_int_source_hop_rate(report.hopping().rate());

        if (report.hopping().has_shuffle())
            set_int_source_hop_shuffle(report.hopping().shuffle());

        if (report.hopping().has_shuffle_skip())
            set_int_source_hop_shuffle_skip((report.hopping().shuffle_skip()));

        if (report.hopping().has_offset())
            set_int_source_hop_offset(report.hopping().offset());

        source_hop_vec->clear();

        for (auto c : report.hopping().channels()) {
            source_hop_vec->push_back(c);
        }
    }

    // Get the sequence number and look up our command
    uint32_t seq = report.success().seqno();
    auto ci = command_ack_map.find(seq);
    if (ci != command_ack_map.end()) {
        auto cb = ci->second->configure_cb;
        auto transaction = ci->second->transaction;

        command_ack_map.erase(ci);

        if (cb != nullptr) {
            lock.unlock();
            cb(transaction, report.success().success(), msg);
            lock.lock();
        }
    }

    if (!report.success().success()) {
        trigger_error(msg);
        set_int_source_error_reason(msg);
    }

}

void kis_datasource::handle_packet_data_report_v2(uint32_t in_seqno,
        const nonstd::string_view& in_content) {
    {
        kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource handle_packet_data_report");

        // If we haven't acquired the gpstracker, do so
        if (gpstracker == nullptr)
            gpstracker = Globalreg::fetch_mandatory_global_as<gps_tracker>();


        // If we're paused, throw away this packet
        if (get_source_paused())
            return;
    }

    auto report = std::make_shared<KismetDatasource::DataReport>();

    if (!report->ParseFromArray(in_content.data(), in_content.length())) {
        _MSG(std::string("Kismet datasource driver ") + get_source_builder()->get_source_type() +
                std::string(" could not parse the data report, something is wrong with "
                    "the remote capture tool"), MSGFLAG_ERROR);
        trigger_error("Invalid KDSDATAREPORT");
        return;
    }

    if (report->has_message())
        handle_msg_proxy(report->message().msgtext(), report->message().msgtype());

    if (report->has_warning())
        set_int_source_warning(report->warning());

    auto packet = packetchain->generate_packet();

    // Process the data chunk
    if (report->has_packet()) {
        handle_rx_datalayer(packet, report->packet());
    }

    // Process JSON
    if (report->has_json()) {
        handle_rx_jsonlayer(packet, report->json());
    }

    // Process protobufs
    if (report->has_buffer()) {
        auto bufinfo = packetchain->new_packet_component<kis_protobuf_packinfo>();

        if (clobber_timestamp && get_source_remote()) {
            gettimeofday(&(packet->ts), NULL);
        } else {
            packet->ts.tv_sec = report->buffer().time_sec();
            packet->ts.tv_usec = report->buffer().time_usec();
        }

        bufinfo->type = report->buffer().type();
        bufinfo->buffer_string = report->buffer().buffer();

        packet->insert(pack_comp_protobuf, bufinfo);
    }

    // Signal
    if (report->has_signal()) {
        auto siginfo = handle_sub_signal(report->signal());
        packet->insert(pack_comp_l1info, siginfo);
    }

    // GPS
    if (report->has_gps()) {
        auto gpsinfo = handle_sub_gps(report->gps());
        packet->insert(pack_comp_gps, gpsinfo);
    } else if (suppress_gps) {
        auto nogpsinfo = packetchain->new_packet_component<kis_no_gps_packinfo>();
        packet->insert(pack_comp_no_gps, nogpsinfo);
    } else if (device_gps != nullptr) {
        auto gpsinfo = device_gps->get_location();

        if (gpsinfo != nullptr)
            packet->insert(pack_comp_gps, gpsinfo);
    }

    // TODO handle spectrum

    handle_rx_packet(packet);

}

void kis_datasource::handle_rx_datalayer_v2(std::shared_ptr<kis_packet> packet,
        const KismetDatasource::SubPacket& report) {

    // If we have a packet report, but somehow we don't have data in the
    // packet report, get out.
    if (!report.has_data())
        return;

    auto datachunk = packetchain->new_packet_component<kis_datachunk>();

    if (clobber_timestamp && get_source_remote()) {
        gettimeofday(&(packet->ts), NULL);
    } else {
        packet->ts.tv_sec = report.time_sec();
        packet->ts.tv_usec = report.time_usec();
    }

    // Override the DLT if we have one
    if (get_source_override_linktype()) {
        datachunk->dlt = get_source_override_linktype();
    } else {
        datachunk->dlt = report.dlt();
    }

    if (report.has_cap_size()) {
        if (report.cap_size() == 0)
            packet->original_len = report.data().length();
        else
            packet->original_len = report.cap_size();
    } else {
        packet->original_len = report.data().length();
    }

    packet->set_data(report.data());
    datachunk->set_data(packet->data);

    get_source_packet_size_rrd()->add_sample(report.data().length(), Globalreg::globalreg->last_tv_sec);

    packet->insert(pack_comp_linkframe, datachunk);
}

void kis_datasource::handle_rx_jsonlayer_v2(std::shared_ptr<kis_packet> packet,
        const KismetDatasource::SubJson& report) {
    auto jsoninfo = packetchain->new_packet_component<kis_json_packinfo>();

    if (clobber_timestamp && get_source_remote()) {
        gettimeofday(&(packet->ts), NULL);
    } else {
        packet->ts.tv_sec = report.time_sec();
        packet->ts.tv_usec = report.time_usec();
    }

    jsoninfo->type = report.type();
    jsoninfo->json_string = report.json();

    packet->insert(pack_comp_json, jsoninfo);
}

void kis_datasource::handle_packet_warning_report_v2(uint32_t in_seqno,
        const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource handle_packet_warning_report");

    KismetDatasource::WarningReport report;

    if (!report.ParseFromArray(in_content.data(), in_content.length())) {
        _MSG(std::string("Kismet datasource driver ") + get_source_builder()->get_source_type() +
                std::string(" could not parse the warning report, something is wrong with "
                    "the remote capture tool"), MSGFLAG_ERROR);
        trigger_error("Invalid KDSWARNINGREPORT");
        return;
    }

    _MSG(report.warning(), MSGFLAG_INFO);
    set_int_source_warning(report.warning());
}

std::shared_ptr<kis_layer1_packinfo> kis_datasource::handle_sub_signal(KismetDatasource::SubSignal in_sig) {
    // Extract l1 info from a KV pair so we can add it to a packet
    auto siginfo = packetchain->new_packet_component<kis_layer1_packinfo>();

    if (in_sig.has_signal_dbm()) {
        siginfo->signal_type = kis_l1_signal_type_dbm;
        siginfo->signal_dbm = in_sig.signal_dbm();
    }

    if (in_sig.has_noise_dbm()) {
        siginfo->signal_type = kis_l1_signal_type_dbm;
        siginfo->noise_dbm = in_sig.noise_dbm();
    }

    if (in_sig.has_signal_rssi()) {
        siginfo->signal_type = kis_l1_signal_type_rssi;
        siginfo->signal_rssi = in_sig.signal_rssi();
    }

    if (in_sig.has_noise_rssi()) {
        siginfo->signal_type = kis_l1_signal_type_rssi;
        siginfo->noise_rssi = in_sig.noise_rssi();
    }

    if (in_sig.has_freq_khz())
        siginfo->freq_khz = in_sig.freq_khz();

    if (in_sig.has_channel())
        siginfo->channel = in_sig.channel();

    if (in_sig.has_datarate())
        siginfo->datarate = in_sig.datarate();

    return siginfo;
}

std::shared_ptr<kis_gps_packinfo> kis_datasource::handle_sub_gps(KismetDatasource::SubGps in_gps) {
    // Extract a GPS record from a packet and turn it into a packinfo gps log
    auto gpsinfo = packetchain->new_packet_component<kis_gps_packinfo>();

    gpsinfo->lat = in_gps.lat();
    gpsinfo->lon = in_gps.lon();
    gpsinfo->alt = in_gps.alt();
    gpsinfo->speed = in_gps.speed();
    gpsinfo->heading = in_gps.heading();
    gpsinfo->precision = in_gps.precision();
    gpsinfo->fix = in_gps.fix();
    gpsinfo->tv.tv_sec = in_gps.time_sec();
    gpsinfo->tv.tv_usec = in_gps.time_usec();
    //gpsinfo->type = in_gps.type();
    gpsinfo->gpsname = in_gps.name();

    return gpsinfo;
}

unsigned int kis_datasource::send_probe_source_v2(std::string in_definition,
        unsigned int in_transaction, probe_callback_t in_cb) {
    kis_unique_lock<kis_mutex> lk(ext_mutex, "datasource send_probe_source");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    std::shared_ptr<tracked_command> cmd;
    uint32_t seqno;

    KismetDatasource::ProbeSource probe;
    probe.set_definition(in_definition);

    if (protocol_version == 0) {
        std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());
        c->set_command("KDSPROBESOURCE");
        c->set_content(probe.SerializeAsString());
        seqno = send_packet(c);
    } else if (protocol_version == 2) {
        seqno = send_packet_v2("KDSPROBESOURCE", 0, probe);
    } else {
        seqno = 0;
    }

    if (seqno == 0) {
        if (in_cb != NULL) {
            lk.unlock();
            in_cb(in_transaction, false, "unable to generate command frame");
            lk.lock();
        }

        return 0;
    }

    cmd.reset(new tracked_command(in_transaction, seqno, this));
    cmd->probe_cb = in_cb;

    command_ack_map.insert(std::make_pair(seqno, cmd));

    return seqno;
}

unsigned int kis_datasource::send_open_source_v2(std::string in_definition,
        unsigned int in_transaction, open_callback_t in_cb) {
    kis_unique_lock<kis_mutex> lk(ext_mutex, "datasource send_open_source");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    std::shared_ptr<tracked_command> cmd;
    uint32_t seqno;

    KismetDatasource::OpenSource o;
    o.set_definition(in_definition);

    if (protocol_version == 0) {
        std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());
        c->set_command("KDSOPENSOURCE");
        c->set_content(o.SerializeAsString());
        seqno = send_packet(c);
    } else if (protocol_version == 2) {
        seqno = send_packet_v2("KDSOPENSOURCE", 0, o);
    } else {
        seqno = 0;
    }

    if (seqno == 0) {
        if (in_cb != NULL) {
            lk.unlock();
            in_cb(in_transaction, false, "unable to generate command frame");
            lk.lock();
        }

        return 0;
    }

    cmd.reset(new tracked_command(in_transaction, seqno, this));
    cmd->open_cb = in_cb;

    command_ack_map.insert(std::make_pair(seqno, cmd));

    return seqno;
}

unsigned int kis_datasource::send_configure_channel_v2(std::string in_chan,
        unsigned int in_transaction, configure_callback_t in_cb) {
    kis_unique_lock<kis_mutex> lk(ext_mutex, "datasource send_configure_channel");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    std::shared_ptr<tracked_command> cmd;
    uint32_t seqno;

    KismetDatasource::Configure o;
    KismetDatasource::SubChanset *ch = new KismetDatasource::SubChanset();

    ch->set_channel(in_chan);
    o.set_allocated_channel(ch);

    if (protocol_version == 0) {
        std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());
        c->set_command("KDSCONFIGURE");
        c->set_content(o.SerializeAsString());
        seqno = send_packet(c);
    } else if (protocol_version == 2) {
        seqno = send_packet_v2("KDSCONFIGURE", 0, o);
    } else {
        seqno = 0;
    }

    if (seqno == 0) {
        if (in_cb != NULL) {
            lk.unlock();
            in_cb(in_transaction, false, "unable to generate command frame");
            lk.lock();
        }

        return 0;
    }

    cmd.reset(new tracked_command(in_transaction, seqno, this));
    cmd->configure_cb = in_cb;

    command_ack_map.insert(std::make_pair(seqno, cmd));

    return seqno;
}

unsigned int kis_datasource::send_configure_channel_hop_v2(double in_rate,
        std::shared_ptr<tracker_element_vector_string> in_chans,
        bool in_shuffle, unsigned int in_offt,
        unsigned int in_transaction,
        configure_callback_t in_cb) {

    kis_unique_lock<kis_mutex> lk(ext_mutex, "datasource send_configure_channel_hop");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    uint32_t seqno;

    KismetDatasource::Configure o;
    KismetDatasource::SubChanhop *ch = new KismetDatasource::SubChanhop();

    ch->set_rate(in_rate);
    ch->set_shuffle(in_shuffle);
    ch->set_offset(in_offt);

    for (const auto& chi : *in_chans)  {
        ch->add_channels(chi);
    }

    o.set_allocated_hopping(ch);

    if (protocol_version == 0) {
        std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());
        c->set_command("KDSCONFIGURE");
        c->set_content(o.SerializeAsString());
        seqno = send_packet(c);
    } else if (protocol_version == 2) {
        seqno = send_packet_v2("KDSCONFIGURE", 0, o);
    } else {
        seqno = 0;
    }

    if (seqno == 0) {
        if (in_cb != NULL) {
            lk.unlock();
            in_cb(in_transaction, false, "unable to generate command frame");
            lk.lock();
        }

        return 0;
    }

    auto cmd = std::make_shared<tracked_command>(in_transaction, seqno, this);
    cmd->configure_cb = in_cb;

    command_ack_map.insert(std::make_pair(seqno, cmd));

    return seqno;
}

unsigned int kis_datasource::send_list_interfaces_v2(unsigned int in_transaction, list_callback_t in_cb) {
    kis_unique_lock<kis_mutex> lk(ext_mutex, "datasource send_list_interfaces");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    std::shared_ptr<tracked_command> cmd;
    uint32_t seqno;

    KismetDatasource::ListInterfaces l;

    if (protocol_version == 0) {
        std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());
        c->set_command("KDSLISTINTERFACES");
        c->set_content(l.SerializeAsString());
        seqno = send_packet(c);
    } else if (protocol_version == 2) {
        seqno = send_packet_v2("KDSLISTINTERFACES", 0, l);
    } else {
        seqno = 0;
    }

    if (seqno == 0) {
        if (in_cb != NULL) {
            lk.unlock();
            in_cb(std::static_pointer_cast<kis_datasource>(shared_from_this()), in_transaction, std::vector<shared_interface>());
            lk.lock();
        }

        return 0;
    }

    cmd.reset(new tracked_command(in_transaction, seqno, this));
    cmd->list_cb = in_cb;

    command_ack_map.insert(std::make_pair(seqno, cmd));

    return seqno;
}
#endif


void kis_datasource::register_fields() {
    tracker_component::register_fields();

    register_field("kismet.datasource.source_number", "internal source number per Kismet instance",
            &source_number);
    register_field("kismet.datasource.source_key", "hashed UUID key", &source_key);

    register_field("kismet.datasource.paused",
            "capture is paused (no packets will be processed from this source)", &source_paused);

    register_field("kismet.datasource.ipc_binary", "capture command", &source_ipc_binary);
    register_field("kismet.datasource.ipc_pid", "capture process", &source_ipc_pid);

    register_field("kismet.datasource.running", "capture is running", &source_running);

    register_field("kismet.datasource.remote",
            "capture is connected from a remote server", &source_remote);

    register_field("kismet.datasource.passive",
            "capture is a post-able passive capture", &source_passive);

    register_field("kismet.datasource.name", "Human-readable name", &source_name);
    register_field("kismet.datasource.uuid", "UUID", &source_uuid);

    register_field("kismet.datasource.definition", "Original source= definition", &source_definition);
    register_field("kismet.datasource.interface", "Interface", &source_interface);
    register_field("kismet.datasource.capture_interface", "Interface", &source_cap_interface);
    register_field("kismet.datasource.hardware", "Hardware / chipset", &source_hardware);

    register_field("kismet.datasource.dlt", "DLT (link type)", &source_dlt);

    register_field("kismet.datasource.warning", "Warning or unusual interface state", &source_warning);

    channel_entry_id =
        register_field("kismet.datasource.channel_entry",
                tracker_element_factory<tracker_element_string>(),
                "Channel");

    register_field("kismet.datasource.channels", "Supported channels", &source_channels_vec);
    register_field("kismet.datasource.hopping", "Source is channel hopping", &source_hopping);
    register_field("kismet.datasource.channel", "Current channel", &source_channel);
    register_field("kismet.datasource.hop_rate", "Hop rate if channel hopping", &source_hop_rate);
    source_hop_vec_id =
        register_field("kismet.datasource.hop_channels", "Hop pattern if hopping", &source_hop_vec);
    register_field("kismet.datasource.hop_split",
            "Split hopping among same type interfaces", &source_hop_split);
    register_field("kismet.datasource.hop_offset",
            "Offset into hopping list for multiple sources", &source_hop_offset);
    register_field("kismet.datasource.hop_shuffle",
            "Shuffle channels while hopping", &source_hop_shuffle);
    register_field("kismet.datasource.hop_shuffle_skip",
            "Number of channels skipped by source during hop shuffling",
            &source_hop_shuffle_skip);

    register_field("kismet.datasource.error", "Source is in error state", &source_error);
    register_field("kismet.datasource.error_reason",
            "Last known reason for error state", &source_error_reason);

    register_field("kismet.datasource.num_packets",
            "Number of packets seen by source", &source_num_packets);
    register_field("kismet.datasource.num_error_packets",
            "Number of invalid/error packets seen by source",
            &source_num_error_packets);

    packet_rate_rrd_id =
        register_dynamic_field("kismet.datasource.packets_rrd",
                "received packet rate RRD",
                &packet_rate_rrd);

    packet_size_rrd_id =
        register_dynamic_field("kismet.datasource.packets_datasize_rrd",
                "received data RRD (in bytes)",
                &packet_size_rrd);

    register_field("kismet.datasource.retry",
            "Source will try to re-open after failure", &source_retry);
    register_field("kismet.datasource.retry_attempts",
            "Consecutive unsuccessful retry attempts", &source_retry_attempts);
    register_field("kismet.datasource.total_retry_attempts",
            "Total unsuccessful retry attempts", &source_total_retry_attempts);

    register_field("kismet.datasource.info.antenna_type",
            "User-supplied antenna type", &source_info_antenna_type);
    register_field("kismet.datasource.info.antenna_gain",
            "User-supplied antenna gain in dB", &source_info_antenna_gain);
    register_field("kismet.datasource.info.antenna_orientation",
            "User-supplied antenna orientation", &source_info_antenna_orientation);
    register_field("kismet.datasource.info.antenna_beamwidth",
            "User-supplied antenna beamwidth", &source_info_antenna_beamwidth);
    register_field("kismet.datasource.info.amp_type",
            "User-supplied amplifier type", &source_info_amp_type);
    register_field("kismet.datasource.info.amp_gain",
            "User-supplied amplifier gain in dB", &source_info_amp_gain);

    register_field("kismet.datasource.linktype_override",
            "Overridden linktype, usually used in custom capture types.", &source_override_linktype);

}

void kis_datasource::handle_source_error() {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasouce handle_source_error");

    // If we're probing or listing we don't do any special handling
    if (mode_listing || mode_probing)
        return;

    if (ping_timer_id > 0) {
        timetracker->remove_timer(ping_timer_id);
        ping_timer_id = -1;
    }

    // Do nothing if we don't handle retry
    if (get_source_remote()) {
        if (get_source_running()) {
            auto alrt = fmt::format("Source {} ({}) has encountered an error ({}).  "
                "Remote sources are not locally reconnected; waiting for the remote source "
                "to reconnect to resume capture.", get_source_name(), get_source_uuid(),
                get_source_error_reason());

            std::shared_ptr<alert_tracker> alertracker =
                Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");
            alertracker->raise_one_shot("SOURCEERROR", "SYSTEM", kis_alert_severity::critical, alrt, -1);

            _MSG(alrt, MSGFLAG_ERROR);
        }

        set_int_source_running(false);
        return;
    }

    if (!get_source_retry()) {
        if (get_source_running()) {
            auto alrt = fmt::format("Source {} ({}) has encountered an error ({}) but "
                "is not configured to automatically re-try opening; it will remain "
                "closed.", get_source_name(), get_source_uuid(), get_source_error_reason());

            std::shared_ptr<alert_tracker> alertracker =
                Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");
            alertracker->raise_one_shot("SOURCEERROR", "SYSTEM", kis_alert_severity::critical, alrt, -1);

            _MSG(alrt, MSGFLAG_ERROR);
        }

        set_int_source_running(false);

        return;
    }

    set_int_source_running(false);

    // If we already have an error timer, we're thinking about restarting,
    // be quiet about things; otherwise, talk about restarting, increment the
    // count, and set a timer
    if (error_timer_id <= 0 && get_source_retry()) {

        // Increment our failures
        inc_int_source_retry_attempts(1);
        inc_int_source_total_retry_attempts(1);

        // Notify about it
        auto alrt = fmt::format("Source {} ({}) has encountered an error ({}) "
            "Kismet will attempt to re-open the source in 5 seconds.  ({} failures)",
            get_source_name(), get_source_uuid(), get_source_error_reason(), get_source_retry_attempts());

        std::shared_ptr<alert_tracker> alertracker =
            Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");
        alertracker->raise_one_shot("SOURCEERROR", "SYSTEM", kis_alert_severity::critical, alrt, -1);

        _MSG(alrt, MSGFLAG_ERROR);

        // Set a new event to try to re-open the interface
        error_timer_id = timetracker->register_timer(std::chrono::seconds(5), false, [this](int tid) -> int {
                kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource error_timer lambda");

                if (get_source_retry() == false)
                    return 0;

                _MSG("Attempting to re-open source " + get_source_name(), MSGFLAG_INFO);

                // Call open on the same sourceline, no transaction
                open_interface(generate_source_definition(), 0,
                        [this](int, bool success, std::string) {
                            if (!success)
                                return;

                            auto evt = eventbus->get_eventbus_event(event_datasource_opened());
                            evt->get_event_content()->insert(event_datasource_opened(), source_uuid);
                            eventbus->publish(evt);

                            auto alrt = fmt::format("Source {} ({}) successfully re-opened",
                                    get_source_name(), get_source_uuid());

                            std::shared_ptr<alert_tracker> alertracker =
                                Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");
                            alertracker->raise_one_shot("SOURCEOPEN", "SYSTEM", kis_alert_severity::critical, alrt, -1);

                            if (get_source_hopping()) {
                                // Reset the channel hop if we're hopping
                                set_channel_hop(get_source_hop_rate(),
                                        get_source_hop_vec(),
                                        get_source_hop_shuffle(),
                                        get_source_hop_offset(),
                                        0, NULL);
                            } else if (get_source_channel() != "") {
                                // Reset the fixed channel if we have one
                                set_channel(get_source_channel(), 0, NULL);
                            }

                        });

                    error_timer_id = -1;

                    return 0;
                });
    } else {
        // fprintf(stderr, "debug - source error but we think a timer is already running\n");
    }
}

bool kis_datasource::launch_ipc() {
    if (get_source_ipc_binary() == "") {
        trigger_error("missing IPC binary definition, can not launch capture tool");
        return false;
    }

    if (io_ != nullptr) {
        io_->stop();
        io_->close();
        io_.reset();
    }

    set_int_source_ipc_pid(-1);

    external_binary = get_source_ipc_binary();

    if (run_ipc()) {
        set_int_source_ipc_pid(ipc.pid);
        return true;
    }

    _MSG_ERROR("Data source '{} / {}' could not launch IPC helper", get_source_name(),
            generate_source_definition());

    return false;
}

