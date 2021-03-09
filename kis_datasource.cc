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

// We never instantiate from a generic tracker component or from a stored
// record so we always re-allocate ourselves
kis_datasource::kis_datasource(shared_datasource_builder in_builder) :
    tracker_component(),
    kis_external_interface() {

    next_transaction = 1;

    if (in_builder != nullptr)
        ext_mutex.set_name(fmt::format("kis_datasource({})", in_builder->get_source_type()));
    else
        ext_mutex.set_name(fmt::format("kis_datasource(base)"));
    
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

    last_pong = time(0);

    quiet_errors = 0;

    set_int_source_running(false);
}

kis_datasource::~kis_datasource() {
    // Cancel any timer
    timetracker->remove_timer(error_timer_id);
    timetracker->remove_timer(ping_timer_id);

    cancel_all_commands("source deleted");

    command_ack_map.clear();

    // We don't call a normal close here because we can't risk double-free
    // or going through commands again - if the source is being deleted, it should
    // be completed!
}

void kis_datasource::list_interfaces(unsigned int in_transaction, list_callback_t in_cb) {
    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock, "datasource list_interfaces");
    lock.lock();

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
    if (!parse_interface_definition(in_definition)) {
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
        send_probe_source(in_definition, in_transaction, in_cb);
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
    if (!parse_interface_definition(in_definition)) {
        if (in_cb != NULL) {
            lock.unlock();
            in_cb(in_transaction, false, "Malformed source config");
            lock.lock();
        }

        return;
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

    // Launch the IPC
    launch_ipc();

    set_int_source_running(true);

    last_pong = time(0);

    // If we got here we're valid; start a PING timer
    timetracker->remove_timer(ping_timer_id);
    ping_timer_id = timetracker->register_timer(std::chrono::seconds(5), true, [this](int) -> int {
        kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource ping_timer lambda");
        
        if (!get_source_running()) {
            ping_timer_id = -1;
            return 0;
        }
       
        send_ping();
        return 1;
    });

    // Create and send open command
    send_open_source(in_definition, in_transaction, in_cb);
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
    auto vec = std::make_shared<tracker_element_vector>(source_hop_vec_id);

    for (auto i : in_chans) {
        auto c = std::make_shared<tracker_element_string>(channel_entry_id);
        c->set(i);
        vec->push_back(c);
    }

    // Call the common function that takes a sharedtrackerelement of channels
    set_channel_hop(in_rate, vec, in_shuffle, in_offt, in_transaction, in_cb);
}

void kis_datasource::set_channel_hop(double in_rate, 
        std::shared_ptr<tracker_element_vector> in_chans,
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
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource connect_remote");

    stopped = false;
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
    if (!parse_interface_definition(in_definition)) {
        set_int_source_running(false);
        set_int_source_error(true);
        set_int_source_error_reason("Unable to parse interface definition of remote source");
        _MSG("Unable to parse interface definition", MSGFLAG_ERROR);

        if (in_cb)
            in_cb(0, false, "Unable to parse definition of remote source");

        return;
    }

    if (in_tcp)  {
        attach_tcp_socket(in_remote->tcpsocket);
    } else {
        write_cb = in_remote->move_write_cb();
        closure_cb = in_remote->move_closure_cb();
    }

    in_buf.consume(in_buf.size());
    out_bufs.clear();

    last_pong = time(0);

    timetracker->remove_timer(ping_timer_id);
    ping_timer_id = timetracker->register_timer(std::chrono::seconds(5), true, [this](int) -> int {
        kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource ping_timer lambda");
        
        if (!get_source_running()) {
            ping_timer_id = -1;
            return 0;
        }

        if (time(0) - last_pong > 15) {
            ping_timer_id = -1;
            trigger_error("did not get a ping response from the capture binary");
            return 0;
        }
       
        send_ping();
        return 1;
    });

    // Send an opensource
    send_open_source(in_definition, 0, in_cb);
}

void kis_datasource::disable_source() {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource disable_source");

    close_source();

    set_int_source_error(false);
    set_int_source_error_reason("Source disabled");

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
    if (!quiet_errors && in_error.length()) {
        _MSG_ERROR("Data source '{} / {}' ('{}') encountered an error: {}",
                get_source_name(), get_source_definition(), get_source_interface(), in_error);
    }

    set_int_source_error(true);
    set_int_source_error_reason(in_error);

    set_int_source_running(false);

    auto evt = eventbus->get_eventbus_event(event_datasource_error());
    evt->get_event_content()->insert(event_datasource_error(), source_uuid);
    eventbus->publish(evt);

    handle_source_error();
    cancel_all_commands(in_error);

    close_external();
}

void kis_datasource::close_source() {
    return close_external();
}

void kis_datasource::close_external() {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource close_external");

    if (ping_timer_id > 0) {
        timetracker->remove_timer(ping_timer_id);
        ping_timer_id = -1;
    }

    auto evt = eventbus->get_eventbus_event(event_datasource_closed());
    evt->get_event_content()->insert(event_datasource_closed(), source_uuid);
    eventbus->publish(evt);

    set_int_source_running(false);

    cancel_all_commands("source closed");

    kis_external_interface::close_external();
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

bool kis_datasource::parse_interface_definition(std::string in_definition) {
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

std::shared_ptr<kis_datasource::tracked_command> kis_datasource::get_command(uint32_t in_transaction) {
    auto i = command_ack_map.find(in_transaction);

    if (i == command_ack_map.end())
        return NULL;

    return i->second;
}

void kis_datasource::cancel_command(uint32_t in_transaction, std::string in_error) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource cancel_command");

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
            cb(std::static_pointer_cast<kis_datasource>(shared_from_this()),
                    cmd->transaction, std::vector<shared_interface>());
        } else if (cmd->probe_cb != NULL) {
            probe_callback_t cb = cmd->probe_cb;
            cmd->probe_cb = NULL;
            cb(cmd->transaction, false, in_error);
        } else if (cmd->open_cb != NULL) {
            open_callback_t cb = cmd->open_cb;
            cmd->open_cb = NULL;
            cb(cmd->transaction, false, in_error);
        } else if (cmd->configure_cb != NULL) {
            configure_callback_t cb = cmd->configure_cb;
            cmd->configure_cb = NULL;
            cb(cmd->transaction, false, in_error);
        }

        cmd.reset();
    }
}

void kis_datasource::cancel_all_commands(std::string in_error) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource cancel_all_commands");

    // fprintf(stderr, "debug - cancel all commands\n");

    while (1) {
        auto i = command_ack_map.begin();

        if (i == command_ack_map.end())
            break;

        cancel_command(i->first, in_error);
    }

    command_ack_map.clear();
}

bool kis_datasource::dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c) {
    // Handle all the default options first; ping, pong, message, etc are all
    // handled for us by the overhead of the KismetExternal protocol, we only need
    // to worry about our specific ones
    if (kis_external_interface::dispatch_rx_packet(c))
        return true;

    // Handle all the KisDataSource sub-protocols
    if (c->command() == "KDSCONFIGUREREPORT") {
        handle_packet_configure_report(c->seqno(), c->content());
        return true;
    } else if (c->command() == "KDSDATAREPORT") {
        handle_packet_data_report(c->seqno(), c->content());
        return true;
    } else if (c->command() == "KDSERRORREPORT") {
        handle_packet_error_report(c->seqno(), c->content());
        return true;
    } else if (c->command() == "KDSINTERFACESREPORT") {
        quiet_errors = true;
        handle_packet_interfaces_report(c->seqno(), c->content());
        return true;
    } else if (c->command() == "KDSOPENSOURCEREPORT") {
        handle_packet_opensource_report(c->seqno(), c->content());
        return true;
    } else if (c->command() == "KDSPROBESOURCEREPORT") {
        quiet_errors = true;
        handle_packet_probesource_report(c->seqno(), c->content());
        return true;
    } else if (c->command() == "KDSWARNINGREPORT") {
        handle_packet_warning_report(c->seqno(), c->content());
        return true;
    }

    return false;
}

void kis_datasource::handle_msg_proxy(const std::string& msg, const int type) {
    if (get_source_remote())
        _MSG(fmt::format("{} - {}", get_source_name(), msg), type);
    else
        _MSG(msg, type);
}

void kis_datasource::handle_packet_probesource_report(uint32_t in_seqno, 
        const std::string& in_content) {
    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock, 
            "datasource handle_packet_probesource_report");
    lock.lock();

    KismetDatasource::ProbeSourceReport report;

    if (!report.ParseFromString(in_content)) {
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
            auto chanstr =
                std::make_shared<tracker_element_string>(channel_entry_id);
            chanstr->set(report.channels().channels(x));
            source_channels_vec->push_back(chanstr);
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

void kis_datasource::handle_packet_opensource_report(uint32_t in_seqno, 
        const std::string& in_content) {
    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock, "datasource handle_packet_opensource_report");
    lock.lock();

    KismetDatasource::OpenSourceReport report;

    if (!report.ParseFromString(in_content)) {
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

    if (report.has_channels()) {
        source_channels_vec->clear();

        for (int x = 0; x < report.channels().channels_size(); x++) {
            auto chanstr = 
                std::make_shared<tracker_element_string>(channel_entry_id);
            chanstr->set(report.channels().channels(x));

            source_channels_vec->push_back(chanstr);
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

    if (report.has_uuid()) {
        uuid u(report.uuid());
        set_source_uuid(u);
        set_source_key(adler32_checksum(u.uuid_to_string()));
    } else if (!local_uuid) {
        uuid nuuid;
        nuuid.generate_time_uuid((uint8_t *) "\x00\x00\x00\x00\x00\x00");
        set_source_uuid(nuuid);
        set_source_key(adler32_checksum(nuuid.uuid_to_string()));
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
        for (auto sci : *source_hop_vec) {
            if (strcasecmp(get_tracker_value<std::string>(sci).c_str(), def_chan.c_str()) == 0) {
                append = false;
                break;
            }
        }

        if (append) {
            auto dce = std::make_shared<tracker_element_string>(channel_entry_id, def_chan);
            source_channels_vec->push_back(dce);
        }
    }

    std::vector<std::string> def_vec = str_tokenize(get_definition_opt("channels"), ",");
    std::vector<std::string> add_vec = str_tokenize(get_definition_opt("add_channels"), ",");
    std::vector<std::string> block_vec = str_tokenize(get_definition_opt("block_channels"), ",");

    if (def_vec.size() != 0) {
        // If we override the channels, use our supplied list entirely, and we don't
        // care about the blocked channels
        for (auto dc : def_vec) {
            auto dce = std::make_shared<tracker_element_string>(channel_entry_id, dc);
            source_hop_vec->push_back(dce);

            // Do we need to add the custom channels to the list of channels the
            // source supports?
            bool append = true;
            for (auto sci : *source_channels_vec) {
                if (strcasecmp(get_tracker_value<std::string>(sci).c_str(), dc.c_str()) == 0) {
                    append = false;
                    break;
                }
            }

            if (append) 
                source_channels_vec->push_back(dce);
        }
    } else if (add_vec.size() != 0) {
        // Add all our existing channels, filtering for blocked channels
        for (auto c : *source_channels_vec) {
            bool skip = false;
            for (auto bchan : block_vec) {
                if (str_lower(get_tracker_value<std::string>(c)) == str_lower(bchan)) {
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
            for (auto sci : *source_channels_vec) {
                if (strcasecmp(get_tracker_value<std::string>(sci).c_str(), ac.c_str()) == 0) {
                    append = false;
                    break;
                }
            }

            if (append) {
                auto ace = std::make_shared<tracker_element_string>(channel_entry_id, ac);
                source_hop_vec->push_back(ace);
                source_channels_vec->push_back(ace);
            }
        }

    } else {
        // Otherwise, or hop list is our channels list, filtering for blocks
        for (auto c : *source_channels_vec) {
            bool skip = false;
            for (auto bchan : block_vec) {
                if (str_lower(get_tracker_value<std::string>(c)) == str_lower(bchan)) {
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

    // If we were successful, reset our retry attempts
    if (!report.success().success()) {
        trigger_error(msg);
        set_int_source_error_reason(msg);
        return;
    } 
}

void kis_datasource::handle_packet_interfaces_report(uint32_t in_seqno, 
        const std::string& in_content) {
    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock, "datasource handle_packet_interfaces_report");
    lock.lock();

    listed_interfaces.clear();

    KismetDatasource::InterfacesReport report;

    if (!report.ParseFromString(in_content)) {
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

void kis_datasource::handle_packet_error_report(uint32_t in_seqno, const std::string& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource handle_packet_error_report");

    KismetDatasource::ErrorReport report;

    if (!report.ParseFromString(in_content)) {
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

void kis_datasource::handle_packet_configure_report(uint32_t in_seqno, const std::string& in_content) {
    kis_unique_lock<kis_mutex> lock(ext_mutex, std::defer_lock, "datasource handle_packet_configure_report");
    lock.lock();

    KismetDatasource::ConfigureReport report;

    if (!report.ParseFromString(in_content)) {
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
            auto chanstr = std::make_shared<tracker_element_string>(channel_entry_id, c);
            source_hop_vec->push_back(chanstr);
        }
    }

    // Get the sequence number and look up our command
    uint32_t seq = report.success().seqno();
    auto ci = command_ack_map.find(seq);
    if (ci != command_ack_map.end()) {
        auto cb = ci->second->configure_cb;
        auto transaction = ci->second->transaction;

        // _MSG_DEBUG("ds configure report seq {} has cb transaction {} success {} msg {}", seq, transaction, report.success().success(), msg);

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

void kis_datasource::handle_packet_data_report(uint32_t in_seqno, const std::string& in_content) {
    // If we're paused, throw away this packet
    {
        kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource handle_packet_data_report");

        if (get_source_paused())
            return;
    }

    auto report = std::make_shared<KismetDatasource::DataReport>();

    if (!report->ParseFromString(in_content)) {
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

    kis_packet *packet = packetchain->generate_packet();

    packet->insert(pack_comp_report, new kis_packreport_packinfo(report));

    // Process the data chunk
    if (report->has_packet()) {
        kis_datachunk *datachunk = new kis_datachunk();

        if (clobber_timestamp && get_source_remote()) {
            gettimeofday(&(packet->ts), NULL);
        } else {
            packet->ts.tv_sec = report->packet().time_sec();
            packet->ts.tv_usec = report->packet().time_usec();
        }

        // Override the DLT if we have one
        if (get_source_override_linktype()) {
            datachunk->dlt = get_source_override_linktype();
        } else {
            datachunk->dlt = report->packet().dlt();
        }

        // datachunk->copy_data((const uint8_t *) report.packet().data().data(), report.packet().data().length());

        datachunk->set_data(const_cast<char *>(report->packet().data().data()), report->packet().data().length(), false);

        get_source_packet_size_rrd()->add_sample(report->packet().data().length(), time(0));

        packet->insert(pack_comp_linkframe, datachunk);
    }

    // Process JSON
    if (report->has_json()) {
        // fprintf(stderr, "debug - got JSON report- %s\n", report.json().json().c_str());
        kis_json_packinfo *jsoninfo = new kis_json_packinfo();
      
        if (clobber_timestamp && get_source_remote()) {
            gettimeofday(&(packet->ts), NULL);
        } else {
            packet->ts.tv_sec = report->json().time_sec();
            packet->ts.tv_usec = report->json().time_usec();
        }

        jsoninfo->type = report->json().type();
        jsoninfo->json_string = report->json().json();

        packet->insert(pack_comp_json, jsoninfo);
    }

    // Process protobufs
    if (report->has_buffer()) {
        kis_protobuf_packinfo *bufinfo = new kis_protobuf_packinfo();

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
        kis_layer1_packinfo *siginfo = NULL;
        siginfo = handle_sub_signal(report->signal());
        packet->insert(pack_comp_l1info, siginfo);
    }

    // GPS
    if (report->has_gps()) {
        kis_gps_packinfo *gpsinfo = NULL;
        gpsinfo = handle_sub_gps(report->gps());
        packet->insert(pack_comp_gps, gpsinfo);
    } else if (suppress_gps) {
        auto nogpsinfo = new kis_no_gps_packinfo();
        packet->insert(pack_comp_no_gps, nogpsinfo);
    }

    // TODO handle spectrum
   
    handle_rx_packet(packet);
}

void kis_datasource::handle_rx_packet(kis_packet *packet) {
    packetchain_comp_datasource *datasrcinfo = new packetchain_comp_datasource();
    datasrcinfo->ref_source = this;

    packet->insert(pack_comp_datasrc, datasrcinfo);

    inc_source_num_packets(1);
    get_source_packet_rrd()->add_sample(1, time(0));

    // Inject the packet into the packetchain if we have one
    packetchain->process_packet(packet);
}

void kis_datasource::handle_packet_warning_report(uint32_t in_seqno, const std::string& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource handle_packet_warning_report");

    KismetDatasource::WarningReport report;

    if (!report.ParseFromString(in_content)) {
        _MSG(std::string("Kismet datasource driver ") + get_source_builder()->get_source_type() + 
                std::string(" could not parse the warning report, something is wrong with "
                    "the remote capture tool"), MSGFLAG_ERROR);
        trigger_error("Invalid KDSWARNINGREPORT");
        return;
    }

    _MSG(report.warning(), MSGFLAG_INFO);
    set_int_source_warning(report.warning());
}

kis_layer1_packinfo *kis_datasource::handle_sub_signal(KismetDatasource::SubSignal in_sig) {
    // Extract l1 info from a KV pair so we can add it to a packet
    
    kis_layer1_packinfo *siginfo = new kis_layer1_packinfo();

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

kis_gps_packinfo *kis_datasource::handle_sub_gps(KismetDatasource::SubGps in_gps) {
    // Extract a GPS record from a packet and turn it into a packinfo gps log
    kis_gps_packinfo *gpsinfo = new kis_gps_packinfo();

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

unsigned int kis_datasource::send_probe_source(std::string in_definition,
        unsigned int in_transaction, probe_callback_t in_cb) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource send_probe_source");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    std::shared_ptr<tracked_command> cmd;
    uint32_t seqno;

    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_command("KDSPROBESOURCE");

    KismetDatasource::ProbeSource probe;
    probe.set_definition(in_definition);

    c->set_content(probe.SerializeAsString());

    seqno = send_packet(c);

    if (seqno == 0) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "unable to generate command frame");
        }

        return 0;
    }

    cmd.reset(new tracked_command(in_transaction, seqno, this));
    cmd->probe_cb = in_cb;

    command_ack_map.insert(std::make_pair(seqno, cmd));

    return seqno;
}

unsigned int kis_datasource::send_open_source(std::string in_definition,
        unsigned int in_transaction, open_callback_t in_cb) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource send_open_source");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    std::shared_ptr<tracked_command> cmd;
    uint32_t seqno;

    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_command("KDSOPENSOURCE");

    KismetDatasource::OpenSource o;
    o.set_definition(in_definition);

    c->set_content(o.SerializeAsString());

    seqno = send_packet(c);

    if (seqno == 0) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "unable to generate command frame");
        }

        return 0;
    }

    cmd.reset(new tracked_command(in_transaction, seqno, this));
    cmd->open_cb = in_cb;

    command_ack_map.insert(std::make_pair(seqno, cmd));

    return seqno;
}

unsigned int kis_datasource::send_configure_channel(std::string in_chan,
        unsigned int in_transaction, configure_callback_t in_cb) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource send_configure_channel");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    std::shared_ptr<tracked_command> cmd;
    uint32_t seqno;

    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_command("KDSCONFIGURE");

    KismetDatasource::Configure o;
    KismetDatasource::SubChanset *ch = new KismetDatasource::SubChanset();

    ch->set_channel(in_chan);
    o.set_allocated_channel(ch);

    c->set_content(o.SerializeAsString());

    seqno = send_packet(c);

    if (seqno == 0) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "unable to generate command frame");
        }

        return 0;
    }

    cmd.reset(new tracked_command(in_transaction, seqno, this));
    cmd->configure_cb = in_cb;

    command_ack_map.insert(std::make_pair(seqno, cmd));

    return seqno;
}

unsigned int kis_datasource::send_configure_channel_hop(double in_rate, 
        std::shared_ptr<tracker_element_vector> in_chans,
        bool in_shuffle, unsigned int in_offt,
        unsigned int in_transaction,
        configure_callback_t in_cb) {

    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource send_configure_channel_hop");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    uint32_t seqno;

    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_command("KDSCONFIGURE");

    KismetDatasource::Configure o;
    KismetDatasource::SubChanhop *ch = new KismetDatasource::SubChanhop();

    ch->set_rate(in_rate);
    ch->set_shuffle(in_shuffle);
    ch->set_offset(in_offt);

    for (auto chi : *in_chans)  {
        ch->add_channels(get_tracker_value<std::string>(chi));
    }

    o.set_allocated_hopping(ch);

    c->set_content(o.SerializeAsString());

    seqno = send_packet(c);

    if (seqno == 0) {
        if (in_cb != NULL) {
            in_cb(in_transaction, false, "unable to generate command frame");
        }

        return 0;
    }

    auto cmd = std::make_shared<tracked_command>(in_transaction, seqno, this);
    cmd->configure_cb = in_cb;

    command_ack_map.insert(std::make_pair(seqno, cmd));

    return seqno;
}

unsigned int kis_datasource::send_list_interfaces(unsigned int in_transaction, list_callback_t in_cb) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource send_list_interfaces");

    if (in_transaction == 0)
        in_transaction = next_transaction++;

    std::shared_ptr<tracked_command> cmd;
    uint32_t seqno;

    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_command("KDSLISTINTERFACES");

    KismetDatasource::ListInterfaces l;

    c->set_content(l.SerializeAsString());

    seqno = send_packet(c);

    if (seqno == 0) {
        if (in_cb != NULL) {
            in_cb(std::static_pointer_cast<kis_datasource>(shared_from_this()), in_transaction, std::vector<shared_interface>());
        }

        return 0;
    }

    cmd.reset(new tracked_command(in_transaction, seqno, this));
    cmd->list_cb = in_cb;

    command_ack_map.insert(std::make_pair(seqno, cmd));

    return seqno;
}


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

    std::stringstream ss;

    if (ping_timer_id > 0) {
        timetracker->remove_timer(ping_timer_id);
        ping_timer_id = -1;
    }

    // Do nothing if we don't handle retry
    if (get_source_remote()) {
        if (get_source_running()) {
            ss << "Source " << get_source_name() << " has encountered an error.  "
                "Remote sources are not locally reconnected; waiting for the remote source "
                "to reconnect to resume capture.";

            std::shared_ptr<alert_tracker> alertracker =
                Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");
            alertracker->raise_one_shot("SOURCEERROR", ss.str(), -1);

            _MSG(ss.str(), MSGFLAG_ERROR);
        }

        set_int_source_running(false);
        return;
    }

    if (!get_source_retry()) {
        if (get_source_running()) {
            ss << "Source " << get_source_name() << " has encountered an error but "
                "is not configured to automatically re-try opening; it will remain "
                "closed.";

            std::shared_ptr<alert_tracker> alertracker =
                Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");
            alertracker->raise_one_shot("SOURCEERROR", ss.str(), -1);

            _MSG(ss.str(), MSGFLAG_ERROR);
        }

        set_int_source_running(false);

        return;
    }
    
    set_int_source_running(false);

    // If we already have an error timer, we're thinking about restarting, 
    // be quiet about things; otherwise, talk about restarting, increment the
    // count, and set a timer
    if (error_timer_id <= 0) {

        // Increment our failures
        inc_int_source_retry_attempts(1);
        inc_int_source_total_retry_attempts(1);

        // Notify about it
        ss << "Source " << get_source_name() << " has encountered an error. "
            "Kismet will attempt to re-open the source in 5 seconds.  (" <<
            get_source_retry_attempts() << " failures)";

        std::shared_ptr<alert_tracker> alertracker =
            Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");
        alertracker->raise_one_shot("SOURCEERROR", ss.str(), -1);

        _MSG(ss.str(), MSGFLAG_ERROR);

        // Set a new event to try to re-open the interface
        error_timer_id = timetracker->register_timer(std::chrono::seconds(5), false, [this](int) -> int {
                kis_lock_guard<kis_mutex> lk(ext_mutex, "datasource error_timer lambda");

                error_timer_id = -1;

                _MSG("Attempting to re-open source " + get_source_name(), MSGFLAG_INFO);

                // Call open on the same sourceline, no transaction, no cb
                open_interface(get_source_definition(), 0, 
                        [this](int, bool success, std::string) {
                            if (!success)
                                return;

                            std::stringstream ss;

                            auto evt = eventbus->get_eventbus_event(event_datasource_opened());
                            evt->get_event_content()->insert(event_datasource_opened(), source_uuid);
                            eventbus->publish(evt);

                            ss << "Source " << get_source_name() << " successfully "
                                "re-opened";

                            std::shared_ptr<alert_tracker> alertracker =
                                Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");
                            alertracker->raise_one_shot("SOURCEOPEN", ss.str(), -1);

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

    ipc_soft_kill();

    set_int_source_ipc_pid(-1);

    external_binary = get_source_ipc_binary();

    if (run_ipc()) {
        set_int_source_ipc_pid(ipc.pid);
        return true;
    }

    _MSG_ERROR("Data source '{} / {}' could not launch IPC helper", get_source_name(), 
            get_source_definition());

    return false;
}

