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

#include <memory>
#include <sys/stat.h>

#include "configfile.h"

#include "json_adapter.h"

#include "kis_external.h"
#include "kis_external_packet.h"

#include "endian_magic.h"

#include "protobuf_cpp/kismet.pb.h"
#include "protobuf_cpp/http.pb.h"
#include "protobuf_cpp/eventbus.pb.h"

kis_external_interface::kis_external_interface() :
    buffer_interface(),
    kis_net_httpd_chain_stream_handler(),
    ext_mutex {std::make_shared<kis_recursive_timed_mutex>()},
    timetracker {Globalreg::fetch_mandatory_global_as<time_tracker>()},
    seqno {0},
    last_pong {0},
    ping_timer_id {-1},
    eventbus {Globalreg::fetch_mandatory_global_as<event_bus>()},
    http_bound{false},
    http_session_id{0} {
        
    bind_httpd_server();
}

kis_external_interface::kis_external_interface(std::shared_ptr<kis_recursive_timed_mutex> mutex) :
    buffer_interface(),
    kis_net_httpd_chain_stream_handler(),
    ext_mutex {mutex != nullptr ? mutex : std::make_shared<kis_recursive_timed_mutex>()},
    timetracker {Globalreg::fetch_mandatory_global_as<time_tracker>()},
    seqno {0},
    last_pong {0},
    ping_timer_id {-1},
    eventbus {Globalreg::fetch_mandatory_global_as<event_bus>()},
    http_session_id{0} {
    bind_httpd_server();
}

kis_external_interface::~kis_external_interface() {
    // Kill any eventbus listeners
    for (const auto& ebid : eventbus_callback_map)
        eventbus->remove_listener(ebid.second);

    // Kill any active http sessions
    for (auto s : http_proxy_session_map) {
        // Fail them
        s.second->connection->httpcode = 501;
        // Unlock them and let the cleanup in the thread handle it and close down 
        // the http server session
        s.second->locker->unlock();
    }

    timetracker->remove_timer(ping_timer_id);

    if (ipc_remote != nullptr) {
        ipc_remote->close_ipc();
    }

    // If we have a ringbuf handler, remove ourselves as the interface, trigger an error
    // to shut it down, and delete our shared reference to it
    if (ringbuf_handler != nullptr) {
        ringbuf_handler->remove_read_buffer_interface();
        ringbuf_handler->protocol_error();
    }

    ipc_remote.reset();
    ringbuf_handler.reset();

}

void kis_external_interface::connect_buffer(std::shared_ptr<buffer_handler_generic> in_ringbuf) {
    local_locker lock(ext_mutex);

    ringbuf_handler = in_ringbuf;
    ext_mutex = in_ringbuf->get_mutex();
    ringbuf_handler->set_read_buffer_interface(this);
}

void kis_external_interface::trigger_error(std::string in_error) {
    local_locker lock(ext_mutex);

    // Kill any eventbus listeners
    for (const auto& ebid : eventbus_callback_map)
        eventbus->remove_listener(ebid.second);

    // Kill any active http sessions
    for (auto s : http_proxy_session_map) {
        // Fail them
        s.second->connection->httpcode = 501;
        // Unlock them and let the cleanup in the thread handle it and close down 
        // the http server session
        s.second->locker->unlock();
    }

    timetracker->remove_timer(ping_timer_id);

    if (ipc_remote != nullptr) {
        ipc_remote->close_ipc();
    }

    // If we have a ringbuf handler, remove ourselves as the interface, trigger an error
    // to shut it down, and delete our shared reference to it
    if (ringbuf_handler != nullptr) {
        ringbuf_handler->remove_read_buffer_interface();
        ringbuf_handler->protocol_error();
    }

    // Remove the IPC remote reference
    ipc_remote.reset();
    ringbuf_handler.reset();

    buffer_error(in_error);
}

void kis_external_interface::buffer_available(size_t in_amt) {
    if (in_amt == 0)
        return;

    local_demand_locker lock(ext_mutex);
    lock.lock();

    kismet_external_frame_t *frame;
    uint32_t frame_sz, data_sz;
    uint32_t data_checksum;

    // Consume everything in the buffer that we can
    while (1) {
        if (ringbuf_handler == NULL)
            return;

        // See if we have enough to get a frame header
        size_t buffamt = ringbuf_handler->get_read_buffer_used();

        if (buffamt < sizeof(kismet_external_frame_t)) {
            return;
        }

        // Peek at the header
        buffamt = ringbuf_handler->peek_read_buffer_data((void **) &frame, buffamt);

        // Make sure we got the right amount
        if (buffamt < sizeof(kismet_external_frame_t)) {
            ringbuf_handler->peek_free_read_buffer_data(frame);
            return;
        }

        // Check the frame signature
        if (kis_ntoh32(frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
            ringbuf_handler->peek_free_read_buffer_data(frame);

            _MSG("Kismet external interface got command frame with invalid signature", MSGFLAG_ERROR);
            trigger_error("Invalid signature on command frame");

            return;
        }

        // Check the length
        data_sz = kis_ntoh32(frame->data_sz);
        frame_sz = data_sz + sizeof(kismet_external_frame);

        // If we'll never be able to read it, blow up
        if ((long int) frame_sz >= ringbuf_handler->get_read_buffer_size()) {
            ringbuf_handler->peek_free_read_buffer_data(frame);

            std::stringstream ss;

            ss << "Kismet external interface got command frame which is too large to "
                "be processed (" << frame_sz << " / " << 
                ringbuf_handler->get_read_buffer_available() << "), this can happen when you "
                "are using an old remote capture tool, make sure you have updated your "
                "systems.";

            _MSG(ss.str(), MSGFLAG_ERROR);
            trigger_error("Command frame too large for buffer");

            return;
        }

        // If we don't have the whole buffer available, bail on this read
        if (frame_sz > buffamt) {
            ringbuf_handler->peek_free_read_buffer_data(frame);
            // fprintf(stderr, "debug - external - read %lu needed %u\n", buffamt, frame_sz);
            return;
        }

        // We have a complete payload, checksum 
        data_checksum = adler32_checksum((const char *) frame->data, data_sz);

        if (data_checksum != kis_ntoh32(frame->data_checksum)) {
            ringbuf_handler->peek_free_read_buffer_data(frame);

            _MSG("Kismet external interface got command frame with invalid checksum",
                    MSGFLAG_ERROR);
            trigger_error("command frame has invalid checksum");

            return;
        }

        // Process the data payload as a protobuf frame
        std::shared_ptr<KismetExternal::Command> cmd(new KismetExternal::Command());

        if (!cmd->ParseFromArray(frame->data, data_sz)) {
            ringbuf_handler->peek_free_read_buffer_data(frame);

            _MSG("Kismet external interface could not interpret the payload of the "
                    "command frame", MSGFLAG_ERROR);
            trigger_error("unparsable command frame");

            return;
        }

        // fprintf(stderr, "debug - KISEXTERNALAPI got command '%s' seq %u sz %lu\n", cmd->command().c_str(), cmd->seqno(), cmd->content().length());

        // Consume the buffer now that we're done; we only consume the 
        // frame size because we could have peeked a much larger buffer
        ringbuf_handler->peek_free_read_buffer_data(frame);
        ringbuf_handler->consume_read_buffer_data(frame_sz);

        // Unlock before processing, individual commands will lock as needed
        lock.unlock();

        // Dispatch the received command
        dispatch_rx_packet(cmd);
    }
}

void kis_external_interface::buffer_error(std::string in_error) {
    // Try to read anything left in the buffer in case we're exiting w/ pending valid data
    buffer_available(0);
    
    close_external();
}

bool kis_external_interface::check_ipc(const std::string& in_binary) {
    struct stat fstat;

    std::vector<std::string> bin_paths = 
        Globalreg::globalreg->kismet_config->fetch_opt_vec("helper_binary_path");

    if (bin_paths.size() == 0) {
        bin_paths.push_back("%B");
    }

    for (auto rp : bin_paths) {
        std::string fp = fmt::format("{}/{}",
                Globalreg::globalreg->kismet_config->expand_log_path(rp, "", "", 0, 1),
                in_binary);

        if (stat(fp.c_str(), &fstat) != -1) {
            if (S_ISDIR(fstat.st_mode))
                continue;

            if ((S_IXUSR & fstat.st_mode))
                return true;
        }
    }

    return false;
}

bool kis_external_interface::run_ipc() {
    local_locker l(ext_mutex);

    std::stringstream ss;

    if (external_binary == "") {
        _MSG("Kismet external interface did not have an IPC binary to launch", MSGFLAG_ERROR);
        return false;
    }

    if (ipc_remote != nullptr) {
        ipc_remote->soft_kill();
    }

    if (ringbuf_handler != nullptr) {
        ringbuf_handler->remove_read_buffer_interface();
        ringbuf_handler->protocol_error();
    }

    ipc_buffer_sz = 
        Globalreg::globalreg->kismet_config->fetch_opt_as<size_t>("ipc_buffer_kb", 512);

    // Make a new handler and new ipc.  Give a generous buffer.  Give it our mutex so that all
    // future related objects inherit from us.
    ringbuf_handler = std::make_shared<buffer_handler<ringbuf_v2>>((ipc_buffer_sz * 1024), (ipc_buffer_sz * 1024), ext_mutex);
    ringbuf_handler->set_read_buffer_interface(this);

    ipc_remote.reset(new ipc_remote_v2(Globalreg::globalreg, ringbuf_handler));

    // Get allowed paths for binaries
    std::vector<std::string> bin_paths = 
        Globalreg::globalreg->kismet_config->fetch_opt_vec("helper_binary_path");

    if (bin_paths.size() == 0) {
        _MSG("No helper_binary_path found in kismet.conf, make sure your config "
                "files are up to date; using the default binary path where Kismet "
                "is installed.", MSGFLAG_ERROR);
        bin_paths.push_back("%B");
    }

    // Explode any expansion macros in the path and add it to the list we search
    for (auto i = bin_paths.begin(); i != bin_paths.end(); ++i) {
        ipc_remote->add_path(Globalreg::globalreg->kismet_config->expand_log_path(*i, "", "", 0, 1));
    }

    int ret = ipc_remote->launch_kis_binary(external_binary, external_binary_args);

    if (ret < 0) {
        ss.str("");
        ss << "failed to launch IPC binary '" << external_binary << "'";
        trigger_error(ss.str());
        return false;
    }

    auto remotehandler = 
        Globalreg::fetch_mandatory_global_as<ipc_remote_v2_tracker>("IPCHANDLER");
    remotehandler->add_ipc(ipc_remote);

    return true;
}

void kis_external_interface::close_external() {
    local_locker lock(ext_mutex);

    timetracker->remove_timer(ping_timer_id);

    if (ipc_remote != nullptr) {
        ipc_remote->soft_kill();
    }

    if (ringbuf_handler != nullptr) {
        ringbuf_handler->remove_read_buffer_interface();
        ringbuf_handler->protocol_error();
    }

    ipc_remote.reset();
    ringbuf_handler.reset();
}

unsigned int kis_external_interface::send_packet(std::shared_ptr<KismetExternal::Command> c) {
    local_locker lock(ext_mutex);

    if (ringbuf_handler == NULL)
        return 0;

    // Set the sequence if one wasn't provided
    if (c->seqno() == 0) {
        if (++seqno == 0)
            seqno = 1;

        c->set_seqno(seqno);
    }

    uint32_t data_csum;

    // Get the serialized size of our message
    size_t content_sz = c->ByteSize();

    // Calc frame size
    ssize_t frame_sz = sizeof(kismet_external_frame_t) + content_sz;

    // Our actual frame
    kismet_external_frame_t *frame = nullptr;

    // Reserve the frame in the buffer
    if (ringbuf_handler->reserve_write_buffer_data((void **) &frame, frame_sz) < frame_sz || frame == nullptr) {
        if (frame != nullptr) {
            ringbuf_handler->commit_write_buffer_data(NULL, 0);
        }

        _MSG("Kismet external interface couldn't find space in the output buffer for "
                "the next command, something may have stalled.", MSGFLAG_ERROR);
        trigger_error("write buffer full");

        return 0;
    }

    // Fill in the headers
    frame->signature = kis_hton32(KIS_EXTERNAL_PROTO_SIG);
    frame->data_sz = kis_hton32(content_sz);

    // serialize into our array
    c->SerializeToArray(frame->data, content_sz);

    // Calculate the checksum and set it in the frame
    data_csum = adler32_checksum((const char *) frame->data, content_sz); 
    frame->data_checksum = kis_hton32(data_csum);

    // Commit our write buffer
    ringbuf_handler->commit_write_buffer_data((void *) frame, frame_sz);

    return c->seqno();
}

bool kis_external_interface::dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c) {
    // Simple dispatcher; this should be called by child implementations who
    // add their own commands
    if (c->command() == "MESSAGE") {
        handle_packet_message(c->seqno(), c->content());
        return true;
    } else if (c->command() == "PING") {
        handle_packet_ping(c->seqno(), c->content());
        return true;
    } else if (c->command() == "PONG") {
        handle_packet_pong(c->seqno(), c->content());
        return true;
    } else if (c->command() == "SHUTDOWN") {
        handle_packet_shutdown(c->seqno(), c->content());
        return true;
    } else if (c->command() == "HTTPREGISTERURI") {
        handle_packet_http_register(c->seqno(), c->content());
        return true;
    } else if (c->command() == "HTTPRESPONSE") {
        handle_packet_http_response(c->seqno(), c->content());
        return true;
    } else if (c->command() == "HTTPAUTHREQ") {
        handle_packet_http_auth_request(c->seqno(), c->content());
        return true;
    } else if (c->command() == "EVENTBUSREGISTER") {
        handle_packet_eventbus_register(c->seqno(), c->content());
        return true;
    } else if (c->command() == "EVENTBUSPUBLISH") {
        handle_packet_eventbus_publish(c->seqno(), c->content());
        return true;
    }

    return false;
}

void kis_external_interface::handle_packet_message(uint32_t in_seqno, const std::string& in_content) {
    KismetExternal::MsgbusMessage m;

    if (!m.ParseFromString(in_content)) {
        _MSG("Kismet external interface got an unparsable MESSAGE", MSGFLAG_ERROR);
        trigger_error("Invalid MESSAGE");
        return;
    }

    handle_msg_proxy(m.msgtext(), m.msgtype());
}

void kis_external_interface::handle_msg_proxy(const std::string& msg, const int msgtype) {
    _MSG(msg, msgtype);
}

void kis_external_interface::handle_packet_ping(uint32_t in_seqno, const std::string& in_content) {
    send_pong(in_seqno);
}

void kis_external_interface::handle_packet_pong(uint32_t in_seqno, const std::string& in_content) {
    local_locker lock(ext_mutex);

    KismetExternal::Pong p;
    if (!p.ParseFromString(in_content)) {
        _MSG("Kismet external interface got an unparsable PONG packet", MSGFLAG_ERROR);
        trigger_error("Invalid PONG");
        return;
    }

    last_pong = time(0);
}

void kis_external_interface::handle_packet_shutdown(uint32_t in_seqno, const std::string& in_content) {
    local_locker lock(ext_mutex);

    KismetExternal::ExternalShutdown s;
    if (!s.ParseFromString(in_content)) {
        _MSG("Kismet external interface got an unparsable SHUTDOWN", MSGFLAG_ERROR);
        trigger_error("invalid SHUTDOWN");
        return;
    }

    _MSG(std::string("Kismet external interface shutting down: ") + s.reason(), MSGFLAG_INFO); 
    trigger_error(std::string("Remote connection requesting shutdown: ") + s.reason());
}

unsigned int kis_external_interface::send_ping() {
    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_command("PING");

    KismetExternal::Ping p;
    c->set_content(p.SerializeAsString());

    return send_packet(c);
}

unsigned int kis_external_interface::send_pong(uint32_t ping_seqno) {
    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_command("PONG");

    KismetExternal::Pong p;
    p.set_ping_seqno(ping_seqno);

    c->set_content(p.SerializeAsString());

    return send_packet(c);
}

unsigned int kis_external_interface::send_shutdown(std::string reason) {
    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_command("SHUTDOWN");

    KismetExternal::ExternalShutdown s;
    s.set_reason(reason);

    c->set_content(s.SerializeAsString());

    return send_packet(c);
}

void kis_external_interface::proxy_event(std::shared_ptr<eventbus_event> evt) {
    auto c = std::make_shared<KismetExternal::Command>();

    c->set_command("EVENT");

    std::stringstream ss;

    json_adapter::pack(ss, evt);

    KismetEventBus::EventbusEvent ebe;
    ebe.set_event_json(ss.str());

    c->set_content(ebe.SerializeAsString());

    send_packet(c);
}

void kis_external_interface::handle_packet_eventbus_register(uint32_t in_seqno,
        const std::string& in_content) {
    local_locker lock(ext_mutex, "kis_external_interface::handle_packet_eventbus_register");

    KismetEventBus::EventbusRegisterListener evtlisten;

    if (!evtlisten.ParseFromString(in_content)) {
        _MSG_ERROR("Kismet external interface got an unparseable EVENTBUSREGISTER");
        trigger_error("Invalid EVENTBUSREGISTER");
        return;
    }

    for (int e = 0; e < evtlisten.event_size(); e++) {
        auto k = eventbus_callback_map.find(evtlisten.event(e));

        if (k != eventbus_callback_map.end())
            eventbus->remove_listener(k->second);

        unsigned long eid = 
            eventbus->register_listener(evtlisten.event(e), 
                    [this](std::shared_ptr<eventbus_event> e) {
                    proxy_event(e);
                    });

        eventbus_callback_map[evtlisten.event(e)] = eid;
    }
}

void kis_external_interface::handle_packet_eventbus_publish(uint32_t in_seqno,
        const std::string& in_content) {
    local_locker lock(ext_mutex, "kis_external_interface::handle_packet_eventbus_publish");
    
    KismetEventBus::EventbusPublishEvent evtpub;

    if (!evtpub.ParseFromString(in_content)) {
        _MSG_ERROR("Kismet external interface got unparseable EVENTBUSPUBLISH");
        trigger_error("Invalid EVENTBUSPUBLISH");
        return;
    }

    auto evt = eventbus->get_eventbus_event(evtpub.event_type());
    evt->get_event_content()->insert("kismet.eventbus.event_json",
            std::make_shared<tracker_element_string>(evtpub.event_content_json()));
    eventbus->publish(evt);
}

void kis_external_interface::handle_packet_http_register(uint32_t in_seqno, 
        const std::string& in_content) {
    local_locker lock(ext_mutex);

    if (!http_bound) {
        http_bound = true;
        bind_httpd_server();
    }

    KismetExternalHttp::HttpRegisterUri uri;

    if (!uri.ParseFromString(in_content)) {
        _MSG("Kismet external interface got an unparsable HTTPREGISTERURI", MSGFLAG_ERROR);
        trigger_error("Invalid HTTPREGISTERURI");
        return;
    }

    struct kis_external_http_uri *exturi = new kis_external_http_uri();
    
    exturi->uri = uri.uri();
    exturi->method = uri.method();

    // Add it to the map of valid URIs
    http_proxy_uri_map[exturi->method].push_back(exturi);
}

void kis_external_interface::handle_packet_http_response(uint32_t in_seqno, 
        const std::string& in_content) {
    local_locker lock(ext_mutex);

    KismetExternalHttp::HttpResponse resp;

    if (!resp.ParseFromString(in_content)) {
        _MSG("Kismet external interface got an unparsable HTTPRESPONSE", MSGFLAG_ERROR);
        trigger_error("Invalid  HTTPRESPONSE");
        return;
    }

    auto si = http_proxy_session_map.find(resp.req_id());

    if (si == http_proxy_session_map.end()) {
        _MSG("Kismet external interface got a HTTPRESPONSE for an unknown session", MSGFLAG_ERROR);
        trigger_error("Invalid HTTPRESPONSE session");
        return;
    }

    auto session = si->second;

    kis_net_httpd_buffer_stream_aux *saux = 
        (kis_net_httpd_buffer_stream_aux *) session->connection->custom_extension;

    // First off, process any headers we're trying to add, they need to come 
    // before data
    for (int hi = 0; hi < resp.header_content_size() && resp.header_content_size() > 0; hi++) {
        KismetExternalHttp::SubHttpHeader hh = resp.header_content(hi);

        MHD_add_response_header(session->connection->response, hh.header().c_str(), 
                hh.content().c_str());
    }

    // Set any connection state
    if (resp.has_resultcode()) {
        session->connection->httpcode = resp.has_resultcode();
    }

    // Copy any response data
    if (resp.has_content() && resp.content().size() > 0) {
        if (!saux->ringbuf_handler->put_write_buffer_data(resp.content())) {
            _MSG("Kismet external interface could not put response data into the HTTP "
                    "buffer for a HTTPRESPONSE session", MSGFLAG_ERROR);
            // We have to kill this session before we shut down everything else
            session->connection->httpcode = 501;
            session->locker->unlock();
            trigger_error("Unable to write to HTTP buffer in HTTPRESPONSE");
            return;
        }
    }

    // Are we finishing the connection?
    if (resp.has_close_response() && resp.close_response()) {
        // Unlock this session
        session->locker->unlock();
    }
}

void kis_external_interface::handle_packet_http_auth_request(uint32_t in_seqno, 
        const std::string& in_content) {
    KismetExternalHttp::HttpAuthTokenRequest rt;

    if (!rt.ParseFromString(in_content)) {
        _MSG("Kismet external interface got an unparsable HTTPAUTHREQ", MSGFLAG_ERROR);
        trigger_error("Invalid HTTPAUTHREQ");
        return;
    }

    std::shared_ptr<kis_net_httpd_session> s = httpd->create_session(NULL, NULL, 0);

    if (s == NULL) {
        _MSG("Kismet external interface unable to create a HTTP auth", MSGFLAG_ERROR);
        trigger_error("Unable to create HTTP auth");
        return;
    }

    send_http_auth(s->sessionid);
}

unsigned int kis_external_interface::send_http_request(uint32_t in_http_sequence, std::string in_uri,
        std::string in_method, std::map<std::string, std::string> in_vardata) {
    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_command("HTTPREQUEST");

    KismetExternalHttp::HttpRequest r;
    r.set_req_id(in_http_sequence);
    r.set_uri(in_uri);
    r.set_method(in_method);

    for (auto pi : in_vardata) {
        KismetExternalHttp::SubHttpVariableData *pd = r.add_variable_data();
        pd->set_field(pi.first);
        pd->set_content(pi.second);
    }

    c->set_content(r.SerializeAsString());

    return send_packet(c);
}

unsigned int kis_external_interface::send_http_auth(std::string in_cookie) {
    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_command("HTTPAUTH");

    KismetExternalHttp::HttpAuthToken a;
    a.set_token(in_cookie);

    c->set_content(a.SerializeAsString());

    return send_packet(c);
}

bool kis_external_interface::httpd_verify_path(const char *path, const char *method) {
    local_locker lock(ext_mutex);

    // Find all the registered endpoints for this method
    auto m = http_proxy_uri_map.find(std::string(method));

    if (m == http_proxy_uri_map.end())
        return false;

    // If an endpoint matches, we're good
    for (auto e : m->second) {
        if (e->uri == std::string(path)) {
            return true;
        }
    }

    return false;
}

// When this function gets called, we're inside a thread for the HTTP server;
// additionally, the HTTP server has it's own thread servicing the chainbuffer
// on the backend of this connection;
//
// Because we are, ourselves, async waiting for the responses from the proxied
// tool, we need to set a lock and sit on it until the proxy has completed.
// We don't need to spawn our own thread - we're already our own thread independent
// of the IO processing system.
KIS_MHD_RETURN kis_external_interface::httpd_create_stream_response(kis_net_httpd *httpd,
        kis_net_httpd_connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    // Use a demand locker instead of pure scope locker because we need to let it go
    // before we go into blocking wait
    local_demand_locker dlock(ext_mutex);
    dlock.lock();

    auto m = http_proxy_uri_map.find(std::string(method));

    if (m == http_proxy_uri_map.end()) {
        connection->httpcode = 501;
        return MHD_YES;
    }

    std::map<std::string, std::string> get_remap;
    for (auto v : connection->variable_cache) 
        get_remap[v.first] = v.second->str();

    for (auto e : m->second) {
        if (e->uri == std::string(url)) {
            // Make a session
            std::shared_ptr<kis_external_http_session> s(new kis_external_http_session());
            s->connection = connection;
            // Lock the waitlock
            s->locker.reset(new conditional_locker<int>());
            s->locker->lock();

            // Log the session number
            uint32_t sess_id = http_session_id++;
            http_proxy_session_map[sess_id] = s;

            // Send the proxy response
            send_http_request(sess_id, connection->url, std::string(method), get_remap);

            // Unlock the demand locker
            dlock.unlock();

            // Block until the external tool sends a connection end; all of the writing
            // to the stream will be handled inside the handle_http_response handler
            // and it will unlock us when we've gotten to the end of the stream.
            s->locker->block_until();

            // Re-acquire the lock
            dlock.lock();

            // Remove the session from our map
            auto mi = http_proxy_session_map.find(sess_id);
            if (mi != http_proxy_session_map.end())
                http_proxy_session_map.erase(mi);

            // The session code should have been set already here so we don't have anything
            // else to do except tell the webserver we're done and let our session
            // de-scope as we exit...
            return MHD_YES;
        }
    }

    connection->httpcode = 501;
    return MHD_YES;
}

KIS_MHD_RETURN kis_external_interface::httpd_post_complete(kis_net_httpd_connection *connection) {
    auto m = http_proxy_uri_map.find(std::string("POST"));

    if (m == http_proxy_uri_map.end()) {
        connection->httpcode = 501;
        return MHD_YES;
    }

    // Use a demand locker instead of pure scope locker because we need to let it go
    // before we go into blocking wait
    local_demand_locker dlock(ext_mutex);
    dlock.lock();

    std::map<std::string, std::string> get_remap;
    for (auto v : connection->variable_cache) 
        get_remap[v.first] = v.second->str();

    for (auto e : m->second) {
        if (e->uri == std::string(connection->url)) {
            // Make a session
            std::shared_ptr<kis_external_http_session> s(new kis_external_http_session());
            s->connection = connection;
            // Lock the waitlock
            s->locker.reset(new conditional_locker<int>());
            s->locker->lock();

            // Log the session number
            uint32_t sess_id = http_session_id++;
            http_proxy_session_map[sess_id] = s;

            // Send the proxy response
            send_http_request(sess_id, connection->url, std::string{"POST"}, get_remap);

            // Unlock the demand locker
            dlock.unlock();

            // Block until the external tool sends a connection end; all of the writing
            // to the stream will be handled inside the handle_http_response handler
            // and it will unlock us when we've gotten to the end of the stream.
            s->locker->block_until();

            // Re-acquire the lock
            dlock.lock();

            // Remove the session from our map
            auto mi = http_proxy_session_map.find(sess_id);
            if (mi != http_proxy_session_map.end())
                http_proxy_session_map.erase(mi);

            // The session code should have been set already here so we don't have anything
            // else to do except tell the webserver we're done and let our session
            // de-scope as we exit...
            return MHD_YES;
        }
    }

    connection->httpcode = 501;
    return MHD_YES;
}

