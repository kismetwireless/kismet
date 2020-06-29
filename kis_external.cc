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

#include "kis_external.h"
#include "kis_external_packet.h"

#include "endian_magic.h"

#include "protobuf_cpp/kismet.pb.h"
#include "protobuf_cpp/http.pb.h"

kis_external_interface::kis_external_interface() :
    timetracker {Globalreg::fetch_mandatory_global_as<time_tracker>()},
    seqno {0},
    last_pong {0},
    ping_timer_id {-1} { }

kis_external_interface::~kis_external_interface() {
    timetracker->remove_timer(ping_timer_id);

    if (ipc_remote != nullptr) {
        ipc_remote->close_ipc();
    }

    if (extern_io_thread.joinable())
        extern_io_thread.join();
}

void kis_external_interface::connect_pair(std::shared_ptr<buffer_pair> in_pair) {
    bufferpair = in_pair;
}

bool kis_external_interface::run_ipc() {
    std::stringstream ss;

    if (external_binary == "") {
        _MSG("Kismet external interface did not have an IPC binary to launch", MSGFLAG_ERROR);
        return false;
    }

    if (ipc_remote != nullptr) {
        ipc_remote->soft_kill();
    }

    /* We shouldn't need to force an exception into the waiting thread because closing it out will 
     * cause that...
     */
    if (bufferpair != nullptr) {
        try {
            throw std::runtime_error("re-opening IPC");
        } catch (const std::exception& e) {
            bufferpair->throw_error(std::current_exception());
        }

        bufferpair.reset();
    }

    ipc_buffer_sz = 
        Globalreg::globalreg->kismet_config->fetch_opt_as<size_t>("ipc_buffer_kb", 512);

    bufferpair = std::make_shared<buffer_pair>(
            std::make_shared<ringbuf_v2>(ipc_buffer_sz * 1024),
            std::make_shared<ringbuf_v2>(ipc_buffer_sz * 1024)
            );

    ipc_remote.reset(new ipc_remote_v2(bufferpair));

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
        _MSG_ERROR("External API IPC failed to launch IPC binary {}", external_binary);
        return false;
    }

    auto remotehandler = 
        Globalreg::fetch_mandatory_global_as<ipc_remote_v2_tracker>("IPCHANDLER");
    remotehandler->add_ipc(ipc_remote);

    return true;
}

void kis_external_interface::extern_io() {
    bool first = true;

    while (1) {
        try {
            if (bufferpair == nullptr)
                throw std::runtime_error("external interface external io launched with no buffer pair");

            kismet_external_frame_t *frame;
            uint32_t frame_sz, data_sz;
            uint32_t data_checksum;

            if (!first)
                bufferpair->new_available_block_rbuf(std::chrono::seconds(10));

            first = false;

            char *buf;

            auto buf_sz =
                bufferpair->peek_block_rbuf(&buf, sizeof(kismet_external_frame_t), std::chrono::seconds(10));

            frame = reinterpret_cast<kismet_external_frame_t *>(buf);

            // Check the frame signature
            if (kis_ntoh32(frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
                bufferpair->peek_free_rbuf(buf);

                throw std::runtime_error("External API interface got command frame with invalid signature.");
            }

            data_sz = kis_ntoh32(frame->data_sz);
            frame_sz = data_sz + sizeof(kismet_external_frame_t);

            // If we'll never be able to read it, blow up
            if ((long int) frame_sz >= bufferpair->size_rbuf()) {
                bufferpair->peek_free_rbuf(buf);

                throw std::runtime_error(fmt::format("External API interface got command frame which is too "
                            "large to be processed ({}, max {}), this can happen if you are using a very "
                            "old capture tool, make sure you have updated both Kismet and any drone or "
                            "remote capture tools.", frame_sz, bufferpair->size_rbuf()));
            }

            // Blocking spin waiting for the rest of the packet
            if (frame_sz > buf_sz) {
                bufferpair->peek_free_rbuf(buf);

                buf_sz =
                    bufferpair->peek_block_rbuf(&buf, sizeof(kismet_external_frame_t), std::chrono::seconds(0));

                if (buf_sz < frame_sz)
                    throw std::runtime_error("External API interface tried to fetch the full frame, "
                            "but something went wrong.");

                frame = reinterpret_cast<kismet_external_frame_t *>(buf);
            }

            // We have a complete payload, checksum 
            data_checksum = adler32_checksum((const char *) frame->data, data_sz);

            if (data_checksum != kis_ntoh32(frame->data_checksum)) {
                bufferpair->peek_free_rbuf(buf);
                throw std::runtime_error("External API interface got command frame with invalid checksum");
            }

            // Process the data payload as a protobuf frame
            std::shared_ptr<KismetExternal::Command> cmd(new KismetExternal::Command());

            if (!cmd->ParseFromArray(frame->data, data_sz)) {
                bufferpair->peek_free_rbuf(buf);
                throw std::runtime_error("External API could not interpret payload of the frame");
            }

            bufferpair->peek_free_rbuf(buf);
            bufferpair->consume_rbuf(frame_sz);

            dispatch_rx_packet(cmd);
        } catch (const common_buffer_timeout& e) {
            _MSG_ERROR("External interface got no data in 30 seconds, disconnecting.");

            timetracker->remove_timer(ping_timer_id);

            if (ipc_remote != nullptr) {
                ipc_remote->close_ipc();
            }

            break;
        } catch (const common_buffer_close& e) {
            _MSG_INFO("External interface IPC closed: {}", e.what());

           timetracker->remove_timer(ping_timer_id);

           if (ipc_remote != nullptr) {
               ipc_remote->close_ipc();
           }

           break;

        } catch (const std::exception& e) {
            _MSG_ERROR("External interface connection lost: {}", e.what());

            timetracker->remove_timer(ping_timer_id);

            if (ipc_remote != nullptr) {
                ipc_remote->close_ipc();
            }
        }
    }

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

void kis_external_interface::close_external() {
    timetracker->remove_timer(ping_timer_id);

    if (bufferpair != nullptr)
        bufferpair->close("external API closing");

    // Kill and close IPC channel
    if (ipc_remote != nullptr) 
        ipc_remote->soft_kill();

    if (extern_io_thread.joinable())
        extern_io_thread.join();

}

unsigned int kis_external_interface::send_packet(std::shared_ptr<KismetExternal::Command> c) {
    if (bufferpair == nullptr)
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

    char *buf = nullptr;

    // Our actual frame
    kismet_external_frame_t *frame = nullptr;

    // Reserve the frame in the buffer
    if (bufferpair->reserve_wbuf(&buf, frame_sz) < frame_sz || buf == nullptr) {
        if (buf!= nullptr) 
            bufferpair->commit_wbuf(buf, 0);

        _MSG("Kismet external interface couldn't find space in the output buffer for "
                "the next command, something may have stalled.", MSGFLAG_ERROR);

        return 0;
    }

    frame = reinterpret_cast<kismet_external_frame_t *>(buf);

    // Fill in the headers
    frame->signature = kis_hton32(KIS_EXTERNAL_PROTO_SIG);
    frame->data_sz = kis_hton32(content_sz);

    // serialize into our array
    c->SerializeToArray(frame->data, content_sz);

    // Calculate the checksum and set it in the frame
    data_csum = adler32_checksum((const char *) frame->data, content_sz); 
    frame->data_checksum = kis_hton32(data_csum);

    // Commit our write buffer
    bufferpair->commit_wbuf(buf, frame_sz);

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
    }

    return false;
}

void kis_external_interface::handle_packet_message(uint32_t in_seqno, const std::string& in_content) {
    KismetExternal::MsgbusMessage m;

    if (!m.ParseFromString(in_content))
        throw std::runtime_error("External API received an unparseable MESSAGE packet");


    handle_msg_proxy(m.msgtext(), m.msgtype());
}

void kis_external_interface::handle_packet_ping(uint32_t in_seqno, const std::string& in_content) {
    send_pong(in_seqno);
}

void kis_external_interface::handle_packet_pong(uint32_t in_seqno, const std::string& in_content) {
    KismetExternal::Pong p;
    if (!p.ParseFromString(in_content))
        throw std::runtime_error("External API received an unparseable PONG packet");

    last_pong = time(0);
}

void kis_external_interface::handle_packet_shutdown(uint32_t in_seqno, const std::string& in_content) {
    KismetExternal::ExternalShutdown s;
    if (!s.ParseFromString(in_content))
        throw std::runtime_error("External API received an unparseable SHUTDOWN packet");

    throw std::runtime_error(fmt::format("Shutting down external API connection: {}", s.reason()));
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

kis_external_http_interface::kis_external_http_interface() :
    kis_external_interface(), 
    kis_net_httpd_chain_stream_handler() {

    mutex.set_name("kis_external_http_interface");

    http_session_id = 0;

    bind_httpd_server();
}

kis_external_http_interface::~kis_external_http_interface() {
    // Kill any active sessions
    for (auto s : http_proxy_session_map) {
        // Fail them
        s.second->connection->httpcode = 501;
        // Unlock them and let the cleanup in the thread handle it and close down 
        // the http server session
        s.second->locker->unlock();
    }
}

bool kis_external_http_interface::dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c) {
    if (kis_external_interface::dispatch_rx_packet(c))
        return true;

    if (c->command() == "HTTPREGISTERURI") {
        handle_packet_http_register(c->seqno(), c->content());
        return true;
    } else if (c->command() == "HTTPRESPONSE") {
        handle_packet_http_response(c->seqno(), c->content());
        return true;
    } else if (c->command() == "HTTPAUTHREQ") {
        handle_packet_http_auth_request(c->seqno(), c->content());
        return true;
    }

    return false;
}

void kis_external_http_interface::handle_msg_proxy(const std::string& msg, const int msgtype) {
    _MSG(msg, msgtype);
}

void kis_external_http_interface::handle_packet_http_register(uint32_t in_seqno, 
        const std::string& in_content) {
    local_locker lock(&mutex, "handle_packet_http_register");

    KismetExternalHttp::HttpRegisterUri uri;

    if (!uri.ParseFromString(in_content))
        throw std::runtime_error("External API got an unparseable HTTPREGISTERURI");

    struct kis_external_http_uri *exturi = new kis_external_http_uri();
    
    exturi->uri = uri.uri();
    exturi->method = uri.method();

    // Add it to the map of valid URIs
    http_proxy_uri_map[exturi->method].push_back(exturi);
}

void kis_external_http_interface::handle_packet_http_response(uint32_t in_seqno, 
        const std::string& in_content) {
    local_locker lock(&mutex, "handle_packet_http_response");

    KismetExternalHttp::HttpResponse resp;

    if (!resp.ParseFromString(in_content)) 
        throw std::runtime_error("External API got an unparseable HTTPRESPONSE");

    auto si = http_proxy_session_map.find(resp.req_id());

    if (si == http_proxy_session_map.end())
        throw std::runtime_error("External API got a HTTPRESPONSE for an unknown session");

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
        if (!saux->buf_handler->write_wbuf(resp.content())) {
            _MSG("Kismet external interface could not put response data into the HTTP "
                    "buffer for a HTTPRESPONSE session", MSGFLAG_ERROR);
            // We have to kill this session before we shut down everything else
            session->connection->httpcode = 501;
            session->locker->unlock();
            
            throw std::runtime_error("External API unable to write to HTTP buffer for HTTPRESPONSE");
        }
    }

    // Are we finishing the connection?
    if (resp.has_close_response() && resp.close_response()) {
        // Unlock this session
        session->locker->unlock();
    }
}

void kis_external_http_interface::handle_packet_http_auth_request(uint32_t in_seqno, 
        const std::string& in_content) {
    KismetExternalHttp::HttpAuthTokenRequest rt;

    if (!rt.ParseFromString(in_content))
        throw std::runtime_error("External API got an unparseable HTTPAUTHREQ packet");

    std::shared_ptr<kis_net_httpd_session> s = httpd->create_session(NULL, NULL, 0);

    if (s == NULL) 
        throw std::runtime_error("External API unable to create a HTTP AUTH token");

    send_http_auth(s->sessionid);
}

unsigned int kis_external_http_interface::send_http_request(uint32_t in_http_sequence, std::string in_uri,
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

unsigned int kis_external_http_interface::send_http_auth(std::string in_cookie) {
    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_command("HTTPAUTH");

    KismetExternalHttp::HttpAuthToken a;
    a.set_token(in_cookie);

    c->set_content(a.SerializeAsString());

    return send_packet(c);
}

bool kis_external_http_interface::httpd_verify_path(const char *path, const char *method) {
    local_locker lock(&mutex, "kis_external_http_interface::httpd_verify_path");

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
int kis_external_http_interface::httpd_create_stream_response(kis_net_httpd *httpd,
        kis_net_httpd_connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    // Use a demand locker instead of pure scope locker because we need to let it go
    // before we go into blocking wait
    local_demand_locker dlock(&mutex, "kis_external_http_interface::httpd_create_stream_response");
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

int kis_external_http_interface::httpd_post_complete(kis_net_httpd_connection *connection) {
    auto m = http_proxy_uri_map.find(std::string("POST"));

    if (m == http_proxy_uri_map.end()) {
        connection->httpcode = 501;
        return MHD_YES;
    }

    // Use a demand locker instead of pure scope locker because we need to let it go
    // before we go into blocking wait
    local_demand_locker dlock(&mutex, "kis_external_http_interface::httpd_post_complete");
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

    return 0;
}

