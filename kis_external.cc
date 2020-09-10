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

#include "timetracker.h"
#include "messagebus.h"

#include "protobuf_cpp/kismet.pb.h"
#include "protobuf_cpp/http.pb.h"
#include "protobuf_cpp/eventbus.pb.h"

kis_external_interface::kis_external_interface() :
    kis_net_httpd_chain_stream_handler(),
    stopped{true},
    timetracker{Globalreg::fetch_mandatory_global_as<time_tracker>()},
    ipctracker{Globalreg::fetch_mandatory_global_as<ipc_tracker_v2>()},
    seqno{0},
    last_pong{0},
    ping_timer_id{-1},
    ipc_in{Globalreg::globalreg->io},
    ipc_out{Globalreg::globalreg->io},
    tcpsocket{Globalreg::globalreg->io},
    eventbus{Globalreg::fetch_mandatory_global_as<event_bus>()},
    http_session_id{0} {

    ext_mutex.set_name("kis_external_interface");
    bind_httpd_server();
}

kis_external_interface::~kis_external_interface() {
    close_external();
}

bool kis_external_interface::attach_tcp_socket(tcp::socket& socket) {
    local_locker l(&ext_mutex, "kei:attach_tcp_socket");

    stopped = true;
    in_buf.consume(in_buf.size());

    if (ipc.pid > 0) {
        _MSG_ERROR("Tried to attach a TCP socket to an external endpoint that already has "
                "an IPC instance running.");
        return false;
    }

    tcpsocket = std::move(socket);

    stopped = false;

    start_tcp_read();

    return true;
}

void kis_external_interface::close_external() {
    stopped = true;
    cancelled = true;

    local_locker l(&ext_mutex, "kei::close");

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

    ipc_hard_kill();

    if (tcpsocket.is_open()) {
        try {
            tcpsocket.cancel();
            tcpsocket.close();
        } catch (const std::exception& e) {
            ;
        }
    }
};

void kis_external_interface::ipc_soft_kill() {
    stopped = true;
    cancelled = true;

    if (ipc_in.is_open()) {
        try {
            ipc_in.cancel();
            ipc_in.close();
        } catch (const std::exception& e) {
            ;
        }
    }

    if (ipc_out.is_open()) {
        try {
            ipc_out.cancel();
            ipc_out.close();
        } catch (const std::exception& e) {
            ;
        }
    }

    if (ipc.pid > 0) {
        ipctracker->remove_ipc(ipc.pid);
        kill(ipc.pid, SIGTERM);
    }
}

void kis_external_interface::ipc_hard_kill() {
    stopped = true;
    cancelled = true;

    if (ipc_in.is_open()) {
        try {
            ipc_in.cancel();
            ipc_in.close();
        } catch (const std::exception& e) {
            ;
        }
    }

    if (ipc_out.is_open()) {
        try {
            ipc_out.cancel();
            ipc_out.close();
        } catch (const std::exception& e) {
            ;
        }
    }

    if (ipc.pid > 0) {
        ipctracker->remove_ipc(ipc.pid);
        kill(ipc.pid, SIGKILL);
    }

}

void kis_external_interface::trigger_error(const std::string& in_error) {
    local_locker lock(&ext_mutex, "kei::trigger_error");

    // Don't loop if we're already stopped
    if (stopped)
        return;

    handle_error(in_error);

    close_external();
}

void kis_external_interface::start_ipc_read() {
    if (stopped)
        return;

    asio::async_read(ipc_in, in_buf,
            asio::transfer_at_least(sizeof(kismet_external_frame_t)),
            [this](const std::error_code& ec, std::size_t t) {
            if (handle_read(ec, t) > 0)
                start_ipc_read();
            });
}

void kis_external_interface::start_tcp_read() {
    if (stopped)
        return;

    asio::async_read(tcpsocket, in_buf,
            asio::transfer_at_least(sizeof(kismet_external_frame_t)),
            [this](const std::error_code& ec, std::size_t t) {
            if (handle_read(ec, t) >= 0)
                start_tcp_read();
            });
}

int kis_external_interface::handle_read(const std::error_code& ec, size_t in_amt) {
    if (stopped)
        return 0;

    if (cancelled)
        close_external();

    if (ec) {
        // Exit on aborted errors, we've already been cancelled and this socket is closing out
        if (ec.value() == asio::error::operation_aborted)
            return -1;

        _MSG_ERROR("External API handler got error reading data: {}", ec.message());
        
        trigger_error(ec.message());

        return -1;
    }

    local_demand_locker lock(&ext_mutex, "kei::handle_read");
    lock.lock();

    const kismet_external_frame_t *frame;
    uint32_t frame_sz, data_sz;
    uint32_t data_checksum;

    // Consume everything in the buffer that we can
    while (1) {
        // See if we have enough to get a frame header
        size_t buffamt = in_buf.size();

        if (buffamt < sizeof(kismet_external_frame_t)) {
            return 1;
        }

        frame = asio::buffer_cast<const kismet_external_frame_t *>(in_buf.data());

        // Check the frame signature
        if (kis_ntoh32(frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
            _MSG_ERROR("Kismet external interface got command frame with invalid signature");
            trigger_error("Invalid signature on command frame");
            return -1;
        }

        // Check the length
        data_sz = kis_ntoh32(frame->data_sz);
        frame_sz = data_sz + sizeof(kismet_external_frame);

        // If we've got a bogus length, blow it up.  Anything over 8k is assumed to be insane.
        if ((long int) frame_sz >= 8192) {
            _MSG_ERROR("Kismet external interface got a command frame which is too large to "
                    "be processed ({}); either the frame is malformed or you are connecting to "
                    "a legacy Kismet remote capture drone; make sure you have updated to modern "
                    "Kismet on all connected systems.", frame_sz);
            trigger_error("Command frame too large for buffer");
            return -1;
        }

        // If we don't have the whole buffer available, bail on this read
        if (frame_sz > buffamt) {
            return 1;
        }

        // We have a complete payload, checksum 
        data_checksum = adler32_checksum((const char *) frame->data, data_sz);

        if (data_checksum != kis_ntoh32(frame->data_checksum)) {
            _MSG_ERROR("Kismet external interface got a command frame with an invalid checksum; "
                    "either the frame is malformed, a network error occurred, or an unsupported tool "
                    "has connected to the external interface API.");
            trigger_error("command frame has invalid checksum");
            return -1;
        }

        // Process the data payload as a protobuf frame
        std::shared_ptr<KismetExternal::Command> cmd(new KismetExternal::Command());

        if (!cmd->ParseFromArray(frame->data, data_sz)) {
            _MSG_ERROR("Kismet external interface could not interpret the payload of the "
                    "command frame; either the frame is malformed, a network error occurred, or "
                    "an unsupported tool is connected to the external interface API");
            trigger_error("unparsable command frame");
            return -1;
        }

        in_buf.consume(frame_sz);

        // Unlock before processing, individual commands will lock as needed
        lock.unlock();

        // Dispatch the received command
        dispatch_rx_packet(cmd);
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

bool kis_external_interface::run_ipc() {
    local_locker l(&ext_mutex, "kei::run_ipc");

    struct stat fstat;

    stopped = true;
    in_buf.consume(in_buf.size());

    if (external_binary == "") {
        _MSG("Kismet external interface did not have an IPC binary to launch", MSGFLAG_ERROR);
        return false;
    }

    // Get allowed paths for binaries
    auto bin_paths = 
        Globalreg::globalreg->kismet_config->fetch_opt_vec("helper_binary_path");

    if (bin_paths.size() == 0) {
        _MSG("No helper_binary_path found in kismet.conf, make sure your config "
                "files are up to date; using the default binary path where Kismet "
                "is installed.", MSGFLAG_ERROR);
        bin_paths.push_back("%B");
    }

    std::string helper_path;

    for (auto rp : bin_paths) {
        std::string fp = fmt::format("{}/{}",
                Globalreg::globalreg->kismet_config->expand_log_path(rp, "", "", 0, 1), external_binary);

        if (stat(fp.c_str(), &fstat) != -1) {
            if (S_ISDIR(fstat.st_mode))
                continue;

            if ((S_IXUSR & fstat.st_mode)) {
                helper_path = fp;
                break;
            }
        }
    }

    if (helper_path.length() == 0) {
        _MSG_ERROR("Kismet external interface can not find IPC binary for launch: {}",
                external_binary);
        return false;
    }

    // See if we can execute the IPC tool
    if (!(fstat.st_mode & S_IXOTH)) {
        if (getuid() != fstat.st_uid && getuid() != 0) {
            bool group_ok = false;
            gid_t *groups;
            int ngroups;

            if (getgid() != fstat.st_gid) {
                ngroups = getgroups(0, NULL);

                if (ngroups > 0) {
                    groups = new gid_t[ngroups];
                    ngroups = getgroups(ngroups, groups);

                    for (int g = 0; g < ngroups; g++) {
                        if (groups[g] == fstat.st_gid) {
                            group_ok = true;
                            break;
                        }
                    }

                    delete[] groups;
                }

                if (!group_ok) {
                    _MSG_ERROR("IPC cannot run binary '{}', Kismet was installed "
                            "setgid and you are not in that group. If you recently added your "
                            "user to the kismet group, you will need to log out and back in to "
                            "activate it.  You can check your groups with the 'groups' command.",
                            helper_path);
                    return false;
                }
            }
        }
    }

    // 'in' to the spawned process, write to the server process, 
    // [1] belongs to us, [0] to them
    int inpipepair[2];
    // 'out' from the spawned process, read to the server process, 
    // [0] belongs to us, [1] to them
    int outpipepair[2];

    if (pipe(inpipepair) < 0) {
        _MSG_ERROR("IPC could not create pipe: {}", kis_strerror_r(errno));
        return false;
    }

    if (pipe(outpipepair) < 0) {
        _MSG_ERROR("IPC could not create pipe: {}", kis_strerror_r(errno));
        ::close(inpipepair[0]);
        ::close(inpipepair[1]);
        return false;
    }

    // We don't need to do signal masking because we run a dedicated signal handling thread

    pid_t child_pid;
    char **cmdarg;

    if ((child_pid = fork()) < 0) {
        _MSG_ERROR("IPC could not fork(): {}", kis_strerror_r(errno));
        ::close(inpipepair[0]);
        ::close(inpipepair[1]);
        ::close(outpipepair[0]);
        ::close(outpipepair[1]);

        return false;
    } else if (child_pid == 0) {
        // We're the child process

        // Unblock all signals in the child so nothing carries over from the parent fork
        sigset_t unblock_mask;
        sigfillset(&unblock_mask);
        pthread_sigmask(SIG_UNBLOCK, &unblock_mask, nullptr);
      
        // argv[0], "--in-fd" "--out-fd" ... NULL
        cmdarg = new char*[external_binary_args.size() + 4];
        cmdarg[0] = strdup(helper_path.c_str());

        // Child reads from inpair
        std::string argstr;

        argstr = fmt::format("--in-fd={}", inpipepair[0]);
        cmdarg[1] = strdup(argstr.c_str());

        // Child writes to writepair
        argstr = fmt::format("--out-fd={}", outpipepair[1]);
        cmdarg[2] = strdup(argstr.c_str());

        for (unsigned int x = 0; x < external_binary_args.size(); x++)
            cmdarg[x+3] = strdup(external_binary_args[x].c_str());

        cmdarg[external_binary_args.size() + 3] = NULL;

        // close the unused half of the pairs on the child
        ::close(inpipepair[1]);
        ::close(outpipepair[0]);

        execvp(cmdarg[0], cmdarg);

        exit(255);
    } 

    // Parent process
   
    // close the remote side of the pipes from the parent, they're open in the child
    ::close(inpipepair[0]);
    ::close(outpipepair[1]);

    ipc_out = asio::posix::stream_descriptor(Globalreg::globalreg->io, inpipepair[1]);
    ipc_in = asio::posix::stream_descriptor(Globalreg::globalreg->io, outpipepair[0]);

    ipc = kis_ipc_record(child_pid,
            [this](const std::string&) {
            close_external();
            },
            [this](const std::string& err) {
            trigger_error(err);
            });
    ipctracker->register_ipc(ipc);

    stopped = false;

    start_ipc_read();

    return true;
}


unsigned int kis_external_interface::send_packet(std::shared_ptr<KismetExternal::Command> c) {
    local_locker lock(&ext_mutex, "kei::send_packet");

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
    char frame_buf[frame_sz];
    kismet_external_frame_t *frame = reinterpret_cast<kismet_external_frame_t *>(frame_buf);

    // Fill in the headers
    frame->signature = kis_hton32(KIS_EXTERNAL_PROTO_SIG);
    frame->data_sz = kis_hton32(content_sz);

    // serialize into our array
    c->SerializeToArray(frame->data, content_sz);

    // Calculate the checksum and set it in the frame
    data_csum = adler32_checksum((const char *) frame->data, content_sz); 
    frame->data_checksum = kis_hton32(data_csum);

    if (ipc_out.is_open())
        asio::async_write(ipc_out, asio::buffer(frame_buf, frame_sz),
                [this](const std::error_code& ec, std::size_t) {
                if (ec) {
                    if (ec.value() == asio::error::operation_aborted)
                        return;

                    _MSG_ERROR("Kismet external interface got an error writing a packet to an "
                            "IPC interface: {}", ec.message());
                    trigger_error("write failure");
                    return;
                }
                });
    else if (tcpsocket.is_open()) 
        asio::async_write(tcpsocket, asio::buffer(frame_buf, frame_sz),
                [this](const std::error_code& ec, std::size_t) {
                if (ec) {
                    if (ec.value() == asio::error::operation_aborted)
                        return;

                    _MSG_ERROR("Kismet external interface got an error writing a packet to a "
                            "TCP interface: {}", ec.message());
                    trigger_error("write failure");
                    return;
                }
                });

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
    local_locker lock(&ext_mutex, "kei::handle_packet_pong");

    KismetExternal::Pong p;
    if (!p.ParseFromString(in_content)) {
        _MSG("Kismet external interface got an unparsable PONG packet", MSGFLAG_ERROR);
        trigger_error("Invalid PONG");
        return;
    }

    last_pong = time(0);
}

void kis_external_interface::handle_packet_shutdown(uint32_t in_seqno, const std::string& in_content) {
    local_locker lock(&ext_mutex, "kei::handle_packet_shutdown");

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
    local_locker lock(&ext_mutex, "kis_external_interface::handle_packet_eventbus_register");

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
    local_locker lock(&ext_mutex, "kis_external_interface::handle_packet_eventbus_publish");
    
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
    local_locker lock(&ext_mutex, "kei::handle_packet_http_register");

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
    local_locker lock(&ext_mutex, "kei::handle_packet_http_response");

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
    local_locker lock(&ext_mutex, "kei::httpd_verify_path");

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
    local_demand_locker dlock(&ext_mutex, "kei::httpd_create_stream_response");
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
    local_demand_locker dlock(&ext_mutex, "kei::httpd_post_complete");
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

