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
    stopped{true},
    cancelled{false},
    timetracker{Globalreg::fetch_mandatory_global_as<time_tracker>()},
    ipctracker{Globalreg::fetch_mandatory_global_as<ipc_tracker_v2>()},
    seqno{0},
    last_pong{0},
    ping_timer_id{-1},
    strand_{Globalreg::globalreg->io},
    ipc_in{Globalreg::globalreg->io},
    ipc_out{Globalreg::globalreg->io},
    ipc_running{false},
    protocol_version{0},
    tcpsocket{Globalreg::globalreg->io},
    eventbus{Globalreg::fetch_mandatory_global_as<event_bus>()},
    http_session_id{0} {

    ext_mutex.set_name("kis_external_interface");
}

kis_external_interface::~kis_external_interface() {
    close_external();
}

bool kis_external_interface::attach_tcp_socket(tcp::socket& socket) {
    // Attach on a strand and wait for it to execute so that we don't interrupt any io in process

    auto tcp_promise = std::promise<bool>();
    auto tcp_ft = tcp_promise.get_future();

    boost::asio::post(strand_, 
            [this, tcp_promise = std::move(tcp_promise), &socket]() mutable {

            if (ipc.pid > 0) {
                _MSG_ERROR("Tried to attach a TCP socket to an external endpoint that already has "
                        "an IPC instance running.");
                tcp_promise.set_value(false);
                return;
            }

            stopped = true;
            in_buf.consume(in_buf.size());
            out_bufs.clear();

            tcpsocket = std::move(socket);

            tcp_promise.set_value(true);
            });

    auto r = tcp_ft.get();

    if (r) {
        stopped = false;
        cancelled = false;

        start_tcp_read(shared_from_this());
    }

    return r;
}

void kis_external_interface::close_external() {
    // This should be safe to do outside a strand b/c inside the strands we handle the states of finding
    // ourselves stopped, cancelled, or the sockets closed

    stopped = true;
    cancelled = true;

    kis_unique_lock<kis_mutex> lk(ext_mutex, "kei close_external");

    // Kill any eventbus listeners
    for (const auto& ebid : eventbus_callback_map)
        eventbus->remove_listener(ebid.second);

    // Kill any active http sessions
    for (auto s : http_proxy_session_map) {
        // Fail them
        s.second->connection->response_stream().cancel();
        // Unlock them and let the cleanup in the thread handle it and close down 
        // the http server session
        s.second->locker->unlock();
    }

    timetracker->remove_timer(ping_timer_id);

    ipc_hard_kill();

    if (tcpsocket.is_open()) {
        try {
            tcpsocket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            tcpsocket.close();
        } catch (const std::exception& e) {
            ;
        }
    }

    if (closure_cb != nullptr) {
        lk.unlock();
        closure_cb();
        lk.lock();
    }

    write_cb = nullptr;
    closure_cb = nullptr;

    in_buf.consume(in_buf.size());
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

    ipc_running = false;
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

    ipc_running = false;
}

void kis_external_interface::trigger_error(const std::string& in_error) {
    // Don't loop if we're already stopped
    if (stopped)
        return;

    handle_error(in_error);

    close_external();
}

void kis_external_interface::start_ipc_read() {
    if (stopped || cancelled) {
        handle_packet(in_buf);
        return;
    }

    boost::asio::async_read(ipc_in, in_buf,
            boost::asio::transfer_at_least(sizeof(kismet_external_frame_t)),
            boost::asio::bind_executor(strand_, 
                [this](const boost::system::error_code& ec, std::size_t t) {
                    if (ec) {
                        if (ec.value() == boost::asio::error::operation_aborted) {
                            if (ipc_running) {
                                handle_packet(in_buf);
                                return trigger_error("IPC connection aborted");
                            }

                            return close_external();
                        }

                        if (ec.value() == boost::asio::error::eof) {
                            if (ipc_running) {
                                handle_packet(in_buf);
                                return trigger_error("IPC connection closed");
                            }

                            return close_external();
                        }

                        return trigger_error(fmt::format("IPC connection error: {}", ec.message()));
                    } 

                    auto r = handle_packet(in_buf);

                    if (r < 0)
                        return trigger_error("IPC read processing error");

                    return start_ipc_read();
                }));
}

void kis_external_interface::start_tcp_read(std::shared_ptr<kis_external_interface> ref) {
    if (stopped)
        return;

    if (cancelled)
        return;

    boost::asio::async_read(tcpsocket, in_buf,
            boost::asio::transfer_at_least(sizeof(kismet_external_frame_t)),
            boost::asio::bind_executor(strand_, [this, ref](const boost::system::error_code& ec, std::size_t t) {
            if (ec) {
                if (ec.value() == boost::asio::error::operation_aborted) {
                    if (!stopped || !cancelled) {
                        handle_packet(in_buf);
                        return trigger_error("TCP connection aborted");
                    }

                    return close_external();
                }

                if (ec.value() == boost::asio::error::eof) {
                    if (!stopped || !cancelled) {
                        handle_packet(in_buf);
                        return trigger_error("TCP connection closed");
                    }

                    return close_external();
                }

                return trigger_error(fmt::format("TCP connection error: {}", ec.message()));
            } 

            auto r = handle_packet(in_buf);

            if (r < 0)
                return trigger_error("TCP read processing error");

            return start_tcp_read(ref);
            }));
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

// std::atomic<int> ipc_strand_g(0);

bool kis_external_interface::run_ipc() {
    // Launch on a strand so we don't risk perturbing any io in progress already, wait on strand exec

    auto ipc_promise = std::promise<bool>();
    auto ipc_ft = ipc_promise.get_future();

    pid_t child_pid;

    // int ipc_strand_no = ipc_strand_g++;

    boost::asio::post(strand_, 
            [self = shared_from_this(), ipc_promise = std::move(ipc_promise), 
            &child_pid]() mutable {

            // _MSG_DEBUG("running on strand {}", ipc_strand_no);

            self->stopped = true;
            self->cancelled = true;
            self->ipc_running = false;

            self->in_buf.consume(self->in_buf.size());
            self->out_bufs.clear();

            struct stat fstat;

            if (self->external_binary == "") {
                _MSG("Kismet external interface did not have an IPC binary to launch", MSGFLAG_ERROR);
                ipc_promise.set_value(false);
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
                        Globalreg::globalreg->kismet_config->expand_log_path(rp, "", "", 0, 1), self->external_binary);

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
                        self->external_binary);
                ipc_promise.set_value(false);
                return;
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
                            ipc_promise.set_value(false);
                            return;
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
                ipc_promise.set_value(false);
                return;
            }

            if (pipe(outpipepair) < 0) {
                _MSG_ERROR("IPC could not create pipe: {}", kis_strerror_r(errno));
                ::close(inpipepair[0]);
                ::close(inpipepair[1]);
                ipc_promise.set_value(false);
                return;
            }

            // We don't need to do signal masking because we run a dedicated signal handling thread

            char **cmdarg;

            if ((child_pid = fork()) < 0) {
                _MSG_ERROR("IPC could not fork(): {}", kis_strerror_r(errno));
                ::close(inpipepair[0]);
                ::close(inpipepair[1]);
                ::close(outpipepair[0]);
                ::close(outpipepair[1]);

                ipc_promise.set_value(false);
                return;
            } else if (child_pid == 0) {
                // We're the child process

                // Unblock all signals in the child so nothing carries over from the parent fork
                sigset_t unblock_mask;
                sigfillset(&unblock_mask);
                pthread_sigmask(SIG_UNBLOCK, &unblock_mask, nullptr);

                // argv[0], "--in-fd" "--out-fd" ... NULL
                cmdarg = new char*[self->external_binary_args.size() + 4];
                cmdarg[0] = strdup(helper_path.c_str());

                // Child reads from inpair
                std::string argstr;

                argstr = fmt::format("--in-fd={}", inpipepair[0]);
                cmdarg[1] = strdup(argstr.c_str());

                // Child writes to writepair
                argstr = fmt::format("--out-fd={}", outpipepair[1]);
                cmdarg[2] = strdup(argstr.c_str());

                for (unsigned int x = 0; x < self->external_binary_args.size(); x++)
                    cmdarg[x+3] = strdup(self->external_binary_args[x].c_str());

                cmdarg[self->external_binary_args.size() + 3] = NULL;

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

            self->ipc_out = boost::asio::posix::stream_descriptor(Globalreg::globalreg->io, inpipepair[1]);
            self->ipc_in = boost::asio::posix::stream_descriptor(Globalreg::globalreg->io, outpipepair[0]);

            // _MSG_DEBUG("exiting strand work {}", ipc_strand_no);
            ipc_promise.set_value(true);
        });

    // _MSG_DEBUG("waiting for strand {}", ipc_strand_no);
    auto r = ipc_ft.get();

    // _MSG_DEBUG("got strand {}", ipc_strand_no);
    if (r) {
        stopped = false;
        cancelled = false;
        ipc_running = true;

        auto self_ref = shared_from_this();

        ipc = kis_ipc_record(child_pid,
                [this, self_ref](const std::string&) {
                close_external();
                },
                [this, self_ref](const std::string& err) {
                trigger_error(err);
                });

        ipctracker->register_ipc(ipc);

        boost::asio::post(strand_,
                [self = shared_from_this()]() {
                    self->start_ipc_read();
                });
    }

    return r;
}

void kis_external_interface::start_write(const char *data, size_t len) {
    if (stopped || cancelled)
        return;

    auto buf = std::make_shared<std::string>(data, len);

    boost::asio::post(strand_, 
            [this, buf]() {
            out_bufs.push_back(buf);

            if (out_bufs.size() > 1) {
                // _MSG_DEBUG("external interface writing len {}, bufs queue {} deep", len, out_bufs.size());
                return;
            }

            // _MSG_DEBUG("external interface triggering writ_impl for len {} bufs depth {}", len, out_bufs.size());
            write_impl();

            });
}

void kis_external_interface::write_impl() {
    auto buf = out_bufs.front();

    if (write_cb != nullptr) {
        write_cb(buf->data(), buf->size(),
                [this](int ec, std::size_t) {
                    boost::system::error_code errc =
                        boost::system::errc::make_error_code(boost::system::errc::success);
                    
                    if (ec == 0)
                        errc = boost::asio::error::make_error_code(boost::asio::stream_errc::eof);
                   
                    strand_.post([this, errc]() { 

                    out_bufs.pop_front();

                    if (errc) {
                        handle_packet(in_buf);

                        _MSG_ERROR("Kismet external interface got an error writing to callback: {}", errc.message());
                        trigger_error("write failure");
                        return;
                    }

                    if (out_bufs.size()) {
                        return write_impl();
                    }

                    });
                });
    } else if (ipc_out.is_open()) {
        boost::asio::async_write(ipc_out, boost::asio::buffer(buf->data(), buf->size()),
                boost::asio::bind_executor(strand_, [this](const boost::system::error_code& ec, std::size_t) {
                    out_bufs.pop_front();

                    if (ec) {
                        handle_packet(in_buf);

                        if (ec.value() == boost::asio::error::operation_aborted) {
                            return;
                        }

                        _MSG_ERROR("Kismet external interface got an error writing to external IPC: {}", ec.message());
                        trigger_error("write failure");
                        return;
                    }

                    if (out_bufs.size()) {
                        return write_impl();
                    }

                    }));
    } else if (tcpsocket.is_open()) {
        boost::asio::async_write(tcpsocket, boost::asio::buffer(buf->data(), buf->size()),
                boost::asio::bind_executor(strand_, [this](const boost::system::error_code& ec, std::size_t) {
                    out_bufs.pop_front();

                    if (ec) {
                        handle_packet(in_buf);

                        if (ec.value() == boost::asio::error::operation_aborted) {
                            return;
                        }

                        _MSG_ERROR("Kismet external interface got an error writing to external IPC: {}", ec.message());
                        trigger_error("write failure");
                        return;
                    }

                    if (out_bufs.size()) {
                        return write_impl();
                    }

                }));
    } else {
        _MSG_ERROR("Kismet external interface got an error writing packet, IPC, TCP, callbacks closed");
        trigger_error("no connections");
    }
}

unsigned int kis_external_interface::send_packet(std::shared_ptr<KismetExternal::Command> c) {
    if (stopped || cancelled) {
        _MSG_DEBUG("Attempt to send {} on closed external interface", c->command());
        return 0;
    }

    // Set the sequence if one wasn't provided
    if (c->seqno() == 0) {
        kis_lock_guard<kis_mutex> lk(ext_mutex, "kei send_packet");

        if (++seqno == 0)
            seqno = 1;

        c->set_seqno(seqno);
    }

    uint32_t data_csum;

    // Get the serialized size of our message
#if GOOGLE_PROTOBUF_VERSION >= 3006001
    size_t content_sz = c->ByteSizeLong();
#else
    size_t content_sz = c->ByteSize();
#endif

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

    start_write(frame_buf, frame_sz);

    return c->seqno();
}

bool kis_external_interface::dispatch_rx_packet(const nonstd::string_view& command,
        uint32_t seqno, const nonstd::string_view& content) {
    // Simple dispatcher; this should be called by child implementations who
    // add their own commands
    if (command.compare("MESSAGE") == 0) {
        handle_packet_message(seqno, content);
        return true;
    } else if (command.compare("PING") == 0) {
        handle_packet_ping(seqno, content);
        return true;
    } else if (command.compare("PONG") == 0) {
        handle_packet_pong(seqno, content);
        return true;
    } else if (command.compare("SHUTDOWN") == 0) {
        handle_packet_shutdown(seqno, content);
        return true;
    } else if (command.compare("HTTPREGISTERURI") == 0) {
        handle_packet_http_register(seqno, content);
        return true;
    } else if (command.compare("HTTPRESPONSE") == 0) {
        handle_packet_http_response(seqno, content);
        return true;
    } else if (command.compare("HTTPAUTHREQ") == 0) {
        handle_packet_http_auth_request(seqno, content);
        return true;
    } else if (command.compare("EVENTBUSREGISTER") == 0) {
        handle_packet_eventbus_register(seqno, content);
        return true;
    } else if (command.compare("EVENTBUSPUBLISH") == 0) {
        handle_packet_eventbus_publish(seqno, content);
        return true;
    }

    return false;

}

void kis_external_interface::handle_packet_message(uint32_t in_seqno, 
        const nonstd::string_view& in_content) {
    KismetExternal::MsgbusMessage m;

    if (!m.ParseFromArray(in_content.data(), in_content.size())) {
        _MSG("Kismet external interface got an unparsable MESSAGE", MSGFLAG_ERROR);
        trigger_error("Invalid MESSAGE");
        return;
    }

    handle_msg_proxy(m.msgtext(), m.msgtype());
}

void kis_external_interface::handle_msg_proxy(const std::string& msg, const int msgtype) {
    _MSG(msg, msgtype);
}

void kis_external_interface::handle_packet_ping(uint32_t in_seqno, 
        const nonstd::string_view& in_content) {
    send_pong(in_seqno);
}

void kis_external_interface::handle_packet_pong(uint32_t in_seqno, 
        const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "kei handle_packet_pong");

    KismetExternal::Pong p;
    if (!p.ParseFromArray(in_content.data(), in_content.size())) {
        _MSG("Kismet external interface got an unparsable PONG packet", MSGFLAG_ERROR);
        trigger_error("Invalid PONG");
        return;
    }

    last_pong = time(0);
}

void kis_external_interface::handle_packet_shutdown(uint32_t in_seqno, 
        const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "kei handle_packet_shutdown");

    KismetExternal::ExternalShutdown s;
    if (!s.ParseFromArray(in_content.data(), in_content.length())) {
        _MSG("Kismet external interface got an unparsable SHUTDOWN", MSGFLAG_ERROR);
        trigger_error("invalid SHUTDOWN");
        return;
    }

    _MSG(std::string("Kismet external interface shutting down: ") + s.reason(), MSGFLAG_INFO); 
    trigger_error(std::string("Remote connection requesting shutdown: ") + s.reason());
}

unsigned int kis_external_interface::send_ping() {
    if (protocol_version == 0) {
        std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

        c->set_command("PING");

        KismetExternal::Ping p;
        c->set_content(p.SerializeAsString());

        return send_packet(c);
    } else if (protocol_version == 2) {
        return send_packet_v2("PING", 0, KismetExternal::Ping{});
    }

    return -1;
}

unsigned int kis_external_interface::send_pong(uint32_t ping_seqno) {
    KismetExternal::Pong p;
    p.set_ping_seqno(ping_seqno);

    if (protocol_version == 0) {
        std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());
        c->set_command("PONG");
        c->set_content(p.SerializeAsString());

        return send_packet(c);
    } else if (protocol_version == 2) {
        return send_packet_v2("PONG", 0, p);
    }

    return -1;
}

unsigned int kis_external_interface::send_shutdown(std::string reason) {
    KismetExternal::ExternalShutdown s;
    s.set_reason(reason);

    if (protocol_version == 0) {
        std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());
        c->set_command("SHUTDOWN");
        c->set_content(s.SerializeAsString());
        return send_packet(c);
    } else if (protocol_version == 2) {
        return send_packet_v2("SHUTDOWN", 0, s);
    }

    return -1;
}

void kis_external_interface::proxy_event(std::shared_ptr<eventbus_event> evt) {
    std::stringstream ss;
    json_adapter::pack(ss, evt);
    KismetEventBus::EventbusEvent ebe;
    ebe.set_event_json(ss.str());

    if (protocol_version == 0) {
        auto c = std::make_shared<KismetExternal::Command>();
        c->set_command("EVENT");
        c->set_content(ebe.SerializeAsString());
        send_packet(c);
    } else if (protocol_version == 2) {
        send_packet_v2("EVENT", 0, ebe);
    }

    return;
}

void kis_external_interface::handle_packet_eventbus_register(uint32_t in_seqno,
        const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "kei handle_packet_eventbus_register");

    KismetEventBus::EventbusRegisterListener evtlisten;

    if (!evtlisten.ParseFromArray(in_content.data(), in_content.length())) {
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
        const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "kei handle_packet_eventbus_publish");
    
    KismetEventBus::EventbusPublishEvent evtpub;

    if (!evtpub.ParseFromArray(in_content.data(), in_content.length())) {
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
        const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "kei handle_packet_http_register");

    KismetExternalHttp::HttpRegisterUri uri;

    if (!uri.ParseFromArray(in_content.data(), in_content.length())) {
        _MSG("Kismet external interface got an unparsable HTTPREGISTERURI", MSGFLAG_ERROR);
        trigger_error("Invalid HTTPREGISTERURI");
        return;
    }

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route(uri.uri(), {uri.method()}, httpd->LOGON_ROLE,
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    kis_unique_lock<kis_mutex> l(ext_mutex, std::defer_lock,
                            fmt::format("proxied req {}", con->uri()));
                    l.lock();

                    auto session = std::make_shared<kis_external_http_session>();
                    session->connection = con;
                    session->locker.reset(new conditional_locker<int>());
                    session->locker->lock();

                    auto sess_id = http_session_id++;
                    http_proxy_session_map[sess_id] = session;

                    auto var_remap = std::map<std::string, std::string>();
                    for (const auto& v : con->http_variables())
                        var_remap[v.first] = v.second;

                    send_http_request(sess_id, static_cast<std::string>(con->uri()), 
                            fmt::format("{}", con->verb()), var_remap);

                    con->set_closure_cb([session]() { session->locker->unlock(-1); });

                    // Unlock the external mutex prior to blocking
                    l.unlock();

                    // Block until we get a response
                    session->locker->block_until();

                    // Reacquire the lock on the external interface
                    l.lock();

                    auto mi = http_proxy_session_map.find(sess_id);
                    if (mi != http_proxy_session_map.end())
                        http_proxy_session_map.erase(mi);
            }));
}

void kis_external_interface::handle_packet_http_response(uint32_t in_seqno, 
        const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "kei handle_packet_http_response");

    KismetExternalHttp::HttpResponse resp;

    if (!resp.ParseFromArray(in_content.data(), in_content.length())) {
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

    // First off, process any headers we're trying to add, they need to come 
    // before data
    try {
        for (int hi = 0; hi < resp.header_content_size() && resp.header_content_size() > 0; hi++) {
            KismetExternalHttp::SubHttpHeader hh = resp.header_content(hi);
            session->connection->append_header(hh.header(), hh.content());
        }
    } catch (const std::runtime_error& e) {
        _MSG_ERROR("Kismet external interface failed setting HTTPRESPONSE headers - {}", e.what());
        trigger_error("Invalid HTTPRESPONSE header block");
        return;
    }

    // Set any connection state
    try {
        if (resp.has_resultcode()) {
            session->connection->set_status(resp.resultcode());
        }
    } catch (const std::runtime_error& e) {
        _MSG_ERROR("Kismet external interface failed setting HTTPRESPONSE status code- {}", e.what());
        trigger_error("invalid HTTPRESPONSE status code");
        return;
    }

    // Copy any response data
    if (resp.has_content() && resp.content().size() > 0) {
        session->connection->response_stream().put_data(resp.content().data(), resp.content().size());
    }

    // Are we finishing the connection?
    if (resp.has_close_response() && resp.close_response()) {
        session->connection->response_stream().complete();
        session->locker->unlock();
    }
}

void kis_external_interface::handle_packet_http_auth_request(uint32_t in_seqno, 
        const nonstd::string_view& in_content) {
    KismetExternalHttp::HttpAuthTokenRequest rt;

    if (!rt.ParseFromArray(in_content.data(), in_content.length())) {
        _MSG("Kismet external interface got an unparsable HTTPAUTHREQ", MSGFLAG_ERROR);
        trigger_error("Invalid HTTPAUTHREQ");
        return;
    }

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();
    auto token = httpd->create_or_find_auth("external plugin", httpd->LOGON_ROLE, 0);

    send_http_auth(token);
}

unsigned int kis_external_interface::send_http_request(uint32_t in_http_sequence, std::string in_uri,
        std::string in_method, std::map<std::string, std::string> in_vardata) {
    KismetExternalHttp::HttpRequest r;
    r.set_req_id(in_http_sequence);
    r.set_uri(in_uri);
    r.set_method(in_method);

    for (auto pi : in_vardata) {
        KismetExternalHttp::SubHttpVariableData *pd = r.add_variable_data();
        pd->set_field(pi.first);
        pd->set_content(pi.second);
    }

    if (protocol_version == 0) {
        std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());
        c->set_command("HTTPREQUEST");
        c->set_content(r.SerializeAsString());
        return send_packet(c);
    } else if (protocol_version == 2) {
        return send_packet_v2("HTTPREQUEST", 0, r);
    }

    return -1;
}

unsigned int kis_external_interface::send_http_auth(std::string in_cookie) {
    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    KismetExternalHttp::HttpAuthToken a;
    a.set_token(in_cookie);

    if (protocol_version == 0) {
        c->set_command("HTTPAUTH");
        c->set_content(a.SerializeAsString());
        return send_packet(c);
    } else if (protocol_version == 2) {
        return send_packet_v2("HTTPAUTH", 0, a);
    }

    return -1;
}

