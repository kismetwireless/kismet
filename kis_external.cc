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

#include <array>

#include "boost/asio/use_future.hpp"
#include "configfile.h"

#include "json_adapter.h"

#include "kis_external.h"
#include "kis_external_packet.h"

#include "endian_magic.h"

#include "kis_mutex.h"
#include "timetracker.h"
#include "messagebus.h"

#include "mpack/mpack.h"
#include "mpack/mpack_cpp.h"

#ifdef HAVE_PROTOBUF_CPP
#include "protobuf_cpp/kismet.pb.h"
#include "protobuf_cpp/http.pb.h"
#include "protobuf_cpp/eventbus.pb.h"
#endif

kis_external_ipc::~kis_external_ipc() {
    close_impl();

    if (ipc_.pid > 0) {
        kill(ipc_.pid, SIGKILL);
    }
}

// read a packet header to get the length of the incoming packet, then
// queue reading the entire packet contents as a second operation
void kis_external_ipc::start_read() {
    if (stopped_) {
        return;
    }

    // grab the buffer for the duration of the operations; it will be handed
    // off to the packet for tracking as it is processed
    in_buf_ = Globalreg::globalreg->streambuf_pool.acquire();

    boost::asio::async_read(ipc_in_, *in_buf_.get(),
            boost::asio::transfer_exactly(sizeof(kismet_external_frame_stub_t)),
            boost::asio::bind_executor(strand(),
                [self = shared_from_this()](const boost::system::error_code& ec, std::size_t t) {
                    if (ec) {
                        if (ec.value() == boost::asio::error::operation_aborted) {
                            self->in_buf_.reset();

                            if (!self->stopped_) {
                                self->close();
                                return self->interface_->trigger_error("IPC connection aborted");
                            }

                            return;
                        }

                        if (ec.value() == boost::asio::error::eof) {
                            if (!self->stopped_) {
                                self->close();
                                self->stopped_ = true;
                                return self->interface_->trigger_error("IPC connection closed");
                            }

                            return;
                        }

                        self->close();

                        return self->interface_->trigger_error(fmt::format("IPC connection error: {}", ec.message()));
                    }

                    // read the full-length packet in a second operation
                    auto r = self->packet_read();

                    // the sub-read should have triggered any errors here, so simply return the buffer to the queue
                    // and close out.
                    if (r < 0) {
                        self->in_buf_.reset();
                        if (self->stopped_) {
                            return;
                        }

                        self->close();
                        return;
                    }

                    // next read op triggered by packet_read
                }));
}

// read the rest of the packet after processing the header
int kis_external_ipc::packet_read() {
    if (stopped_) {
        return -1;
    }

    const auto frame = static_cast<const kismet_external_frame_stub_t *>(in_buf_->data().data());

    if (kis_ntoh32(frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
        _MSG_ERROR("Kismet external interface got command frame with invalid "
                "signature; either lost position in the external stream or "
                "an unknown protocol was used");
        interface_->trigger_error("invalid signature on frame");
        return -1;
    }

    size_t total_length = kis_ntoh32(frame->data_sz);

    if (kis_ntoh16(frame->proto_sentinel) == KIS_EXTERNAL_V2_SIG &&
            kis_ntoh16(frame->proto_version) == 0x02) {
        total_length += sizeof(kismet_external_frame_v2_t);
    } else if (kis_ntoh16(frame->proto_sentinel) == KIS_EXTERNAL_V3_SIG) {
        total_length += sizeof(kismet_external_frame_v3_t);
    }

    // subtract the amount we already read in the form of the short header
    total_length -= sizeof(kismet_external_frame_stub_t);

    if (total_length > MAX_EXTERNAL_FRAME_LEN) {
        _MSG_ERROR("Kismet external interface got command frame which is "
                "too large to be processed ({}); either the frame is malformed "
                "or the connection is from a very old legacy Kismet version using "
                "a different protocol; make sure that you have updated to a "
                "current Kismet version on all systems.", total_length);
        interface_->trigger_error("external packet too large for buffer");
        return -1;
    }

    // read the rest of the packet
    boost::asio::async_read(ipc_in_, *(in_buf_.get()),
            boost::asio::transfer_exactly(total_length),
            boost::asio::bind_executor(strand(),
                [self = shared_from_this()](const boost::system::error_code& ec, std::size_t t) {
                    if (ec) {
                        self->in_buf_.reset();

                        if (ec.value() == boost::asio::error::operation_aborted) {
                            if (!self->stopped_) {
                                self->close();
                                return self->interface_->trigger_error("IPC connection aborted");
                            }

                            return;
                        }

                        if (ec.value() == boost::asio::error::eof) {
                            if (!self->stopped_) {
                                self->close();
                                self->stopped_ = true;
                                return self->interface_->trigger_error("IPC connection closed");
                            }

                            return;
                        }

                        self->close();

                        return self->interface_->trigger_error(fmt::format("IPC connection error: {}", ec.message()));
                    }

                    auto r = self->interface_->handle_packet(self->in_buf_);

                    if (r < 0) {
                        self->in_buf_.reset();

                        if (self->stopped_) {
                            return;
                        }

                        self->close();
                        return;
                    }

                    return self->start_read();
                }));

    return 1;
}


void kis_external_ipc::write_impl() {
    if (out_bufs_.size() == 0)
        return;

    if (stopped_)
        return;

    auto buf = out_bufs_.front();

    boost::asio::async_write(ipc_out_, boost::asio::buffer(buf->data(), buf->size()),
            boost::asio::bind_executor(strand(),
                [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
                if (self->out_bufs_.size())
                    self->out_bufs_.pop_front();

                if (ec) {
                    self->interface_->handle_packet(self->in_buf_);

                    if (self->stopped() || ec.value() == boost::asio::error::operation_aborted) {
                        return;
                    }

                    self->close();

                    _MSG_ERROR("Kismet external interface got an error writing to external IPC: {}", ec.message());
                    self->interface_->trigger_error("write failure");

                    return;
                }

                if (self->out_bufs_.size()) {
                    return self->write_impl();
                }

            }));
}

void kis_external_ipc::close() {
    if (strand().running_in_this_thread()) {
        close_impl();
    } else {
        boost::asio::post(strand(),
                [self = shared_from_base<kis_external_ipc>()]() mutable {
                self->close_impl();
                });
    }
}

void kis_external_ipc::close_impl() {
    stopped_ = true;

    if (ipc_.pid > 0) {
        ipctracker_->remove_ipc(ipc_.pid);
    }

    if (ipc_in_.is_open()) {
        try {
            ipc_in_.cancel();
            ipc_in_.close();
        } catch (...) { }
    }

    if (ipc_out_.is_open()) {
        try {
            ipc_out_.cancel();
            ipc_out_.close();
        } catch (...) { }
    }

    if (ipc_.pid > 0) {
        kill(ipc_.pid, SIGTERM);
    }

    out_bufs_.clear();
}

kis_external_tcp::~kis_external_tcp() {
    close_impl();
}

void kis_external_tcp::start_read() {
    if (stopped_) {
        return;
    }

    in_buf_ = Globalreg::globalreg->streambuf_pool.acquire();

    boost::asio::async_read(tcpsocket_, *in_buf_.get(),
            boost::asio::transfer_exactly(sizeof(kismet_external_frame_stub_t)),
            boost::asio::bind_executor(strand(),
                [self = shared_from_this()](const boost::system::error_code& ec, std::size_t t) {
                    if (ec) {
                        self->in_buf_.reset();

                        if (ec.value() == boost::asio::error::operation_aborted) {
                            if (!self->stopped_) {
                                self->close();
                                return self->interface_->trigger_error("IPC connection aborted");
                            }

                            return;
                        }

                        if (ec.value() == boost::asio::error::eof) {
                            if (!self->stopped_) {
                                self->close();
                                self->stopped_ = true;
                                return self->interface_->trigger_error("IPC connection closed");
                            }

                            return;
                        }

                        self->close();

                        return self->interface_->trigger_error(fmt::format("IPC connection error: {}", ec.message()));
                    }

                    // read the full-length packet in a second operation
                    auto r = self->packet_read();

                    // the sub-read should have triggered any errors here, so simply return the buffer to the queue
                    // and close out.
                    if (r < 0) {
                        self->in_buf_.reset();

                        if (self->stopped_) {
                            return;
                        }

                        self->close();
                        return;
                    }

                    // next read op triggered by packet_read
                }));
}

int kis_external_tcp::packet_read() {
    if (stopped_) {
        return -1;
    }

    const auto frame = static_cast<const kismet_external_frame_stub_t *>(in_buf_->data().data());

    if (kis_ntoh32(frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
        _MSG_ERROR("Kismet external interface got command frame with invalid "
                "signature; either lost position in the external stream or "
                "an unknown protocol was used");
        interface_->trigger_error("invalid signature on frame");
        return -1;
    }

    size_t total_length = kis_ntoh32(frame->data_sz);

    if (kis_ntoh16(frame->proto_sentinel) == KIS_EXTERNAL_V2_SIG &&
            kis_ntoh16(frame->proto_version) == 0x02) {
        total_length += sizeof(kismet_external_frame_v2_t);
    } else if (kis_ntoh16(frame->proto_sentinel) == KIS_EXTERNAL_V3_SIG) {
        total_length += sizeof(kismet_external_frame_v3_t);
    }

    total_length -= sizeof(kismet_external_frame_stub_t);

    if (total_length > MAX_EXTERNAL_FRAME_LEN) {
        _MSG_ERROR("Kismet external interface got command frame which is "
                "too large to be processed ({}); either the frame is malformed "
                "or the connection is from a very old legacy Kismet version using "
                "a different protocol; make sure that you have updated to a "
                "current Kismet version on all systems.", total_length);
        interface_->trigger_error("external packet too large for buffer");
        return -1;
    }

    // read the rest of the packet
    boost::asio::async_read(tcpsocket_, *in_buf_.get(),
            boost::asio::transfer_exactly(total_length),
            boost::asio::bind_executor(strand(),
                [self = shared_from_this()](const boost::system::error_code& ec, std::size_t t) {
                    if (self->stopped_) {
                        self->in_buf_.reset();
                        return;
                    }

                    if (ec) {
                        self->in_buf_.reset();

                        if (ec.value() == boost::asio::error::operation_aborted) {
                            if (!self->stopped_) {
                                self->close();
                                return self->interface_->trigger_error("IPC connection aborted");
                            }

                            return;
                        }

                        if (ec.value() == boost::asio::error::eof) {
                            if (!self->stopped_) {
                                self->close();
                                self->stopped_ = true;
                                return self->interface_->trigger_error("IPC connection closed");
                            }

                            return;
                        }

                        self->close();

                        return self->interface_->trigger_error(fmt::format("IPC connection error: {}", ec.message()));
                    }

                    auto r = self->interface_->handle_packet(self->in_buf_);

                    // if we couldn't handle the packet, return the packet to the queue and error out
                    if (r < 0) {
                        self->in_buf_.reset();

                        if (self->stopped_) {
                            return;
                        }

                        self->close();
                        return;
                    }

                    return self->start_read();
                }));

    // work will be completed in the async read
    return 1;
}

void kis_external_tcp::close() {
    if (strand().running_in_this_thread()) {
        close_impl();
    } else {
        boost::asio::post(strand(),
                [self = shared_from_base<kis_external_tcp>()]() mutable {
                self->close_impl();
                });
    }
}

void kis_external_tcp::close_impl() {
    stopped_ = true;

    if (tcpsocket_.is_open()) {
        try {
            tcpsocket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            tcpsocket_.close();
        } catch (...) { }

    }

    out_bufs_.clear();
}

void kis_external_tcp::write_impl() {
    if (out_bufs_.size() == 0)
        return;

    if (stopped_)
        return;

    auto buf = out_bufs_.front();

    boost::asio::async_write(tcpsocket_, boost::asio::buffer(buf->data(), buf->size()),
            boost::asio::bind_executor(strand(),
                [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
                if (self->out_bufs_.size())
                    self->out_bufs_.pop_front();

                if (ec) {
                    // self->interface_->handle_packet(self->in_buf_);

                    if (self->stopped() || ec.value() == boost::asio::error::operation_aborted) {
                        return;
                    }

                    self->close();

                    _MSG_ERROR("Kismet external interface got an error writing to external TCP: {}", ec.message());
                    self->interface_->trigger_error("write failure");
                    return;
                }

                if (self->out_bufs_.size()) {
                    return self->write_impl();
                }

            }));
}

void kis_external_ws::write_impl() {
    if (out_bufs_.size() == 0)
        return;

    if (stopped_)
        return;

    auto buf = out_bufs_.front();


    write_cb_(buf->data(), buf->size(),
            [self = shared_from_this()](int ec, std::size_t) {
            boost::system::error_code errc =
            boost::system::errc::make_error_code(boost::system::errc::success);

            if (ec == 0)
                errc = boost::asio::error::make_error_code(boost::asio::stream_errc::eof);

            boost::asio::post(self->strand(),
                    boost::beast::bind_front_handler([self, errc]() {
                        self->out_bufs_.pop_front();

                        if (errc) {
                            self->close();

                            // self->interface_->handle_packet(self->in_buf_);

                            _MSG_ERROR("Kismet external interface got an error writing to ws callback: {}", errc.message());
                            self->interface_->trigger_error("write failure");
                            return;
                        }

                        if (self->out_bufs_.size()) {
                            return self->write_impl();
                        }
                }));
        });
}

void kis_external_ws::close() {
    stopped_ = true;
    ws_->close();
    out_bufs_.clear();
}

kis_external_interface::kis_external_interface() :
    cancelled{false},
    timetracker{Globalreg::fetch_mandatory_global_as<time_tracker>()},
    ipctracker{Globalreg::fetch_mandatory_global_as<ipc_tracker_v2>()},
    seqno{0},
    last_pong{0},
    ping_timer_id{-1},
    io_{nullptr},
    protocol_version{3},
    eventbus{Globalreg::fetch_mandatory_global_as<event_bus>()},
    http_session_id{0} {

    ext_mutex.set_name("kis_external_interface");
}

kis_external_interface::~kis_external_interface() {
    close_external();
}

bool kis_external_interface::attach_tcp_socket(tcp::socket& socket) {
    // This is only called inside other IO loops which are themselves
    // running stranded, so we should be able to directly call our
    // operations safely without waiting.

    if (ipc.pid > 0) {
        _MSG_ERROR("Tried to attach a TCP socket to an external endpoint that already has "
                "an IPC instance running.");
        return false;
    }

    cancelled = false;

    io_ = std::make_shared<kis_external_tcp>(shared_from_this(), socket);
    io_->start_read();

    return true;
}

void kis_external_interface::close_external() {
    if (io_ == nullptr || (io_ != nullptr && io_->strand().running_in_this_thread())) {
        close_external_impl();
    } else {
        auto ft = boost::asio::post(io_->strand(),
                std::packaged_task<void()>([this]() mutable {
                    close_external_impl();
                }));
        ft.wait();
    }
}

void kis_external_interface::close_external_impl() {
    // Internal implementation of closing the external interface, called
    // inside a strand by the close_external wrapper
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

    if (io_ != nullptr) {
        io_->close();
        io_.reset();
    }

    if (closure_cb != nullptr) {
        lk.unlock();
        closure_cb();
        lk.lock();
    }

    closure_cb = nullptr;
};


void kis_external_interface::trigger_error(const std::string& in_error) {
    // Don't loop if we're already stopped
    if (cancelled)
        return;

    cancelled = true;

    handle_error(in_error);

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

// std::atomic<int> ipc_strand_g(0);

bool kis_external_interface::run_ipc() {
    // Close using the strand & wait for it to complete, then fork and launch.

    pid_t child_pid;

    cancelled = true;

    struct stat fstat;

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
                Globalreg::globalreg->kismet_config->expand_log_path(rp, "", "", 0, 1),
                external_binary);

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

    auto ipc_out = boost::asio::posix::stream_descriptor(Globalreg::globalreg->io, inpipepair[1]);
    auto ipc_in = boost::asio::posix::stream_descriptor(Globalreg::globalreg->io, outpipepair[0]);

    cancelled = false;

    auto self_ref = shared_from_this();

    ipc = kis_ipc_record(child_pid,
                         [this, self_ref](const std::string&) {
                             close_external();
                         },
                         [this, self_ref](const std::string& err) {
                             trigger_error(err);
                         });

    ipctracker->register_ipc(ipc);

    io_ = std::make_shared<kis_external_ipc>(shared_from_this(), ipc, ipc_in, ipc_out);

    io_->start_read();

    return true;
}

int kis_external_interface::handle_packet(std::shared_ptr<boost::asio::streambuf> buffer) {
    const kismet_external_frame_t *frame = nullptr;
    const kismet_external_frame_v2_t *frame_v2 = nullptr;
    const kismet_external_frame_v3_t *frame_v3 = nullptr;
    uint32_t frame_sz, data_sz;

    // See if we have enough to get a frame header
    size_t buffamt = buffer->size();

    if (buffamt < sizeof(kismet_external_frame_t)) {
        _MSG_ERROR("Kismet external interface got command frame with invalid size");
        return result_handle_packet_needbuf;
    }

    frame = static_cast<const kismet_external_frame_t *>(buffer->data().data());
    frame_v2 = static_cast<const kismet_external_frame_v2_t *>(buffer->data().data());
    frame_v3 = static_cast<const kismet_external_frame_v3_t *>(buffer->data().data());

    // Check the frame signature
    if (kis_ntoh32(frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
        _MSG_ERROR("Kismet external interface got an unexpected command "
                "frame.  You most likely need to upgrade the Kismet datasource "
                "binaries (kismet_cap_...) to match your Kismet server version.");
        trigger_error("invalid signature on command frame");
        return result_handle_packet_error;
    }

    // Detect and process the v2 frames
    if (kis_ntoh16(frame_v2->v2_sentinel) == KIS_EXTERNAL_V2_SIG &&
            kis_ntoh16(frame_v2->frame_version) == 0x02) {

        // Protobuf v2 is being phased out, and is now optional; if the
        // server has v2 support, we can still process it (for now)

#ifdef HAVE_PROTOBUF_CPP
        data_sz = kis_ntoh32(frame_v2->data_sz);
        frame_sz = data_sz + sizeof(kismet_external_frame_v2);

        if (frame_sz >= MAX_EXTERNAL_FRAME_LEN) {
            _MSG_ERROR("Kismet external interface got an oversized command "
                    "frame.  You most likely need to upgrade the Kismet datasource "
                    "binaries (kismet_cap_...) to match your Kismet server version.");
            trigger_error("command frame too large for buffer");
            return result_handle_packet_error;
        }

        // If we don't have the whole buffer available, bail on this read
        if (frame_sz > buffamt) {
            return result_handle_packet_needbuf;
        }

        uint32_t seqno = kis_ntoh32(frame_v2->seqno);

        nonstd::string_view command(frame_v2->command, 32);

        auto trim_pos = command.find('\0');
        if (trim_pos != command.npos)
            command.remove_suffix(command.size() - trim_pos);

        nonstd::string_view content((const char *) frame_v2->data, data_sz);

        // if we've gotten this far, switch us to v2
        protocol_version = 2;

        // Dispatch the received command & see if we need to purge the buffer ourselves
        dispatch_rx_packet(command, seqno, content);

#else
        _MSG_ERROR("Kismet external interface got an v2 command frame, but this "
                "Kismet server was not compiled with protobufs support.  Either "
                "upgrade the capture tool (kismet_cap_...) or install a "
                "build of the Kismet server with protobufs enabled.");
        trigger_error("Unsupported Kismet protocol");
        return result_handle_packet_error;
#endif
    } else if (kis_ntoh16(frame_v3->v3_sentinel) == KIS_EXTERNAL_V3_SIG &&
            kis_ntoh16(frame_v3->v3_version) == 0x03) {

        // The V3 kismet protocol uses msgpack and will be the new target

        data_sz = kis_ntoh32(frame_v3->length);
        frame_sz = data_sz + sizeof(kismet_external_frame_v3);

        if (frame_sz >= MAX_EXTERNAL_FRAME_LEN) {
            _MSG_ERROR("Kismet external interface got an oversized command "
                    "frame.  You most likely need to upgrade the Kismet datasource "
                    "binaries (kismet_cap_...) to match your Kismet server version.");
            trigger_error("command frame too large for buffer");
            return result_handle_packet_error;
        }

        // If we don't have the whole buffer available, bail on this read
        if (frame_sz > buffamt) {
            return result_handle_packet_needbuf;
        }

        uint32_t seqno = kis_ntoh32(frame_v3->seqno);
        uint16_t command = kis_ntoh16(frame_v3->pkt_type);
        uint16_t code = kis_ntoh16(frame_v3->code);

        nonstd::string_view content((const char *) frame_v3->data, data_sz);

        // If we've gotten this far it's a valid newer protocol, switch to v2 mode
        protocol_version = 3;

        // Dispatch the received command
        dispatch_rx_packet_v3(buffer, command, seqno, code, content);

        return result_handle_packet_ok;
    } else {
        // Unknown type of packet (or legacy v0 protocol which we're phasing out)
        _MSG_ERROR("Kismet external interface got an v2 command frame, but this "
                "Kismet server was not compiled with protobufs support.  Either "
                "upgrade the capture tool (kismet_cap_...) or install a "
                "build of the Kismet server with protobufs enabled.");
        trigger_error("Unsupported Kismet protocol");
        return result_handle_packet_error;
    }

    return result_handle_packet_ok;

}


void kis_external_interface::start_write(const char *data, size_t len) {
    if (cancelled)
        return;

    if (io_ == nullptr) {
        throw(std::runtime_error("kis_external tried to write with no io handler"));
    }

    if (io_->stopped())
        return;

    io_->write(data, len);
}

bool kis_external_interface::dispatch_rx_packet_v3(std::shared_ptr<boost::asio::streambuf> buffer, uint16_t command,
        uint16_t code, uint32_t seqno, const nonstd::string_view& content) {
    // V3 dispatcher based on packet type numbers, carrying msgpacked payloads.

    // Implementations should directly call this for automatic dispatch before implementing
    // their own dispatch if this returns false.

    switch (command) {
        case KIS_EXTERNAL_V3_CMD_MESSAGE:
            handle_packet_message_v3(seqno, code, content);
            return true;
        case KIS_EXTERNAL_V3_CMD_PING:
            handle_packet_ping_v3(seqno, code, content);
            return true;
        case KIS_EXTERNAL_V3_CMD_PONG:
            handle_packet_pong_v3(seqno, code, content);
            return true;
        case KIS_EXTERNAL_V3_CMD_SHUTDOWN:
            handle_packet_shutdown_v3(seqno, code, content);
            return true;
        case KIS_EXTERNAL_V3_WEB_REGISTERURI:
            handle_packet_http_register_v3(seqno, code, content);
            return true;
        case KIS_EXTERNAL_V3_WEB_RESPONSE:
            handle_packet_http_response_v3(seqno, code, content);
            return true;
        case KIS_EXTERNAL_V3_WEB_AUTHREQ:
            handle_packet_http_auth_request_v3(seqno, code, content);
            return true;
        case KIS_EXTERNAL_V3_EVT_REGISTER:
            handle_packet_eventbus_register_v3(seqno, code, content);
            return true;
        case KIS_EXTERNAL_V3_EVT_PUBLISH:
            handle_packet_eventbus_publish_v3(seqno, code, content);
            return true;
    }

    return false;
}

void kis_external_interface::handle_msg_proxy(const std::string& msg, const int msgtype) {
    _MSG(msg, msgtype);
}

void kis_external_interface::handle_packet_message_v3(uint32_t in_seqno,
        uint16_t code, const nonstd::string_view& in_content) {

    mpack_tree_raii tree;
    mpack_node_t root;

    unsigned int msgtype;

    mpack_tree_init_data(&tree, in_content.data(), in_content.length());

    if (!mpack_tree_try_parse(&tree)) {
        _MSG_ERROR("Kismet external interface got unparseable v3 MESSAGE");
        trigger_error("invalid v3 MESSAGE");
        return;
    }

    root = mpack_tree_root(&tree);

    msgtype = mpack_node_u16(mpack_node_map_uint(root, KIS_EXTERNAL_V3_MESSAGE_FIELD_TYPE));

    auto message_n = mpack_node_map_uint(root, KIS_EXTERNAL_V3_MESSAGE_FIELD_STRING);
    auto message_s = mpack_node_str(message_n);
    auto message_sz = mpack_node_data_len(message_n);

    if (mpack_tree_error(&tree) != mpack_ok) {
        _MSG_ERROR("Kismet external interface got malformed v3 MESSAGE");
        trigger_error("invalid v3 MESSAGE");

        return;
    }

    auto message_str = std::string(message_s, message_sz);
    if (message_sz == 0) {
        message_str = "[no message provided by datasource]";
    }

    handle_msg_proxy(message_str, msgtype);
}

void kis_external_interface::handle_packet_ping_v3(uint32_t in_seqno,
        uint16_t code, const nonstd::string_view& in_content) {
    send_pong(in_seqno);
}

void kis_external_interface::handle_packet_pong_v3(uint32_t in_seqno,
        uint16_t code, const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "kei handle_packet_pong_v3");
    last_pong = time(0);

    if (!v2_probe_ack) {
        v2_probe_ack = true;
        handle_v2_pong_event();
    }
}

void kis_external_interface::handle_packet_shutdown_v3(uint32_t in_seqno,
        uint16_t code, const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "kei handle_packet_shutdown_v3");

    mpack_tree_raii tree;
    mpack_node_t root;

    mpack_tree_init_data(&tree, in_content.data(), in_content.length());

    if (!mpack_tree_try_parse(&tree)) {
        _MSG_ERROR("Kismet external interface got unparseable v3 SHUTDOWN");
        trigger_error("invalid v3 SHUTDOWN");
        return;
    }

    root = mpack_tree_root(&tree);

    auto reason_n = mpack_node_map_uint(root, KIS_EXTERNAL_V3_SHUTDOWN_FIELD_REASON);
    auto reason_s = mpack_node_str(reason_n);
    auto reason_sz = mpack_node_data_len(reason_n);

    if (mpack_tree_error(&tree) != mpack_ok) {
        _MSG_INFO("Kismet external interface shutting down: no reason");
        trigger_error("remote connection triggered shutdown: no reason");
    } else {
        auto reason = std::string(reason_s, reason_sz);
        _MSG_INFO("Kismet external interface shutting down: {}", reason_s);
        trigger_error(fmt::format("remote connection triggered shutdown: {}", reason_s));
    }
}

// Send events from the eventbus to any subscribed consumers on the external protocol
void kis_external_interface::proxy_event(std::shared_ptr<eventbus_event> evt) {
    std::stringstream ss;
    json_adapter::pack(ss, evt);

#ifdef HAVE_PROTOBUF_CPP
    if (protocol_version < 3) {
        KismetEventBus::EventbusEvent ebe;
        ebe.set_event_json(ss.str());

        if (protocol_version == 2) {
            send_packet_v2("EVENT", 0, ebe);
        }

        _MSG_ERROR("unhandled legacy protocol version {}", protocol_version.load());
    }
#endif

    if (protocol_version == 3) {
        char *data = NULL;
        size_t size;
        mpack_writer_t writer;

        const auto json_str = ss.str();

        mpack_writer_init_growable(&writer, &data, &size);

        mpack_build_map(&writer);
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_EVT_EVENT_FIELD_EVENT);
        mpack_write_cstr(&writer, json_str.c_str());
        mpack_complete_map(&writer);

        if (mpack_writer_destroy(&writer) != mpack_ok) {
            if (data != nullptr) {
                free(data);
            }

            _MSG_ERROR("Kismet external interface failed serializing v3 event");
            trigger_error("failed to serialize v3 EVENT");
            return;
        }

        send_packet_v3(KIS_EXTERNAL_V3_EVT_EVENT, 0, 1, data, size);

        free(data);
    }

    return;
}

void kis_external_interface::handle_packet_eventbus_register_v3(uint32_t in_seqno,
        uint16_t code, const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "kei handle_packet_eventbus_register_v3");

    mpack_tree_raii tree;
    mpack_node_t root;

    mpack_tree_init_data(&tree, in_content.data(), in_content.length());

    if (!mpack_tree_try_parse(&tree)) {
        _MSG_ERROR("Kismet external interface got unparseable v3 EVENTREGISTER");
        trigger_error("invalid v3 EVENTREGISTER");
        return;
    }

    root = mpack_tree_root(&tree);

    mpack_node_t evtlist = mpack_node_map_uint(root, KIS_EXTERNAL_V3_EVT_EVENTREGISTER_FIELD_EVENT);
    if (mpack_tree_error(&tree) != mpack_ok) {
        _MSG_ERROR("Kismet external interface got unparseable v3 EVENTREGISTER event list");
        trigger_error("invalid v3 EVENTREGISTER");
        return;
    }

    auto events_sz = mpack_node_array_length(evtlist);

    for (size_t szi = 0; szi < events_sz; szi++) {
        auto evt_n = mpack_node_array_at(evtlist, szi);
        auto evt_s = mpack_node_str(evt_n);
        auto evt_sz = mpack_node_data_len(evt_n);

        if (mpack_tree_error(&tree) != mpack_ok) {
            _MSG_ERROR("Kismet external interface got unparseable v3 EVENTREGISTER event list");
            trigger_error("invalid v3 EVENTREGISTER");
            return;
        }

        auto evt = std::string(evt_s, evt_sz);

        auto k = eventbus_callback_map.find(evt);

        if (k != eventbus_callback_map.end())
            eventbus->remove_listener(k->second);

        unsigned long eid =
            eventbus->register_listener(evt,
                    [this](std::shared_ptr<eventbus_event> e) {
                    proxy_event(e);
                    });

        eventbus_callback_map[evt] = eid;
    }
}

void kis_external_interface::handle_packet_eventbus_publish_v3(uint32_t in_seqno,
        uint16_t code, const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "kei handle_packet_eventbus_publish_v3");

    mpack_tree_raii tree;
    mpack_node_t root;

    mpack_tree_init_data(&tree, in_content.data(), in_content.length());

    if (!mpack_tree_try_parse(&tree)) {
        _MSG_ERROR("Kismet external interface got unparseable v3 EVENTPUBLISH");
        trigger_error("invalid v3 EVENTPUBLISH");
        return;
    }

    root = mpack_tree_root(&tree);

    auto evt_type_n = mpack_node_map_uint(root, KIS_EXTERNAL_V3_EVT_EVENTPUBLISH_FIELD_TYPE);
    auto evt_type_s = mpack_node_str(evt_type_n);
    auto evt_type_sz = mpack_node_data_len(evt_type_n);

    auto evt_event_n =mpack_node_map_uint(root, KIS_EXTERNAL_V3_EVT_EVENTREGISTER_FIELD_EVENT);
    auto evt_event_s = mpack_node_str(evt_event_n);
    auto evt_event_sz = mpack_node_data_len(evt_event_n);

    if (mpack_tree_error(&tree) != mpack_ok) {
        _MSG_ERROR("Kismet external interface got unparseable v3 EVENTPUBLISH");
        trigger_error("invalid v3 EVENTPUBLISH");

        return;
    }

    auto evt_event = std::string(evt_event_s, evt_event_sz);
    auto evt_type = std::string(evt_type_s, evt_type_sz);

    auto evt = eventbus->get_eventbus_event(evt_type);
    evt->get_event_content()->insert("kismet.eventbus.event_json",
            std::make_shared<tracker_element_string>(evt_event));
    eventbus->publish(evt);
}

void kis_external_interface::handle_packet_http_register_v3(uint32_t in_seqno,
        uint16_t code, const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "kei handle_packet_http_register_v3");

    const auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    mpack_tree_raii tree;
    mpack_node_t root;

    mpack_tree_init_data(&tree, in_content.data(), in_content.length());

    if (!mpack_tree_try_parse(&tree)) {
        _MSG_ERROR("Kismet external interface got unparseable v3 HTTPREGISTER");
        trigger_error("invalid v3 HTTPREGISTER");
        return;
    }

    root = mpack_tree_root(&tree);

    auto method_n = mpack_node_map_uint(root, KIS_EXTERNAL_V3_WEB_REGISTERURI_FIELD_METHOD);
    auto method_s = mpack_node_str(method_n);
    auto method_sz = mpack_node_data_len(method_n);

    auto uri_n = mpack_node_map_uint(root, KIS_EXTERNAL_V3_WEB_REGISTERURI_FIELD_URI);
    auto uri_s = mpack_node_str(uri_n);
    auto uri_sz = mpack_node_data_len(uri_n);

    if (mpack_tree_error(&tree) != mpack_ok) {
        _MSG_ERROR("Kismet external interface got unparseable v3 HTTPREGISTER");
        trigger_error("invalid v3 HTTPREGISTER");

        return;
    }

    auto uri = std::string(uri_s, uri_sz);
    auto method = std::string(method_s, method_sz);

    httpd->register_route(uri, {method}, httpd->LOGON_ROLE,
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

                send_http_request_v3(sess_id, static_cast<std::string>(con->uri()),
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

void kis_external_interface::handle_packet_http_response_v3(uint32_t in_seqno,
        uint16_t code, const nonstd::string_view& in_content) {
    kis_lock_guard<kis_mutex> lk(ext_mutex, "kei handle_packet_http_response_v3");

    const auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    mpack_tree_raii tree;
    mpack_node_t root;

    mpack_tree_init_data(&tree, in_content.data(), in_content.length());

    if (!mpack_tree_try_parse(&tree)) {
        _MSG_ERROR("Kismet external interface got unparseable v3 HTTPRESPONSE");
        trigger_error("invalid v3 HTTPRESPONSE");
        return;
    }

    root = mpack_tree_root(&tree);

    const auto req_id =
        mpack_node_uint(mpack_node_map_uint(root, KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_REQID));

    if (mpack_tree_error(&tree) != mpack_ok) {
        _MSG_ERROR("Kismet external interface got unparseable v3 HTTPRESPONSE");
        trigger_error("invalid v3 HTTPRESPONSE");
        return;
    }

    auto si = http_proxy_session_map.find(req_id);

    if (si == http_proxy_session_map.end()) {
        _MSG("Kismet external interface got a HTTPRESPONSE for an unknown session", MSGFLAG_ERROR);
        trigger_error("Invalid HTTPRESPONSE session");
        return;
    }

    auto session = si->second;

    // process any headers before processing data.  the caller can screw us up by returning a
    // continued stream *and* including headers here, but that's their problem.
    if (mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_HEADERS)) {
        mpack_node_t hdrmap = mpack_node_map_uint(root, KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_HEADERS);
        auto hdr_sz = mpack_node_map_count(hdrmap);

        for (size_t szi = 0; szi < hdr_sz; szi++) {
            auto key_n = mpack_node_map_key_at(hdrmap, szi);
            auto key_s = mpack_node_str(key_n);
            auto key_sz = mpack_node_data_len(key_n);

            auto hdr_n = mpack_node_map_value_at(hdrmap, szi);
            auto hdr_s = mpack_node_str(hdr_n);
            auto hdr_sz = mpack_node_data_len(hdr_n);

            if (mpack_tree_error(&tree) != mpack_ok) {
                _MSG_ERROR("Kismet external interface got unparseable v3 HTTPRESPONSE");
                trigger_error("invalid v3 HTTPRESPONSE");

                return;
            }

            auto hdr_key = std::string(key_s, key_sz);
            auto hdr_val = std::string(hdr_s, hdr_sz);

            session->connection->append_header(hdr_key, hdr_val);
        }
    }

    // process any result code
    if (mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_RESULTCODE)) {
        auto code =
            mpack_node_u32(mpack_node_map_uint(root, KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_RESULTCODE));

        if (mpack_tree_error(&tree) != mpack_ok) {
            _MSG_ERROR("Kismet external interface got unparseable v3 HTTPRESPONSE");
            trigger_error("invalid v3 HTTPRESPONSE");
            return;
        }

        session->connection->set_status(code);
    }

    // process any data
    if (mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_CONTENT)) {
        auto content_sz =
            mpack_node_bin_size(mpack_node_map_uint(root, KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_CONTENT));
        auto content =
            mpack_node_bin_data(mpack_node_map_uint(root, KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_CONTENT));

        if (mpack_tree_error(&tree) != mpack_ok) {
            _MSG_ERROR("Kismet external interface got unparseable v3 HTTPRESPONSE");
            trigger_error("invalid v3 HTTPRESPONSE");
            return;
        }

        session->connection->response_stream().put_data(content, content_sz);
    }

    // process terminating the connection
    if (mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_CLOSE)) {
        auto close =
            mpack_node_bool(mpack_node_map_uint(root, KIS_EXTERNAL_V3_WEB_RESPONSE_FIELD_CLOSE));

        if (close) {
            session->connection->response_stream().complete();
            session->locker->unlock();
        }
    }
}

void kis_external_interface::handle_packet_http_auth_request_v3(uint32_t in_seqno,
        uint16_t code, const nonstd::string_view& in_content) {
    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();
    auto token = httpd->create_or_find_auth("external plugin", httpd->LOGON_ROLE, 0);

    send_http_auth_v3(token);
}

unsigned int kis_external_interface::send_http_request_v3(uint32_t in_http_sequence,
        const std::string& in_uri, const std::string& in_method,
        std::map<std::string, std::string> in_vardata) {

    char *data = NULL;
    size_t size;
    mpack_writer_t writer;

    mpack_writer_init_growable(&writer, &data, &size);

    mpack_build_map(&writer);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_WEB_REQUEST_FIELD_REQID);
    mpack_write_u32(&writer, in_http_sequence);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_WEB_REQUEST_FIELD_URI);
    mpack_write_cstr(&writer, in_uri.c_str());

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_WEB_REQUEST_FIELD_METHOD);
    mpack_write_cstr(&writer, in_method.c_str());

    if (in_vardata.size() > 0) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_WEB_REQUEST_FIELD_VARIABLES);
        mpack_build_map(&writer);

        for (const auto& pi : in_vardata) {
            mpack_write_cstr(&writer, pi.first.c_str());
            mpack_write_cstr(&writer, pi.second.c_str());
        }

        mpack_complete_map(&writer);
    }

    mpack_complete_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) {
        if (data != nullptr) {
            free(data);
        }

        _MSG_ERROR("Kismet external interface failed serializing v3 HTTPREQ");
        trigger_error("failed to serialize v3 HTTPREQ");
        return -1;
    }

    send_packet_v3(KIS_EXTERNAL_V3_WEB_REQUEST, 0, 1, data, size);

    free(data);

    return 1;
}

unsigned int kis_external_interface::send_http_auth_v3(const std::string& in_cookie) {
    char *data = NULL;
    size_t size;
    mpack_writer_t writer;

    mpack_writer_init_growable(&writer, &data, &size);

    mpack_build_map(&writer);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_WEB_AUTHRESP);
    mpack_write_cstr(&writer, in_cookie.c_str());

    mpack_complete_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) {
        if (data != nullptr) {
            free(data);
        }

        _MSG_ERROR("Kismet external interface failed serializing v3 HTTPAUTH");
        trigger_error("failed to serialize v3 HTTPAUTH");
        return -1;
    }

    send_packet_v3(KIS_EXTERNAL_V3_WEB_AUTHRESP, 0, 1, data, size);

    free(data);

    return 1;
}

unsigned int kis_external_interface::send_ping() {
#ifdef HAVE_PROTOBUF_CPP
    if (protocol_version == 2) {
        return send_packet_v2("PING", 0, KismetExternal::Ping{});
    }
#endif

    if (protocol_version == 3) {
        return send_packet_v3(KIS_EXTERNAL_V3_CMD_PING, 0, 1, "");
    }

    _MSG_ERROR("unhandled protocol version {}", protocol_version.load());

    return -1;
}

unsigned int kis_external_interface::send_v2_probe_ping() {
    // craft a v2 ping
    const ssize_t frame_sz = sizeof(kismet_external_frame_v2_t);
    std::array<char, frame_sz> frame_buf;
    auto frame = reinterpret_cast<kismet_external_frame_v2_t *>(frame_buf.data());

    frame->signature = kis_hton32(KIS_EXTERNAL_PROTO_SIG);
    frame->data_sz = 0;
    frame->v2_sentinel = kis_hton16(KIS_EXTERNAL_V2_SIG);
    frame->frame_version = kis_hton16(2);
    strncpy(frame->command, "PING", 31);
    frame->seqno = 0;

    v2_probe_ack = false;

    start_write(frame_buf.data(), frame_sz);

    return 1;
}

unsigned int kis_external_interface::send_pong(uint32_t ping_seqno) {
#ifdef HAVE_PROTOBUF_CPP
    KismetExternal::Pong p;
    p.set_ping_seqno(ping_seqno);

    if (protocol_version == 2) {
        return send_packet_v2("PONG", 0, p);
    }
#endif

    if (protocol_version == 3) {
        return send_packet_v3(KIS_EXTERNAL_V3_CMD_PONG, ping_seqno, 1, "");
    }

    _MSG_ERROR("unhandled protocol version {}", protocol_version.load());

    return -1;
}

unsigned int kis_external_interface::send_shutdown(std::string reason) {
#ifdef HAVE_PROTOBUF_CPP
    KismetExternal::ExternalShutdown s;
    s.set_reason(reason);

    if (protocol_version == 2) {
        return send_packet_v2("SHUTDOWN", 0, s);
    }
#endif

    _MSG_ERROR("unhandled protocol version {}", protocol_version.load());

    return -1;
}



#ifdef HAVE_PROTOBUF_CPP
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

    if (!v2_probe_ack) {
        v2_probe_ack = true;
        handle_v2_pong_event();
    }
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

    if (protocol_version == 2) {
        return send_packet_v2("HTTPREQUEST", 0, r);
    }

    _MSG_ERROR("unhandled legacy protocol version {}", protocol_version.load());

    return -1;
}

unsigned int kis_external_interface::send_http_auth(std::string in_cookie) {
    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    KismetExternalHttp::HttpAuthToken a;
    a.set_token(in_cookie);

    if (protocol_version == 2) {
        return send_packet_v2("HTTPAUTH", 0, a);
    }

    _MSG_ERROR("unhandled protocol version {}", protocol_version.load());

    return -1;
}
#endif
