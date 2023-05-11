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

#ifndef __KIS_EXTERNAL_H__
#define __KIS_EXTERNAL_H__

/* Kismet External Tool API
 *
 * This superclass marshals the external tool API and implements the kismet-level
 * commands and options; It should be subclassed by specific tool implementations,
 * such as data sources or plugins.
 *
 * More docs on the external tool api are in:
 * docs/dev/helper_interface.md
 *
 */

#include "config.h"

#include <functional>
#include <list>

#include "endian_magic.h"
#include "eventbus.h"
#include "globalregistry.h"
#include "ipctracker_v2.h"
#include "kis_external_packet.h"
#include "kis_net_beast_httpd.h"

#include "boost/asio.hpp"
using boost::asio::ip::tcp;

#include <google/protobuf/message_lite.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

#include "protobuf_cpp/kismet.pb.h"
#include "protobuf_cpp/http.pb.h"
#include "protobuf_cpp/eventbus.pb.h"

// Namespace stub and forward class definition to make deps hopefully easier going forward
namespace KismetExternal {
    class Command;
};

struct kis_external_http_session {
    std::shared_ptr<kis_net_beast_httpd_connection> connection;
    std::shared_ptr<conditional_locker<int> > locker;
};

class kis_external_interface;

class kis_external_io : public std::enable_shared_from_this<kis_external_io> {
public:
    template <class d>
    std::shared_ptr<d> shared_from_base() {
        return std::static_pointer_cast<d>(shared_from_this());
    }

    kis_external_io(std::shared_ptr<kis_external_interface> ext) :
        stopped_{false},
        interface_{ext},
        strand_{Globalreg::globalreg->io} { }
    
    virtual ~kis_external_io() {
        close();
    }

    virtual void attach_interface(std::shared_ptr<kis_external_interface> ext) {
        boost::asio::post(strand(), 
                [self = shared_from_this(), ext]() mutable {
            self->interface_ = ext;
        });
    }

    virtual void start_read() = 0;

    virtual void write(const char *data, size_t len) {
        if (stopped_)
            return;

        auto buf = std::make_shared<std::string>(data, len);

        boost::asio::post(strand(), 
                [self = shared_from_this(), buf]() mutable {

                self->out_bufs_.push_back(buf);

                if (self->out_bufs_.size() > 1) {
                return;
                }

                self->write_impl();
                });
    }

    virtual void write_impl() = 0;

    virtual bool connected() { return false; }

    virtual boost::asio::io_service::strand &strand() { return strand_; }

    virtual void close() { 
        stopped_ = true;
    };

    virtual bool stopped() {
        return stopped_;
    }

    std::atomic<bool> stopped_;

    std::shared_ptr<kis_external_interface> interface_;
    boost::asio::io_service::strand strand_;

    boost::asio::streambuf in_buf_;
    std::list<std::shared_ptr<std::string>> out_bufs_;
};

class kis_external_ipc : public kis_external_io {
public:
    kis_external_ipc(std::shared_ptr<kis_external_interface> iface,
            kis_ipc_record& ipc,
            boost::asio::posix::stream_descriptor &ipc_in, 
            boost::asio::posix::stream_descriptor &ipc_out) :
        kis_external_io{iface},
        ipc_in_{std::move(ipc_in)},
        ipc_out_{std::move(ipc_out)},
        ipc_{ipc},
        ipctracker_{Globalreg::fetch_mandatory_global_as<ipc_tracker_v2>()} { }

    virtual ~kis_external_ipc() override;

    virtual void start_read() override;

    virtual bool connected() override {
        return (ipc_in_.is_open() && ipc_out_.is_open());
    }

    virtual void write_impl() override;

    virtual void close() override;

    boost::asio::posix::stream_descriptor ipc_in_, ipc_out_;

    kis_ipc_record &ipc_;

    std::shared_ptr<ipc_tracker_v2> ipctracker_;
};

class kis_external_tcp : public kis_external_io {
public:
    kis_external_tcp(std::shared_ptr<kis_external_interface> iface,
            tcp::socket& socket) :
        kis_external_io{iface},
        tcpsocket_{std::move(socket)} { }

    virtual void start_read() override;

    virtual bool connected() override {
        return tcpsocket_.is_open();
    }

    virtual void write_impl() override;

    virtual void close() override;

    tcp::socket tcpsocket_;
};

class kis_external_ws : public kis_external_io {
public:
    using cb_func_t = std::function<int (const char *, size_t, std::function<void (int, std::size_t)>)>;

    kis_external_ws(std::shared_ptr<kis_external_interface> iface,
            std::shared_ptr<kis_net_web_websocket_endpoint> ws,
            cb_func_t write_cb) :
        kis_external_io(iface),
        ws_{ws},
        ws_strand_{ws->strand()},
        write_cb_{write_cb} { }

    virtual boost::asio::io_service::strand &strand() override {
        return ws_strand_;
    }

    virtual void start_read() override { };

    virtual void write_impl() override;

    virtual bool connected() override {
        return true;
    }

    virtual void close() override;


    std::shared_ptr<kis_net_web_websocket_endpoint> ws_;
    boost::asio::io_service::strand ws_strand_;
    cb_func_t write_cb_;
};

// External interface API bridge;
class kis_external_interface : public std::enable_shared_from_this<kis_external_interface> {
public:
    kis_external_interface();
    virtual ~kis_external_interface();

    std::shared_ptr<kis_external_interface> get_shared() {
        return shared_from_this();
    }

    // Launch the external binary and connect the IPC channel to our buffer
    // interface; most tools will use this unless they support network; 
    // datasources are the primary exception
    virtual bool run_ipc();

    // Attach a tcp socket
    virtual bool attach_tcp_socket(tcp::socket& socket);

    // Attach an IO handler
    virtual void attach_io(std::shared_ptr<kis_external_io> io) {
        io_ = io;
        io_->start_read();
    }

    // Check to see if an IPC binary is available
    static bool check_ipc(const std::string& in_binary);

    // Set a closure callback, for instance when being driven from a websocket
    virtual void set_closure_cb(std::function<void ()> cb) {
        kis_lock_guard<kis_mutex> lk(ext_mutex, "external set_closure_cb");
        closure_cb = cb;
    }

    // Move a closure cb to a new entity and clear it
    virtual std::function<void ()> move_closure_cb() {
        kis_lock_guard<kis_mutex> lk(ext_mutex, "external move_closure_cb");
        auto ret = closure_cb;
        closure_cb = nullptr;
        return ret;
    }

    // close the external interface, opportunistically wraps in strand
    virtual void close_external();

    // We use the raw http server APIs instead of the newer endpoint handlers because we
    // potentially mess with the headers and other internals

    // Trigger an error
    virtual void trigger_error(const std::string& in_error);

    // Get the IO handler
    virtual std::shared_ptr<kis_external_io> move_io(std::shared_ptr<kis_external_interface> newif) {
        auto io_ref = io_;
        io_ = nullptr;
        io_ref->attach_interface(newif);
        return io_ref;
    }

protected:
    // Internal implementation of closing
    virtual void close_external_impl();

    std::function<void (void)> closure_cb;

    // Handle an error; override in child classes; called when an error causes a shutdown
    virtual void handle_error(const std::string& error) { }

    // Wrap a protobuf'd packet in our network framing and send it, returning the sequence number
    // Uses the legacy v0 protocol
    unsigned int send_packet(std::shared_ptr<KismetExternal::Command> c);

    // Wrap a protobuf packet in a v2 header and transmit it, returning the sequence number
    template<class T>
    unsigned int send_packet_v2(const std::string& command, uint32_t in_seqno, const T& content) {
        if ((io_ != nullptr && io_->stopped()) || cancelled) {
            _MSG_DEBUG("Attempt to send {} on closed external interface", command);
            return 0;
        }

        if (in_seqno == 0) {
            kis_lock_guard<kis_mutex> lk(ext_mutex, "kei send_packet_v2");
            if (++seqno == 0)
                seqno = 1;
            in_seqno = seqno;
        }

        // Get the serialized size of our message
#if GOOGLE_PROTOBUF_VERSION >= 3006001
        size_t content_sz = content.ByteSizeLong();
#else
        size_t content_sz = content.ByteSize();
#endif

        ssize_t frame_sz = sizeof(kismet_external_frame_v2_t) + content_sz;

        char frame_buf[frame_sz];
        auto frame = reinterpret_cast<kismet_external_frame_v2_t *>(frame_buf);

        frame->signature = kis_hton32(KIS_EXTERNAL_PROTO_SIG);
        frame->data_sz = kis_hton32(content_sz);
        frame->v2_sentinel = kis_hton16(KIS_EXTERNAL_V2_SIG);
        frame->frame_version = kis_hton16(2);
        strncpy(frame->command, command.c_str(), 31);
        frame->seqno = kis_hton32(in_seqno);

        content.SerializeToArray(frame->data, content_sz);

        start_write(frame_buf, frame_sz);

        return in_seqno;
    }

    // Central packet dispatch handler, common layer and v2+ handler
    virtual bool dispatch_rx_packet(const nonstd::string_view& command, 
            uint32_t seqno, const nonstd::string_view& content);

    // Generic msg proxy
    virtual void handle_msg_proxy(const std::string& msg, const int msgtype); 

    // Packet handlers
    virtual void handle_packet_message(uint32_t in_seqno, const nonstd::string_view& in_content);
    virtual void handle_packet_ping(uint32_t in_seqno, const nonstd::string_view& in_content);
    virtual void handle_packet_pong(uint32_t in_seqno, const nonstd::string_view& in_content);
    virtual void handle_packet_shutdown(uint32_t in_seqno, const nonstd::string_view& in_content);
    virtual void handle_packet_eventbus_register(uint32_t in_seqno, const nonstd::string_view& in_content);
    virtual void handle_packet_eventbus_publish(uint32_t in_seqno, const nonstd::string_view& in_content);

    unsigned int send_ping();
    unsigned int send_pong(uint32_t ping_seqno);
    unsigned int send_shutdown(std::string reason);

    std::atomic<bool> cancelled;

    kis_mutex ext_mutex;

    std::shared_ptr<time_tracker> timetracker;
    std::shared_ptr<ipc_tracker_v2> ipctracker;

    std::atomic<uint32_t> seqno;
    std::atomic<time_t> last_pong;

    int ping_timer_id;

    void start_write(const char *data, size_t len);

    std::shared_ptr<kis_external_io> io_;


    // Pipe IPC
    std::string external_binary;
    std::vector<std::string> external_binary_args;

    kis_ipc_record ipc;

    std::atomic<unsigned int> protocol_version;

    // Eventbus proxy code
    std::shared_ptr<event_bus> eventbus;
    std::map<std::string, unsigned long> eventbus_callback_map;

    void proxy_event(std::shared_ptr<eventbus_event>);


    // Webserver proxy code

    virtual void handle_packet_http_register(uint32_t in_seqno, const nonstd::string_view& in_content);
    virtual void handle_packet_http_response(uint32_t in_seqno, const nonstd::string_view& in_content);
    virtual void handle_packet_http_auth_request(uint32_t in_seqno, const nonstd::string_view& in_content);

    unsigned int send_http_request(uint32_t in_http_sequence, std::string in_uri,
            std::string in_method, std::map<std::string, std::string> in_postdata);
    unsigned int send_http_auth(std::string in_session);

    // HTTP session identities for multi-packet responses
    uint32_t http_session_id;
    std::map<uint32_t, std::shared_ptr<kis_external_http_session> > http_proxy_session_map;

public:
    static const int result_handle_packet_cancelled = -2;
    static const int result_handle_packet_error = -1;
    static const int result_handle_packet_needbuf = 1;
    static const int result_handle_packet_ok = 2;

    std::shared_ptr<KismetExternal::Command> cached_cmd;

    // Handle a buffer containing a network frame packet
    template<class BoostBuffer>
    int handle_packet(BoostBuffer& buffer) {
        const kismet_external_frame_t *frame = nullptr;
        const kismet_external_frame_v2_t *frame_v2 = nullptr;
        uint32_t frame_sz, data_sz;

        // Consume everything in the buffer that we can
        while (1) {
            // See if we have enough to get a frame header
            size_t buffamt = buffer.size();

            if (buffamt < sizeof(kismet_external_frame_t)) {
                return result_handle_packet_needbuf;
            }

            frame = boost::asio::buffer_cast<const kismet_external_frame_t *>(buffer.data());
            frame_v2 = boost::asio::buffer_cast<const kismet_external_frame_v2_t *>(buffer.data());

            // Check the frame signature
            if (kis_ntoh32(frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
                _MSG_ERROR("Kismet external interface got command frame with invalid signature");
                trigger_error("Invalid signature on command frame");
                return result_handle_packet_error;
            }

            // Detect and process the v2 frames
            if (kis_ntoh16(frame_v2->v2_sentinel) == KIS_EXTERNAL_V2_SIG &&
                    kis_ntoh16(frame_v2->frame_version) == 0x02) {

                data_sz = kis_ntoh32(frame_v2->data_sz);
                frame_sz = data_sz + sizeof(kismet_external_frame_v2);

                if (frame_sz >= 16384) {
                    _MSG_ERROR("Kismet external interface got a command frame which is too large to "
                            "be processed ({}); either the frame is malformed or you are connecting to "
                            "a legacy Kismet remote capture drone; make sure you have updated to modern "
                            "Kismet on all connected systems.", frame_sz);
                    trigger_error("Command frame too large for buffer");
                    return result_handle_packet_error;
                }

                // If we don't have the whole buffer available, bail on this read
                if (frame_sz > buffamt) {
                    return result_handle_packet_needbuf;
                }

                // No checksum anymore

                uint32_t seqno = kis_ntoh32(frame_v2->seqno);

                nonstd::string_view command(frame_v2->command, 32);

                auto trim_pos = command.find('\0');
                if (trim_pos != command.npos)
                    command.remove_suffix(command.size() - trim_pos);

                nonstd::string_view content((const char *) frame_v2->data, data_sz);

                // If we've gotten this far it's a valid newer protocol, switch to v2 mode
                protocol_version = 2;

                // Dispatch the received command
                dispatch_rx_packet(command, seqno, content);

                buffer.consume(frame_sz);
            } else {
                // Check the length
                data_sz = kis_ntoh32(frame->data_sz);
                frame_sz = data_sz + sizeof(kismet_external_frame);

                // If we've got a bogus length, blow it up.  Anything over 8k is assumed to be insane.
                if ((long int) frame_sz >= 16384) {
                    _MSG_ERROR("Kismet external interface got a command frame which is too large to "
                            "be processed ({}); either the frame is malformed or you are connecting to "
                            "a legacy Kismet remote capture drone; make sure you have updated to modern "
                            "Kismet on all connected systems.", frame_sz);
                    trigger_error("Command frame too large for buffer");
                    return result_handle_packet_error;
                }

                // If we don't have the whole buffer available, bail on this read
                if (frame_sz > buffamt) {
                    return result_handle_packet_needbuf;
                }

                // Process the data payload as a protobuf frame
                // std::shared_ptr<KismetExternal::Command> cmd(new KismetExternal::Command());

                // Re-use a cached command
                if (cached_cmd == nullptr) {
                    cached_cmd = std::make_shared<KismetExternal::Command>();
                } else {
                    cached_cmd->Clear();
                }

                auto ai = new google::protobuf::io::ArrayInputStream(frame->data, data_sz);

                if (!cached_cmd->ParseFromZeroCopyStream(ai)) {
                    delete(ai);
                    _MSG_ERROR("Kismet external interface could not interpret the payload of the "
                            "command frame; either the frame is malformed, a network error occurred, or "
                            "an unsupported tool is connected to the external interface API");
                    trigger_error("unparsable command frame");
                    return result_handle_packet_error;
                }

                // Dispatch the received command
                dispatch_rx_packet(cached_cmd->command(), cached_cmd->seqno(),
                        cached_cmd->content());

                delete(ai);

                buffer.consume(frame_sz);
            }
        }

        return result_handle_packet_ok;
    }

    // Handle a buffer with a single frame in it; for instance, fed by the websocket api.  The buffer is not
    // consumed.
    template<class ConstBufferSequence>
    int handle_external_command(const ConstBufferSequence& data, size_t sz) {
        const kismet_external_frame_t *frame = nullptr;
        const kismet_external_frame_v2_t *frame_v2 = nullptr;

        uint32_t frame_sz, data_sz;
        uint32_t data_checksum;

        if (sz < sizeof(kismet_external_frame_t)) {
            return result_handle_packet_needbuf;
        }

        frame = boost::asio::buffer_cast<const kismet_external_frame_t *>(data);
        frame_v2 = boost::asio::buffer_cast<const kismet_external_frame_v2_t *>(data);

        // Check the frame signature
        if (kis_ntoh32(frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
            _MSG_ERROR("Kismet external interface got command frame with invalid signature");
            trigger_error("Invalid signature on command frame");
            return result_handle_packet_error;
        }

        // Detect and process the v2 frames
        if (kis_ntoh16(frame_v2->v2_sentinel) == KIS_EXTERNAL_V2_SIG &&
                kis_ntoh16(frame_v2->frame_version) == 0x02) {

            data_sz = kis_ntoh32(frame_v2->data_sz);
            frame_sz = data_sz + sizeof(kismet_external_frame_v2);

            if (frame_sz >= 16386) {
                _MSG_ERROR("Kismet external interface got a command frame which is too large to "
                           "be processed ({}); either the frame is malformed or you are connecting to "
                           "a legacy Kismet remote capture drone; make sure you have updated to modern "
                           "Kismet on all connected systems.", frame_sz);
                trigger_error("Command frame too large for buffer");
                return result_handle_packet_error;
            }

            // If we don't have the whole buffer available, bail on this read
            if (frame_sz > sz) {
                return result_handle_packet_needbuf;
            }

            // No checksum anymore

            uint32_t seqno = kis_ntoh32(frame_v2->seqno);

            nonstd::string_view command(frame_v2->command, 32);

            auto trim_pos = command.find('\0');
            if (trim_pos != command.npos)
                command.remove_suffix(command.size() - trim_pos);

            nonstd::string_view content((const char *) frame_v2->data, data_sz);

            // If we've gotten this far it's a valid newer protocol, switch to v2 mode
            protocol_version = 2;

            // Dispatch the received command
            dispatch_rx_packet(command, seqno, content);

            return result_handle_packet_ok;
        } else {
            // Check the length
            data_sz = kis_ntoh32(frame->data_sz);
            frame_sz = data_sz + sizeof(kismet_external_frame);

            // If we've got a bogus length, blow it up.  Anything over 8k is assumed to be insane.
            if ((long int) frame_sz >= 16384) {
                _MSG_ERROR("Kismet external interface got a command frame which is too large to "
                           "be processed ({}); either the frame is malformed or you are connecting to "
                           "a legacy Kismet remote capture drone; make sure you have updated to modern "
                           "Kismet on all connected systems.", frame_sz);
                trigger_error("Command frame too large for buffer");
                return result_handle_packet_error;
            }

            // If we don't have the whole buffer available, bail on this read
            if (frame_sz > sz) {
                return result_handle_packet_needbuf;
            }

            // We have a complete payload, checksum 
            data_checksum = adler32_checksum((const char *) frame->data, data_sz);

            if (data_checksum != kis_ntoh32(frame->data_checksum)) {
                _MSG_ERROR("Kismet external interface got a command frame with an invalid checksum; "
                           "either the frame is malformed, a network error occurred, or an unsupported tool "
                           "has connected to the external interface API.");
                trigger_error("command frame has invalid checksum");
                return result_handle_packet_error;
            }

            // Process the data payload as a protobuf frame
            // std::shared_ptr<KismetExternal::Command> cmd(new KismetExternal::Command());

            // Re-use a cached command
            if (cached_cmd == nullptr) {
                cached_cmd = std::make_shared<KismetExternal::Command>();
            } else {
                cached_cmd->Clear();
            }

            auto ai = new google::protobuf::io::ArrayInputStream(frame->data, data_sz);

            if (!cached_cmd->ParseFromZeroCopyStream(ai)) {
                delete(ai);
                _MSG_ERROR("Kismet external interface could not interpret the payload of the "
                           "command frame; either the frame is malformed, a network error occurred, or "
                           "an unsupported tool is connected to the external interface API");
                trigger_error("unparsable command frame");
                return result_handle_packet_error;
            }

            // Dispatch the received command
            dispatch_rx_packet(cached_cmd->command(), cached_cmd->seqno(),
                    cached_cmd->content());

            delete(ai);

            return result_handle_packet_ok;

        }
    }
};

#endif

