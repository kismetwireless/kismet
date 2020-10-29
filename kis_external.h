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

    // Detach a TCP socket (migrate it to another datasource, for instance, while making a remote
    // capture source)
    tcp::socket move_tcp_socket() { 
        if (tcpsocket.is_open())
            tcpsocket.cancel();

        stopped = true;

        return std::move(tcpsocket);
    }


    // Check to see if an IPC binary is available
    static bool check_ipc(const std::string& in_binary);

    // Set a closure callback, for instance when being driven from a websocket
    virtual void set_closure_cb(std::function<void ()> cb) {
        local_locker l(&ext_mutex, "set_closure_cb");
        closure_cb = cb;
    }

    // Set a write callback, which is called instead of an asio async write, for use for 
    // instance when being driven from a websocket connection and we need to proxy it
    // to the ws
    virtual void set_write_cb(std::function<int (const char *, size_t, std::function<void (int, std::size_t)>)> cb) {
        local_locker l(&ext_mutex, "set_write_cb");
        write_cb = cb;
    }

    // close the external interface
    virtual void close_external();

    // We use the raw http server APIs instead of the newer endpoint handlers because we
    // potentially mess with the headers and other internals

    // Trigger an error
    virtual void trigger_error(const std::string& in_error);

protected:
    std::function<void (void)> closure_cb;
    std::function<int (const char *, size_t, std::function<void (int, std::size_t)>)> write_cb;

    // Handle an error; override in child classes; called when an error causes a shutdown
    virtual void handle_error(const std::string& error) { }

    // Wrap a protobuf'd packet in our network framing and send it, returning the sequence
    // number
    virtual unsigned int send_packet(std::shared_ptr<KismetExternal::Command> c);

    // Central packet dispatch handler
    virtual bool dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c);

    // Generic msg proxy
    virtual void handle_msg_proxy(const std::string& msg, const int msgtype); 

    // Packet handlers
    virtual void handle_packet_message(uint32_t in_seqno, const std::string& in_content);
    virtual void handle_packet_ping(uint32_t in_seqno, const std::string& in_content);
    virtual void handle_packet_pong(uint32_t in_seqno, const std::string& in_content);
    virtual void handle_packet_shutdown(uint32_t in_seqno, const std::string& in_content);
    virtual void handle_packet_eventbus_register(uint32_t in_seqno, const std::string& in_content);
    virtual void handle_packet_eventbus_publish(uint32_t in_seqno, const std::string& in_content);

    unsigned int send_ping();
    unsigned int send_pong(uint32_t ping_seqno);
    unsigned int send_shutdown(std::string reason);

    std::atomic<bool> stopped;
    std::atomic<bool> cancelled;

    kis_recursive_timed_mutex ext_mutex;

    std::shared_ptr<time_tracker> timetracker;
    std::shared_ptr<ipc_tracker_v2> ipctracker;

    std::atomic<uint32_t> seqno;
    std::atomic<time_t> last_pong;

    int ping_timer_id;

    // Async input
    boost::asio::streambuf in_buf;

    int handle_read(std::shared_ptr<kis_external_interface> ref, 
            const boost::system::error_code& ec, size_t sz);

    std::list<std::shared_ptr<std::string>> out_bufs;

    void start_write(const char *data, size_t len);
    void write_impl();
    void handle_write(const boost::system::error_code& ec);

    // Common strand
    boost::asio::io_service::strand strand_;

    // Pipe IPC
    std::string external_binary;
    std::vector<std::string> external_binary_args;

    kis_ipc_record ipc;
    boost::asio::posix::stream_descriptor ipc_in, ipc_out;


    void start_ipc_read(std::shared_ptr<kis_external_interface> ref);

    void ipc_soft_kill();
    void ipc_hard_kill();

    // TCP socket
    tcp::socket tcpsocket;

    void start_tcp_read(std::shared_ptr<kis_external_interface> ref);


    // Eventbus proxy code
    std::shared_ptr<event_bus> eventbus;
    std::map<std::string, unsigned long> eventbus_callback_map;

    void proxy_event(std::shared_ptr<eventbus_event>);


    // Webserver proxy code

    virtual void handle_packet_http_register(uint32_t in_seqno, const std::string& in_content);
    virtual void handle_packet_http_response(uint32_t in_seqno, const std::string& in_content);
    virtual void handle_packet_http_auth_request(uint32_t in_seqno, const std::string& in_content);

    unsigned int send_http_request(uint32_t in_http_sequence, std::string in_uri,
            std::string in_method, std::map<std::string, std::string> in_postdata);
    unsigned int send_http_auth(std::string in_session);

    // HTTP session identities for multi-packet responses
    uint32_t http_session_id;
    std::map<uint32_t, std::shared_ptr<kis_external_http_session> > http_proxy_session_map;

public:
    static const int result_handle_packet_error = -1;
    static const int result_handle_packet_needbuf = 1;
    static const int result_handle_packet_ok = 2;

    // Handle a buffer containing a network frame packet
    template<class BoostBuffer>
    int handle_packet(BoostBuffer& buffer) {
        const kismet_external_frame_t *frame;
        uint32_t frame_sz, data_sz;
        uint32_t data_checksum;

        // Consume everything in the buffer that we can
        while (1) {
            // See if we have enough to get a frame header
            size_t buffamt = buffer.size();

            if (buffamt < sizeof(kismet_external_frame_t)) {
                return result_handle_packet_needbuf;
            }

            frame = boost::asio::buffer_cast<const kismet_external_frame_t *>(buffer.data());

            // Check the frame signature
            if (kis_ntoh32(frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
                _MSG_ERROR("Kismet external interface got command frame with invalid signature");
                trigger_error("Invalid signature on command frame");
                return result_handle_packet_error;
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
                return result_handle_packet_error;
            }

            // If we don't have the whole buffer available, bail on this read
            if (frame_sz > buffamt) {
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
            std::shared_ptr<KismetExternal::Command> cmd(new KismetExternal::Command());

            if (!cmd->ParseFromArray(frame->data, data_sz)) {
                _MSG_ERROR("Kismet external interface could not interpret the payload of the "
                        "command frame; either the frame is malformed, a network error occurred, or "
                        "an unsupported tool is connected to the external interface API");
                trigger_error("unparsable command frame");
                return result_handle_packet_error;
            }

            buffer.consume(frame_sz);

            // Dispatch the received command
            dispatch_rx_packet(cmd);
        }

        return result_handle_packet_ok;
    }

    // Handle a buffer with a single frame in it; for instance, fed by the websocket api.  The buffer is not
    // consumed.
    template<class ConstBufferSequence>
    int handle_external_command(const ConstBufferSequence& data, size_t sz) {
        const kismet_external_frame_t *frame;
        uint32_t frame_sz, data_sz;
        uint32_t data_checksum;

        if (sz < sizeof(kismet_external_frame_t)) {
            return result_handle_packet_needbuf;
        }

        frame = boost::asio::buffer_cast<const kismet_external_frame_t *>(data);

        // Check the frame signature
        if (kis_ntoh32(frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
            _MSG_ERROR("Kismet external interface got command frame with invalid signature");
            trigger_error("Invalid signature on command frame");
            return result_handle_packet_error;
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
        std::shared_ptr<KismetExternal::Command> cmd(new KismetExternal::Command());

        if (!cmd->ParseFromArray(frame->data, data_sz)) {
            _MSG_ERROR("Kismet external interface could not interpret the payload of the "
                    "command frame; either the frame is malformed, a network error occurred, or "
                    "an unsupported tool is connected to the external interface API");
            trigger_error("unparsable command frame");
            return result_handle_packet_error;
        }

        // Dispatch the received command
        dispatch_rx_packet(cmd);

        return result_handle_packet_ok;
    }
};

#endif

