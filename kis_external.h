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

#include <eventbus.h>
#include "globalregistry.h"
#include "ipctracker_v2.h"
#include "kis_net_microhttpd.h"



#include "asio.hpp"
using asio::ip::tcp;

// Namespace stub and forward class definition to make deps hopefully easier going forward
namespace KismetExternal {
    class Command;
};

struct kis_external_http_session {
    kis_net_httpd_connection *connection; 
    std::shared_ptr<conditional_locker<int> > locker;
};

struct kis_external_http_uri {
    std::string uri;
    std::string method;
    bool auth_req;
};

// External interface API bridge;
class kis_external_interface : public kis_net_httpd_chain_stream_handler {
public:
    kis_external_interface();
    virtual ~kis_external_interface();

    // Launch the external binary and connect the IPC channel to our buffer
    // interface; most tools will use this unless they support network; 
    // datasources are the primary exception
    virtual bool run_ipc();

    // Attach a tcp socket
    virtual bool attach_tcp_socket(tcp::socket& socket);


    // Check to see if an IPC binary is available
    static bool check_ipc(const std::string& in_binary);

    // close the external interface
    virtual void close_external();

    // We use the raw http server APIs instead of the newer endpoint handlers because we
    // potentially mess with the headers and other internals

    // Webserver proxy interface - standard verifypath
    virtual bool httpd_verify_path(const char *path, const char *method) override;

    // Called as a connection is being set up;  brokers access with the http
    // proxy
    //
    // Returns:
    //  MHD_NO  - Streambuffer should not automatically close out the buffer; this
    //            is used when spawning an independent thread for managing the stream,
    //            for example with pcap streaming
    //  MHD_YES - Streambuffer should automatically close the buffer when the
    //            streamresponse is complete, typically used when streaming a finite
    //            amount of data through a memchunk buffer like a json serialization
    virtual KIS_MHD_RETURN httpd_create_stream_response(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) override;

    // Called when a POST event is complete - all data has been uploaded and
    // cached in the connection info; brokers connections to to the proxy
    //
    // Returns:
    //  MHD_NO  - Streambuffer should not automatically close out the buffer
    //  MHD_YES - Streambuffer should automatically close the buffer when the
    //            streamresponse is complete
    virtual KIS_MHD_RETURN httpd_post_complete(kis_net_httpd_connection *con __attribute__((unused))) override;

    // Trigger an error
    virtual void trigger_error(const std::string& in_error);

protected:
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

    kis_recursive_timed_mutex ext_mutex;

    std::shared_ptr<time_tracker> timetracker;
    std::shared_ptr<ipc_tracker_v2> ipctracker;

    std::atomic<uint32_t> seqno;
    std::atomic<time_t> last_pong;

    int ping_timer_id;

    // Input buffer
    asio::streambuf in_buf;
    int handle_read(const std::error_code& ec, size_t sz);

    // Pipe IPC
    std::string external_binary;
    std::vector<std::string> external_binary_args;

    kis_ipc_record ipc;
    asio::posix::stream_descriptor ipc_in, ipc_out;

    void start_ipc_read();

    void ipc_soft_kill();
    void ipc_hard_kill();

    // TCP socket
    tcp::socket tcpsocket;

    void start_tcp_read();


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

    // Valid URIs, mapped by method (GET, POST, etc); these are matched in
    // httpd_verify_path and then passed on; if a URI is present here, it's mapped
    // to true
    std::map<std::string, std::vector<struct kis_external_http_uri *> > http_proxy_uri_map;

    // HTTP session identities for multi-packet responses
    uint32_t http_session_id;
    std::map<uint32_t, std::shared_ptr<kis_external_http_session> > http_proxy_session_map;
};

#endif

