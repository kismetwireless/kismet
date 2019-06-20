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

#include "globalregistry.h"
#include "buffer_handler.h"
#include "ipc_remote2.h"
#include "kis_net_microhttpd.h"

// Namespace stub and forward class definition to make deps hopefully
// easier going forward
namespace KismetExternal {
    class Command;
};

struct KisExternalHttpSession {
    Kis_Net_Httpd_Connection *connection; 
    std::shared_ptr<conditional_locker<int> > locker;
};

struct KisExternalHttpUri {
    std::string uri;
    std::string method;
    bool auth_req;
};

// Basic external interface, implements the core ping/pong/id/message/etc protocols
class KisExternalInterface : public BufferInterface {
public:
    KisExternalInterface();
    virtual ~KisExternalInterface();

    // Connect an existing buffer, such as a TCP socket or IPC pipe
    virtual void connect_buffer(std::shared_ptr<BufferHandlerGeneric> in_ringbuf);

    // Trigger an error condition and call all the related functions
    virtual void trigger_error(std::string reason);

    // Buffer interface - called when the attached ringbuffer has data available.
    virtual void BufferAvailable(size_t in_amt);

    // Buffer interface - handles error on IPC or TCP, called when there is a 
    // low-level error on the communications stack (process death, etc).
    // Passes error to the the internal source_error function
    virtual void BufferError(std::string in_error);

    // Check to see if an IPC binary is available
    static bool check_ipc(const std::string& in_binary);
    

    // Launch the external binary and connect the IPC channel to our buffer
    // interface; most tools will use this unless they support network; 
    // datasources are the primary exception
    virtual bool run_ipc();

    // Close the external interface
    virtual void close_external();

protected:
    // Wrap a protobuf'd packet in our network framing and send it, returning the sequence
    // number
    virtual unsigned int send_packet(std::shared_ptr<KismetExternal::Command> c);

    // Central packet dispatch handler
    virtual bool dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c);

    // Generic msg proxy
    virtual void handle_msg_proxy(const std::string& msg, const int msgtype) = 0; 

    // Packet handlers
    virtual void handle_packet_message(uint32_t in_seqno, const std::string& in_content);
    virtual void handle_packet_ping(uint32_t in_seqno, const std::string& in_content);
    virtual void handle_packet_pong(uint32_t in_seqno, const std::string& in_content);
    virtual void handle_packet_shutdown(uint32_t in_seqno, const std::string& in_content);

    unsigned int send_ping();
    unsigned int send_pong(uint32_t ping_seqno);
    unsigned int send_shutdown(std::string reason);

    std::shared_ptr<kis_recursive_timed_mutex> ext_mutex;

    // Communications API.  We implement a buffer interface and listen to the
    // incoming read buffer, we're agnostic if it's a network or IPC buffer.
    std::shared_ptr<BufferHandlerGeneric> ringbuf_handler;

    // If we're an IPC instance, the IPC control.  The ringbuf_handler is associated
    // with the IPC instance.
    std::shared_ptr<IPCRemoteV2> ipc_remote;

    std::shared_ptr<Timetracker> timetracker;

    std::atomic<uint32_t> seqno;
    std::atomic<time_t> last_pong;

    std::string external_binary;
    std::vector<std::string> external_binary_args;

    int ping_timer_id;
};

class KisExternalHttpInterface : public KisExternalInterface, Kis_Net_Httpd_Chain_Stream_Handler {
public:
    KisExternalHttpInterface();
    virtual ~KisExternalHttpInterface();

    // Trigger an error condition and call all the related functions
    virtual void trigger_error(std::string reason) override;

    // Webserver proxy interface - standard verifypath
    virtual bool Httpd_VerifyPath(const char *path, const char *method) override;

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
    virtual int Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) override;

    // Called when a POST event is complete - all data has been uploaded and
    // cached in the connection info; brokers connections to to the proxy
    //
    // Returns:
    //  MHD_NO  - Streambuffer should not automatically close out the buffer
    //  MHD_YES - Streambuffer should automatically close the buffer when the
    //            streamresponse is complete
    virtual int Httpd_PostComplete(Kis_Net_Httpd_Connection *con __attribute__((unused))) override;

protected:
    // Central packet dispatch handler
    virtual bool dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c) override;

    virtual void handle_msg_proxy(const std::string& msg, const int msgtype) override; 

    // Packet handlers
    virtual void handle_packet_http_register(uint32_t in_seqno, const std::string& in_content);
    virtual void handle_packet_http_response(uint32_t in_seqno, const std::string& in_content);
    virtual void handle_packet_http_auth_request(uint32_t in_seqno, const std::string& in_content);

    unsigned int send_http_request(uint32_t in_http_sequence, std::string in_uri,
            std::string in_method, std::map<std::string, std::string> in_postdata);
    unsigned int send_http_auth(std::string in_session);

    // Webserver proxy code
    
    // Valid URIs, mapped by method (GET, POST, etc); these are matched in
    // Httpd_VerifyPath and then passed on; if a URI is present here, it's mapped
    // to true
    std::map<std::string, std::vector<struct KisExternalHttpUri *> > http_proxy_uri_map;

    // Map request identities
    uint32_t http_session_id;
    std::map<uint32_t, std::shared_ptr<KisExternalHttpSession> > http_proxy_session_map;
};


#endif

