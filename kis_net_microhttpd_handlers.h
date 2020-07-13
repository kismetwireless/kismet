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

#ifndef __KIS_NET_MICROHTTPD_HANDLERS__
#define __KIS_NET_MICROHTTPD_HANDLERS__

#include "config.h"

#include <memory>
#include "buffer_handler.h"
#include "chainbuf.h"
#include "ringbuf2.h"
#include "trackedelement.h"

#include "microhttpd_shim.h"

class kis_net_httpd;
class kis_net_httpd_connection;

// Basic request handler from MHD
class kis_net_httpd_handler {
public:
    kis_net_httpd_handler();
    virtual ~kis_net_httpd_handler();

    // Bind a http server if we need to do that later in the instantiation
    void bind_httpd_server();

    // Handle a GET request; must allocate the response mechanism via
    // MHD_create_response_from_... and will typically call some other
    // function to generate the data for the response
    virtual KIS_MHD_RETURN httpd_handle_get_request(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) = 0;

    virtual KIS_MHD_RETURN httpd_handle_post_request(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection, 
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) = 0;

    // Can this handler process this request?
    virtual bool httpd_verify_path(const char *path, const char *method) = 0;

    // Shortcut to checking if the serializer can handle this, since most
    // endpoints will be implementing serialization
    virtual bool httpd_can_serialize(const std::string& path);

    // Shortcut for serializing; expects the path or the final element of the path
    virtual void httpd_serialize(const std::string& path, 
            std::ostream& stream,
            std::shared_ptr<tracker_element> elem, 
            std::shared_ptr<tracker_element_serializer::rename_map> rename,
            kis_net_httpd_connection *connection);

    // Shortcuts for getting path info
    virtual std::string httpd_get_suffix(const std::string& path);
    virtual std::string httpd_strip_suffix(const std::string& path);


    // By default, the Kismet HTTPD implementation will cache all POST variables
    // in the variable_cache map in the connection record, and call
    // httpd_post_complete(connection, stream&) to generate the output.
    // If this is inappropriate for your endpoint, for instance if you are
    // implementing some sort of file upload, then this function should
    // return 'true' and you should implement it in httpd_post_iterator
    virtual bool httpd_use_custom_post_iterator() {
        return false;
    }

    // Called when a POST event is complete - all data has been uploaded and
    // cached in the connection info.
    virtual KIS_MHD_RETURN httpd_post_complete(kis_net_httpd_connection *con __attribute__((unused))) {
        return MHD_NO;
    }

    // If httpd_use_custom_post_iterator() is true, this is expected to perform
    // a custom handling of POST.  Properly handling post is non-trivial
    //
    // By default does nothing and bails on the post data.
    //
    // Override this to do useful post interpreting.  This implements parsing
    // iterative data and will be called multiple times; if you are implementing
    // a post system which takes multiple values you will need to index the state
    // via the connection info and parse them all as you are called from the
    // microhttpd handler.
    virtual KIS_MHD_RETURN httpd_post_iterator(void *coninfo_cls __attribute__((unused)), 
            enum MHD_ValueKind kind __attribute__((unused)), 
            const char *key __attribute__((unused)), 
            const char *filename __attribute__((unused)), 
            const char *content_type __attribute__((unused)),
            const char *transfer_encoding __attribute__((unused)), 
            const char *data __attribute__((unused)), 
            uint64_t off __attribute__((unused)), 
            size_t size __attribute__((unused))) {
        // Do nothing
        return MHD_NO;
    }

    // If httpd_use_custom_post_iterator() is true, this is expected to perform
    // and cleanup at the end of handling a POST event, for instance, closing
    // files, etc
    virtual void httpd_post_request_completed(void *cls __attribute__((unused)),
            struct MHD_Connection *connection __attribute__((unused)),
            void **con_cls __attribute__((unused)),
            enum MHD_RequestTerminationCode toe __attribute__((unused))) {
        // Do nothing
    }

protected:
    std::shared_ptr<kis_net_httpd> httpd;
};

// Take a C++ stream and use it as a response
class kis_net_httpd_cppstream_handler : public kis_net_httpd_handler {
public:
    kis_net_httpd_cppstream_handler() : 
        kis_net_httpd_handler() { }
    virtual ~kis_net_httpd_cppstream_handler() { };

    virtual bool httpd_verify_path(const char *path, const char *method) = 0;

    virtual void httpd_create_stream_response(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream) = 0;

    virtual KIS_MHD_RETURN httpd_handle_get_request(kis_net_httpd *httpd, 
            kis_net_httpd_connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size);

    virtual KIS_MHD_RETURN httpd_handle_post_request(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection, 
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size);
};

// Fallback handler to report that we can't serve static files
class kis_net_httpd_no_files_handler : public kis_net_httpd_cppstream_handler {
public:
    virtual bool httpd_verify_path(const char *path, const char *method);

    virtual void httpd_create_stream_response(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);
};

// A buffer-based stream handler which will continually stream output from
// the buffer to the HTTP connection
//
// Because this is a long-running handler, it must track the buffer state
// inside a connection object.
class kis_net_httpd_buffer_stream_handler : public kis_net_httpd_handler {
public:
    kis_net_httpd_buffer_stream_handler() : 
        kis_net_httpd_handler(),
        k_n_h_r_ringbuf_size {1024 * 1024 * 4} { }

    virtual ~kis_net_httpd_buffer_stream_handler();

    virtual KIS_MHD_RETURN httpd_handle_get_request(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size);
    virtual KIS_MHD_RETURN httpd_handle_post_request(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection, 
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size);

    // Can this handler process this request?
    virtual bool httpd_verify_path(const char *path, const char *method) = 0;

    // Called as a connection is being set up; responsible for populating
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
            size_t *upload_data_size) = 0;

    // Called when a POST event is complete - all data has been uploaded and
    // cached in the connection info.
    //
    // Returns:
    //  MHD_NO  - Streambuffer should not automatically close out the buffer
    //  MHD_YES - Streambuffer should automatically close the buffer when the
    //            streamresponse is complete
    virtual KIS_MHD_RETURN httpd_post_complete(kis_net_httpd_connection *con __attribute__((unused))) = 0;

    // Called by microhttpd during servicing a connecting; cls is a 
    // kis_net_httpd_buffer_stream_aux which contains all our references to
    // this class instance, the buf streams, etc.  Locks waiting for the
    // buf to have data available to write.
    static ssize_t buffer_event_cb(void *cls, uint64_t pos, char *buf, size_t max);

    virtual void httpd_set_buffer_size(size_t in_sz) {
        k_n_h_r_ringbuf_size = in_sz;
    }

protected:
    virtual std::shared_ptr<buffer_handler_generic> allocate_buffer() = 0;

    size_t k_n_h_r_ringbuf_size;
};

// Ringbuf-based stream handler
class kis_net_httpd_ringbuf_stream_handler : public kis_net_httpd_buffer_stream_handler {
public:
    kis_net_httpd_ringbuf_stream_handler() : kis_net_httpd_buffer_stream_handler() { }

protected:
    virtual std::shared_ptr<buffer_handler_generic> allocate_buffer() {
        return std::static_pointer_cast<buffer_handler_generic>(std::shared_ptr<buffer_handler<ringbuf_v2> >(new buffer_handler<ringbuf_v2>(0, k_n_h_r_ringbuf_size)));
    }
};

class kis_net_httpd_chain_stream_handler : public kis_net_httpd_buffer_stream_handler {
public:
    kis_net_httpd_chain_stream_handler() : kis_net_httpd_buffer_stream_handler() { }

protected:
    virtual std::shared_ptr<buffer_handler_generic> allocate_buffer() {
        // Allocate a buffer directly, in a multiple of the max output size for the webserver
        // buffer
        return std::static_pointer_cast<buffer_handler_generic>(std::shared_ptr<buffer_handler<chainbuf> >(new buffer_handler<chainbuf>(NULL, new chainbuf(64 * 1024, 512))));
    }

};

// A buffer-stream auxiliary class which is passed to the callback, added to the
// connection record.  This holds the per-connection states.
//
// Free_aux_cb is called to free any aux data added into this record; the stream_aux
// itself will be freed by the httpd system.
class kis_net_httpd_buffer_stream_aux : public buffer_interface {
public:
    kis_net_httpd_buffer_stream_aux(kis_net_httpd_buffer_stream_handler *in_handler,
            kis_net_httpd_connection *in_httpd_connection, 
            std::shared_ptr<buffer_handler_generic> in_ringbuf_handler,
            void *in_aux,
            std::function<void (kis_net_httpd_buffer_stream_aux *)> in_free_aux);

    virtual ~kis_net_httpd_buffer_stream_aux();

    bool get_in_error() { 
        return in_error;
    }

    void trigger_error() {
        in_error = true;
        cl->unlock(0);
    }

    void set_aux(void *in_aux, 
            std::function<void (kis_net_httpd_buffer_stream_aux *)> in_free_aux) {
        local_locker lock(&aux_mutex);

        aux = in_aux;
        free_aux_cb = in_free_aux;
    }

    void set_sync(std::function<void (kis_net_httpd_buffer_stream_aux *)> in_cb) {
        local_locker lock(&aux_mutex);

        sync_cb = in_cb;
    }

    void sync() {
        local_locker lock(&aux_mutex);

        if (sync_cb)
            sync_cb(this);
    }

    // RBI interface to notify when data is in the buffer
    virtual void buffer_available(size_t in_amt);

    // Let the httpd callback pull the rb handler out
    std::shared_ptr<buffer_handler_generic> get_rbhandler() { return ringbuf_handler; }

    // Block until data is available (called by the buffer_event_cb in the http
    // session)
    void block_until_data(std::shared_ptr<buffer_handler_generic> rbh);

    // Get the buffer event mutex
    kis_recursive_timed_mutex *get_buffer_event_mutex() {
        return &buffer_event_mutex;
    }

public:
    kis_recursive_timed_mutex aux_mutex;
    kis_recursive_timed_mutex buffer_event_mutex;

    // Stream handler we belong to
    kis_net_httpd_buffer_stream_handler *httpd_stream_handler;

    // kis httpd connection we belong to
    kis_net_httpd_connection *httpd_connection;

    // Buffer handler
    std::shared_ptr<buffer_handler_generic> ringbuf_handler;

    // Conditional locker while waiting for the stream to have data
    std::shared_ptr<conditional_locker<int> > cl;

    // Are we in error?
    std::atomic<bool> in_error;

    // Possible worker thread for processing the buffer fill
    std::thread generator_thread;

    // Additional arbitrary data - Used by the buffer streamer to store the
    // buffer processor, and by the CPP Streamer to store the streambuf
    void *aux;

    // Free function
    std::function<void (kis_net_httpd_buffer_stream_aux *)> free_aux_cb;

    // Sync function; called to make sure the buffer is flushed and fully synced 
    // prior to flagging it complete
    std::function<void (kis_net_httpd_buffer_stream_aux *)> sync_cb;
    
};


#endif

