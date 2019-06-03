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
#include <microhttpd.h>

#include "buffer_handler.h"
#include "chainbuf.h"
#include "ringbuf2.h"
#include "trackedelement.h"

class Kis_Net_Httpd;
class Kis_Net_Httpd_Connection;

// Basic request handler from MHD
class Kis_Net_Httpd_Handler {
public:
    Kis_Net_Httpd_Handler();
    virtual ~Kis_Net_Httpd_Handler();

    // Bind a http server if we need to do that later in the instantiation
    void Bind_Httpd_Server();

    // Handle a GET request; must allocate the response mechanism via
    // MHD_create_response_from_... and will typically call some other
    // function to generate the data for the response
    virtual int Httpd_HandleGetRequest(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) = 0;

    virtual int Httpd_HandlePostRequest(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection, 
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) = 0;

    // Can this handler process this request?
    virtual bool Httpd_VerifyPath(const char *path, const char *method) = 0;

    // Shortcut to checking if the serializer can handle this, since most
    // endpoints will be implementing serialization
    virtual bool Httpd_CanSerialize(const std::string& path);

    // Shortcut for serializing; expects the path or the final element of the path
    virtual void Httpd_Serialize(const std::string& path, 
            std::ostream& stream,
            std::shared_ptr<TrackerElement> elem, 
            std::shared_ptr<TrackerElementSerializer::rename_map> rename = nullptr);

    // Shortcuts for getting path info
    virtual std::string Httpd_GetSuffix(const std::string& path);
    virtual std::string Httpd_StripSuffix(const std::string& path);


    // By default, the Kismet HTTPD implementation will cache all POST variables
    // in the variable_cache map in the connection record, and call
    // Httpd_PostComplete(connection, stream&) to generate the output.
    // If this is inappropriate for your endpoint, for instance if you are
    // implementing some sort of file upload, then this function should
    // return 'true' and you should implement it in Httpd_PostIterator
    virtual bool Httpd_UseCustomPostIterator() {
        return false;
    }

    // Called when a POST event is complete - all data has been uploaded and
    // cached in the connection info.
    virtual int Httpd_PostComplete(Kis_Net_Httpd_Connection *con __attribute__((unused))) {
        return MHD_NO;
    }

    // If Httpd_UseCustomPostIterator() is true, this is expected to perform
    // a custom handling of POST.  Properly handling post is non-trivial
    //
    // By default does nothing and bails on the post data.
    //
    // Override this to do useful post interpreting.  This implements parsing
    // iterative data and will be called multiple times; if you are implementing
    // a post system which takes multiple values you will need to index the state
    // via the connection info and parse them all as you are called from the
    // microhttpd handler.
    virtual int Httpd_PostIterator(void *coninfo_cls __attribute__((unused)), 
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

    // If Httpd_UseCustomPostIterator() is true, this is expected to perform
    // and cleanup at the end of handling a POST event, for instance, closing
    // files, etc
    virtual void Httpd_PostRequestCompleted(void *cls __attribute__((unused)),
            struct MHD_Connection *connection __attribute__((unused)),
            void **con_cls __attribute__((unused)),
            enum MHD_RequestTerminationCode toe __attribute__((unused))) {
        // Do nothing
    }

protected:
    std::shared_ptr<Kis_Net_Httpd> httpd;
};

// Take a C++ stream and use it as a response
class Kis_Net_Httpd_CPPStream_Handler : public Kis_Net_Httpd_Handler {
public:
    Kis_Net_Httpd_CPPStream_Handler() : 
        Kis_Net_Httpd_Handler() { }
    virtual ~Kis_Net_Httpd_CPPStream_Handler() { };

    virtual bool Httpd_VerifyPath(const char *path, const char *method) = 0;

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream) = 0;

    virtual int Httpd_HandleGetRequest(Kis_Net_Httpd *httpd, 
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size);

    virtual int Httpd_HandlePostRequest(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection, 
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size);
};

// Fallback handler to report that we can't serve static files
class Kis_Net_Httpd_No_Files_Handler : public Kis_Net_Httpd_CPPStream_Handler {
public:
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);
};

// A buffer-based stream handler which will continually stream output from
// the buffer to the HTTP connection
//
// Because this is a long-running handler, it must track the buffer state
// inside a connection object.
class Kis_Net_Httpd_Buffer_Stream_Handler : public Kis_Net_Httpd_Handler {
public:
    Kis_Net_Httpd_Buffer_Stream_Handler() : Kis_Net_Httpd_Handler() {
        // Default rb size
        k_n_h_r_ringbuf_size = 1024*1024*4;
    }
    virtual ~Kis_Net_Httpd_Buffer_Stream_Handler();

    virtual int Httpd_HandleGetRequest(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size);
    virtual int Httpd_HandlePostRequest(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection, 
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size);

    // Can this handler process this request?
    virtual bool Httpd_VerifyPath(const char *path, const char *method) = 0;

    // Called as a connection is being set up; responsible for populating
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
            size_t *upload_data_size) = 0;

    // Called when a POST event is complete - all data has been uploaded and
    // cached in the connection info.
    //
    // Returns:
    //  MHD_NO  - Streambuffer should not automatically close out the buffer
    //  MHD_YES - Streambuffer should automatically close the buffer when the
    //            streamresponse is complete
    virtual int Httpd_PostComplete(Kis_Net_Httpd_Connection *con __attribute__((unused))) = 0;

    // Called by microhttpd during servicing a connecting; cls is a 
    // kis_net_httpd_buffer_stream_aux which contains all our references to
    // this class instance, the buf streams, etc.  Locks waiting for the
    // buf to have data available to write.
    static ssize_t buffer_event_cb(void *cls, uint64_t pos, char *buf, size_t max);

    virtual void Httpd_Set_Buffer_Size(size_t in_sz) {
        k_n_h_r_ringbuf_size = in_sz;
    }

protected:
    virtual std::shared_ptr<BufferHandlerGeneric> allocate_buffer() = 0;

    size_t k_n_h_r_ringbuf_size;
};

// Ringbuf-based stream handler
class Kis_Net_Httpd_Ringbuf_Stream_Handler : public Kis_Net_Httpd_Buffer_Stream_Handler {
public:
    Kis_Net_Httpd_Ringbuf_Stream_Handler() : Kis_Net_Httpd_Buffer_Stream_Handler() { }

protected:
    virtual std::shared_ptr<BufferHandlerGeneric> allocate_buffer() {
        return std::static_pointer_cast<BufferHandlerGeneric>(std::shared_ptr<BufferHandler<RingbufV2> >(new BufferHandler<RingbufV2>(0, k_n_h_r_ringbuf_size)));
    }
};

class Kis_Net_Httpd_Chain_Stream_Handler : public Kis_Net_Httpd_Buffer_Stream_Handler {
public:
    Kis_Net_Httpd_Chain_Stream_Handler() : Kis_Net_Httpd_Buffer_Stream_Handler() { }

protected:
    virtual std::shared_ptr<BufferHandlerGeneric> allocate_buffer() {
        // Allocate a buffer directly, in a multiple of the max output size for the webserver
        // buffer
        return std::static_pointer_cast<BufferHandlerGeneric>(std::shared_ptr<BufferHandler<Chainbuf> >(new BufferHandler<Chainbuf>(NULL, new Chainbuf(64 * 1024, 512))));
    }

};

// A buffer-stream auxiliary class which is passed to the callback, added to the
// connection record.  This holds the per-connection states.
//
// Free_aux_cb is called to free any aux data added into this record; the stream_aux
// itself will be freed by the httpd system.
class Kis_Net_Httpd_Buffer_Stream_Aux : public BufferInterface {
public:
    Kis_Net_Httpd_Buffer_Stream_Aux(Kis_Net_Httpd_Buffer_Stream_Handler *in_handler,
            Kis_Net_Httpd_Connection *in_httpd_connection, 
            std::shared_ptr<BufferHandlerGeneric> in_ringbuf_handler,
            void *in_aux,
            std::function<void (Kis_Net_Httpd_Buffer_Stream_Aux *)> in_free_aux);

    virtual ~Kis_Net_Httpd_Buffer_Stream_Aux();

    bool get_in_error() { 
        return in_error;
    }

    void trigger_error() {
        in_error = true;
        cl->unlock(0);
    }

    void set_aux(void *in_aux, 
            std::function<void (Kis_Net_Httpd_Buffer_Stream_Aux *)> in_free_aux) {
        local_locker lock(&aux_mutex);

        aux = in_aux;
        free_aux_cb = in_free_aux;
    }

    void set_sync(std::function<void (Kis_Net_Httpd_Buffer_Stream_Aux *)> in_cb) {
        local_locker lock(&aux_mutex);

        sync_cb = in_cb;
    }

    void sync() {
        local_locker lock(&aux_mutex);

        if (sync_cb)
            sync_cb(this);
    }

    // RBI interface to notify when data is in the buffer
    virtual void BufferAvailable(size_t in_amt);

    // Let the httpd callback pull the rb handler out
    std::shared_ptr<BufferHandlerGeneric> get_rbhandler() { return ringbuf_handler; }

    // Block until data is available (called by the buffer_event_cb in the http
    // session)
    void block_until_data(std::shared_ptr<BufferHandlerGeneric> rbh);

    // Get the buffer event mutex
    kis_recursive_timed_mutex *get_buffer_event_mutex() {
        return &buffer_event_mutex;
    }

public:
    kis_recursive_timed_mutex aux_mutex;
    kis_recursive_timed_mutex buffer_event_mutex;

    // Stream handler we belong to
    Kis_Net_Httpd_Buffer_Stream_Handler *httpd_stream_handler;

    // kis httpd connection we belong to
    Kis_Net_Httpd_Connection *httpd_connection;

    // Buffer handler
    std::shared_ptr<BufferHandlerGeneric> ringbuf_handler;

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
    std::function<void (Kis_Net_Httpd_Buffer_Stream_Aux *)> free_aux_cb;

    // Sync function; called to make sure the buffer is flushed and fully synced 
    // prior to flagging it complete
    std::function<void (Kis_Net_Httpd_Buffer_Stream_Aux *)> sync_cb;
    
};


#endif

