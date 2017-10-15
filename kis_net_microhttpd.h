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

#ifndef __KIS_NET_MICROHTTPD__
#define __KIS_NET_MICROHTTPD__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>
#include <pthread.h>
#include <microhttpd.h>
#include <memory>

#include "globalregistry.h"
#include "trackedelement.h"
#include "ringbuf2.h"
#include "chainbuf.h"
#include "buffer_handler.h"

class Kis_Net_Httpd;
class Kis_Net_Httpd_Session;
class Kis_Net_Httpd_Connection;

class EntryTracker;

// Basic request handler from MHD
class Kis_Net_Httpd_Handler {
public:
    Kis_Net_Httpd_Handler() { }
    Kis_Net_Httpd_Handler(GlobalRegistry *in_globalreg);
    virtual ~Kis_Net_Httpd_Handler();

    // Bind a http server if we need to do that later in the instantiation
    void Bind_Httpd_Server(GlobalRegistry *in_globalreg);

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
    virtual bool Httpd_CanSerialize(string path);

    // Shortcuts for getting path info
    virtual string Httpd_GetSuffix(string path);
    virtual string Httpd_StripSuffix(string path);


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
    GlobalRegistry *http_globalreg;

    std::shared_ptr<Kis_Net_Httpd> httpd;
    std::shared_ptr<EntryTracker> entrytracker;

};

// Take a C++ stream and use it as a response
class Kis_Net_Httpd_CPPStream_Handler : public Kis_Net_Httpd_Handler {
public:
    Kis_Net_Httpd_CPPStream_Handler() { }
    Kis_Net_Httpd_CPPStream_Handler(GlobalRegistry *in_globalreg) :
        Kis_Net_Httpd_Handler(in_globalreg) { };
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

    // Shortcuts to the entry tracker and serializer since most endpoints will
    // need to serialize
    virtual bool Httpd_Serialize(string path, std::stringstream &stream,
            SharedTrackerElement e, 
            TrackerElementSerializer::rename_map *name_map = NULL);
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
    Kis_Net_Httpd_Buffer_Stream_Handler(GlobalRegistry *in_globalreg) :
        Kis_Net_Httpd_Handler(in_globalreg) { 
        // Default rb size
        k_n_h_r_ringbuf_size = 1024*1024*4;
    };
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
    //  MHD_NO  - Streambuffer should not automatically close out the buffer
    //  MHD_YES - Streambuffer should automatically close the buffer when the
    //            streamresponse is complete
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
    virtual shared_ptr<BufferHandlerGeneric> allocate_buffer() = 0;

    size_t k_n_h_r_ringbuf_size;
};

// Ringbuf-based stream handler
class Kis_Net_Httpd_Ringbuf_Stream_Handler : public Kis_Net_Httpd_Buffer_Stream_Handler {
public:
    Kis_Net_Httpd_Ringbuf_Stream_Handler() : Kis_Net_Httpd_Buffer_Stream_Handler() { }

    Kis_Net_Httpd_Ringbuf_Stream_Handler(GlobalRegistry *in_globalreg) :
        Kis_Net_Httpd_Buffer_Stream_Handler(in_globalreg) { }

protected:
    virtual shared_ptr<BufferHandlerGeneric> allocate_buffer() {
        return static_pointer_cast<BufferHandlerGeneric>(shared_ptr<BufferHandler<RingbufV2> >(new BufferHandler<RingbufV2>(0, k_n_h_r_ringbuf_size)));
    }
};

class Kis_Net_Httpd_Chain_Stream_Handler : public Kis_Net_Httpd_Buffer_Stream_Handler {
public:
    Kis_Net_Httpd_Chain_Stream_Handler() : Kis_Net_Httpd_Buffer_Stream_Handler() { }

    Kis_Net_Httpd_Chain_Stream_Handler(GlobalRegistry *in_globalreg) :
        Kis_Net_Httpd_Buffer_Stream_Handler(in_globalreg) { }

protected:
    virtual shared_ptr<BufferHandlerGeneric> allocate_buffer() {
        // Allocate a buffer directly, in a multiple of the max output size for the webserver
        // buffer
        return static_pointer_cast<BufferHandlerGeneric>(shared_ptr<BufferHandler<Chainbuf> >(new BufferHandler<Chainbuf>(NULL, new Chainbuf(64 * 1024, 512))));
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
            shared_ptr<BufferHandlerGeneric> in_ringbuf_handler,
            void *in_aux,
            function<void (Kis_Net_Httpd_Buffer_Stream_Aux *)> in_free_aux);

    virtual ~Kis_Net_Httpd_Buffer_Stream_Aux();

    bool get_in_error() { 
        local_locker lock(&aux_mutex);
        return in_error;
    }

    void trigger_error() {
        local_locker lock(&aux_mutex);

        in_error = true;
        cl->unlock("triggered");
    }

    void set_aux(void *in_aux, 
            function<void (Kis_Net_Httpd_Buffer_Stream_Aux *)> in_free_aux) {
        local_locker lock(&aux_mutex);

        aux = in_aux;
        free_aux_cb = in_free_aux;
    }

    void set_sync(function<void (Kis_Net_Httpd_Buffer_Stream_Aux *)> in_cb) {
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
    shared_ptr<BufferHandlerGeneric> get_rbhandler() { return ringbuf_handler; }

    // Block until data is available (called by the buffer_event_cb in the http
    // session)
    void block_until_data();

public:
    std::recursive_timed_mutex aux_mutex;

    // Stream handler we belong to
    Kis_Net_Httpd_Buffer_Stream_Handler *httpd_stream_handler;

    // kis httpd connection we belong to
    Kis_Net_Httpd_Connection *httpd_connection;

    // Buffer handler
    shared_ptr<BufferHandlerGeneric> ringbuf_handler;

    // Conditional locker while waiting for the stream to have data
    shared_ptr<conditional_locker<string> > cl;

    // Are we in error?
    bool in_error;

    // Possible worker thread for processing the buffer fill
    std::thread generator_thread;

    // Additional arbitrary data - Used by the buffer streamer to store the
    // buffer processor, and by the CPP Streamer to store the streambuf
    void *aux;

    // Free function
    function<void (Kis_Net_Httpd_Buffer_Stream_Aux *)> free_aux_cb;

    // Sync function; called to make sure the buffer is flushed and fully synced 
    // prior to flagging it complete
    function<void (Kis_Net_Httpd_Buffer_Stream_Aux *)> sync_cb;
    
};


#define KIS_SESSION_COOKIE      "KISMET"
#define KIS_HTTPD_POSTBUFFERSZ  (1024 * 32)

// Connection data, generated for all requests by the processing system;
// contains per-handler states, request information, request type, session
// data if known, POST variables if the standard POST processing is enabled
class Kis_Net_Httpd_Connection {
public:
    const static int CONNECTION_GET = 0;
    const static int CONNECTION_POST = 1;

    Kis_Net_Httpd_Connection() {
        httpcode = 200;
        postprocessor = NULL;
        post_complete = false;
        connection_type = CONNECTION_GET;
        httpd = NULL;
        httpdhandler = NULL;
        session = NULL;
        connection = NULL;
        response = NULL;
        custom_extension = NULL;
    }

    // response generated by post
    std::stringstream response_stream;

    // Cache of variables in session
    map<string, std::unique_ptr<std::stringstream> > variable_cache;

    // Optional alternate filename to pass to the browser for downloading
    string optional_filename;

    // HTTP code of response
    int httpcode;

    // URL
    string url;

    // Post processor struct
    struct MHD_PostProcessor *postprocessor;

    // Is the post complete?
    bool post_complete;

    // Type of request/connection
    int connection_type;

    // httpd parent
    Kis_Net_Httpd *httpd;    

    // Handler
    Kis_Net_Httpd_Handler *httpdhandler;    

    // Login session
    shared_ptr<Kis_Net_Httpd_Session> session;

    // Connection
    struct MHD_Connection *connection;

    // Response created elsewhere, if any
    struct MHD_Response *response;

    // Custom arbitrary value inserted by other processors
    void *custom_extension;
};

class Kis_Net_Httpd_Session {
public:
    // Session ID
    string sessionid;

    // Time session was created
    time_t session_created;

    // Last time the session was seen active
    time_t session_seen;

    // Amount of time session is valid for after last active
    time_t session_lifetime;
};

class Kis_Httpd_Websession;

class Kis_Net_Httpd : public LifetimeGlobal {
public:
    static shared_ptr<Kis_Net_Httpd> create_httpd(GlobalRegistry *in_globalreg) {
        shared_ptr<Kis_Net_Httpd> mon(new Kis_Net_Httpd(in_globalreg));
        in_globalreg->RegisterLifetimeGlobal(mon);
        in_globalreg->InsertGlobal("HTTPD_SERVER", mon);
        return mon;
    }

private:
    Kis_Net_Httpd(GlobalRegistry *in_globalreg);

public:
    virtual ~Kis_Net_Httpd();

    int StartHttpd();
    int StopHttpd();

    bool HttpdRunning() { return running; }
    unsigned int FetchPort() { return http_port; };
    bool FetchUsingSSL() { return use_ssl; };

    void RegisterSessionHandler(shared_ptr<Kis_Httpd_Websession> in_session);

    void RegisterHandler(Kis_Net_Httpd_Handler *in_handler);
    void RemoveHandler(Kis_Net_Httpd_Handler *in_handler);

    static string GetSuffix(string url);
    static string StripSuffix(string url);

    void RegisterMimeType(string suffix, string mimetype);
    string GetMimeType(string suffix);

    // Register a static files directory (used for system, home, and plugin data)
    void RegisterStaticDir(string in_url_prefix, string in_path);

    // Interrogate the session handler and figure out if this connection has a
    // valid session; optionally sends basic auth failure automatically
    bool HasValidSession(Kis_Net_Httpd_Connection *connection, bool send_reject = true);

    // Create a session; if connection is not null, insert session into connection.
    // If response is not null, append to the response
    void CreateSession(Kis_Net_Httpd_Connection *connection, 
            struct MHD_Response *response, time_t in_lifetime);

    // Append a session cookie if we have a valid session for this connection
    static void AppendHttpSession(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection);

    // Append timestamp and mime headers
    static void AppendStandardHeaders(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection, const char *url);

    // Queue a http response
    static int SendHttpResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection);

    // Send a standard HTTP response appending the session and standard 
    // headers
    static int SendStandardHttpResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection, const char *url);

    // Catch MHD panics and try to close more elegantly
    static void MHD_Panic(void *cls, const char *file, unsigned int line,
            const char *reason);

protected:
    GlobalRegistry *globalreg;

    unsigned int http_port;

    bool http_serve_files, http_serve_user_files;

    struct MHD_Daemon *microhttpd;
    std::vector<Kis_Net_Httpd_Handler *> handler_vec;

    string conf_username, conf_password;

    bool use_ssl;
    char *cert_pem, *cert_key;
    string pem_path, key_path;

    bool running;

    std::map<string, string> mime_type_map;

    class static_dir {
    public:
        static_dir(string prefix, string path) {
            this->prefix = prefix;
            this->path = path;
        };

        string prefix;
        string path;
    };

    vector<static_dir> static_dir_vec;

    pthread_mutex_t controller_mutex;

    // Handle the requests and dispatch to controllers
    static int http_request_handler(void *cls, struct MHD_Connection *connection,
            const char *url, const char *method, const char *version,
            const char *upload_data, size_t *upload_data_size, void **ptr);

    static void http_request_completed(void *cls, struct MHD_Connection *connection,
            void **con_cls, enum MHD_RequestTerminationCode toe);

    static int handle_static_file(void *cls, Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method);

    static int http_post_handler(void *coninfo_cls, enum MHD_ValueKind kind, 
            const char *key, const char *filename, const char *content_type,
            const char *transfer_encoding, const char *data, 
            uint64_t off, size_t size);

    char *read_ssl_file(string in_fname);

    void AddSession(shared_ptr<Kis_Net_Httpd_Session> in_session);
    void DelSession(string in_key);
    void DelSession(map<string, shared_ptr<Kis_Net_Httpd_Session> >::iterator in_itr);
    void WriteSessions();

    map<string, shared_ptr<Kis_Net_Httpd_Session> > session_map;

    bool store_sessions;
    string sessiondb_file;
    ConfigFile *session_db;

    shared_ptr<Kis_Httpd_Websession> websession;
    unsigned int session_timeout;

};

#endif

