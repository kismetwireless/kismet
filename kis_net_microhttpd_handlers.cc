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

#include "config.h"

#include "entrytracker.h"
#include "kis_httpd_websession.h"
#include "kis_net_microhttpd_handlers.h"
#include "kis_net_microhttpd.h"
#include "messagebus.h"

Kis_Net_Httpd_Handler::Kis_Net_Httpd_Handler() {
    httpd = Globalreg::FetchMandatoryGlobalAs<Kis_Net_Httpd>();

    // Bind_Httpd_Server(Globalreg::globalreg);
}

Kis_Net_Httpd_Handler::~Kis_Net_Httpd_Handler() {
    httpd = 
        Globalreg::FetchGlobalAs<Kis_Net_Httpd>("HTTPD_SERVER");

    // Remove as both type of handlers for safety
    if (httpd != nullptr) {
        httpd->RemoveHandler(this);
        httpd->RemoveUnauthHandler(this);
    }
}

void Kis_Net_Httpd_Handler::Bind_Httpd_Server() {
    httpd->RegisterHandler(this);
}

bool Kis_Net_Httpd_Handler::Httpd_CanSerialize(const std::string& path) {
    return Globalreg::globalreg->entrytracker->CanSerialize(httpd->GetSuffix(path));
}

void Kis_Net_Httpd_Handler::Httpd_Serialize(const std::string& path, 
        std::ostream& stream,
        std::shared_ptr<TrackerElement> elem, 
        std::shared_ptr<TrackerElementSerializer::rename_map> rename) {
    Globalreg::globalreg->entrytracker->Serialize(httpd->GetSuffix(path), stream, elem, rename);
}

std::string Kis_Net_Httpd_Handler::Httpd_GetSuffix(const std::string& path) {
    return httpd->GetSuffix(path);
}

std::string Kis_Net_Httpd_Handler::Httpd_StripSuffix(const std::string& path) {
    return httpd->StripSuffix(path);
}

int Kis_Net_Httpd_CPPStream_Handler::Httpd_HandleGetRequest(Kis_Net_Httpd *httpd, 
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    std::stringstream stream;
    int ret;

    if (connection == NULL)
        return MHD_NO;

    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    Httpd_CreateStreamResponse(httpd, connection, url, method, upload_data,
            upload_data_size, stream);

    if (connection->response == NULL) {
        connection->response = 
            MHD_create_response_from_buffer(stream.str().length(),
                    (void *) stream.str().data(), MHD_RESPMEM_MUST_COPY);

        ret = httpd->SendStandardHttpResponse(httpd, connection, url);

        return ret;
    }
    
    return MHD_YES;
}

int Kis_Net_Httpd_CPPStream_Handler::Httpd_HandlePostRequest(Kis_Net_Httpd *httpd, 
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method __attribute__((unused)), 
        const char *upload_data __attribute__((unused)),
        size_t *upload_data_size __attribute__((unused))) {

    // Call the post complete and populate our stream
    if (connection == NULL)
        return MHD_NO;

    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    try {
        Httpd_PostComplete(connection);
    } catch (const std::exception& e) {
        auto err = fmt::format("Server error:  Uncaught exception '{}'\n", e.what());

        connection->response = 
            MHD_create_response_from_buffer(err.length(), (void *) err.c_str(), MHD_RESPMEM_MUST_COPY);
        connection->httpcode = 500;
        return httpd->SendStandardHttpResponse(httpd, connection, url);
    }

    if (connection->response == NULL) {
        connection->response = 
            MHD_create_response_from_buffer(connection->response_stream.str().length(),
                    (void *) connection->response_stream.str().data(), 
                    MHD_RESPMEM_MUST_COPY);

        return httpd->SendStandardHttpResponse(httpd, connection, url);
    } 

    return MHD_YES;
}


bool Kis_Net_Httpd::HasValidSession(Kis_Net_Httpd_Connection *connection, bool send_invalid) {
    if (connection->session != NULL)
        return true;

    std::shared_ptr<Kis_Net_Httpd_Session> s;
    const char *cookieval;

    cookieval = MHD_lookup_connection_value(connection->connection,
            MHD_COOKIE_KIND, KIS_SESSION_COOKIE);

    if (cookieval != NULL) {
        local_shared_demand_locker csl(&session_mutex);

        auto si = session_map.find(cookieval);
        if (si != session_map.end()) {
            s = si->second;

            // Does the session never expire?
            if (s->session_lifetime == 0) {
                connection->session = s;
                return true;
            }

            // Is the session still valid?
            if (time(0) < s->session_created + s->session_lifetime) {
                connection->session = s;
                return true;
            } else {
                connection->session = NULL;
                csl.unlock();
                DelSession(si);
            }
        }
    }

    // If we got here, we either don't have a session, or the session isn't valid.
    if (websession != NULL && websession->validate_login(connection->connection)) {
        CreateSession(connection, NULL, session_timeout);
        return true;
    }

    // If we got here it's invalid.  Do we automatically send an invalidation 
    // response?
    if (send_invalid) {
        auto fourohone = fmt::format("<h1>401 - Access denied</h1>Login required to access this resource.\n");

        connection->response = 
            MHD_create_response_from_buffer(fourohone.length(),
                    (void *) fourohone.c_str(), MHD_RESPMEM_MUST_COPY);

        // Queue a 401 fail instead of a basic auth fail so we don't cause a bunch of prompting in the browser
        // Make sure this doesn't actually break anything...
        MHD_queue_response(connection->connection, 401, connection->response);

        // MHD_queue_basic_auth_fail_response(connection->connection, "Kismet", connection->response);
    }

    return false;
}

std::shared_ptr<Kis_Net_Httpd_Session> 
Kis_Net_Httpd::CreateSession(Kis_Net_Httpd_Connection *connection, 
        struct MHD_Response *response, time_t in_lifetime) {
    
    std::shared_ptr<Kis_Net_Httpd_Session> s;

    // Use 128 bits of entropy to make a session key

    char rdata[16];
    FILE *urandom;

    if ((urandom = fopen("/dev/urandom", "rb")) == NULL) {
        _MSG("Failed to open /dev/urandom to create a HTTPD session, unable to "
                "assign a sessionid, not creating session", MSGFLAG_ERROR);
        return NULL;
    }

    if (fread(rdata, 16, 1, urandom) != 1) {
        _MSG("Failed to read entropy from /dev/urandom to create a HTTPD session, "
                "unable to assign a sessionid, not creating session", MSGFLAG_ERROR);
        fclose(urandom);
        return NULL;
    }
    fclose(urandom);

    std::stringstream cookiestr;
    std::stringstream cookie;
    
    cookiestr << KIS_SESSION_COOKIE << "=";

    for (unsigned int x = 0; x < 16; x++) {
        cookie << std::uppercase << std::setfill('0') << std::setw(2) 
            << std::hex << (int) (rdata[x] & 0xFF);
    }

    cookiestr << cookie.str();

    cookiestr << "; Path=/";

    if (response != NULL) {
        if (MHD_add_response_header(response, MHD_HTTP_HEADER_SET_COOKIE, 
                    cookiestr.str().c_str()) == MHD_NO) {
            _MSG("Failed to add session cookie to response header, unable to create "
                    "a session", MSGFLAG_ERROR);
            return NULL;
        }
    }

    s = std::make_shared<Kis_Net_Httpd_Session>();
    s->sessionid = cookie.str();
    s->session_created = time(0);
    s->session_seen = s->session_created;
    s->session_lifetime = in_lifetime;

    if (connection != NULL)
        connection->session = s;

    AddSession(s);

    return s;
}

bool Kis_Net_Httpd_No_Files_Handler::Httpd_VerifyPath(const char *path, 
        const char *method) {

    if (strcmp(method, "GET") != 0)
        return false;

    if (strcmp(path, "/index.html") == 0 ||
            strcmp(path, "/") == 0)
        return true;

    return false;
}


void Kis_Net_Httpd_No_Files_Handler::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection __attribute__((unused)),
        const char *url __attribute__((unused)), 
        const char *method __attribute__((unused)), 
        const char *upload_data __attribute__((unused)),
        size_t *upload_data_size __attribute__((unused)), 
        std::stringstream &stream) {

    stream << "<html>";
    stream << "<head><title>Web UI Disabled</title></head>";
    stream << "<body>";
    stream << "<h2>Sorry</h2>";
    stream << "<p>The Web UI in Kismet is disabled because Kismet cannot serve ";
    stream << "static web pages.";
    stream << "<p>Check the output of kismet_server and make sure your ";
    stream << "<blockquote><pre>httpd_home=...</pre>";
    stream << "and/or<br>";
    stream << "<pre>httpd_user_home=...</pre></blockquote>";
    stream << "configuration values are set in kismet.conf or kismet_httpd.conf ";
    stream << "and restart Kismet";
    stream << "</body>";
    stream << "</html>";
}

Kis_Net_Httpd_Buffer_Stream_Aux::Kis_Net_Httpd_Buffer_Stream_Aux(
        Kis_Net_Httpd_Buffer_Stream_Handler *in_handler,
        Kis_Net_Httpd_Connection *in_httpd_connection,
        std::shared_ptr<BufferHandlerGeneric> in_ringbuf_handler,
        void *in_aux, std::function<void (Kis_Net_Httpd_Buffer_Stream_Aux *)> in_free_aux) :
    httpd_stream_handler(in_handler),
    httpd_connection(in_httpd_connection),
    ringbuf_handler(in_ringbuf_handler),
    in_error(false),
    aux(in_aux),
    free_aux_cb(in_free_aux) {

    httpd_stream_handler = in_handler;
    httpd_connection = in_httpd_connection;
    ringbuf_handler = in_ringbuf_handler;
    aux = in_aux;
    free_aux_cb = in_free_aux;

    cl = std::make_shared<conditional_locker<int>>();
    cl->lock();

    // If the buffer encounters an error, unlock the variable and set the error state
    ringbuf_handler->SetProtocolErrorCb([this]() {
            trigger_error();
        });

    // Lodge ourselves as the write handler
    ringbuf_handler->SetWriteBufferInterface(this);
}

Kis_Net_Httpd_Buffer_Stream_Aux::~Kis_Net_Httpd_Buffer_Stream_Aux() {
    // Get out of the lock and flag an error so we end
    in_error = true;

    cl->unlock(0);

    if (ringbuf_handler) {
        ringbuf_handler->RemoveWriteBufferInterface();
        ringbuf_handler->SetProtocolErrorCb(NULL);
    }
}

void Kis_Net_Httpd_Buffer_Stream_Aux::BufferAvailable(size_t in_amt __attribute__((unused))) {
    // All we need to do here is unlock the conditional lock; the 
    // buffer_event_cb callback will unlock and read from the buffer, then
    // re-lock and block
    // fmt::print(stderr, "buffer available {}\n", in_amt);
    cl->unlock(1);
}

void Kis_Net_Httpd_Buffer_Stream_Aux::block_until_data(std::shared_ptr<BufferHandlerGeneric> rbh) {
    while (1) {
        { 
            local_locker lock(&aux_mutex);

            // fmt::print(stderr, "buffer block until sees {}\n", rbh->GetReadBufferUsed());

            // Immediately return if we have pending data
            if (rbh->GetReadBufferUsed()) {
                return;
            }

            // Immediately return so we can flush out the buffer before we fail
            if (get_in_error()) {
                return;
            }

            cl->lock();
        }

        if (cl->block_for_ms(std::chrono::milliseconds(500)))
            return;
    }
}

Kis_Net_Httpd_Buffer_Stream_Handler::~Kis_Net_Httpd_Buffer_Stream_Handler() {

}

ssize_t Kis_Net_Httpd_Buffer_Stream_Handler::buffer_event_cb(void *cls, uint64_t pos,
        char *buf, size_t max) {
    Kis_Net_Httpd_Buffer_Stream_Aux *stream_aux = (Kis_Net_Httpd_Buffer_Stream_Aux *) cls;

    // Protect that we have to exit the buffer cb before the stream can be killed, don't
    // use an automatic locker because we can't let it time out.  This could sit locked for
    // a long time while the generator populates data; if there's a HTTP error we need to
    // let this end gracefully.
    stream_aux->get_buffer_event_mutex()->lock();

    std::shared_ptr<BufferHandlerGeneric> rbh = stream_aux->get_rbhandler();

    // Target buffer before we send it out via MHD
    size_t read_sz = 0;
    unsigned char *zbuf;

    // Keep going until we have something to send
    while (read_sz == 0) {
        // We get called as soon as the webserver has either a) processed our request
        // or b) sent what we gave it; we need to hold the thread until we
        // get more data in the buf, so we block until we have data
        stream_aux->block_until_data(rbh);

        // We want to send everything we had in the buffer, even if we're in an error 
        // state, because the error text might be in the buffer (or the buffer generator
        // has completed and it's time to return)
        read_sz = rbh->ZeroCopyPeekWriteBufferData((void **) &zbuf, max);

        // fmt::print(stderr, "buffer read sz {}\n", read_sz);

        // If we've got nothing left either it's the end of the buffer or we're pending
        // more data hitting the request
        if (read_sz == 0) {
            rbh->PeekFreeWriteBufferData(zbuf);

            if (stream_aux->get_in_error()) {
                // fmt::print(stderr, "buffer hit end of stream, error flagged\n");
                stream_aux->get_buffer_event_mutex()->unlock();
                return MHD_CONTENT_READER_END_OF_STREAM;
            }
        }
    }

    // We've got data to send; copy it into the microhttpd output buffer
    if (read_sz != 0 && zbuf != NULL && buf != NULL) {
        memcpy(buf, zbuf, read_sz);
    }

    // Clean up the writebuffer access
    rbh->PeekFreeWriteBufferData(zbuf);
    rbh->ConsumeWriteBufferData(read_sz);

    // Unlock the stream
    stream_aux->get_buffer_event_mutex()->unlock();

    return (ssize_t) read_sz;
}

static void free_buffer_aux_callback(void *cls) {
    Kis_Net_Httpd_Buffer_Stream_Aux *aux = (Kis_Net_Httpd_Buffer_Stream_Aux *) cls;

    // fprintf(stderr, "debug - free_buffer_aux\n");

    aux->get_buffer_event_mutex()->lock();

    aux->ringbuf_handler->ProtocolError();

    // Consume any backlog if the thread is still processing
    std::shared_ptr<BufferHandlerGeneric> rbh = aux->get_rbhandler();

    size_t read_sz = 0;
    unsigned char *zbuf;

    while (aux->get_in_error() == false) {
        aux->block_until_data(rbh);

        read_sz = rbh->ZeroCopyPeekWriteBufferData((void **) &zbuf, 1024);

        if (read_sz == 0) {
            rbh->PeekFreeWriteBufferData(zbuf);

            if (aux->get_in_error()) {
                break;
            }
        }

        rbh->PeekFreeWriteBufferData(zbuf);
        rbh->ConsumeWriteBufferData(read_sz);
    }

    aux->get_buffer_event_mutex()->unlock();

    // Get the thread that's generating data
    aux->generator_thread.join();

    if (aux->free_aux_cb != NULL) {
        aux->free_aux_cb(aux);
    }

    delete(aux);
}

int Kis_Net_Httpd_Buffer_Stream_Handler::Httpd_HandleGetRequest(Kis_Net_Httpd *httpd, 
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    if (connection == NULL)
        return MHD_NO;

    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    if (connection->response == NULL) {
        std::shared_ptr<BufferHandlerGeneric> rbh(allocate_buffer());

        Kis_Net_Httpd_Buffer_Stream_Aux *aux = 
            new Kis_Net_Httpd_Buffer_Stream_Aux(this, connection, rbh, NULL, NULL);
        connection->custom_extension = aux;

        // Set up a locker to make sure the thread is up and running; this keeps us from
        // processing the stream contents until that thread is up and doing something.
        conditional_locker<int> aux_startup_cl;
        aux_startup_cl.lock();

        // Run it in its own thread and set up the connection streaming object; we MUST pass
        // the aux as a direct pointer because the microhttpd backend can delete the 
        // connection BEFORE calling our cleanup on our response!
        
        // Copy our function parameters in case we lose them before the lambda thread executes
        // on a very slow or single-core system
        auto url_copy = std::string(url);
        auto method_copy = std::string(method);
        auto upload_data_copy = std::string(upload_data, *upload_data_size);

        aux->generator_thread =
            std::thread([this, &aux_startup_cl, aux, httpd, connection, url_copy, 
                    method_copy, upload_data_copy] {
                // fmt::print(stderr, "generator thread starting for url {}\n", url_copy);

                // Unlock the http thread as soon as we've spawned it
                aux_startup_cl.unlock(1);

                // Callbacks can do two things - either run forever until their data is
                // done being generated, or spawn their own processing systems that write
                // back to the stream over time.  Most generate all their data in one go and
                // flush it out the stream at the same time, while pcap live streams and a
                // few others generate data over time.
                //
                // When the populator returns a MHD_YES it has completed and the stream should
                // be shut down.  We accomplish this by setting a stream error, which should in
                // turn unlock the callback and complete the stream.
                //
                // If it returns MHD_NO we let it run on forever until it kills its stream itself.
                // Exceptions are treated as MHD_YES and the stream closed - something went wrong
                // in the generator and it's not going to clean itself up.
                try {
                    size_t sz = upload_data_copy.size();
                    int r = Httpd_CreateStreamResponse(httpd, connection, url_copy.c_str(), 
                            method_copy.c_str(), upload_data_copy.data(), &sz);

                    // fmt::print(stderr, "generator completed callback\n");

                    if (r == MHD_YES) {
                        aux->sync();
                        aux->trigger_error();
                    }
                } catch (const std::exception& e) {
                    // fmt::print(stderr, "generator thread exception: {}\n", e.what());
                    aux->sync();
                    aux->trigger_error();
                }

                });

        // We unlock when the generator thread has started
        // fmt::print(stderr, "blocking until generator\n");
        aux_startup_cl.block_until();
        // fmt::print(stderr, "unblocked from generator\n");

        connection->response = 
            MHD_create_response_from_callback(MHD_SIZE_UNKNOWN, 32 * 1024,
                    &buffer_event_cb, aux, &free_buffer_aux_callback);

        return httpd->SendStandardHttpResponse(httpd, connection, url);
    }

    return MHD_NO;
}

int Kis_Net_Httpd_Buffer_Stream_Handler::Httpd_HandlePostRequest(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection, 
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    if (connection == NULL)
        return MHD_NO;

    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    if (connection->response == NULL) {
        // No read, default write
        std::shared_ptr<BufferHandlerGeneric> rbh(allocate_buffer());

        Kis_Net_Httpd_Buffer_Stream_Aux *aux = 
            new Kis_Net_Httpd_Buffer_Stream_Aux(this, connection, rbh, NULL, NULL);
        connection->custom_extension = aux;

        // fprintf(stderr, "debug - made post aux %p\n", aux);

        // Call the post complete and populate our stream;
        // Run it in its own thread and set up the connection streaming object; we MUST pass
        // the aux as a direct pointer because the microhttpd backend can delete the 
        // connection BEFORE calling our cleanup on our response!
        //
        // Set up a locker to make sure the thread is up and running
        conditional_locker<int> cl;
        cl.lock();

        aux->generator_thread =
            std::thread([this, &cl, aux, connection] {
                cl.unlock(1);

                try {
                    int r = Httpd_PostComplete(connection);
                    if (r == MHD_YES) {
                        // fprintf(stderr, "debug - triggering complete\n");
                        aux->sync();
                        aux->trigger_error();
                    }
                } catch (const std::exception& e) {
                    // fprintf(stderr, "debug - exception - triggering error\n");
                    _MSG_ERROR("HTTPD: Uncaught exception '{}' on '{}'", e.what(), connection->url);
                    aux->sync();
                    aux->trigger_error();
                }
                });

        cl.block_until();

        connection->response = 
            MHD_create_response_from_callback(MHD_SIZE_UNKNOWN, 32 * 1024,
                    &buffer_event_cb, aux, &free_buffer_aux_callback);

        return httpd->SendStandardHttpResponse(httpd, connection, url);
    }

    return MHD_NO;
}

