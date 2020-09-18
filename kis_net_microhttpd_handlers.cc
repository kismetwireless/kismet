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

#include <future>

#include "entrytracker.h"
#include "kis_httpd_websession.h"
#include "kis_net_microhttpd_handlers.h"
#include "kis_net_microhttpd.h"
#include "messagebus.h"

kis_net_httpd_handler::kis_net_httpd_handler() {
    httpd = Globalreg::fetch_mandatory_global_as<kis_net_httpd>();

    // bind_httpd_server(Globalreg::globalreg);
}

kis_net_httpd_handler::~kis_net_httpd_handler() {
    httpd = 
        Globalreg::fetch_global_as<kis_net_httpd>("HTTPD_SERVER");

    // Remove as both type of handlers for safety
    if (httpd != nullptr) {
        httpd->remove_handler(this);
        httpd->remove_unauth_handler(this);
    }
}

void kis_net_httpd_handler::bind_httpd_server() {
    httpd->register_handler(this);
}

bool kis_net_httpd_handler::httpd_can_serialize(const std::string& path) {
    return Globalreg::globalreg->entrytracker->can_serialize(httpd->get_suffix(path));
}

void kis_net_httpd_handler::httpd_serialize(const std::string& path, 
        std::ostream& stream,
        std::shared_ptr<tracker_element> elem, 
        std::shared_ptr<tracker_element_serializer::rename_map> rename,
        kis_net_httpd_connection *connection) {
    int r;

    r = Globalreg::globalreg->entrytracker->serialize(httpd->get_suffix(path), stream, elem, rename);

    if (r < 0) 
        connection->httpcode = 501;
}

std::string kis_net_httpd_handler::httpd_get_suffix(const std::string& path) {
    return httpd->get_suffix(path);
}

std::string kis_net_httpd_handler::httpd_strip_suffix(const std::string& path) {
    return httpd->strip_suffix(path);
}

KIS_MHD_RETURN kis_net_httpd_cppstream_handler::httpd_handle_get_request(kis_net_httpd *httpd, 
        kis_net_httpd_connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    std::stringstream stream;
    KIS_MHD_RETURN ret;

    if (connection == NULL)
        return MHD_NO;

    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    httpd_create_stream_response(httpd, connection, url, method, upload_data,
            upload_data_size, stream);

    if (connection->response == NULL) {
        connection->response = 
            MHD_create_response_from_buffer(stream.str().length(),
                    (void *) stream.str().data(), MHD_RESPMEM_MUST_COPY);

        ret = httpd->send_standard_http_response(httpd, connection, url);

        return ret;
    }
    
    return MHD_YES;
}

KIS_MHD_RETURN kis_net_httpd_cppstream_handler::httpd_handle_post_request(kis_net_httpd *httpd, 
        kis_net_httpd_connection *connection,
        const char *url, const char *method __attribute__((unused)), 
        const char *upload_data __attribute__((unused)),
        size_t *upload_data_size __attribute__((unused))) {

    // Call the post complete and populate our stream
    if (connection == NULL)
        return MHD_NO;

    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    try {
        httpd_post_complete(connection);
    } catch (const std::exception& e) {
        auto err = fmt::format("Server error:  Uncaught exception '{}'\n", e.what());

        connection->response = 
            MHD_create_response_from_buffer(err.length(), (void *) err.c_str(), MHD_RESPMEM_MUST_COPY);
        connection->httpcode = 500;
        return httpd->send_standard_http_response(httpd, connection, url);
    }

    if (connection->response == NULL) {
        connection->response = 
            MHD_create_response_from_buffer(connection->response_stream.str().length(),
                    (void *) connection->response_stream.str().data(), 
                    MHD_RESPMEM_MUST_COPY);

        return httpd->send_standard_http_response(httpd, connection, url);
    } 

    return MHD_YES;
}

bool kis_net_httpd_no_files_handler::httpd_verify_path(const char *path, 
        const char *method) {

    if (strcmp(method, "GET") != 0)
        return false;

    if (strcmp(path, "/index.html") == 0 ||
            strcmp(path, "/") == 0)
        return true;

    return false;
}

void kis_net_httpd_no_files_handler::httpd_create_stream_response(kis_net_httpd *httpd __attribute__((unused)),
        kis_net_httpd_connection *connection __attribute__((unused)),
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

kis_net_httpd_buffer_stream_aux::kis_net_httpd_buffer_stream_aux(
        kis_net_httpd_buffer_stream_handler *in_handler,
        kis_net_httpd_connection *in_httpd_connection,
        std::shared_ptr<buffer_handler_generic> in_ringbuf_handler,
        void *in_aux, std::function<void (kis_net_httpd_buffer_stream_aux *)> in_free_aux) :
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
    ringbuf_handler->set_protocol_error_cb([this]() {
            trigger_error();
        });

    // Lodge ourselves as the write handler
    ringbuf_handler->set_write_buffer_interface(this);
}

kis_net_httpd_buffer_stream_aux::~kis_net_httpd_buffer_stream_aux() {
    // Get out of the lock and flag an error so we end
    in_error = true;

    if (ringbuf_handler) {
        ringbuf_handler->remove_write_buffer_interface();
        ringbuf_handler->set_protocol_error_cb(NULL);
    }

    cl->unlock(0);
}

void kis_net_httpd_buffer_stream_aux::buffer_available(size_t in_amt __attribute__((unused))) {
    // All we need to do here is unlock the conditional lock; the 
    // buffer_event_cb callback will unlock and read from the buffer, then
    // re-lock and block
    // fmt::print(stderr, "buffer available {}\n", in_amt);
    cl->unlock(1);
}

void kis_net_httpd_buffer_stream_aux::block_until_data(std::shared_ptr<buffer_handler_generic> rbh) {
    while (1) {
        { 
            if (rbh->get_read_buffer_used()) {
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

kis_net_httpd_buffer_stream_handler::~kis_net_httpd_buffer_stream_handler() {

}

ssize_t kis_net_httpd_buffer_stream_handler::buffer_event_cb(void *cls, uint64_t pos,
        char *buf, size_t max) {
    kis_net_httpd_buffer_stream_aux *stream_aux = (kis_net_httpd_buffer_stream_aux *) cls;

    // Protect that we have to exit the buffer cb before the stream can be killed, don't
    // use an automatic locker because we can't let it time out.  This could sit locked for
    // a long time while the generator populates data; if there's a HTTP error we need to
    // let this end gracefully.
    stream_aux->get_buffer_event_mutex()->lock();

    std::shared_ptr<buffer_handler_generic> rbh = stream_aux->get_rbhandler();

    if (rbh == nullptr) {
        _MSG_ERROR("httpd buffer_event got a null rbhhandler, something is up.");
        return MHD_CONTENT_READER_END_OF_STREAM;
    }

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
        read_sz = rbh->zero_copy_peek_write_buffer_data((void **) &zbuf, max);

        // fmt::print(stderr, "buffer read sz {}\n", read_sz);

        // If we've got nothing left either it's the end of the buffer or we're pending
        // more data hitting the request
        if (read_sz == 0) {
            rbh->peek_free_write_buffer_data(zbuf);

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
    rbh->peek_free_write_buffer_data(zbuf);
    rbh->consume_write_buffer_data(read_sz);

    // Unlock the stream
    stream_aux->get_buffer_event_mutex()->unlock();

    return (ssize_t) read_sz;
}

static void free_buffer_aux_callback(void *cls) {
    kis_net_httpd_buffer_stream_aux *aux = (kis_net_httpd_buffer_stream_aux *) cls;

    // fprintf(stderr, "debug - free_buffer_aux\n");

    aux->get_buffer_event_mutex()->lock();

    aux->ringbuf_handler->protocol_error();

    // Consume any backlog if the thread is still processing
    std::shared_ptr<buffer_handler_generic> rbh = aux->get_rbhandler();

    size_t read_sz = 0;
    unsigned char *zbuf;

    while (aux->get_in_error() == false) {
        // aux->block_until_data(rbh);

        read_sz = rbh->zero_copy_peek_write_buffer_data((void **) &zbuf, 1024);

        rbh->peek_free_write_buffer_data(zbuf);
        rbh->consume_write_buffer_data(read_sz);

        if (read_sz == 0)
            break;
    }

    aux->get_buffer_event_mutex()->unlock();

    // Get the thread that's generating data
    aux->generator_thread.join();

    if (aux->free_aux_cb != nullptr) {
        aux->free_aux_cb(aux);
    }

    delete(aux);
}

KIS_MHD_RETURN kis_net_httpd_buffer_stream_handler::httpd_handle_get_request(kis_net_httpd *httpd, 
        kis_net_httpd_connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    if (connection == NULL)
        return MHD_NO;

    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    if (connection->response == NULL) {
        std::shared_ptr<buffer_handler_generic> rbh(allocate_buffer());

        if (rbh == nullptr) {
            _MSG_ERROR("Error allocating RBH in buffer_stream_handler, something is up");

            auto err = fmt::format("Error allocating RBH in buffer_stream_handler");
            struct MHD_Response *response = 
                MHD_create_response_from_buffer(err.length(), 
                        (void *) err.c_str(), MHD_RESPMEM_MUST_COPY);
            return MHD_queue_response(connection->connection, MHD_HTTP_NOT_FOUND, response);

        }

        kis_net_httpd_buffer_stream_aux *aux = 
            new kis_net_httpd_buffer_stream_aux(this, connection, rbh, NULL, NULL);
        connection->custom_extension = aux;

        std::promise<int> launch_promise;
        std::future<int> launch_future = launch_promise.get_future();

        // Run it in its own thread and set up the connection streaming object; we MUST pass
        // the aux as a direct pointer because the microhttpd backend can delete the 
        // connection BEFORE calling our cleanup on our response!
        
        // Copy our function parameters in case we lose them before the lambda thread executes
        // on a very slow or single-core system
        auto url_copy = std::string(url);
        auto method_copy = std::string(method);
        auto upload_data_copy = std::string(upload_data, *upload_data_size);

        aux->generator_thread =
            std::thread([this, &launch_promise, aux, httpd, connection, url_copy, 
                    method_copy, upload_data_copy] {
                // Unlock the http thread as soon as we've spawned the generator here
                launch_promise.set_value(1);

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
                    int r = httpd_create_stream_response(httpd, connection, url_copy.c_str(), 
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

        // Don't make the response until we're sure the populating service thread has started up
        launch_future.wait();

        connection->response = 
            MHD_create_response_from_callback(MHD_SIZE_UNKNOWN, 32 * 1024,
                    &buffer_event_cb, aux, &free_buffer_aux_callback);

        return httpd->send_standard_http_response(httpd, connection, url);
    }

    return MHD_NO;
}

KIS_MHD_RETURN kis_net_httpd_buffer_stream_handler::httpd_handle_post_request(kis_net_httpd *httpd,
        kis_net_httpd_connection *connection, 
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    if (connection == NULL)
        return MHD_NO;

    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    if (connection->response == NULL) {
        // No read, default write
        std::shared_ptr<buffer_handler_generic> rbh(allocate_buffer());

        kis_net_httpd_buffer_stream_aux *aux = 
            new kis_net_httpd_buffer_stream_aux(this, connection, rbh, NULL, NULL);
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
                    int r = httpd_post_complete(connection);
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

        return httpd->send_standard_http_response(httpd, connection, url);
    }

    return MHD_NO;
}

