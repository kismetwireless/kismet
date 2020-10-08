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

#ifndef __KIS_NET_BEAST_HTTPD_H__
#define __KIS_NET_BEAST_HTTPD_H__ 

#include "config.h"

#include <atomic>
#include <list>
#include <regex>
#include <string>
#include <thread>
#include <unordered_map>


#include "boost/asio.hpp"
#include "boost/beast.hpp"
#include "boost/optional.hpp"

#include "entrytracker.h"
#include "globalregistry.h"
#include "json/json.h"
#include "kis_mutex.h"
#include "messagebus.h"
#include "trackedelement.h"

class kis_net_beast_httpd_connection;
class kis_net_beast_route;
class kis_net_beast_auth;
class kis_net_web_endpoint;

class kis_net_beast_httpd : public lifetime_global, public deferred_startup,
    public std::enable_shared_from_this<kis_net_beast_httpd> {
public:
    static std::string global_name() { return "BEAST_HTTPD_SERVER"; }
    static std::shared_ptr<kis_net_beast_httpd> create_httpd();

    using http_var_map_t = std::unordered_map<std::string, std::string>;

    virtual void trigger_deferred_startup() override;

    const static std::string LOGON_ROLE;
    const static std::string ANY_ROLE;
    const static std::string RO_ROLE;

private:
    kis_net_beast_httpd(boost::asio::ip::tcp::endpoint& endpoint);

public:
    virtual ~kis_net_beast_httpd();

    int start_httpd();
    int stop_httpd();

    bool httpd_running() { return running; }
    unsigned int fetch_port() { return port; }
    bool fetch_using_ssl() { return use_ssl; }

    static std::string decode_uri(boost::beast::string_view in);
    static void decode_variables(const boost::beast::string_view decoded, http_var_map_t& var_map);
    static std::string escape_html(const boost::beast::string_view& html);

    void register_mime_type(const std::string& extension, const std::string& type);
    void remove_mime_type(const std::string& extension);
    std::string resolve_mime_type(const std::string& extension);
    std::string resolve_mime_type(const boost::beast::string_view& extension);

    // The majority of routing requires authentication.  Any route that operates outside of 
    // authentication must *explicitly* register as unauthenticated.
    void register_route(const std::string& route, const std::list<std::string>& verbs, 
            const std::string& role, std::shared_ptr<kis_net_web_endpoint> handler);
    void register_route(const std::string& route, const std::list<std::string>& verbs, 
            const std::string& role, const std::list<std::string>& extensions, 
            std::shared_ptr<kis_net_web_endpoint> handler);
    void remove_route(const std::string& route);

    void register_unauth_route(const std::string& route, const std::list<std::string>& verbs, 
            std::shared_ptr<kis_net_web_endpoint> handler);
    void register_unauth_route(const std::string& route, const std::list<std::string>& verbs,
            const std::list<std::string>& extensions, 
            std::shared_ptr<kis_net_web_endpoint> handler);


    // Create an auth entry & return it
    std::string create_auth(const std::string& name, const std::string& role, time_t expiry);
    // Remove an auth entry based on token
    void remove_auth(const std::string& token);
    void load_auth();
    void store_auth();

    std::shared_ptr<kis_net_beast_auth> check_auth_token(const boost::beast::string_view& token);
    bool check_admin_login(const std::string& username, const std::string& password);


    // Map a content directory into the virtual paths
    void register_static_dir(const std::string& prefix, const std::string& path);


    // Find an endpoint
    std::shared_ptr<kis_net_beast_route> find_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con);


    const bool& allow_cors() { return allow_cors_; }
    const std::string& allowed_cors_referrer() { return allowed_cors_referrer_; }

    bool serve_file(std::shared_ptr<kis_net_beast_httpd_connection> con);

protected:
    std::atomic<bool> running;
    unsigned int port;

    kis_recursive_timed_mutex mime_mutex;
    std::unordered_map<std::string, std::string> mime_map;

    kis_recursive_timed_mutex route_mutex;
    std::vector<std::shared_ptr<kis_net_beast_route>> route_vec;

    kis_recursive_timed_mutex auth_mutex;
    std::vector<std::shared_ptr<kis_net_beast_auth>> auth_vec;

    kis_recursive_timed_mutex static_mutex;
    class static_content_dir {
    public:
        static_content_dir(const std::string& prefix, const std::string& path) :
            prefix{prefix},
            path{path} { }

        std::string prefix;
        std::string path;
    };
    std::vector<static_content_dir> static_dir_vec;


    boost::asio::ip::tcp::endpoint endpoint;
    boost::asio::ip::tcp::acceptor acceptor;

    void start_accept();
    void handle_connection(const boost::system::error_code& ec, boost::asio::ip::tcp::socket socket);

    bool use_ssl;
    bool serve_files;

    bool allow_cors_;
    std::string allowed_cors_referrer_;

    // Yes, these are stored in ram.  yes, I'm ok with this.
    std::string admin_username, admin_password;
    bool global_login_config;

    void set_admin_login(const std::string& username, const std::string& password);

};

// Future chainbuf, based on stringbuf
// Provides an inter-thread feeder/consumer model with locking based on futures
//
// Can be operated in stream (default) mode where it can be fed from a 
// std::ostream or similar, or in packet mode (set_packet()) where it operates
// in a packetized mode where each chunk is either allocated or reserved directly.
//
// Once in packet mode it can not be set to stream mode
class future_chainbuf : public std::stringbuf {
protected:
    class data_chunk {
    public:
        data_chunk(size_t sz):
            sz_{sz},
            start_{0},
            end_{0} {
            chunk_ = new char[sz];
        }

        data_chunk(const char *data, size_t sz) :
            sz_{sz},
            start_{0},
            end_{sz} {
            chunk_ = new char[sz];
            memcpy(chunk_, data, sz);
        }

        ~data_chunk() {
            delete[] chunk_;
        }

        size_t write(const char *data, size_t len) {
            // Can't write more than is left in the chunk
            size_t write_sz = std::min(sz_ - end_, len);

            if (write_sz == 0)
                return len;

            memcpy(chunk_ + end_, data, write_sz);
            end_ += write_sz;

            return write_sz;
        }

        size_t consume(size_t len) {
            // Can't consume more than we've populated
            size_t consume_sz = std::min(end_ - start_, len);

            start_ += consume_sz;

            return consume_sz;
        }

        char *content() {
            return chunk_ + start_;
        }

        bool exhausted() const {
            return sz_ == end_ && end_ == start_;
        }

        size_t available() const {
            return sz_ - end_;
        }

        size_t used() const {
            return end_ - start_;
        }

        void recycle() {
            start_ = end_ = 0;
        }

        char *chunk_;
        size_t sz_;
        size_t start_, end_;
    };

public:
    future_chainbuf() :
        chunk_sz_{4096},
        sync_sz_{4096},
        total_sz_{0},
        waiting_{false},
        complete_{false},
        cancel_{false},
        packet_{false} {
        chunk_list_.push_front(new data_chunk(chunk_sz_));
    }
        
    future_chainbuf(size_t chunk_sz, size_t sync_sz = 1024) :
        chunk_sz_{chunk_sz},
        sync_sz_{sync_sz},
        total_sz_{0},
        waiting_{false},
        complete_{false},
        cancel_{false},
        packet_{false} {
        chunk_list_.push_front(new data_chunk(chunk_sz_));
    }

    ~future_chainbuf() {
        cancel();

        for (auto c : chunk_list_) {
            delete c;
        }
    }

    size_t get(char **data) {
        const std::lock_guard<std::mutex> lock(mutex_);

        if (total_sz_ == 0) {
            *data = nullptr;
            return 0;
        }

        data_chunk *target = chunk_list_.front();
        *data = target->content();
        return target->used();
    }

    void consume(size_t sz) {
        const std::lock_guard<std::mutex> lock(mutex_);

        if (chunk_list_.size() == 0)
            return;

        data_chunk *target = chunk_list_.front();

        size_t consumed_sz = 0;

        while (consumed_sz < sz && total_sz_ > 0) {
            size_t consumed_chunk_sz;

            consumed_chunk_sz = target->consume(sz);
            consumed_sz += consumed_chunk_sz;

            if (target->exhausted()) {
                if (chunk_list_.size() == 1) {
                    if (packet_) {
                        chunk_list_.pop_front();
                        delete target;
                        target = nullptr;
                    } else {
                        target->recycle();
                    }
                    break;
                } else {
                    chunk_list_.pop_front();
                    delete target;
                    target = chunk_list_.front();
                }
            }

            total_sz_ -= consumed_chunk_sz;
        }
    }

    void put_data(const char *data, size_t sz) {
        const std::lock_guard<std::mutex> lock(mutex_);

        if (packet_) {
            data_chunk *target = new data_chunk(data, sz);
            chunk_list_.push_back(target);
            total_sz_ += sz;
            sync();
            return;
        }

        data_chunk *target = chunk_list_.back();
        size_t written_sz = 0;

        while (written_sz < sz) {
            size_t written_chunk_sz;

            written_chunk_sz = target->write(data + written_sz, sz - written_sz);
            written_sz += written_chunk_sz;

            if (target->available() == 0) {
                target = new data_chunk(chunk_sz_);
                chunk_list_.push_back(target);
            }
        }

        total_sz_ += sz;
    }

    char *reserve(size_t sz) {
        const std::lock_guard<std::mutex> lock(mutex_);

        if (!packet_)
            throw std::runtime_error("cannot reserve in stream mode");

        // Trim the current chunk, and make a new chunk big enough to hold the entire record,
        // returning a pointer to the data; committed with a call to sync()
        
        auto current = chunk_list_.back();

        if (sz < current->available())
            return current->chunk_ + current->start_;

        auto sized = new data_chunk(std::max(sz, chunk_sz_));
        chunk_list_.push_back(sized);

        total_sz_ += sz;

        return sized->chunk_;
    }

    virtual std::streamsize xsputn(const char_type *s, std::streamsize n) override {
        if (packet_)
            throw std::runtime_error("cannot use stream methods in packet mode");

        put_data(s, n);

        if (size() > sync_sz_)
            sync();

        return n;
    }

    virtual int_type overflow(int_type ch) override {
        if (packet_)
            throw std::runtime_error("cannot use stream methods in packet mode");

        put_data((char *) &ch, 1);

        if (size() > sync_sz_)
            sync();

        return ch;
    }

    int sync() override {
        const std::lock_guard<std::mutex> lock(mutex_);
        try {
            if (waiting_)
                wait_promise_.set_value(true);
        } catch (const std::future_error& e) {
            ;
        }

        waiting_ = false;

        return 1;
    }

    bool running() const {
        return (!complete_ && !cancel_);
    }

    size_t size() {
        const std::lock_guard<std::mutex> lock(mutex_);
        return total_sz_;
    }

    void reset() {
        const std::lock_guard<std::mutex> lock(mutex_);

        if (waiting_)
            throw std::runtime_error("reset futurechainbuf while waiting");

        for (auto c : chunk_list_)
            delete c;
        chunk_list_.clear();
        chunk_list_.push_front(new data_chunk(chunk_sz_));

        total_sz_ = 0;
        complete_ = false;
        cancel_ = false;
        waiting_ = false;
    }

    void cancel() {
        cancel_ = true;
        sync();
    }

    void complete() {
        complete_ = true;
        sync();
    }

    void set_packetmode() {
        packet_ = true;
    }

    size_t wait() {
        if (waiting_)
            throw std::runtime_error("future_stream already blocking");

        if (total_sz_ > 0 || !running()) {
            return total_sz_;
        }

        mutex_.lock();
        waiting_ = true;
        wait_promise_ = std::promise<bool>();
        auto ft = wait_promise_.get_future();
        mutex_.unlock();

        ft.wait();

        return total_sz_;
    }

protected:
    std::mutex mutex_;

    std::list<data_chunk *> chunk_list_;

    size_t chunk_sz_;
    size_t sync_sz_;
    size_t total_sz_;

    std::promise<bool> wait_promise_;
    std::atomic<bool> waiting_;

    std::atomic<bool> complete_;
    std::atomic<bool> cancel_;

    std::atomic<bool> packet_;
};


// Central entity which tracks everything about a connection, parsed variables, generator thread, etc.
class kis_net_beast_httpd_connection : public std::enable_shared_from_this<kis_net_beast_httpd_connection> {
public:
    friend class kis_net_beast_httpd;

    kis_net_beast_httpd_connection(boost::beast::tcp_stream& stream,
            std::shared_ptr<kis_net_beast_httpd> httpd);
    virtual ~kis_net_beast_httpd_connection();

    using uri_param_t = std::unordered_map<std::string, std::string>;

    bool start();

    boost::beast::http::request<boost::beast::http::string_body>& request() { return request_; }
    boost::beast::http::verb& verb() { return verb_; }

    // Raw stream
    boost::beast::tcp_stream& stream() { return stream_; }

    // Stream suitable for std::ostream
    future_chainbuf& response_stream() { return response_stream_; }

    // Login validity
    bool login_valid() const { return login_valid_; }
    const std::string& login_role() const { return login_role_; }

    // These may be set by the endpoint handler prior to the first writing of data; once the
    // first block of the response has been sent, it is too late to include these and they will 
    // raise a runtime error exception
    void set_status(unsigned int response);
    void set_status(boost::beast::http::status status);
    void set_mime_type(const std::string& type);
    void set_target_file(const std::string& type);

    const boost::beast::http::verb& verb() const { return verb_; }
    const boost::beast::string_view& uri() const { return uri_; }

    // These can't be const for [] to work
    uri_param_t& uri_params() { return uri_params_; }
    kis_net_beast_httpd::http_var_map_t& http_variables() { return http_variables_; }
    Json::Value& json() { return json_; }

    static std::string escape_html(const boost::beast::string_view& html) {
        return kis_net_beast_httpd::escape_html(html);
    }

protected:
    const std::string AUTH_COOKIE = "KISMET";

    std::shared_ptr<kis_net_beast_httpd> httpd;

    boost::beast::tcp_stream& stream_;
    boost::beast::flat_buffer buffer;

    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser_;
    boost::beast::http::request<boost::beast::http::string_body> request_;

    boost::beast::http::response<boost::beast::http::buffer_body> response;
    future_chainbuf response_stream_;

    // Request type
    boost::beast::http::verb verb_;

    // Login data
    bool login_valid_;
    std::string login_role_;

    // All variables
    kis_net_beast_httpd::http_var_map_t http_variables_;
    // Decoded JSON from post json= or from post json document
    Json::Value json_;

    std::string auth_token_;
    boost::beast::string_view uri_;
    uri_param_t uri_params_;

    boost::beast::string_view http_post;

    std::atomic<bool> first_response_write;

    bool do_close();

    template<class Response>
    void append_common_headers(Response& r, boost::beast::string_view uri) {
        // Append the common headers
        r.set(boost::beast::http::field::server, "Kismet");
        r.version(request_.version());
        r.keep_alive(request_.keep_alive());
        
        r.set(boost::beast::http::field::content_type, httpd->resolve_mime_type(uri));

        // Last modified is always "now"
        char lastmod[31];
        struct tm tmstruct;
        time_t now;
        time(&now);
        gmtime_r(&now, &tmstruct);
        strftime(lastmod, 31, "%a, %d %b %Y %H:%M:%S %Z", &tmstruct);
        r.set(boost::beast::http::field::last_modified, lastmod);

        // Defer adding mime type until the first block
        // Defer adding disposition until the first block

        // Append the session headers
        if (auth_token_.length()) {
            r.set(boost::beast::http::field::set_cookie,
                    fmt::format("{}={}; Path=/", AUTH_COOKIE, auth_token_));
        }

        // Turn off caching
        r.set(boost::beast::http::field::cache_control, "no-cache");
        r.set(boost::beast::http::field::pragma, "no-cache");
        r.set(boost::beast::http::field::expires, "Sat, 01 Jan 2000 00:00:00 GMT");

        // Append the CORS headers
        if (httpd->allow_cors()) {
            if (httpd->allowed_cors_referrer().length()) {
                r.set(boost::beast::http::field::access_control_allow_origin, httpd->allowed_cors_referrer());
            } else {
                auto origin = request_.find(boost::beast::http::field::origin);

                if (origin != request_.end())
                    r.set(boost::beast::http::field::access_control_allow_origin, origin->value());
                else
                    r.set(boost::beast::http::field::access_control_allow_origin, "*");
            }

            r.set(boost::beast::http::field::access_control_allow_credentials, "true");
            r.set(boost::beast::http::field::vary, "Origin");
            r.set(boost::beast::http::field::access_control_max_age, "86400");
            r.set(boost::beast::http::field::access_control_allow_methods, "POST, GET, OPTIONS, UPGRADE");
            r.set(boost::beast::http::field::access_control_allow_headers, "Content-Type, Authorization");
        }
    }

public:
    // Summarize based on a summarization dictionary, if one is present.
    // MAY THROW EXCEPTIONS if summarization is malformed.
    // Calls the standard, nested/vectorization summarization if passed a vector, single summarization
    // if passed a map/trackedcomponent object.
    // Modifies the rename_map field, which must be provided by the caller.
    // Returns a summarized vector (if passed a vector) or summarized device (if passed
    // a summarized device)
    template<typename T>
    std::shared_ptr<tracker_element> summarize_with_json(const std::shared_ptr<T>& in_data,
            std::shared_ptr<tracker_element_serializer::rename_map> rename_map) {

        auto summary_vec = std::vector<SharedElementSummary>{};
        auto fields = json_.get("fields", Json::Value(Json::arrayValue));

        for (const auto& i : fields) {
            if (i.isString()) {
                summary_vec.push_back(std::make_shared<tracker_element_summary>(i.asString()));
            } else if (i.isArray()) {
                if (i.size() != 2)
                    throw std::runtime_error("Invalid field mapping, expected [field, name]");
                summary_vec.push_back(std::make_shared<tracker_element_summary>(i[0].asString(), i[1].asString()));
            } else {
                throw std::runtime_error("Invalid field mapping, expected field or [field,rename]");
            }
        }

        return summarize_tracker_element(in_data, summary_vec, rename_map);
    }
};

class kis_net_web_endpoint {
public:
    kis_net_web_endpoint() { }
    virtual ~kis_net_web_endpoint() { }

    virtual void handle_request(std::shared_ptr<kis_net_beast_httpd_connection>) { }
};

class kis_net_web_function_endpoint : public kis_net_web_endpoint {
public:
    using function_t = std::function<void (std::shared_ptr<kis_net_beast_httpd_connection>)>;

    kis_net_web_function_endpoint(function_t function) :
        kis_net_web_endpoint{},
        function{function} { }
    virtual ~kis_net_web_function_endpoint() { }

    virtual void handle_request(std::shared_ptr<kis_net_beast_httpd_connection> con) {
        function(con);
    }

protected:
    function_t function;
};

class kis_net_web_tracked_endpoint : public kis_net_web_endpoint {
public:
    using gen_func_t = 
        std::function<std::shared_ptr<tracker_element> (std::shared_ptr<kis_net_beast_httpd_connection>)>;
    using wrapper_func_t = std::function<void (std::shared_ptr<tracker_element>)>;

    kis_net_web_tracked_endpoint(std::shared_ptr<tracker_element> content,
            kis_recursive_timed_mutex *mutex,
            wrapper_func_t pre_func = nullptr,
            wrapper_func_t post_func = nullptr) : 
        content{content},
        mutex{mutex}, 
        pre_func{pre_func},
        post_func{post_func} { }

    kis_net_web_tracked_endpoint(gen_func_t generator, 
            wrapper_func_t pre_func = nullptr,
            wrapper_func_t post_func = nullptr) :
        mutex{nullptr},
        generator{generator},
        pre_func{pre_func},
        post_func{post_func} { }

    virtual void handle_request(std::shared_ptr<kis_net_beast_httpd_connection> con) override;

protected:
    std::shared_ptr<tracker_element> content;
    kis_recursive_timed_mutex *mutex;
    gen_func_t generator;
    wrapper_func_t pre_func;
    wrapper_func_t post_func;
};

// Routes map a templated URL path to a callback generator which creates the content.
//
// Routes are formatted of the type /path/:key/etc
//
// Routes constructed with no role match any role.
// Routes constructed with a role match "login" *or* that role.
//
// Routes constructed with *no* extensions list match *only* that route
// Routes constructed with an *empty* extensions list {} match *all file types* and resolve at serialization
// Routes constructed with an explicit extensions list {"json", "prettyjson"} resolve ONLY those types
//
// Keys are extracted from the URL and placed in the uri_params dictionary.
// The FILETYPE key is automatically populated with the extracted request file extension (HTML, JSON, etc)
// The GETVARS key is automatically populated with the raw HTTP GET variables string
class kis_net_beast_route {
public:
    kis_net_beast_route(const std::string& route, const std::list<boost::beast::http::verb>& verbs,
            bool login, const std::string& role, std::shared_ptr<kis_net_web_endpoint> handler);
    kis_net_beast_route(const std::string& route, const std::list<boost::beast::http::verb>& verbs,
            bool login, const std::string& role, const std::list<std::string>& extensions, 
            std::shared_ptr<kis_net_web_endpoint> handler);

    // Does a URL match this route?  If so, populate uri params and uri variables
    bool match_url(const std::string& url, kis_net_beast_httpd_connection::uri_param_t& uri_params,
            kis_net_beast_httpd::http_var_map_t& uri_variables);

    // Is the verb compatible?
    bool match_verb(boost::beast::http::verb verb);

    // Is the role compatible?
    bool match_role(bool login, const std::string& role);
    
    // Invoke our registered callback
    void invoke(std::shared_ptr<kis_net_beast_httpd_connection> connection);

    std::string& route() { return route_; }

protected:
    std::shared_ptr<kis_net_web_endpoint> handler;

    std::string route_;

    std::list<boost::beast::http::verb> verbs_;

    bool login_;
    std::string role_;

    const std::string path_id_pattern = ":([a-zA-Z0-9]+)?";
    const std::string path_capture_pattern = "(?:([a-zA-Z0-9]+?))";
    const std::regex path_re = std::regex(path_id_pattern);

    bool match_types;
    std::vector<std::string> match_keys;

    std::regex match_re;
};

struct auth_construction_error : public std::exception {
    const char *what() const throw () {
        return "could not process auth json";
    }
};

// Authentication record, loading from the http auth file.  Authentication tokens may have 
// optional role; a role of '*' has full access to all capabilities.  The meaning of roles is
// defined by the endpoints
class kis_net_beast_auth {
public:
    kis_net_beast_auth(const Json::Value& json);
    kis_net_beast_auth(const std::string& token, const std::string& name, 
            const std::string& role, time_t expires);

    bool check_auth(const boost::beast::string_view& token) const;

    const std::string& token() { return token_; }
    const std::string& name() { return name_; }
    const std::string& role() { return role_; }

    bool is_valid() const { return time_expires_ == 0 || time_expires_ < time(0); }
    void access() { time_accessed_ = time(0); }

    Json::Value as_json();

protected:
    std::string token_;
    std::string name_;
    std::string role_;
    time_t time_created_, time_accessed_, time_expires_;

};

// Basic constant-time string compare for passwords and session keys
struct boost_stringview_constant_time_string_compare_ne {
    bool operator()(const boost::beast::string_view& a, const boost::beast::string_view& b) const {
        bool r = true;

        if (a.length() != b.length())
            r = false;

        for (size_t x = 0; x < a.length() && x < b.length(); x++) {
            if (a[x] != b[x])
                r = false;
        }

        return r == false;
    }

};

#endif /* ifndef KIS_NET_BEAST_HTTPD_H */
