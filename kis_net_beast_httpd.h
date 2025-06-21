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

#include "jwt-cpp/jwt.h"

#include "jwt-cpp/traits/kazuho-picojson/traits.h"
#include "nlohmann/json.hpp"

#include "entrytracker.h"
#include "future_chainbuf.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "messagebus.h"
#include "trackedelement.h"

#include "fmt_asio.h"

template <>struct fmt::formatter<boost::beast::http::verb> : fmt::ostream_formatter {};
template <>struct fmt::formatter<boost::beast::string_view> : fmt::ostream_formatter {};

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
    using http_cookie_map_t = std::unordered_map<std::string, std::string>;

    virtual void trigger_deferred_startup() override;

    const static std::string LOGON_ROLE;
    const static std::string ANY_ROLE;
    const static std::string RO_ROLE;
    const static std::string AUTH_COOKIE;


private:
    kis_net_beast_httpd(boost::asio::ip::tcp::endpoint& endpoint);

public:
    virtual ~kis_net_beast_httpd();

    int start_httpd();
    int stop_httpd();

    bool httpd_running() { return running; }
    unsigned int fetch_port() { return port; }
    bool fetch_using_ssl() { return use_ssl; }

    static std::string decode_uri(boost::beast::string_view in, bool query);
    static void decode_variables(const boost::beast::string_view decoded, http_var_map_t& var_map);
    static std::string decode_get_variables(const boost::beast::string_view decoded, http_var_map_t& var_map);
    static void decode_cookies(const boost::beast::string_view decoded, http_cookie_map_t& cookie_map);
    static std::string escape_html(const boost::beast::string_view& html);

    // Register mime types.  These functions are NOT THREAD SAFE and must not be called
    // currently or while the webserver is serving content.
    void register_mime_type(const std::string& extension, const std::string& type);
    void remove_mime_type(const std::string& extension);
    std::string resolve_mime_type(const std::string& extension);
    std::string resolve_mime_type(const boost::beast::string_view& extension);

    // The majority of routing requires authentication.  Any route that operates outside of
    // authentication must *explicitly* register as unauthenticated.
    void register_route(const std::string& route, const std::list<std::string>& verbs,
            const std::string& role, std::shared_ptr<kis_net_web_endpoint> handler);
    void register_route(const std::string& route, const std::list<std::string>& verbs,
            const std::list<std::string>& roles, std::shared_ptr<kis_net_web_endpoint> handler);
    void register_route(const std::string& route, const std::list<std::string>& verbs,
            const std::string& role, const std::list<std::string>& extensions,
            std::shared_ptr<kis_net_web_endpoint> handler);
    void register_route(const std::string& route, const std::list<std::string>& verbs,
            const std::list<std::string>& role, const std::list<std::string>& extensions,
            std::shared_ptr<kis_net_web_endpoint> handler);
    void remove_route(const std::string& route);

    // These routes do NOT require authentication; this is of course very dangerous and should
    // be limited to those endpoints used for logging in, etc
    void register_unauth_route(const std::string& route, const std::list<std::string>& verbs,
            std::shared_ptr<kis_net_web_endpoint> handler);
    void register_unauth_route(const std::string& route, const std::list<std::string>& verbs,
            const std::list<std::string>& extensions,
            std::shared_ptr<kis_net_web_endpoint> handler);

    // Websocket handlers are their own special things.  All websockets must be authenticated.
    void register_websocket_route(const std::string& route, const std::string& role,
            const std::list<std::string>& extensions, std::shared_ptr<kis_net_web_endpoint> handler);
    void register_websocket_route(const std::string& route, const std::list<std::string>& roles,
            const std::list<std::string>& extensions, std::shared_ptr<kis_net_web_endpoint> handler);


    // Create an auth entry & return it; if the auth exists in the system already, throw a runtime exception
    std::string create_auth(const std::string& name, const std::string& role, time_t expiry);

    // Create or find an auth entity; if an API key exists for this name, return the existing token;
    // (legacy auth model code with a per-login-role token)
    std::string create_or_find_auth(const std::string& name, const std::string& role, time_t expiry);

    // Create a JWT token
    std::string create_jwt_auth(const std::string& name, const std::string& role, time_t expiry);


    // Remove an auth entry based on token
    bool remove_auth(const std::string& token);
    void load_auth();
    void store_auth();

    std::shared_ptr<kis_net_beast_auth> check_auth_token(const boost::beast::string_view& token);
    std::shared_ptr<kis_net_beast_auth> check_jwt_token(const boost::beast::string_view& token);
    bool check_admin_login(const std::string& username, const std::string& password);


    // Map a content directory into the virtual paths.  This is NOT THREAD SAFE and must not be
    // called concurrently or while the webserver is serving content.
    void register_static_dir(const std::string& prefix, const std::string& path);


    // Find an endpoint in the route table
    std::shared_ptr<kis_net_beast_route> find_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con);
    // Find a websocket endpoint in the route table
    std::shared_ptr<kis_net_beast_route> find_websocket_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con);


    const bool& allow_cors() { return allow_cors_; }
    const std::string& allowed_cors_referrer() { return allowed_cors_referrer_; }

    bool serve_file(std::shared_ptr<kis_net_beast_httpd_connection> con);
    bool serve_file(std::shared_ptr<kis_net_beast_httpd_connection> con, std::string filepath);

    void strip_uri_prefix(boost::beast::string_view& uri_view);

    const bool& redirect_unknown() const {
        return redirect_unknown_;
    }

    const std::string& redirect_unknown_target() const {
        return redirect_unknown_target_;
    }

protected:
    std::atomic<bool> running;
    unsigned int port;

    bool allow_auth_creation;
    bool allow_auth_view;

    std::unordered_map<std::string, std::string> mime_map;

    kis_mutex route_mutex;
    std::vector<std::shared_ptr<kis_net_beast_route>> route_vec;
    std::vector<std::shared_ptr<kis_net_beast_route>> websocket_route_vec;

    kis_mutex auth_mutex;
    std::vector<std::shared_ptr<kis_net_beast_auth>> auth_vec;

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

    std::string allowed_prefix;

    bool allow_cors_;
    std::string allowed_cors_referrer_;

    bool redirect_unknown_;
    std::string redirect_unknown_target_;

    // Yes, these are stored in ram.  yes, I'm ok with this.
    std::string admin_username, admin_password;
    bool global_login_config;

    // Encryption token for JWT
    std::string jwt_auth_key;
    std::string jwt_auth_issuer;

    void set_admin_login(const std::string& username, const std::string& password);

    // Internal non-locked implementation of auth creation
    std::string create_auth_impl(const std::string& name, const std::string& role, time_t expiry);

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

    // Relinquish raw stream entirely
    boost::beast::tcp_stream release_stream() { return std::move(stream_); }

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
    void clear_timeout();
    void append_header(const std::string& header, const std::string& value);

    const boost::beast::http::verb& verb() const { return verb_; }
    const boost::beast::string_view& uri() const { return uri_; }

    // These can't be const for [] to work
    uri_param_t& uri_params() { return uri_params_; }
    kis_net_beast_httpd::http_var_map_t& http_variables() { return http_variables_; }
    kis_net_beast_httpd::http_cookie_map_t& cookies() { return cookies_; }
    nlohmann::json& json() { return json_; }

    // Optional closure callback to signal to an async operation that there's a problem (for example
    // long-running packet streams)
    void set_closure_cb(std::function<void ()> cb) {
        closure_cb = cb;
    }

    static std::string escape_html(const boost::beast::string_view& html) {
        return kis_net_beast_httpd::escape_html(html);
    }

protected:
    std::shared_ptr<kis_net_beast_httpd> httpd;

    std::function<void ()> closure_cb;

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

    kis_net_beast_httpd::http_var_map_t http_variables_;
    nlohmann::json json_;
    kis_net_beast_httpd::http_cookie_map_t cookies_;
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
                    fmt::format("{}={}; Path=/", httpd->AUTH_COOKIE, auth_token_));
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
    std::shared_ptr<tracker_element> summarize_with_json(std::shared_ptr<T> in_data,
            std::shared_ptr<tracker_element_serializer::rename_map> rename_map) {

        auto summary_vec = std::vector<SharedElementSummary>{};

        auto fields = json_["fields"];

        if (!fields.is_null() && fields.is_array()) {
            for (const auto& i : fields) {
                if (i.is_string()) {
                    summary_vec.push_back(std::make_shared<tracker_element_summary>(i.get<std::string>()));
                } else if (i.is_array()) {
                    if (i.size() != 2)
                        throw std::runtime_error("Invalid field mapping, expected [field, name]");
                    summary_vec.push_back(std::make_shared<tracker_element_summary>(i[0].get<std::string>(), i[1].get<std::string>()));
                    // _MSG_DEBUG("Assigning summary vec {} {}", i[0].get<std::string>(), i[1].get<std::string>());
                } else {
                    throw std::runtime_error("Invalid field mapping, expected field or [field,rename]");
                }
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
    using wrapper_func_t = std::function<void ()>;

    kis_net_web_function_endpoint(function_t function, wrapper_func_t pre_func = nullptr,
            wrapper_func_t post_func = nullptr) :
        kis_net_web_endpoint{},
        function{function},
        mutex{dfl_mutex},
        use_mutex{false},
        pre_func{pre_func},
        post_func{post_func} { }

    kis_net_web_function_endpoint(function_t function,
            kis_mutex& mutex,
            wrapper_func_t pre_func = nullptr,
            wrapper_func_t post_func = nullptr) :
        kis_net_web_endpoint{},
        function{function},
        mutex{mutex},
        use_mutex{true},
        pre_func{pre_func},
        post_func{post_func} { }

    virtual ~kis_net_web_function_endpoint() { }

    virtual void handle_request(std::shared_ptr<kis_net_beast_httpd_connection> con) override;

protected:
    function_t function;

    kis_mutex& mutex;
    kis_mutex dfl_mutex;
    bool use_mutex;

    wrapper_func_t pre_func, post_func;
};

class kis_net_web_tracked_endpoint : public kis_net_web_endpoint {
public:
    using gen_func_t =
        std::function<std::shared_ptr<tracker_element> (std::shared_ptr<kis_net_beast_httpd_connection>)>;
    using wrapper_func_t = std::function<void (std::shared_ptr<tracker_element>)>;

    kis_net_web_tracked_endpoint(std::shared_ptr<tracker_element> content,
            kis_mutex& mutex,
            wrapper_func_t pre_func = nullptr,
            wrapper_func_t post_func = nullptr) :
        content{content},
        mutex{mutex},
        use_mutex{true},
        pre_func{pre_func},
        post_func{post_func} { }

    kis_net_web_tracked_endpoint(std::shared_ptr<tracker_element> content) :
        content{content},
        mutex{dfl_mutex} { }

    kis_net_web_tracked_endpoint(gen_func_t generator,
            wrapper_func_t pre_func = nullptr,
            wrapper_func_t post_func = nullptr) :
        mutex{dfl_mutex},
        use_mutex{true},
        generator{generator},
        pre_func{pre_func},
        post_func{post_func} { }

    kis_net_web_tracked_endpoint(gen_func_t generator, kis_mutex& mutex) :
        mutex{mutex},
        use_mutex{true},
        generator{generator} { }

    virtual void handle_request(std::shared_ptr<kis_net_beast_httpd_connection> con) override;

protected:
    std::shared_ptr<tracker_element> content;

    kis_mutex& mutex;
    kis_mutex dfl_mutex;
    bool use_mutex;

    gen_func_t generator;
    wrapper_func_t pre_func;
    wrapper_func_t post_func;
};

class kis_net_web_websocket_endpoint : public kis_net_web_endpoint,
    public std::enable_shared_from_this<kis_net_web_websocket_endpoint> {

        typedef struct {
            std::string data;
            bool text;
        } ws_data;

public:
    using handler_func_t = std::function<void (std::shared_ptr<kis_net_web_websocket_endpoint> ws,
            std::shared_ptr<boost::asio::streambuf> buf, bool text)>;

    kis_net_web_websocket_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con, handler_func_t handler_func) :
        kis_net_web_endpoint{},
        ws_{con->release_stream()},
		strand_{Globalreg::globalreg->io},
        handler_cb{handler_func} { }

    virtual ~kis_net_web_websocket_endpoint() { }

    virtual void handle_request(std::shared_ptr<kis_net_beast_httpd_connection> con) override;

    void write(std::string data) {
        boost::asio::post(strand_,
                boost::beast::bind_front_handler(&kis_net_web_websocket_endpoint::on_write,
                    shared_from_this(), data));
    }

    void write(const char *data, size_t len) {
        boost::asio::post(strand_,
                boost::beast::bind_front_handler(&kis_net_web_websocket_endpoint::on_write,
                    shared_from_this(), std::string(data, len)));
    }

    virtual void close();

	virtual void binary() {
		ws_.binary(true);
	}

	virtual void text() {
		ws_.text(true);
	}

	boost::asio::io_context::strand &strand() { return strand_; };

protected:
    virtual void close_impl();

    virtual void start_read(std::shared_ptr<kis_net_web_websocket_endpoint> ref);
    void handle_read(boost::beast::error_code ec, std::size_t);

    void on_write(const std::string& msg);
    void handle_write();

    boost::beast::websocket::stream<boost::beast::tcp_stream> ws_;

    // boost::beast::flat_buffer buffer_;
    std::shared_ptr<boost::asio::streambuf> buffer_;
	boost::asio::io_context::strand strand_;

	std::queue<std::string, std::deque<std::string>> ws_write_queue_;

    std::promise<void> handle_pr;

    handler_func_t handler_cb;

    std::atomic<bool> running;
    std::promise<void> running_promise;

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
            bool login, const std::list<std::string>& roles,
            std::shared_ptr<kis_net_web_endpoint> handler);
    kis_net_beast_route(const std::string& route, const std::list<boost::beast::http::verb>& verbs,
            bool login, const std::list<std::string>& roles,
            const std::list<std::string>& extensions,
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

    std::list<std::string> roles_;

    const std::string path_id_pattern = ":([^\\/]+)?";
    const std::string path_capture_pattern = "(?:([^\\/]+?))";
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
    kis_net_beast_auth(const nlohmann::json& json);
    kis_net_beast_auth(const std::string& token, const std::string& name,
            const std::string& role, time_t expires);
    kis_net_beast_auth(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& jwt);

    bool check_auth(const boost::beast::string_view& token) const;

    const std::string& token() { return token_; }
    const std::string& name() { return name_; }
    const std::string& role() { return role_; }

    const time_t& expires() { return time_expires_; }
    const time_t& accessed() { return time_accessed_; }
    const time_t& created() { return time_created_; }

    bool is_valid() const { return time_expires_ == 0 || time_expires_ < time(0); }
    void access() { time_accessed_ = time(0); }
    void set_expiration(time_t e) { time_expires_ = e; }
    void set_role(const std::string& r) { role_ = r; }

    nlohmann::json as_json();

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
