/* Tests for saving the web login: a username or password must read back from the config
 * file unchanged, and can never add another line to it.
 *
 *   make test/httpd_login_conf/login_conf_test && test/httpd_login_conf/login_conf_test
 */

#include "config.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <dirent.h>
#include <unistd.h>

#include "configfile.h"
#include "entrytracker.h"
#include "eventbus.h"
#include "globalregistry.h"
#include "kis_net_beast_httpd.h"
#include "messagebus.h"
#include "timetracker.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

static std::string tmpdir;

static std::string path_of(const std::string& name) {
    return tmpdir + "/" + name;
}

static bool exists(const std::string& path) {
    return access(path.c_str(), F_OK) == 0;
}

static void write_file(const std::string& path, const std::string& text) {
    std::ofstream f(path);
    f << text;
}

// Save a login and read it back as the server does at startup
static bool round_trip(const std::string& user, const std::string& pass, const std::string& name) {
    auto path = path_of(name);

    config_file out;
    out.set_opt("httpd_username", user, true);
    out.set_opt("httpd_password", pass, true);
    if (out.save_config(path) < 0)
        return false;

    config_file in;
    in.set_plain(true);
    in.parse_config(path);

    return in.fetch_opt("httpd_username") == user && in.fetch_opt("httpd_password") == pass;
}

// Passwords with the characters the parser treats specially still read back unchanged
static void test_round_trip() {
    CHECK(round_trip("kismet", "simple", "rt1.conf"));
    CHECK(round_trip("kismet", "a=b=c", "rt2.conf"));
    CHECK(round_trip("kismet", "#notacomment", "rt3.conf"));
    CHECK(round_trip("kismet", "ends+", "rt4.conf"));
    CHECK(round_trip("kismet", "in side spaces", "rt5.conf"));
    CHECK(round_trip("k\xc3\xa9smet", "p\xc3\xa4ss\xe2\x9c\x93", "rt6.conf"));
    CHECK(round_trip(std::string(256, 'u'), std::string(256, 'p'), "rt7.conf"));
}

// A value that would not read back the same is never written, and the file isn't created
static void test_unsafe_not_saved() {
    const char *bad[] = {
        "pw\ninclude=/etc/passwd",
        "pw\rhttpd_username=other",
        " leading",
        "trailing ",
        "tab\t",
    };

    int n = 0;
    for (const auto b : bad) {
        auto name = "bad" + std::to_string(n++) + ".conf";
        CHECK(!round_trip("kismet", b, name));
        CHECK(!exists(path_of(name)));
    }

    // NUL inside the value
    CHECK(!round_trip("kismet", std::string("before\0after", 12), "badnul.conf"));
    CHECK(!exists(path_of("badnul.conf")));

    // Longer than the parser reads, which would drop the line and lose the login
    CHECK(!round_trip("kismet", std::string(9000, 'x'), "badlong.conf"));
    CHECK(!exists(path_of("badlong.conf")));
}

// The longest line that still reads back is allowed, one more byte is not
static void test_line_limit() {
    const std::string key = "httpd_password";
    const auto fit = config_file::max_line_len - key.length() - 3;
    CHECK(config_file::line_safe(key, std::string(fit, 'x')));
    CHECK(!config_file::line_safe(key, std::string(fit + 1, 'x')));
    CHECK(round_trip("kismet", std::string(fit, 'x'), "maxline.conf"));
}

static void test_key_rules() {
    CHECK(!config_file::line_safe("", "v"));
    CHECK(!config_file::line_safe("a=b", "v"));
    CHECK(!config_file::line_safe("#a", "v"));
    CHECK(!config_file::line_safe("a+", "v"));
    CHECK(!config_file::line_safe("a", ""));
    CHECK(config_file::line_safe("a", "v"));
}

// A plain file ignores include and override lines; a normal one still follows them
static void test_plain_ignores_includes() {
    write_file(path_of("inc.conf"), "httpd_password=from_include\n");
    write_file(path_of("main.conf"),
            "httpd_username=kismet\ninclude=" + path_of("inc.conf") + "\n");

    config_file plain;
    plain.set_plain(true);
    plain.parse_config(path_of("main.conf"));
    CHECK(plain.fetch_opt("httpd_username") == "kismet");
    CHECK(plain.fetch_opt("httpd_password").empty());

    config_file normal;
    normal.parse_config(path_of("main.conf"));
    CHECK(normal.fetch_opt("httpd_password") == "from_include");

    write_file(path_of("main2.conf"),
            "httpd_username=kismet\nopt_include=" + path_of("inc.conf") + "\n"
            "opt_override=" + path_of("inc.conf") + "\nopt_override_dir=" + tmpdir + "\n");
    config_file plain2;
    plain2.set_plain(true);
    plain2.parse_config(path_of("main2.conf"));
    CHECK(plain2.fetch_opt("httpd_password").empty());
}

static void test_login_problem() {
    CHECK(kis_net_beast_httpd::admin_login_problem("kismet").empty());
    CHECK(kis_net_beast_httpd::admin_login_problem("a=b#c+ d").empty());
    CHECK(kis_net_beast_httpd::admin_login_problem("p\xc3\xa4ss").empty());
    CHECK(kis_net_beast_httpd::admin_login_problem(std::string(256, 'x')).empty());

    CHECK(!kis_net_beast_httpd::admin_login_problem("").empty());
    CHECK(!kis_net_beast_httpd::admin_login_problem(std::string(257, 'x')).empty());
    CHECK(!kis_net_beast_httpd::admin_login_problem("a\nb").empty());
    CHECK(!kis_net_beast_httpd::admin_login_problem("a\rb").empty());
    CHECK(!kis_net_beast_httpd::admin_login_problem(std::string("a\0b", 3)).empty());
    CHECK(!kis_net_beast_httpd::admin_login_problem("a\tb").empty());
    CHECK(!kis_net_beast_httpd::admin_login_problem("a\x7f" "b").empty());
    CHECK(!kis_net_beast_httpd::admin_login_problem(" a").empty());
    CHECK(!kis_net_beast_httpd::admin_login_problem("a ").empty());

    // Everything it accepts can be saved and read back
    for (const auto& v : {std::string("kismet"), std::string("a=b#c+ d"), std::string(256, 'x')})
        CHECK(config_file::line_safe("httpd_password", v));
}

int main() {
    Globalreg::globalreg = new global_registry;

    // Config errors are reported through the message bus
    auto entrytracker = entry_tracker::create_entrytracker();
    auto timetracker = time_tracker::create_timetracker();
    auto eventbus = event_bus::create_eventbus();
    Globalreg::globalreg->messagebus = message_bus::create_messagebus();

    char tmpl[] = "/tmp/kis_login_conf_XXXXXX";
    if (mkdtemp(tmpl) == nullptr) {
        perror("mkdtemp");
        return 1;
    }
    tmpdir = tmpl;

    test_round_trip();
    test_unsafe_not_saved();
    test_line_limit();
    test_key_rules();
    test_plain_ignores_includes();
    test_login_problem();

    if (failures) {
        fprintf(stderr, "%d check(s) failed; files left in %s\n", failures, tmpdir.c_str());
        return 1;
    }

    // Only the files this test made are in its own directory
    if (auto d = opendir(tmpdir.c_str())) {
        while (auto e = readdir(d)) {
            std::string n = e->d_name;
            if (n != "." && n != "..")
                unlink(path_of(n).c_str());
        }
        closedir(d);
    }
    rmdir(tmpdir.c_str());

    printf("httpd login config tests passed\n");
    return 0;
}
