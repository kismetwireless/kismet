/* Tests for kis_datasource_interface::populate(): a probed interface keeps the
 * flags its lister reported, which list_interfaces then returns as options_vec.
 *
 *   make test/datasource_probed/probed_test && test/datasource_probed/probed_test
 */

#include "config.h"

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "entrytracker.h"
#include "globalregistry.h"
#include "kis_datasource.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

static std::vector<std::string> options_of(const std::shared_ptr<kis_datasource_interface>& intf) {
    std::vector<std::string> r;
    for (const auto& e : *intf->get_options_vec())
        r.push_back(get_tracker_value<std::string>(e));
    return r;
}

// The lister's flags, as both list reports pass them: one comma-joined string
static void test_flags_string() {
    auto intf = std::make_shared<kis_datasource_interface>();
    intf->populate("wlan0", std::string("foo,bar"));
    CHECK(intf->get_interface() == "wlan0");
    CHECK((options_of(intf) == std::vector<std::string>{"foo", "bar"}));
}

// No flags (what every stock lister sends) is no options, not one empty option
static void test_no_flags() {
    auto intf = std::make_shared<kis_datasource_interface>();
    intf->populate("wlan0", std::string(""));
    CHECK(options_of(intf).empty());
}

// An empty token (a doubled or trailing comma) is not an option
static void test_empty_tokens() {
    auto intf = std::make_shared<kis_datasource_interface>();
    intf->populate("wlan0", std::vector<std::string>{"a", "", "b"});
    CHECK((options_of(intf) == std::vector<std::string>{"a", "b"}));
}

int main() {
    Globalreg::globalreg = new global_registry;
    auto entrytracker = entry_tracker::create_entrytracker();

    test_flags_string();
    test_no_flags();
    test_empty_tokens();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }

    printf("datasource probed interface tests passed\n");
    return 0;
}
