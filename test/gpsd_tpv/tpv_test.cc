/* Tests for gpsd_json::parse_tpv (gpsgpsd_tpv.h): gpsd TPV fields out of range or of
 * the wrong type are dropped, missing ones read as 0, an invalid mode drops the fix,
 * and a 3d fix without a usable altitude is reported as 2d.
 *
 *   make test/gpsd_tpv/tpv_test && test/gpsd_tpv/tpv_test
 */

#include "config.h"

#include <cstdio>
#include <string>

#include "gpsgpsd_tpv.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

static gpsd_json::tpv tpv(const std::string& s) {
    return gpsd_json::parse_tpv(nlohmann::json::parse(s));
}

static void test_good_fix() {
    auto r = tpv(R"({"class":"TPV","mode":3,"lat":-45.5,"lon":-140.25,"alt":12.5,)"
            R"("track":359.5,"magtrack":10,"speed":10,"epx":3,"epy":4,"epv":5})");
    CHECK(r.has_fix && r.fix == 3);
    CHECK(r.has_position && r.lat == -45.5 && r.lon == -140.25);
    CHECK(r.has_alt && r.alt == 12.5);
    CHECK(r.has_heading && r.heading == 359.5);
    CHECK(r.has_magheading && r.magheading == 10);
    CHECK(r.has_speed && r.speed_kph == 36);
    CHECK(r.has_error_x && r.error_x == 3 && r.has_error_y && r.error_y == 4);
    CHECK(r.has_error_v && r.error_v == 5);

    // Bounds themselves are accepted
    r = tpv(R"({"mode":3,"lat":90,"lon":-180,"alt":-100000,"track":0,"speed":0})");
    CHECK(r.has_position && r.lat == 90 && r.lon == -180);
    CHECK(r.has_alt && r.alt == -100000);
    CHECK(r.has_heading && r.has_speed);
    r = tpv(R"({"mode":3,"lat":-90,"lon":180,"alt":1000000,"track":360})");
    CHECK(r.has_position && r.has_alt && r.has_heading);
}

static void test_missing() {
    // Missing fields read as 0, as before
    auto r = tpv(R"({"class":"TPV"})");
    CHECK(r.has_fix && r.fix == 0);
    CHECK(!r.has_position && !r.has_alt);

    // A 3d fix with no altitude is a 2d fix
    r = tpv(R"({"mode":3,"lat":-45.5,"lon":-140.25})");
    CHECK(r.has_fix && r.fix == 2 && !r.has_alt);
    CHECK(r.has_position);
    CHECK(!r.has_heading && !r.has_speed && !r.has_error_x);

    // A 2d fix carries no altitude
    r = tpv(R"({"mode":2,"lat":-45.5,"lon":-140.25,"alt":50})");
    CHECK(r.has_position && !r.has_alt);

    // No position without a 2d fix
    r = tpv(R"({"mode":1,"lat":-45.5,"lon":-140.25,"epx":3})");
    CHECK(r.has_fix && r.fix == 1 && !r.has_position && r.has_error_x);
}

static void test_out_of_range() {
    auto r = tpv(R"({"mode":3,"lat":91,"lon":-140.25})");
    CHECK(r.has_fix && !r.has_position);
    r = tpv(R"({"mode":3,"lat":-45.5,"lon":-180.5})");
    CHECK(!r.has_position);
    r = tpv(R"({"mode":3,"lat":-45.5,"lon":-140.25,"alt":1e9})");
    CHECK(r.has_position && !r.has_alt && r.fix == 2);
    r = tpv(R"({"mode":3,"alt":-100001})");
    CHECK(!r.has_alt && r.fix == 2);
    r = tpv(R"({"mode":3,"track":360.5,"magtrack":-1})");
    CHECK(!r.has_heading && !r.has_magheading);
    r = tpv(R"({"mode":3,"speed":-1})");
    CHECK(!r.has_speed);
    r = tpv(R"({"mode":3,"speed":1e300})");
    CHECK(!r.has_speed);
    r = tpv(R"({"mode":3,"epx":-1,"epy":1e7,"epv":-0.5,"eph":0})");
    CHECK(!r.has_error_x && !r.has_error_y && !r.has_error_v && !r.has_error_h);
    r = tpv(R"({"mode":2,"eph":"8"})");
    CHECK(r.has_fix && !r.has_error_h);
    r = tpv(R"({"mode":2,"eph":8})");
    CHECK(r.has_error_h && r.error_h == 8);
}

static void test_wrong_type() {
    // These threw from json.value() before, dropping the gpsd connection
    auto r = tpv(R"({"mode":3,"lat":"-45.5","lon":-140.25,"alt":"high","track":null,)"
            R"("speed":[1],"epx":{},"epy":true})");
    CHECK(r.has_fix && r.fix == 2);
    CHECK(!r.has_position && !r.has_alt && !r.has_heading && !r.has_speed);
    CHECK(!r.has_error_x && !r.has_error_y);
}

static void test_altitude() {
    // gpsd 3.20+: altMSL first, then the deprecated alt, then altHAE less geoidSep
    auto r = tpv(R"({"mode":3,"lat":-45.5,"lon":-140.25,"altMSL":12.5,"altHAE":40})");
    CHECK(r.fix == 3 && r.has_alt && r.alt == 12.5);
    r = tpv(R"({"mode":3,"altMSL":12.5,"alt":20,"altHAE":40})");
    CHECK(r.has_alt && r.alt == 12.5);
    r = tpv(R"({"mode":3,"alt":20,"altHAE":40})");
    CHECK(r.has_alt && r.alt == 20);
    r = tpv(R"({"mode":3,"altHAE":40,"geoidSep":27.5})");
    CHECK(r.fix == 3 && r.has_alt && r.alt == 12.5);
    r = tpv(R"({"mode":3,"altHAE":40})");
    CHECK(r.has_alt && r.alt == 40);
    r = tpv(R"({"mode":3,"altHAE":40,"geoidSep":"x"})");
    CHECK(r.has_alt && r.alt == 40);

    // An unusable field falls through to the next
    r = tpv(R"({"mode":3,"altMSL":"high","alt":20})");
    CHECK(r.has_alt && r.alt == 20);
    r = tpv(R"({"mode":3,"altMSL":1e9,"altHAE":40,"geoidSep":27.5})");
    CHECK(r.has_alt && r.alt == 12.5);

    // None usable: 2d
    r = tpv(R"({"mode":3,"altMSL":null,"alt":"x","altHAE":-1e9})");
    CHECK(r.has_fix && r.fix == 2 && !r.has_alt);
    r = tpv(R"({"mode":3,"altHAE":1e300,"geoidSep":-1e300})");
    CHECK(r.fix == 2 && !r.has_alt);

    // Altitude is ignored below a 3d fix
    r = tpv(R"({"mode":2,"altMSL":12.5})");
    CHECK(r.fix == 2 && !r.has_alt);
}

static void test_mode() {
    CHECK(!tpv(R"({"mode":4,"lat":-45.5,"lon":-140.25})").has_fix);
    CHECK(!tpv(R"({"mode":-1})").has_fix);
    CHECK(!tpv(R"({"mode":2.5})").has_fix);
    CHECK(!tpv(R"({"mode":"3"})").has_fix);
    CHECK(!tpv(R"({"mode":1e300})").has_fix);

    auto r = tpv(R"({"mode":"3","lat":-45.5,"lon":-140.25,"alt":10,"eph":8})");
    CHECK(!r.has_fix && !r.has_position && !r.has_alt && !r.has_error_h);

    for (int m = 0; m <= 3; m++) {
        auto t = tpv("{\"mode\":" + std::to_string(m) + ",\"altMSL\":5}");
        CHECK(t.has_fix && t.fix == m);
    }
}

static void test_predicates() {
    CHECK(!gpsd_json::lat_valid(90.0001));
    CHECK(!gpsd_json::lon_valid(-180.0001));
    CHECK(!gpsd_json::heading_valid(-0.0001));
    CHECK(gpsd_json::speed_valid(gps_bounds::max_speed));
    CHECK(!gpsd_json::speed_valid(gps_bounds::max_speed + 1));
    CHECK(gpsd_json::error_valid(0));
}

int main() {
    test_good_fix();
    test_missing();
    test_out_of_range();
    test_wrong_type();
    test_mode();
    test_altitude();
    test_predicates();

    if (failures != 0) {
        fprintf(stderr, "tpv_test: %d failure(s)\n", failures);
        return 1;
    }

    printf("tpv_test: all passed\n");
    return 0;
}
