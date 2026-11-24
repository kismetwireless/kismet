/* Tests for kismetdb_row_gps (capture_kismetdb_gps.h): only 0,0 is "no GPS"
 * (GPS_BOUNDS_NO_POSITION), so the equator and the prime meridian keep their fix;
 * non-finite or out-of-range positions are sent as fix 0 at 0,0, and a bad altitude or
 * heading alone is dropped from an otherwise good fix; kismetdb_column_coord reads a
 * NULL (stored NaN) or non-numeric coordinate as NaN rather than 0.
 *
 *   unit.sh <tree> test/kismetdb_helper/gps_test.c --libs -lsqlite3
 */

#include "config.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#include "capture_kismetdb_gps.h"

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

static struct cf_params_gps row(double lat, double lon, double alt, double heading) {
    struct cf_params_gps g;

    memset(&g, 0xA5, sizeof(g));
    g.gps_type = NULL;
    g.gps_name = NULL;
    g.gps_uuid = NULL;
    kismetdb_row_gps(&g, lat, lon, alt, heading);
    return g;
}

static int no_fix(struct cf_params_gps g) {
    return g.fix == 0 && g.lat == 0 && g.lon == 0 && g.alt == 0 && g.heading == 0;
}

static void test_no_gps(void) {
    CHECK(no_fix(row(0, 0, 0, 0)));
    CHECK(no_fix(row(0, 0, 12.5, 90)));
    CHECK(no_fix(row(-0.0, 0, 0, 0)));
    CHECK(no_fix(row(0, -0.0, 12.5, 0)));
}

static void test_axes(void) {
    struct cf_params_gps g;

    /* Equator, open ocean */
    g = row(0, -140.25, 0, 0);
    CHECK(g.fix == 2 && g.lat == 0 && g.lon == -140.25);
    g = row(0, -140.25, 12.5, 45);
    CHECK(g.fix == 3 && g.lat == 0 && g.lon == -140.25 && g.alt == 12.5f && g.heading == 45);

    /* Prime meridian, open ocean */
    g = row(-45.5, 0, 0, 0);
    CHECK(g.fix == 2 && g.lat == -45.5 && g.lon == 0);
    g = row(-45.5, -0.0, 12.5, 0);
    CHECK(g.fix == 3 && g.lat == -45.5 && g.lon == 0 && g.alt == 12.5f);

    /* Poles and the antimeridian */
    CHECK(row(90, 0, 0, 0).fix == 2);
    CHECK(row(-90, 0, 0, 0).fix == 2);
    CHECK(row(0, 180, 0, 0).fix == 2);
    CHECK(row(0, -180, 0, 0).fix == 2);
}

static void test_bad_position(void) {
    CHECK(no_fix(row(NAN, -140.25, 12.5, 0)));
    CHECK(no_fix(row(-45.5, NAN, 12.5, 0)));
    CHECK(no_fix(row(INFINITY, -140.25, 0, 0)));
    CHECK(no_fix(row(-45.5, -INFINITY, 0, 0)));
    CHECK(no_fix(row(200, -140.25, 0, 0)));
    CHECK(no_fix(row(-90.0001, -140.25, 0, 0)));
    CHECK(no_fix(row(-45.5, -181, 0, 0)));
    CHECK(no_fix(row(-45.5, 180.0001, 0, 0)));
    /* An axis value with an unusable other half is still no fix */
    CHECK(no_fix(row(0, NAN, 0, 0)));
    CHECK(no_fix(row(NAN, 0, 0, 0)));
    CHECK(no_fix(row(0, 200, 0, 0)));
    CHECK(no_fix(row(100, 0, 0, 0)));
}

static void test_bad_alt_heading(void) {
    struct cf_params_gps g;

    g = row(-45.5, -140.25, INFINITY, 0);
    CHECK(g.fix == 2 && g.alt == 0 && g.lat == -45.5);
    g = row(-45.5, -140.25, NAN, 0);
    CHECK(g.fix == 2 && g.alt == 0);
    g = row(-45.5, -140.25, 1e300, 0);
    CHECK(g.fix == 2 && g.alt == 0);
    g = row(-45.5, -140.25, -100001, 0);
    CHECK(g.fix == 2 && g.alt == 0);
    g = row(0, -140.25, 1000001, 0);
    CHECK(g.fix == 2 && g.alt == 0 && g.lat == 0);
    g = row(-45.5, -140.25, -100000, 0);
    CHECK(g.fix == 3 && g.alt == -100000);

    g = row(-45.5, -140.25, 12.5, 1e300);
    CHECK(g.fix == 3 && g.heading == 0);
    g = row(-45.5, 0, 12.5, NAN);
    CHECK(g.fix == 3 && g.heading == 0);
    g = row(-45.5, -140.25, 12.5, -1);
    CHECK(g.heading == 0);
    g = row(-45.5, -140.25, 12.5, 360);
    CHECK(g.heading == 360);
}

/* Stored NaN comes back as NULL; NULL, text and blobs must not read as a 0 coordinate */
static void test_column_coord(void) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;

    CHECK(sqlite3_open(":memory:", &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "CREATE TABLE t (lat REAL, lon REAL); "
                "INSERT INTO t VALUES (0.0/0.0, -140.25);", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(sqlite3_prepare_v2(db, "SELECT NULL, 'abc', '0', x'00', 0, -45.5, -140, lat, lon, "
                "(lat / 100000.0) FROM t", -1, &stmt, NULL) == SQLITE_OK);

    if (stmt != NULL && sqlite3_step(stmt) == SQLITE_ROW) {
        CHECK(isnan(kismetdb_column_coord(stmt, 0)));
        CHECK(isnan(kismetdb_column_coord(stmt, 1)));
        CHECK(isnan(kismetdb_column_coord(stmt, 2)));
        CHECK(isnan(kismetdb_column_coord(stmt, 3)));
        CHECK(kismetdb_column_coord(stmt, 4) == 0);
        CHECK(kismetdb_column_coord(stmt, 5) == -45.5);
        CHECK(kismetdb_column_coord(stmt, 6) == -140);
        CHECK(isnan(kismetdb_column_coord(stmt, 7)));
        CHECK(kismetdb_column_coord(stmt, 8) == -140.25);
        CHECK(isnan(kismetdb_column_coord(stmt, 9)));

        /* A NULL lat beside a good lon is no position, not the equator */
        CHECK(no_fix(row(kismetdb_column_coord(stmt, 7), kismetdb_column_coord(stmt, 8), 0, 0)));
    } else {
        CHECK(!"select row");
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

/* Pre-v5 logs: text or a blob in lat/lon must not divide to 0.0, a position on an axis */
static void test_v4_coord_sql(void) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int i;

    CHECK(sqlite3_open(":memory:", &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "CREATE TABLE p (lat, lon); "
                "INSERT INTO p VALUES (-4550000, -14025000); "
                "INSERT INTO p VALUES (0, -14025000); "
                "INSERT INTO p VALUES (-4550000.0, 0.0); "
                "INSERT INTO p VALUES ('abc', -14025000); "
                "INSERT INTO p VALUES (-4550000, x'00'); "
                "INSERT INTO p VALUES (NULL, -14025000); "
                "INSERT INTO p VALUES ('0', '-14025000');", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(sqlite3_prepare_v2(db, "SELECT " KISMETDB_V4_COORD_SQL("lat") ", "
                KISMETDB_V4_COORD_SQL("lon") " FROM p ORDER BY rowid", -1, &stmt, NULL) == SQLITE_OK);

    for (i = 0; stmt != NULL && sqlite3_step(stmt) == SQLITE_ROW; i++) {
        const double lat = kismetdb_column_coord(stmt, 0);
        const double lon = kismetdb_column_coord(stmt, 1);
        const struct cf_params_gps g = row(lat, lon, 0, 0);

        switch (i) {
            case 0:
                CHECK(g.fix == 2 && g.lat == -45.5 && g.lon == -140.25);
                break;
            case 1:
                CHECK(g.fix == 2 && g.lat == 0 && g.lon == -140.25);
                break;
            case 2:
                CHECK(g.fix == 2 && g.lat == -45.5 && g.lon == 0);
                break;
            case 3:
            case 5:
                CHECK(isnan(lat) && no_fix(g));
                break;
            case 4:
                CHECK(isnan(lon) && no_fix(g));
                break;
            case 6:
                /* Text in an untyped column stays text */
                CHECK(isnan(lat) && isnan(lon) && no_fix(g));
                break;
        }
    }

    CHECK(i == 7);

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

static void test_no_position(void) {
    CHECK(GPS_BOUNDS_NO_POSITION(0.0, 0.0));
    CHECK(GPS_BOUNDS_NO_POSITION(-0.0, 0.0));
    CHECK(!GPS_BOUNDS_NO_POSITION(0.0, -140.25));
    CHECK(!GPS_BOUNDS_NO_POSITION(-45.5, 0.0));
    CHECK(!GPS_BOUNDS_NO_POSITION(NAN, 0.0));
}

int main(void) {
    test_no_gps();
    test_no_position();
    test_column_coord();
    test_v4_coord_sql();
    test_axes();
    test_bad_position();
    test_bad_alt_heading();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }

    printf("kismetdb gps: all tests passed\n");
    return 0;
}
