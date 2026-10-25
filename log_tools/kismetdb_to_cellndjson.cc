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

/* kismetdb_to_cellndjson — extract decoded cell observations from a kismetdb
 * (.kismet) drive into an NDJSON sidecar.
 *
 * The cellat/celldiag datasources emit one decoded observation per AT/DIAG poll
 * as a JSON blob via cf_send_json(); the Kismet server logs each into the
 * kismetdb `data` table (type "Cellular" once phy_cell accepts it, else
 * "CellModem" — see cell_types_where() in main), host-timestamped
 * (ts_sec/ts_usec) and geotagged (lat/lon) by the server. This tool reads those
 * rows back out — one NDJSON record per observation — so a drive's decoded
 * observations can be processed without leaving Kismet's own log format.
 *
 * It covers the decoded layer, plus the RawAT and ClockAnchor rows.  The raw
 * DIAG stream is logged to the kismetdb `packets` table and is out of scope
 * here (see kismetdb_to_hdlc).
 *
 * Sibling of kismetdb_dump_devices (JSON emit) and kismetdb_to_wiglecsv (cell
 * decode). Deliberately does NOT VACUUM/clean the input: a captured .kismet is an
 * artifact of record and must never be mutated, so the db is opened READONLY.
 *
 * Each output line is one JSON object (keys sorted by nlohmann default):
 *   {"ts_utc":"2026-04-08T17:01:10.123456Z","ts_epoch":1775092069.123456,
 *    "type":"Cellular","source_uuid":"…","source_name":"cellat-…",
 *    "lat":…,"lon":…,"alt":…,"speed":…,"heading":…,
 *    "obs":{…the decoded observation JSON, verbatim…}}
 * A row whose blob will not parse still emits a record: "obs":null plus "err".
 */

#include "config.h"

#include <map>
#include <iomanip>
#include <ctime>
#include <iostream>
#include <sstream>

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sqlite3.h>

#include "getopt.h"

#include "fmt.h"
#include "nlohmann/json.hpp"
#include "sqlite3_cpp11.h"

void print_help(char *argv) {
    printf("Kismetdb to cell NDJSON\n");
    printf("Extract decoded cell observations (the `data` table's Cellular/CellModem\n"
           "rows) plus raw AT exchanges (type=\"RawAT\") and host<->modem\n"
           "clock anchors (type=\"ClockAnchor\") from a KismetDB log into an\n"
           "NDJSON sidecar, one host-timestamped record per line.\n"
           "Each line carries its `type`, so a consumer filters RawAT/ClockAnchor\n"
           "vs. the decoded Cellular/CellModem observations.\n");
    printf("usage: %s [OPTION]\n", argv);
    printf(" -i, --in [filename]          Input kismetdb file\n"
           " -o, --out [filename]         Output NDJSON file ('-' for stdout)\n"
           " -f, --force                  Force writing to the target file, even if it exists.\n"
           " -v, --verbose                Verbose output\n");
}

/* Format a host UTC timestamp from a data row's ts_sec / ts_usec. */
static std::string format_ts_utc(uint64_t ts_sec, uint64_t ts_usec) {
    time_t t = (time_t) ts_sec;
    struct tm tm_buf;
    gmtime_r(&t, &tm_buf);

    char base[32];
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm_buf);

    char out[48];
    snprintf(out, sizeof(out), "%s.%06" PRIu64 "Z", base, ts_usec);
    return std::string(out);
}

int main(int argc, char *argv[]) {
    static struct option longopt[] = {
        { "in", required_argument, 0, 'i' },
        { "out", required_argument, 0, 'o' },
        { "verbose", no_argument, 0, 'v' },
        { "force", no_argument, 0, 'f' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0 }
    };

    int option_idx = 0;
    optind = 0;
    opterr = 0;

    std::string in_fname, out_fname;
    bool verbose = false;
    bool force = false;

    int sql_r = 0;
    sqlite3 *db = NULL;

    FILE *ofile = NULL;

    struct stat statbuf;

    while (1) {
        int r = getopt_long(argc, argv,
                            "-hi:o:vf",
                            longopt, &option_idx);
        if (r < 0) break;

        if (r == 'h') {
            print_help(argv[0]);
            exit(1);
        } else if (r == 'i') {
            in_fname = std::string(optarg);
        } else if (r == 'o') {
            out_fname = std::string(optarg);
        } else if (r == 'v') {
            verbose = true;
        } else if (r == 'f') {
            force = true;
        }
    }

    if (out_fname == "" || in_fname == "") {
        fprintf(stderr, "ERROR: Expected --in [kismetdb file] and "
                "--out [NDJSON file]\n");
        exit(1);
    }

    if (stat(in_fname.c_str(), &statbuf) < 0) {
        if (errno == ENOENT)
            fprintf(stderr, "ERROR:  Input file '%s' does not exist.\n", in_fname.c_str());
        else
            fprintf(stderr, "ERROR:  Unexpected problem checking input "
                    "file '%s': %s\n", in_fname.c_str(), strerror(errno));
        exit(1);
    }

    if (out_fname != "-") {
        if (stat(out_fname.c_str(), &statbuf) < 0) {
            if (errno != ENOENT) {
                fprintf(stderr, "ERROR:  Unexpected problem checking output "
                        "file '%s': %s\n", out_fname.c_str(), strerror(errno));
                exit(1);
            }
        } else if (force == false) {
            fprintf(stderr, "ERROR:  Output file '%s' exists already; use --force to "
                    "clobber the file.\n", out_fname.c_str());
            exit(1);
        }
    }

    /* A captured .kismet is an artifact of record: open READONLY and never
     * VACUUM/mutate it (unlike the device/wigle exporters, which clean first). */
    sql_r = sqlite3_open_v2(in_fname.c_str(), &db, SQLITE_OPEN_READONLY, nullptr);
    if (sql_r) {
        fprintf(stderr, "ERROR:  Unable to open '%s': %s\n",
                in_fname.c_str(), sqlite3_errmsg(db));
        exit(1);
    }

    using namespace kissqlite3;

    int db_version = 0;
    unsigned long n_data_db = 0L;

    /* The `data` row types this tool exports. They are the types the SERVER
     * writes, not the ones the sources send:
     *   Cellular    - a cell observation phy_cell ACCEPTED: the server logs it via
     *                 the packet metablob phy_cell sets (phy_cell.cc
     *                 set_data("Cellular", ...)), and kis_databaselogfile.cc logs a
     *                 metablob in preference to the source's own JSON type. This is
     *                 where nearly every decoded cell lands.
     *   CellModem   - a cell observation phy_cell REJECTED (no metablob), under the
     *                 type cellat/celldiag sent.
     *   Cell        - the PHY's name before it became "Cellular"; kept so a
     *                 kismetdb logged before the rename still reads.
     *   RawAT       - raw AT exchanges; no PHY handler, so it keeps its type.
     *   ClockAnchor - host<->modem clock anchors; likewise.
     * Used by BOTH the count and the export query, so the two cannot disagree. */
    auto cell_types_where = []() {
        return _WHERE("type", EQ, "Cellular", OR, "type", EQ, "CellModem",
                      OR, "type", EQ, "Cell", OR, "type", EQ, "RawAT",
                      OR, "type", EQ, "ClockAnchor");
    };

    try {
        auto version_query = _SELECT(db, "KISMET", {"db_version"});
        auto version_ret = version_query.begin();
        if (version_ret == version_query.end()) {
            fprintf(stderr, "ERROR:  '%s' is not a kismetdb (no KISMET table).\n",
                    in_fname.c_str());
            sqlite3_close(db);
            exit(1);
        }
        db_version = sqlite3_column_as<int>(*version_ret, 0);

        auto ndata_q = _SELECT(db, "data", {"count(*)"}, cell_types_where());
        auto ndata_ret = ndata_q.begin();
        if (ndata_ret != ndata_q.end())
            n_data_db = sqlite3_column_as<unsigned long>(*ndata_ret, 0);

        if (verbose)
            fprintf(stderr, "* KismetDB version %d, %lu Cellular/CellModem/RawAT/ClockAnchor data rows\n",
                    db_version, n_data_db);
    } catch (const std::exception& e) {
        fprintf(stderr, "ERROR:  Could not read database information from '%s': %s\n",
                in_fname.c_str(), e.what());
        sqlite3_close(db);
        exit(1);
    }

    /* uuid -> source name map, so each record carries a human-readable source. */
    std::map<std::string, std::string> source_names;
    try {
        auto src_q = _SELECT(db, "datasources", {"uuid", "name"});
        for (auto s : src_q) {
            auto uuid = sqlite3_column_as<std::string>(s, 0);
            auto name = sqlite3_column_as<std::string>(s, 1);
            source_names[uuid] = name;
        }
    } catch (const std::exception& e) {
        /* Non-fatal: names are a convenience, the uuid is always emitted. */
        if (verbose)
            fprintf(stderr, "* Warning: could not read datasources: %s\n", e.what());
    }

    if (out_fname == "-") {
        ofile = stdout;
    } else {
        ofile = fopen(out_fname.c_str(), "w");
        if (ofile == NULL) {
            fprintf(stderr, "ERROR:  Unable to open output file for writing: %s\n",
                    strerror(errno));
            sqlite3_close(db);
            exit(1);
        }
    }

    unsigned long n_rows = 0;
    unsigned long n_bad = 0;

    try {
        auto query = _SELECT(db, "data",
                {"ts_sec", "ts_usec", "lat", "lon", "alt", "speed", "heading",
                 "datasource", "type", "json"},
                cell_types_where());

        for (auto row : query) {
            auto ts_sec = sqlite3_column_as<uint64_t>(row, 0);
            auto ts_usec = sqlite3_column_as<uint64_t>(row, 1);
            auto lat = sqlite3_column_as<double>(row, 2);
            auto lon = sqlite3_column_as<double>(row, 3);
            auto alt = sqlite3_column_as<double>(row, 4);
            auto speed = sqlite3_column_as<double>(row, 5);
            auto heading = sqlite3_column_as<double>(row, 6);
            auto uuid = sqlite3_column_as<std::string>(row, 7);
            auto type = sqlite3_column_as<std::string>(row, 8);
            auto blob = sqlite3_column_as<std::string>(row, 9);

            nlohmann::json rec;
            rec["ts_utc"] = format_ts_utc(ts_sec, ts_usec);
            rec["ts_epoch"] = (double) ts_sec + ((double) ts_usec / 1000000.0);
            rec["type"] = type;
            rec["source_uuid"] = uuid;

            auto ni = source_names.find(uuid);
            if (ni != source_names.end())
                rec["source_name"] = ni->second;
            else
                rec["source_name"] = nullptr;

            rec["lat"] = lat;
            rec["lon"] = lon;
            rec["alt"] = alt;
            rec["speed"] = speed;
            rec["heading"] = heading;

            try {
                rec["obs"] = nlohmann::json::parse(blob);
            } catch (const std::exception& e) {
                rec["obs"] = nullptr;
                rec["err"] = std::string(e.what());
                n_bad++;
            }

            fmt::print(ofile, "{}\n", rec.dump());
            n_rows++;

            if (verbose && n_data_db > 0 && n_rows % 5000 == 0)
                fprintf(stderr, "* %lu / %lu rows\n", n_rows, n_data_db);
        }
    } catch (const std::exception& e) {
        fprintf(stderr, "ERROR:  Failed reading `data` rows from '%s': %s\n",
                in_fname.c_str(), e.what());
        if (ofile != stdout)
            fclose(ofile);
        sqlite3_close(db);
        exit(1);
    }

    if (ofile != stdout)
        fclose(ofile);
    sqlite3_close(db);

    if (verbose) {
        fprintf(stderr, "* Wrote %lu NDJSON record(s)", n_rows);
        if (n_bad)
            fprintf(stderr, " (%lu with unparseable obs)", n_bad);
        fprintf(stderr, "\n* Done!\n");
    }

    return 0;
}
