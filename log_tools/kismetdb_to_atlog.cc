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

/* kismetdb_to_atlog — write the raw AT exchanges a cellat source logged into a
 * kismetdb `data` table as type="RawAT", one JSON record per line.
 *
 * Sibling of kismetdb_to_cellndjson. That reader wraps each row in a
 * host-timestamped, geotagged NDJSON *envelope* ({ts_utc, lat, lon, …,
 * obs:<record>}); this tool emits the *bare* record, as the cellat capture
 * formatted it (atlog_format_record).
 *
 * The stored `data.json` blob already is the record line, trailing '\n'
 * included, so this tool emits it verbatim and never re-serializes (no %.2f
 * rounding drift, no key-order or escaping divergence).
 *
 * Ordering: the record's own ts_mono_ns (host CLOCK_MONOTONIC, captured just
 * before each exchange) is the authoritative capture order. kismetdb rowid does
 * NOT preserve it — the server drains a ringbuffer of JSON packets from several
 * independent cellat capture processes, so inserts interleave and reorder even
 * WITHIN a single source. This tool therefore sorts by ts_mono_ns. Because every
 * capture process shares the one host monotonic clock, ts_mono_ns is a global
 * total order, so the merged (all-sources) output is a valid unified timeline
 * too.
 *
 * Use --source <uuid> for one modem's exchanges. --source also accepts a
 * datasource *name*, but names are not unique (a drive can run two of the same
 * model), so a name may merge several sources; a uuid never does.
 *
 * Deliberately opens the db READONLY and never VACUUMs/mutates it: a captured
 * .kismet is an artifact of record. A blob that will not parse is skipped,
 * counted and reported, never fatal: written verbatim it could inject lines
 * into the transcript. A parsed record spread over several lines is written
 * re-serialized onto one.
 */

#include "config.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>
#include <iostream>

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

#define RAWLOG_TYPE "RawAT"
#define RAWLOG_NAME "atlog"

void print_help(char *argv) {
    printf("Kismetdb to raw AT JSONL\n");
    printf("Write the raw AT command exchanges from a KismetDB log's\n"
           "type=\"RawAT\" `data` rows, one JSON record per line, sorted by\n"
           "the record's ts_mono_ns (capture order).\n"
           "\n"
           "Pass --source <uuid> for one modem's exchanges.\n");
    printf("usage: %s [OPTION]\n", argv);
    printf(" -i, --in [filename]          Input kismetdb file\n"
           " -o, --out [filename]         Output JSONL file ('-' for stdout)\n"
           " -s, --source [uuid|name]     Only this datasource (uuid is unambiguous;\n"
           "                              a name may match several sources)\n"
           " -f, --force                  Force writing to the target file, even if it exists.\n"
           " -v, --verbose                Verbose output\n");
}

int main(int argc, char *argv[]) {
    static struct option longopt[] = {
        { "in", required_argument, 0, 'i' },
        { "out", required_argument, 0, 'o' },
        { "source", required_argument, 0, 's' },
        { "verbose", no_argument, 0, 'v' },
        { "force", no_argument, 0, 'f' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0 }
    };

    int option_idx = 0;
    optind = 0;
    opterr = 0;

    std::string in_fname, out_fname, source_filter;
    bool verbose = false;
    bool force = false;

    int sql_r = 0;
    sqlite3 *db = NULL;

    FILE *ofile = NULL;

    struct stat statbuf;

    while (1) {
        int r = getopt_long(argc, argv,
                            "-hi:o:s:vf",
                            longopt, &option_idx);
        if (r < 0) break;

        if (r == 'h') {
            print_help(argv[0]);
            exit(1);
        } else if (r == 'i') {
            in_fname = std::string(optarg);
        } else if (r == 'o') {
            out_fname = std::string(optarg);
        } else if (r == 's') {
            source_filter = std::string(optarg);
        } else if (r == 'v') {
            verbose = true;
        } else if (r == 'f') {
            force = true;
        }
    }

    if (out_fname == "" || in_fname == "") {
        fprintf(stderr, "ERROR: Expected --in [kismetdb file] and "
                "--out [JSONL file]\n");
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
    } catch (const std::exception& e) {
        fprintf(stderr, "ERROR:  Could not read database information from '%s': %s\n",
                in_fname.c_str(), e.what());
        sqlite3_close(db);
        exit(1);
    }

    /* uuid -> source name map. Used to resolve a --source name filter to uuids,
     * and (reverse) to let a uuid filter also match rows by name. */
    std::map<std::string, std::string> source_names;
    try {
        auto src_q = _SELECT(db, "datasources", {"uuid", "name"});
        for (auto s : src_q) {
            auto uuid = sqlite3_column_as<std::string>(s, 0);
            auto name = sqlite3_column_as<std::string>(s, 1);
            source_names[uuid] = name;
        }
    } catch (const std::exception& e) {
        /* Non-fatal: names are a convenience; a uuid filter still works. */
        if (verbose)
            fprintf(stderr, "* Warning: could not read datasources: %s\n", e.what());
    }

    /* A row is kept when no filter is set, or when the filter equals the row's
     * datasource uuid, or the name that uuid maps to. */
    auto source_matches = [&](const std::string& uuid) -> bool {
        if (source_filter.empty())
            return true;
        if (uuid == source_filter)
            return true;
        auto ni = source_names.find(uuid);
        return ni != source_names.end() && ni->second == source_filter;
    };

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

    /* One reconstructed record. `line` is the stored blob verbatim when it is
     * one line (it already carries the emitter's trailing '\n'). `mono_ok`
     * false means no usable ts_mono_ns: kept, sorted to the end, and counted. */
    struct rec_t {
        uint64_t mono;
        bool mono_ok;
        std::string line;
    };
    std::vector<rec_t> recs;

    unsigned long n_bad = 0;
    unsigned long n_unordered = 0;

    try {
        auto query = _SELECT(db, "data", {"datasource", "json"},
                _WHERE("type", EQ, RAWLOG_TYPE));

        for (auto row : query) {
            auto uuid = sqlite3_column_as<std::string>(row, 0);
            if (!source_matches(uuid))
                continue;

            auto blob = sqlite3_column_as<std::string>(row, 1);

            auto j = nlohmann::json::parse(blob, nullptr, false);
            if (j.is_discarded() || !j.is_object()) {
                n_bad++;
                continue;
            }

            rec_t rec;
            rec.mono = 0;
            rec.mono_ok = false;

            auto it = j.find("ts_mono_ns");
            if (it != j.end() && it->is_number_unsigned()) {
                rec.mono = it->get<uint64_t>();
                rec.mono_ok = true;
            } else {
                n_unordered++;
            }

            if (!blob.empty() && blob.back() == '\n')
                blob.pop_back();

            if (blob.find_first_of("\r\n") == std::string::npos)
                rec.line = std::move(blob);
            else
                rec.line = j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
            rec.line += '\n';

            recs.push_back(std::move(rec));
        }
    } catch (const std::exception& e) {
        fprintf(stderr, "ERROR:  Failed reading `data` rows from '%s': %s\n",
                in_fname.c_str(), e.what());
        if (ofile != stdout)
            fclose(ofile);
        sqlite3_close(db);
        exit(1);
    }

    /* Stable sort by ts_mono_ns; records without one sort to the end in their
     * original db order. */
    std::stable_sort(recs.begin(), recs.end(),
            [](const rec_t& a, const rec_t& b) {
                if (a.mono_ok != b.mono_ok)
                    return a.mono_ok;               /* good (true) before bad */
                if (!a.mono_ok)
                    return false;                   /* both bad: keep db order */
                return a.mono < b.mono;
            });

    unsigned long n_rows = 0;
    for (const auto& rec : recs) {
        fwrite(rec.line.data(), 1, rec.line.size(), ofile);
        n_rows++;
    }

    if (ofile != stdout)
        fclose(ofile);
    sqlite3_close(db);

    if (n_bad)
        fprintf(stderr, "WARNING: %lu " RAWLOG_TYPE " row(s) are not JSON records "
                "and were skipped.\n", n_bad);

    if (verbose) {
        fprintf(stderr, "* KismetDB version %d\n", db_version);
        if (!source_filter.empty())
            fprintf(stderr, "* Source filter: '%s'\n", source_filter.c_str());
        fprintf(stderr, "* Wrote %lu " RAWLOG_NAME " record(s)", n_rows);
        if (n_unordered)
            fprintf(stderr, " (%lu without ts_mono_ns, sorted last)", n_unordered);
        fprintf(stderr, "\n* Done!\n");
    }

    return 0;
}
