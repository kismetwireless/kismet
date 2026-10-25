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

/* kismetdb_to_atlog — reconstruct the `atlog=` JSONL transcript (the atlog
 * record schema) from the raw AT exchanges a cellat source logged into a
 * kismetdb `data` table as type="RawAT".
 *
 * Sibling of kismetdb_to_cellndjson. That reader wraps each row in a
 * host-timestamped, geotagged NDJSON *envelope* ({ts_utc, lat, lon, …,
 * obs:<record>}) — a full transcript, but NOT the atlog= sidecar. This tool
 * emits the *bare* atlog record, one per line, so a "kismet-only" drive (one
 * that logged RawAT into the db but never wrote an atlog= sidecar) reconstructs a
 * transcript in the atlog= format, holding every record an atlog= sidecar of the
 * same run would have, byte for byte and in order. That lets an in-db drive and
 * a sidecar drive be ingested the same way, instead of maintaining two ingest
 * paths.
 *
 * Per RECORD, not per FILE: the reconstruction is an ordered SUPERSET of the
 * sidecar. RawAT is live from the source's open callback, and the tee arms
 * later, so the open-time capability probe (e.g. AT+QENG="servingcell", ATE0)
 * lands in the kismetdb and not in the sidecar; a source whose open FAILS emits
 * RawAT for every probe and never arms the tee at all. Typically the kismetdb
 * holds a couple of records more per source, every shared record byte-identical
 * and in order. Diff the two as a superset, never for equality.
 *
 * Per-record byte fidelity is free by construction: the cellat capture formats
 * each record ONCE (atlog_format_record) and feeds the SAME buffer to both the
 * atlog= file tee and the in-db cf_send_json(type="RawAT"). So the stored
 * `data.json` blob already IS the sidecar line, trailing '\n' included — this
 * tool emits it verbatim and never re-serializes (no %.2f rounding drift, no
 * key-order or escaping divergence).
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
 * A single atlog= sidecar is per capture process (= per datasource uuid), so use
 * --source <uuid> to reconstruct one modem's sidecar exactly. --source also
 * accepts a datasource *name*, but names are not unique (a drive can run two of
 * the same model), so a name may merge several sources; a uuid never does.
 *
 * Deliberately opens the db READONLY and never VACUUMs/mutates it: a captured
 * .kismet is an artifact of record. A blob that will not parse is emitted
 * verbatim anyway (fidelity first) but counted and reported, never fatal —
 * the same robustness rule as kismetdb_to_cellndjson.
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

/* kismetdb_to_qmilog is THIS reader with another row type
 * (it #defines these and #includes this file), so the two raw lanes share one
 * ordering / fidelity / robustness implementation instead of drifting apart. */
#ifndef RAWLOG_TYPE
#define RAWLOG_TYPE "RawAT"
#define RAWLOG_NAME "atlog"
#endif

void print_help(char *argv) {
#ifdef RAWLOG_HELP
    printf(RAWLOG_HELP);
#else
    printf("Kismetdb to atlog= JSONL\n");
    printf("Reconstruct the raw-AT `atlog=` transcript (the atlog record schema)\n"
           "from a KismetDB log's type=\"RawAT\" `data` rows, one JSON\n"
           "record per line, sorted by the record's ts_mono_ns (capture order).\n"
           "Every record an atlog= sidecar holds is reproduced byte for byte and\n"
           "in order, so a kismet-only drive onboards like a sidecar one. The\n"
           "output is a SUPERSET of the sidecar, not identical to it: it also\n"
           "holds the open-time probe exchanges (sent before the tee arms) and\n"
           "every exchange of a source that never opened. Diff as a superset.\n"
           "\n"
           "A single atlog= sidecar is per capture process (= per datasource);\n"
           "pass --source <uuid> to reconstruct one modem's sidecar exactly.\n");
#endif
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

    /* One reconstructed record. `blob` is emitted verbatim (it already carries
     * the trailing '\n' the emitter wrote). `mono` is parsed out for ordering;
     * `mono_ok` false means the blob would not parse — kept for fidelity, sorted
     * to the end, and counted. */
    struct rec_t {
        uint64_t mono;
        bool mono_ok;
        std::string blob;
    };
    std::vector<rec_t> recs;

    unsigned long n_bad = 0;

    try {
        auto query = _SELECT(db, "data", {"datasource", "json"},
                _WHERE("type", EQ, RAWLOG_TYPE));

        for (auto row : query) {
            auto uuid = sqlite3_column_as<std::string>(row, 0);
            if (!source_matches(uuid))
                continue;

            auto blob = sqlite3_column_as<std::string>(row, 1);

            rec_t rec;
            rec.blob = blob;
            rec.mono = 0;
            rec.mono_ok = false;

            try {
                auto j = nlohmann::json::parse(blob);
                auto it = j.find("ts_mono_ns");
                if (it != j.end() && it->is_number()) {
                    rec.mono = it->get<uint64_t>();
                    rec.mono_ok = true;
                } else {
                    n_bad++;
                }
            } catch (const std::exception&) {
                n_bad++;
            }

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

    /* Stable sort by ts_mono_ns; unparseable records (mono_ok == false) sort to
     * the end in their original db order, so a corrupt blob never displaces a
     * good record's position or aborts the run. */
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
        /* Emit the stored blob verbatim: it already ends in '\n'. Guard the rare
         * case of a blob missing its newline so lines never run together. */
        fputs(rec.blob.c_str(), ofile);
        if (rec.blob.empty() || rec.blob.back() != '\n')
            fputc('\n', ofile);
        n_rows++;
    }

    if (ofile != stdout)
        fclose(ofile);
    sqlite3_close(db);

    if (verbose) {
        fprintf(stderr, "* KismetDB version %d\n", db_version);
        if (!source_filter.empty())
            fprintf(stderr, "* Source filter: '%s'\n", source_filter.c_str());
        fprintf(stderr, "* Wrote %lu " RAWLOG_NAME " record(s)", n_rows);
        if (n_bad)
            fprintf(stderr, " (%lu unparseable, emitted verbatim + sorted last)", n_bad);
        fprintf(stderr, "\n* Done!\n");
    }

    return 0;
}
