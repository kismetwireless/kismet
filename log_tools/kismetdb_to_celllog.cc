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

/* kismetdb_to_celllog -- the cell sources' session and debug log, read back
 * from the CellLog `data` rows (capture_cell_diag/cell_log.h), merged with the
 * RawAT exchanges of the same source into one transcript per datasource.
 *
 * Text output (the default) groups by source, in capture order: the session
 * records as key=value lines, then every event by ts_mono_ns. --json writes
 * the same records as JSON lines, each wrapped as
 * {"datasource":..., "type":"CellLog"|"RawAT", "record":{...}}.
 *
 * Opens the db READONLY. A row that does not parse is skipped and counted.
 */

#include "config.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sqlite3.h>

#include "getopt.h"

#include "nlohmann/json.hpp"
#include "sqlite3_cpp11.h"

namespace {

/* ordered, so a session record lists its fields as the helper wrote them */
using json_t = nlohmann::ordered_json;

constexpr const char *celllog_type = "CellLog";
constexpr const char *rawat_type = "RawAT";

struct rec_t {
    std::string uuid;
    std::string type;
    uint64_t mono;
    bool mono_ok;
    size_t order;
    json_t j;
};

std::string jstr(const json_t& j, const char *key) {
    auto it = j.find(key);
    if (it == j.end() || !it->is_string())
        return "";
    return it->get<std::string>();
}

bool ju64(const json_t& j, const char *key, uint64_t& out) {
    auto it = j.find(key);
    if (it == j.end() || !it->is_number_unsigned())
        return false;
    out = it->get<uint64_t>();
    return true;
}

/* Control characters in the transcript would let a modem's reply move the
 * reader's terminal; shown as \xNN instead. */
std::string printable(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (c == '\t' || (c >= 0x20 && c != 0x7f)) {
            out += static_cast<char>(c);
        } else if (c == '\r') {
            out += "\\r";
        } else if (c == '\n') {
            out += "\\n";
        } else {
            char esc[8];
            snprintf(esc, sizeof(esc), "\\x%02x", c);
            out += esc;
        }
    }
    return out;
}

void put_line(FILE *f, const std::string& ts, uint64_t mono, uint64_t base,
              const char *dir, const std::string& text) {
    double rel = mono >= base ? static_cast<double>(mono - base) / 1e9 : 0.0;
    fprintf(f, "%-27s +%12.6f %-7s %s\n", ts.c_str(), rel, dir,
            printable(text).c_str());
}

void write_text(FILE *f, const rec_t& r, uint64_t base) {
    const auto& j = r.j;
    std::string ts = jstr(j, "ts_utc");

    if (r.type == rawat_type) {
        put_line(f, ts, r.mono, base, "TX", jstr(j, "cmd"));

        auto err = j.find("err");
        if (err != j.end() && err->is_string()) {
            put_line(f, "", r.mono, base, "RX", "(" + err->get<std::string>() + ")");
            return;
        }

        uint64_t rx = 0;
        if ((!ju64(j, "first_rx_ns", rx) || rx == 0) &&
            (!ju64(j, "rx_done_ns", rx) || rx == 0))
            rx = r.mono;

        std::string resp = jstr(j, "response");
        size_t start = 0;
        do {
            size_t nl = resp.find('\n', start);
            std::string line = resp.substr(start, nl == std::string::npos ?
                                           std::string::npos : nl - start);
            put_line(f, "", rx, base, "RX", line);
            start = nl == std::string::npos ? std::string::npos : nl + 1;
        } while (start != std::string::npos);
        return;
    }

    std::string kind = jstr(j, "kind");
    if (kind == "log") {
        std::string text = jstr(j, "text");
        uint64_t full = 0;
        if (ju64(j, "text_len", full))
            text += " ... (" + std::to_string(full) + " bytes)";
        put_line(f, ts, r.mono, base, jstr(j, "dir").c_str(), text);
        return;
    }

    /* session, or a kind this reader does not know: every string field */
    fprintf(f, "%-27s +%12.6f %-7s %s\n", ts.c_str(),
            r.mono >= base ? static_cast<double>(r.mono - base) / 1e9 : 0.0,
            kind.empty() ? "?" : printable(kind).c_str(),
            printable(jstr(j, "src")).c_str());
    for (auto it = j.begin(); it != j.end(); ++it) {
        const auto& k = it.key();
        if (k == "schema" || k == "src" || k == "kind" || k == "ts_utc" ||
            k == "ts_mono_ns")
            continue;
        std::string v = it->is_string() ? it->get<std::string>() : it->dump();
        fprintf(f, "%50s %s=%s\n", "", printable(k).c_str(), printable(v).c_str());
    }
}

}

void print_help(char *argv) {
    printf("Kismetdb to cell log\n");
    printf("Read back the cell sources' CellLog rows -- one session record per\n"
           "capture, and with debug=true every DIAG configuration exchange and\n"
           "what an AT exchange discarded -- merged with the source's RawAT\n"
           "exchanges into one transcript per datasource, in capture order.\n");
    printf("usage: %s [OPTION]\n", argv);
    printf(" -i, --in [filename]          Input kismetdb file\n"
           " -o, --out [filename]         Output file ('-' for stdout)\n"
           " -s, --source [uuid|name]     Only this datasource (uuid is unambiguous;\n"
           "                              a name may match several sources)\n"
           " -j, --json                   Write JSON lines instead of text\n"
           " -n, --no-rawat               CellLog rows only, without the RawAT exchanges\n"
           " -S, --sessions               Session records only\n"
           " -f, --force                  Force writing to the target file, even if it exists.\n"
           " -v, --verbose                Verbose output\n");
}

int main(int argc, char *argv[]) {
    static struct option longopt[] = {
        { "in", required_argument, 0, 'i' },
        { "out", required_argument, 0, 'o' },
        { "source", required_argument, 0, 's' },
        { "json", no_argument, 0, 'j' },
        { "no-rawat", no_argument, 0, 'n' },
        { "sessions", no_argument, 0, 'S' },
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
    bool json_out = false;
    bool with_rawat = true;
    bool sessions_only = false;

    sqlite3 *db = NULL;
    FILE *ofile = NULL;
    struct stat statbuf;

    while (1) {
        int r = getopt_long(argc, argv, "-hi:o:s:jnSvf", longopt, &option_idx);
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
        } else if (r == 'j') {
            json_out = true;
        } else if (r == 'n') {
            with_rawat = false;
        } else if (r == 'S') {
            sessions_only = true;
            with_rawat = false;
        } else if (r == 'v') {
            verbose = true;
        } else if (r == 'f') {
            force = true;
        }
    }

    if (out_fname == "" || in_fname == "") {
        fprintf(stderr, "ERROR: Expected --in [kismetdb file] and --out [file]\n");
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

    if (sqlite3_open_v2(in_fname.c_str(), &db, SQLITE_OPEN_READONLY, nullptr)) {
        fprintf(stderr, "ERROR:  Unable to open '%s': %s\n",
                in_fname.c_str(), sqlite3_errmsg(db));
        sqlite3_close(db);
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

    std::map<std::string, std::string> source_names;
    try {
        auto src_q = _SELECT(db, "datasources", {"uuid", "name"});
        for (auto s : src_q)
            source_names[sqlite3_column_as<std::string>(s, 0)] =
                sqlite3_column_as<std::string>(s, 1);
    } catch (const std::exception& e) {
        if (verbose)
            fprintf(stderr, "* Warning: could not read datasources: %s\n", e.what());
    }

    auto source_matches = [&](const std::string& uuid) -> bool {
        if (source_filter.empty() || uuid == source_filter)
            return true;
        auto ni = source_names.find(uuid);
        return ni != source_names.end() && ni->second == source_filter;
    };

    std::vector<rec_t> recs;
    unsigned long n_bad = 0;
    unsigned long n_unordered = 0;
    unsigned long n_celllog_sources = 0;

    auto read_type = [&](const char *type) {
        auto query = _SELECT(db, "data", {"datasource", "json"},
                _WHERE("type", EQ, type));

        for (auto row : query) {
            auto uuid = sqlite3_column_as<std::string>(row, 0);
            if (!source_matches(uuid))
                continue;

            auto j = json_t::parse(sqlite3_column_as<std::string>(row, 1),
                                   nullptr, false);
            if (j.is_discarded() || !j.is_object()) {
                n_bad++;
                continue;
            }
            if (sessions_only && jstr(j, "kind") != "session")
                continue;

            rec_t rec;
            rec.uuid = uuid;
            rec.type = type;
            rec.order = recs.size();
            rec.mono = 0;
            rec.mono_ok = ju64(j, "ts_mono_ns", rec.mono);
            if (!rec.mono_ok)
                n_unordered++;
            rec.j = std::move(j);
            recs.push_back(std::move(rec));
        }
    };

    try {
        read_type(celllog_type);

        /* RawAT only for the sources that wrote CellLog rows, so a cellat
         * source's transcript is whole and celldiag-only output stays so. */
        std::map<std::string, bool> has_celllog;
        for (const auto& r : recs)
            has_celllog[r.uuid] = true;
        n_celllog_sources = has_celllog.size();

        if (with_rawat) {
            size_t before = recs.size();
            read_type(rawat_type);
            recs.erase(std::remove_if(recs.begin() + before, recs.end(),
                        [&](const rec_t& r) { return has_celllog.count(r.uuid) == 0; }),
                    recs.end());
        }
    } catch (const std::exception& e) {
        fprintf(stderr, "ERROR:  Failed reading `data` rows from '%s': %s\n",
                in_fname.c_str(), e.what());
        sqlite3_close(db);
        exit(1);
    }

    sqlite3_close(db);

    /* Sources in order of their first record; within one, by ts_mono_ns, and
     * records without one last in db order. */
    std::map<std::string, uint64_t> first_mono;
    for (const auto& r : recs) {
        if (!r.mono_ok)
            continue;
        auto fi = first_mono.find(r.uuid);
        if (fi == first_mono.end() || r.mono < fi->second)
            first_mono[r.uuid] = r.mono;
    }

    auto src_key = [&](const std::string& uuid) {
        auto fi = first_mono.find(uuid);
        return fi == first_mono.end() ? UINT64_MAX : fi->second;
    };

    std::stable_sort(recs.begin(), recs.end(),
            [&](const rec_t& a, const rec_t& b) {
                if (a.uuid != b.uuid) {
                    uint64_t ka = src_key(a.uuid), kb = src_key(b.uuid);
                    if (ka != kb)
                        return ka < kb;
                    return a.uuid < b.uuid;
                }
                if (a.mono_ok != b.mono_ok)
                    return a.mono_ok;
                if (!a.mono_ok)
                    return a.order < b.order;
                return a.mono < b.mono;
            });

    if (out_fname == "-") {
        ofile = stdout;
    } else {
        ofile = fopen(out_fname.c_str(), "w");
        if (ofile == NULL) {
            fprintf(stderr, "ERROR:  Unable to open output file for writing: %s\n",
                    strerror(errno));
            exit(1);
        }
    }

    std::string cur;
    bool first = true;
    for (const auto& r : recs) {
        if (json_out) {
            json_t w;
            w["datasource"] = r.uuid;
            w["type"] = r.type;
            w["record"] = r.j;
            std::string line = w.dump(-1, ' ', false,
                                      json_t::error_handler_t::replace);
            fprintf(ofile, "%s\n", line.c_str());
            continue;
        }

        if (r.uuid != cur) {
            cur = r.uuid;
            auto ni = source_names.find(cur);
            fprintf(ofile, "%s# source %s %s\n", first ? "" : "\n",
                    ni != source_names.end() ? printable(ni->second).c_str() : "?",
                    printable(cur).c_str());
            first = false;
        }
        write_text(ofile, r, src_key(r.uuid) == UINT64_MAX ? 0 : src_key(r.uuid));
    }

    if (ofile != stdout)
        fclose(ofile);

    if (n_bad)
        fprintf(stderr, "WARNING: %lu row(s) are not JSON records and were skipped.\n",
                n_bad);

    if (verbose) {
        fprintf(stderr, "* KismetDB version %d\n", db_version);
        if (!source_filter.empty())
            fprintf(stderr, "* Source filter: '%s'\n", source_filter.c_str());
        fprintf(stderr, "* Wrote %zu record(s) from %lu source(s)", recs.size(),
                n_celllog_sources);
        if (n_unordered)
            fprintf(stderr, " (%lu without ts_mono_ns, sorted last)", n_unordered);
        fprintf(stderr, "\n* Done!\n");
    }

    return 0;
}
