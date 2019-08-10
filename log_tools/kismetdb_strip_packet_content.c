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

/* 
 * Simple tool to clean up a kismetdb log file, duplicate it, and strip the packet
 * content, in preparation to uploading to a site like wigle.
 */

#include "config.h"

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

void print_help(char *argv) {
    printf("Kismet packet content strip tool.\n");
    printf("A simple tool for stripping the packet data from a KismetDB log file.\n");
    printf("usage: %s [OPTION]\n", argv);
    printf(" -i, --in [filename]          Input kismetdb file\n"
           " -o, --out [filename]         Output kismetdb file with packet content stripped\n"
           " -v, --verbose                Verbose output\n"
           " -f, --force                  Force writing to the target file, even if it exists.\n");
}

int main(int argc, char *argv[]) {
    static struct option longopt[] = {
        { "in", required_argument, 0, 'i' },
        { "out", required_argument, 0, 'o' },
        { "verbose", no_argument, 0, 'b' },
        { "force", no_argument, 0, 'f' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0 }
    };

    int option_idx = 0;
    optind = 0;
    opterr = 0;

    char *in_fname = NULL, *out_fname = NULL;
    bool verbose = false;
    bool force = false;

    int sql_r = 0;
    char *sql_errmsg = NULL;
    sqlite3 *db = NULL;

    FILE *ifile = NULL, *ofile = NULL;
    char copybuf[4096];
    size_t copysz, writesz;

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
            in_fname = strdup(optarg);
        } else if (r == 'o') {
            out_fname = strdup(optarg);
        } else if (r == 'v') { 
            verbose = true;
        } else if (r == 'f') {
            force = true;
        }
    }

    if (out_fname == NULL || in_fname == NULL) {
        fprintf(stderr, "ERROR: Expected --in [kismetdb file] and "
                "--out [stripped kismetdb file]\n");
        exit(1);
    }

    /* Open the database and run the vacuum command to clean up any stray journals */

    if (verbose)
        printf("* Preparing input database '%s'...\n", in_fname);

    if (stat(out_fname, &statbuf) < 0) {
        if (errno != ENOENT) {
            fprintf(stderr, "ERROR:  Unexpected problem checking output "
                    "file '%s': %s\n", out_fname, strerror(errno));
            exit(1);
        }
    } else if (force == false) {
        fprintf(stderr, "ERROR:  Output file '%s' exists already; use --force to "
                "clobber the file.\n", out_fname);
        exit(1);
    }

    sql_r = sqlite3_open(in_fname, &db);

    if (sql_r) {
        fprintf(stderr, "ERROR:  Unable to open '%s': %s\n",
                in_fname, sqlite3_errmsg(db));
        exit(1);
    }

    sql_r = sqlite3_exec(db, "VACUUM;", NULL, NULL, &sql_errmsg);

    if (sql_r != SQLITE_OK) {
        fprintf(stderr, "ERROR:  Unable to clean up (vacuum) database before copying: %s\n",
                sql_errmsg);
        sqlite3_close(db);
        exit(1);
    }

    sqlite3_close(db);


    /* Now that the database is closed, copy it as a binary 
     * file to the target database */
   
    ifile = fopen(in_fname, "rb");
    if (ifile == NULL) {
        fprintf(stderr, "ERROR:  Unable to open input file for reading: %s\n", 
                strerror(errno));
        exit(1);
    }

    ofile = fopen(out_fname, "wb");
    if (ofile == NULL) {
        fprintf(stderr, "ERROR:  Unable to open output file for writing: %s\n",
                strerror(errno));
        exit(1);
    }

    if (verbose)
        printf("* Copying '%s' to '%s'...\n", in_fname, out_fname);

    while (true) {
        copysz = fread(copybuf, 1, 4096, ifile);

        if (copysz == 0) {
            if (ferror(ifile)) {
                printf("ERROR: Reading from '%s' failed: %s\n",
                        in_fname, strerror(errno));
                fclose(ifile);
                fclose(ofile);
                unlink(out_fname);
                exit(1);
            }

            break;
        }

        writesz = fwrite(copybuf, 1, copysz, ofile);

        if (writesz != copysz) {
            printf("ERROR: Writing %lu to '%s' failed: %s\n",
                    copysz, out_fname, strerror(errno));
            fclose(ifile);
            fclose(ofile);
            unlink(out_fname);
            exit(1);
        }
    }

    fclose(ifile);
    fclose(ofile);

    ifile = NULL;
    ofile = NULL;

    if (verbose)
        printf("* Cleaning packet content from output database...\n");

    /* Open the target file as a sqlite3 db */

    if (verbose)
        printf("* Stripping packet data from '%s'...\n", out_fname);

    sql_r = sqlite3_open(out_fname, &db);

    if (sql_r) {
        fprintf(stderr, "ERROR:  Unable to open '%s': %s\n",
                out_fname, sqlite3_errmsg(db));
        exit(1);
    }

    sql_r = sqlite3_exec(db, "UPDATE packets SET packet = '';", NULL, NULL, &sql_errmsg);

    if (sql_r != SQLITE_OK) {
        fprintf(stderr, "ERROR:  Unable to clear packet data: %s\n",
                sql_errmsg);
        sqlite3_close(db);
        exit(1);
    }

    sql_r = sqlite3_exec(db, "VACUUM;", NULL, NULL, &sql_errmsg);

    if (sql_r != SQLITE_OK) {
        fprintf(stderr, "ERROR:  Unable to clean up (vacuum) database after stripping: %s\n",
                sql_errmsg);
        sqlite3_close(db);
        exit(1);
    }

    sqlite3_close(db);

    if (verbose) 
        printf("* Done!\n");

    return 0;
}

