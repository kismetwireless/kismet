#include "config.h"

#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include "getopt.h"
#include <unistd.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <zlib.h>

#include "gpsdump.h"
#include "expat.h"

string Mac2String(uint8_t *mac, char seperator) {
    char tempstr[MAC_STR_LEN];

    // There must be a better way to do this...
    if (seperator != '\0')
        snprintf(tempstr, MAC_STR_LEN, "%02X%c%02X%c%02X%c%02X%c%02X%c%02X",
                 mac[0], seperator, mac[1], seperator, mac[2], seperator,
                 mac[3], seperator, mac[4], seperator, mac[5]);
    else
        snprintf(tempstr, MAC_STR_LEN, "%02X%02X%02X%02X%02X%02X",
                 mac[0], mac[1], mac[2],
                 mac[3], mac[4], mac[5]);

    string temp = tempstr;
    return temp;
}

int ProcessGPSFile(char *in_fname, char *in_oname) {
    int file_samples = 0;

#ifdef HAVE_LIBZ
    gzFile gpsfz;
#else
    FILE *gpsf;
#endif


#ifdef HAVE_LIBZ
    if ((gpsfz = gzopen(in_fname, "rb")) == NULL) {
        fprintf(stderr, "FATAL:  Could not open data file\n");
        return -1;
    }
#else
    if ((gpsf = fopen(in_fname, "r")) == NULL) {
        fprintf(stderr, "FATAL:  Could not open data file.\n");
        return -1;
    }
#endif

    FILE *outf;
    if (in_oname == NULL) {
        outf = stdout;
    } else {
        if ((outf = fopen(in_oname, "a")) == NULL) {
            fprintf(stderr, "FATAL:  Could not open output file (%s) for appending\n",
                    in_oname);
            return -1;
        }
    }


    fprintf(stderr, "NOTICE:  Processing gps file '%s'\n", in_fname);

    vector<gps_point *> file_points;
#ifdef HAVE_LIBZ
    file_points = XMLFetchGpsList(gpsfz);
#else
    file_points = XMLFetchGpsList(gpsf);
#endif
    if (file_points.size() == 0) {
        fprintf(stderr, "WARNING:  No sample points found in '%s'.\n", in_fname);
    }

    // We handle the points themselves after we handle the network component

    file_samples = file_points.size();

#ifdef HAVE_LIBZ
    gzclose(gpsfz);
#else
    fclose(gpsf);
#endif

    // We have all our gps points loaded into the local struct now, so if they had a
    // network file specified, load the networks from that and mesh it with the network
    // data we already (may) have from ther files.

    vector<wireless_network *> file_networks;

    int foundnetfile = 0;
    string comp;

    if ((comp = XMLFetchGpsNetfile()) != "") {
        fprintf(stderr, "NOTICE:  Reading associated network file, '%s'\n", XMLFetchGpsNetfile().c_str());
#ifdef HAVE_LIBZ
        if ((gpsfz = gzopen(XMLFetchGpsNetfile().c_str(), "r")) == NULL) {
            fprintf(stderr, "WARNING:  Could not open associated network xml file '%s'.\n",
                    XMLFetchGpsNetfile().c_str());
        } else {
            foundnetfile = 1;
        }

        // Try our alternate file methods

        if (foundnetfile == 0) {
            comp = XMLFetchGpsNetfile();
            comp += ".gz";

            if ((gpsfz = gzopen(comp.c_str(), "r")) == NULL) {
                fprintf(stderr, "WARNING:  Could not open compressed network xml file '%s'\n",
                        comp.c_str());
            } else {
                foundnetfile = 1;
            }
        }

        if (foundnetfile == 0) {
            string orignetfile = XMLFetchGpsNetfile();
            string origxmlfile = in_fname;

            // Break up the path to the gpsxml file and form a path based on that
            unsigned int lastslash = 0;
            for (unsigned int x = origxmlfile.find('/'); x != string::npos;
                 lastslash = x, x = origxmlfile.find('/', lastslash+1)) {
                // We don't actually need to do anything...
            }

            comp = origxmlfile.substr(0, lastslash);

            lastslash = 0;
            for (unsigned int x = orignetfile.find('/'); x != string::npos;
                 lastslash = x, x = orignetfile.find('/', lastslash+1)) {
                // We don't actually need to do anything...
            }

            comp += "/" + orignetfile.substr(lastslash, orignetfile.size() - lastslash);

            if (comp != origxmlfile) {
                if ((gpsfz = gzopen(comp.c_str(), "r")) == NULL) {
                    fprintf(stderr, "WARNING:  Could not open network xml file relocated to %s\n",
                            comp.c_str());
                } else {
                    foundnetfile = 1;
                }

                // And look again for our relocated compressed file.
                if (foundnetfile == 0) {
                    comp += ".gz";
                    if ((gpsfz = gzopen(comp.c_str(), "r")) == NULL) {
                        fprintf(stderr, "WARNING:  Could not open compressed network xml file relocated to %s\n",
                                comp.c_str());
                    } else {
                        foundnetfile = 1;
                    }
                }
            }
        }

#else
        if ((gpsf = fopen(XMLFetchGpsNetfile().c_str(), "r")) == NULL) {
            fprintf(stderr, "WARNING:  Could not open associated network xml file '%s'\n",
                    XMLFetchGpsNetfile().c_str());
        } else {
            foundnetfile = 1;
        }

        // Try our alternate file methods

        if (foundnetfile == 0) {
            string orignetfile = XMLFetchGpsNetfile();
            string origxmlfile = in_fname;

            // Break up the path to the gpsxml file and form a path based on that
            unsigned int lastslash = 0;
            for (unsigned int x = origxmlfile.find('/'); x != string::npos;
                 lastslash = x, x = origxmlfile.find('/', lastslash+1)) {
                // We don't actually need to do anything...
            }

            comp = origxmlfile.substr(0, lastslash);

            lastslash = 0;
            for (unsigned int x = orignetfile.find('/'); x != string::npos;
                 lastslash = x, x = orignetfile.find('/', lastslash+1)) {
                // We don't actually need to do anything...
            }

            comp += "/" + orignetfile.substr(lastslash, orignetfile.size() - lastslash - 1);

            if (comp != origxmlfile) {
                if ((gpsf = fopen(comp.c_str(), "r")) == NULL) {
                    fprintf(stderr, "WARNING:  Could not open network xml file relocated to %s\n",
                            comp.c_str());
                } else {
                    foundnetfile = 1;
                }

            }
        }

#endif

        if (foundnetfile) {
            fprintf(stderr, "NOTICE:  Opened associated network xml file '%s'\n", comp.c_str());

            fprintf(stderr, "NOTICE:  Processing network XML file.\n");

#ifdef HAVE_LIBZ
            file_networks = XMLFetchNetworkList(gpsfz);
#else
            file_networks = XMLFetchNetworkList(gpsf);
#endif
            if (file_networks.size() == 0) {
                fprintf(stderr, "WARNING:  No network entries found in '%s'.\n",
                        XMLFetchGpsNetfile().c_str());
            }
#ifdef HAVE_LIBZ
            gzclose(gpsfz);
#else
            fclose(gpsf);
#endif
        }
    }

    time_t now = time(0);

    fprintf(outf, "# COMMON WIRELESS GPS DATA\n"
            "# File format 1.0\n"
            "# Generated by kismet2cwgd on %.24s\n\n"
            "# BSSID SSID LAT LON ALT SPEED FIX QUALITY POWER NOISE TIME\n\n",
            ctime(&now));

    map<mac_addr, wireless_network *> bssid_cache;

    for (unsigned int i = 0; i < file_points.size(); i++) {
        double lat, lon, alt, spd;
        int fix;

        lat = file_points[i]->lat;
        lon = file_points[i]->lon;
        alt = file_points[i]->alt;
        spd = file_points[i]->spd;
        fix = file_points[i]->fix;

        now = file_points[i]->tv_sec;

        if (strncmp(file_points[i]->bssid, gps_track_bssid, MAC_STR_LEN) == 0) {
            fprintf(outf, "00:00:00:00:00:00\t__TRACK__\t%3.6f\t%3.6f\t%3.6f\t%3.6f\t%d\t%d\t%d\t%d\t%.24s\n",
                    lat, lon, alt, spd, fix,
                    file_points[i]->quality, file_points[i]->signal, file_points[i]->noise,
                    ctime(&now));
        } else {
            char ssid[32] = "<no ssid>";

            mac_addr bssid = file_points[i]->bssid;

            if (bssid_cache.find(bssid) == bssid_cache.end()) {
                int matched = 0;
                for (unsigned int f = 0; f < file_networks.size(); f++) {
                    if (bssid == file_networks[f]->bssid) {
                        snprintf(ssid, 32, "%s", file_networks[f]->ssid.c_str());
                        bssid_cache[bssid] = file_networks[f];
                        matched = 1;
                        break;
                    }
                }
                if (!matched)
                    bssid_cache[bssid] = NULL;
            } else {
                if (bssid_cache[bssid] != NULL)
                    snprintf(ssid, 32, "%s", bssid_cache[bssid]->ssid.c_str());
            }

            fprintf(outf, "%s\t%s\t%3.6f\t%3.6f\t%3.6f\t%3.6f\t%d\t%d\t%d\t%d\t%.24s\n",
                    bssid.Mac2String().c_str(),
                    ssid,
                    lat, lon, alt, spd, fix,
                    file_points[i]->quality, file_points[i]->signal, file_points[i]->noise,
                    ctime(&now));
        }

    }

    fclose(outf);
    return 1;
}



int Usage(char *argv) {
    printf("Usage: %s [OPTION] <gpsfile>\n", argv);
    printf(
           "  -o, --output <file>          Output cwgd data to <file> (default stdout)\n"
           "  -h, --help                   What do you think you're reading?\n");
    exit(1);
}

char *exec_name;

int main(int argc, char *argv[]) {
    exec_name = argv[0];

    static struct option long_options[] = {   /* options table */
        { "output", required_argument, 0, 'o' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0 }
    };
    int option_index;

    char *foutname = NULL;

    while(1) {
        int r = getopt_long(argc, argv, "ho:",
                            long_options, &option_index);

        if (r < 0) break;

        switch(r) {
        case 'o':
            foutname = optarg;
            break;
        default:
            Usage(argv[0]);
            break;
        }
    }

    if (optind == argc) {
        fprintf(stderr, "FATAL:  No gps files given.\n");
        exit(1);
    }

    for (int x = optind; x < argc; x++) {
        if (ProcessGPSFile(argv[x], foutname) < 0) {
            fprintf(stderr, "FATAL:  Unrecoverable error processing GPS data file \"%s\".\n",
                    argv[x]);
            exit(1);
        }
    }

    exit(0);
}

