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

#include "config.h"

#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <math.h>
#include <gmp.h>
#include <time.h>
#include "getopt.h"
#include <unistd.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <deque>
#include <algorithm>
#include <zlib.h>
#include "configfile.h"

#include "gpsdump.h"
#include "expat.h"
#include "manuf.h"
#include "gpsmap_samples.h"

int verbose = 0;

int ProcessGPSFile(char *in_fname) {

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

    fprintf(stderr, "\n\nProcessing gps file '%s'\n", in_fname);

    vector<gps_point *> file_points;
    map<int, int> file_screen;
#ifdef HAVE_LIBZ
    file_points = XMLFetchGpsList(gpsfz);
#else
    file_points = XMLFetchGpsList(gpsf);
#endif

    if (file_points.size() == 0) {
        fprintf(stderr, "WARNING:  No sample points found in '%s'.\n", in_fname);
        return 0;
    }

    // We handle the points themselves after we handle the network component

#ifdef HAVE_LIBZ
    gzclose(gpsfz);
#else
    fclose(gpsf);
#endif

    time_t xmlct = XMLFetchGpsStart();
    fprintf(stderr, "File '%s', version %d, netfile '%s', start time '%.24s'\n",
            in_fname, (int) XMLFetchGpsVersion(), XMLFetchGpsNetfile().c_str(),
            ctime(&xmlct));
    
    fprintf(stderr, "Sanitizing %d sample points...\n", 
            file_points.size());

    SanitizeSamplePoints(file_points, &file_screen);

    fprintf(stderr, "Removing %d junk samples...\n", file_screen.size());

    printf("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE gps-run SYSTEM \"http://kismetwireless.net/kismet-gps-2.9.1.dtd\">\n\n");

    // Write the start of the run
    printf("<gps-run gps-version=\"%d\" start-time=\"%.24s\">\n\n",
           GPS_VERSION, ctime(&xmlct));

    if (XMLFetchGpsNetfile().length() > 0) {
        printf("    <network-file>%s</network-file>\n\n", 
               XMLFetchGpsNetfile().c_str());
    }

    for (unsigned int x = 0; x < file_points.size(); x++) {
        if (file_screen.find(file_points[x]->id) != file_screen.end())
            continue;

        printf("    <gps-point bssid=\"%s\" source=\"%s\" time-sec=\"%ld\" "
               "time-usec=\"%ld\" lat=\"%f\" lon=\"%f\" alt=\"%f\" spd=\"%f\" "
               "heading=\"%f\" fix=\"%d\" signal=\"%d\" noise=\"%d\"/>\n",
               file_points[x]->bssid, file_points[x]->source,
               (long int) file_points[x]->tv_sec, 
               (long int) file_points[x]->tv_usec,
               file_points[x]->lat, file_points[x]->lon, file_points[x]->alt,
               file_points[x]->spd, file_points[x]->heading, file_points[x]->fix,
               file_points[x]->signal, file_points[x]->noise);
    }

    printf("</gps-run>\n");
    
    return 0;
}

int main(int argc, char *argv[]) {
    fprintf(stderr, "Kismet GPSXML Sample Sanitizer\n");
    fprintf(stderr, "Sanitized XML will be printed to stdout.\n");

    if (argc != 2) {
        fprintf(stderr, "FATAL: Must specifiy only one GPS file.\n");
    }

    ProcessGPSFile(argv[1]);
    
    return 0;
}

