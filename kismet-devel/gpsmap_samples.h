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
    Magic bits of gpsmap that manipulate the sample points.  Useful to other
    utilities so it lives in its own linkable file.
*/

#ifndef __GPSMAP_SAMPLES_H__
#define __GPSMAP_SAMPLES_H__

#include "config.h"

#include <algorithm>
#include <string>
#include <vector>
#include <map>

#include "gpsdump.h"
#include "expat.h"

/* offset amount for relevance-finding */
#define CHUNK_DIFF 0.00005

// Algo sort by lon
class PointSortLon {
public:
    inline bool operator() (const gps_point *x, const gps_point *y) const {
        if (isnan(x->lon))
            return 1;

        if (isnan(y->lon))
            return 0;

        if (x->lon < y->lon)
            return 1;
        return 0;
    }
};

// Algo sort by lon
class PointSortLat {
public:
    inline bool operator() (const gps_point *x, const gps_point *y) const {
        if (isnan(x->lat))
            return 1;

        if (isnan(y->lon))
            return 0;

        if (x->lat < y->lat)
            return 1;
        return 0;
    }
};

// Do lots of manipulation to try to screen out crap data
void SanitizeSamplePoints(vector<gps_point *> in_samples, 
                          map<int,int> *dead_sample_ids); 

/* A chunk of points */
typedef struct {
    int start;
    int end;
} relptrecord;

/* This tries to chunk the network into groups of points so that we can
 * pick the most concentrated chunk to do the average center with */
vector<gps_point *> RelevantCenterPoints(vector<gps_point *> in_samples);

#endif

