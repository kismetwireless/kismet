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

#include "gpsmap_samples.h"

void SanitizeSamplePoints(vector<gps_point *> in_samples, map<int,int> *dead_sample_ids) {
    dead_sample_ids->clear();

    // Two copies of our sample vector... yeah, this eats ram.  So does the whole app.
    vector<gps_point *> lat_samples = in_samples;
    vector<gps_point *> lon_samples = in_samples;

    // Clean up offset-valid (in broken, limited capture files) points
    for (unsigned int pos = 0; pos < in_samples.size(); pos++) {
        if ((in_samples[pos]->lat == 0 && in_samples[pos]->lon == 0) ||
            (isnan(in_samples[pos]->lat) || isinf(in_samples[pos]->lat) ||
             isnan(in_samples[pos]->lon) || isinf(in_samples[pos]->lon)))
            (*dead_sample_ids)[in_samples[pos]->id] = 1;
    }

    // Bail out on small lists that we won't be able to get anything out of
    if (in_samples.size() < 4)
        return;

    // Sort the networks
    stable_sort(lat_samples.begin(), lat_samples.end(), PointSortLat());
    stable_sort(lon_samples.begin(), lon_samples.end(), PointSortLon());

    // Lets make the assumption that half our sample points can't be crap....
    int slice_point = -1;
    for (unsigned int pos = 0; pos < (lat_samples.size() / 2) + 1; pos++) {
        float lat_offset = lat_samples[pos + 1]->lat - lat_samples[pos]->lat;

        // Slice if we have a major break, it can only get worse from here...
        if (lat_offset > 0.5 || lat_offset < -0.5) {
            /*
              printf("Major lat break at pos %d in sorted lats, %f,%f id %d\n",
                pos, lat_samples[pos]->lat, lat_samples[pos]->lon, lat_samples[pos]->id);
            */
            slice_point = pos;
            break;
        }
    }

    if (slice_point != -1) {
        for (unsigned int pos = 0; pos <= (unsigned int) slice_point; pos++) {
            //printf("Discarding point lat violation %f,%f %d...\n", lat_samples[pos]->lat, lat_samples[pos]->lon, lat_samples[pos]->id);
            (*dead_sample_ids)[lat_samples[pos]->id] = 1;
        }
    }

    // Now for the upper bounds of the lat...
    slice_point = -1;
    for (unsigned int pos = (lat_samples.size() / 2) - 1; pos < lat_samples.size(); pos++) {
        float lat_offset = lat_samples[pos - 1]->lat - lat_samples[pos]->lat;

        // Slice if we have a major break, it can only get worse from here...
        if (lat_offset > 0.5 || lat_offset < -0.5) {
            /*
             printf("Major lat break at pos %d in sorted lats, %f,%f id %d\n",
             pos, lat_samples[pos]->lat, lat_samples[pos]->lon, lat_samples[pos]->id);
             */
            slice_point = pos;
            break;
        }
    }

    if (slice_point != -1) {
        for (unsigned int pos = slice_point; pos < lat_samples.size(); pos++) {
            //printf("Discarding point lat violation %f,%f %d...\n", lat_samples[pos]->lat, lat_samples[pos]->lon, lat_samples[pos]->id);
            (*dead_sample_ids)[lat_samples[pos]->id] = 1;
        }
    }


    // Now for the lon...
    slice_point = -1;
    for (unsigned int pos = 0; pos < (lon_samples.size() / 2) + 1; pos++) {
        float lon_offset = lon_samples[pos + 1]->lon - lon_samples[pos]->lon;

        // Slice if we have a major break, it can only get worse from here...
        if (lon_offset > 0.5 || lon_offset < -0.5) {
            /*
            printf("Major lon break at pos %d in sorted lons, %f,%f id %d\n",
            pos, lon_samples[pos]->lon, lon_samples[pos]->lon, lon_samples[pos]->id);
            */
            slice_point = pos;
            break;
        }
    }

    if (slice_point != -1) {
        for (unsigned int pos = 0; pos <= (unsigned int) slice_point; pos++) {
            // printf("Discarding point lon violation %f,%f %d...\n", lon_samples[pos]->lon, lon_samples[pos]->lon, lon_samples[pos]->id);
            (*dead_sample_ids)[lon_samples[pos]->id] = 1;
        }
    }

    // Now for the lon upper bound...
    slice_point = -1;
    for (unsigned int pos = lon_samples.size() / 2; pos < lon_samples.size(); pos++) {
        float lon_offset = lon_samples[pos - 1]->lon - lon_samples[pos]->lon;

        // Slice if we have a major break, it can only get worse from here...
        if (lon_offset > 0.5 || lon_offset < -0.5) {
            /*
            printf("Major lon break at pos %d in sorted lons, %f,%f id %d\n",
            pos, lon_samples[pos]->lon, lon_samples[pos]->lon, lon_samples[pos]->id);
            */
            slice_point = pos;
            break;
        }
    }

    if (slice_point != -1) {
        for (unsigned int pos = slice_point; pos < lon_samples.size(); pos++) {
            // printf("Discarding point lon violation %f,%f %d...\n", lon_samples[pos]->lon, lon_samples[pos]->lon, lon_samples[pos]->id);
            (*dead_sample_ids)[lon_samples[pos]->id] = 1;
        }
    }

}

/* This tries to chunk the network into groups of points so that we can
 * pick the most concentrated chunk to do the average center with */
vector<gps_point *> RelevantCenterPoints(vector<gps_point *> in_samples) {
    vector<gps_point *> lat_samples = in_samples;
    vector<gps_point *> lon_samples = in_samples;
    vector<gps_point *> retvec;
    map<int, int> union_samples;

    /* Bounce right back */
    if (in_samples.size() < 30)
        return in_samples;

    stable_sort(lat_samples.begin(), lat_samples.end(), PointSortLat());
    stable_sort(lon_samples.begin(), lon_samples.end(), PointSortLon());

    vector<relptrecord> rel_chunks;
    relptrecord rec;
    int largest = 0;
    int largestlen = 0;

    /* Build the lat relevant list */
    rec.start = 0;
    rec.end = 0;

    for (unsigned int x = 1; x < lat_samples.size(); x++) {
        if (lat_samples[x]->lat - lat_samples[x-1]->lat > CHUNK_DIFF) {
            rec.end = x;
            rel_chunks.push_back(rec);
            rec.start = x+1;
        }
    }
    rec.end = lat_samples.size() - 1;
    rel_chunks.push_back(rec);

    for (unsigned int x = 0; x < rel_chunks.size(); x++) {
        int len = rel_chunks[x].end - rel_chunks[x].start;
        if (largestlen < len) {
            largestlen = len;
            largest = x;
        }
    }

    /* Set the map count to 1 for each element id */
    for (unsigned int x = rel_chunks[largest].start; 
            x <= (unsigned int) rel_chunks[largest].end; x++)  {
        union_samples[lat_samples[x]->id] = 1;
    }

    /* Now do it again for lon */
    rec.start = 0;
    rec.end = 0;

    for (unsigned int x = 1; x < lon_samples.size(); x++) {
        if (lon_samples[x]->lon - lon_samples[x-1]->lon > CHUNK_DIFF) {
            rec.end = x;
            rel_chunks.push_back(rec);
            rec.start = x+1;
        }
    }
    rec.end = lon_samples.size() - 1;
    rel_chunks.push_back(rec);

    largestlen = 0;
    largest = 0;
    for (unsigned int x = 0; x < rel_chunks.size(); x++) {
        int len = rel_chunks[x].end - rel_chunks[x].start;
        if (largestlen < len) {
            largestlen = len;
            largest = x;
        }
    }

    /* Add the union points to the return vector */
    for (unsigned int x = rel_chunks[largest].start; 
            x <= (unsigned int) rel_chunks[largest].end; x++)  {
        map<int, int>::iterator itr = union_samples.find(lon_samples[x]->id);
        if (itr != union_samples.end())
            retvec.push_back(lon_samples[x]);
    }

    // Bail if we didn't get enough to make sense
    if (retvec.size() < 30)
        return in_samples;
    
    return retvec;
}

