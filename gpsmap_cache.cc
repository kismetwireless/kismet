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
#include "gpsmap_cache.h"

// Read a cache from a file, error out if there isn't a cache or there isn't a
// valid cache
int ReadGpsCacheFile(const char *in_gpsfname, 
                     vector<wireless_network *> *in_networklist,
                     vector<gps_point *> *in_points) {
    gpscache_header fheader;
    struct stat fstat;
    time_t gpsmod;
    int slashpos;
    char cachefname[1024];
    struct passwd *pw;

#ifdef HAVE_LIBZ
    gzFile cachefile;
#else
    FILE *cachefile;
#endif

    // Get home dir
    pw = getpwuid(getuid());
    if (pw == NULL) {
        fprintf(stderr, "ERROR:  Could not find home directory path for gpscache, "
                "getpwuid() failed, %s\n", strerror(errno));
        return -1;
    }

    // Get gps and net xml timestamps 
    if (stat(in_gpsfname, &fstat) == -1) {
        fprintf(stderr, "ERROR: Could not stat gpsxml file %s\n",
                in_gpsfname);
        return -1;
    }
    gpsmod = fstat.st_mtime;

    // Find the file name of the gps file
    for (slashpos = strlen(in_gpsfname); slashpos >= 0; slashpos--) {
        if (in_gpsfname[slashpos] == '/')
            break;
    }
    slashpos++;

    snprintf(cachefname, 1024, "%s/%s/%s%s", pw->pw_dir, GPSCACHE_DIR,
             in_gpsfname + slashpos, GPSCACHE_SUFFIX);

    // Bail if the cache file doesn't exist
#ifdef HAVE_LIBZ
    if ((cachefile = gzopen(cachefname, "rb")) == NULL)
#else
    if ((cachefile = fopen(cachefname, "r")) == NULL) 
#endif
        return -1;

    // Read the header
#ifdef HAVE_LIBZ
    if (gzread(cachefile, &fheader, sizeof(gpscache_header)) < 
        (int) sizeof(gpscache_header)) {
        gzclose(cachefile);
        return -1;
    }
#else
    if ((fread(&fheader, sizeof(gpscache_header), 1, cachefile)) < 
        (int) sizeof(gpscache_header)) {
        fclose(cachefile);
        return -1;
    }
#endif

    if (fheader.cache_magic != GPSCACHE_MAGIC || 
        fheader.cache_version != GPSCACHE_VERSION) {
#ifdef HAVE_LIBZ
        gzclose(cachefile);
#else
        fclose(cachefile);
#endif
        return -1;
    }

    if (fheader.gps_last_mod != gpsmod) {
        fprintf(stderr, "NOTICE: Cache file %s doesn't match %s modification time.\n",
                cachefname, in_gpsfname);
#ifdef HAVE_LIBZ
        gzclose(cachefile);
#else
        fclose(cachefile);
#endif
        return -1;
    }

    // Now our file is good, so read in all the networks and points
    in_networklist->reserve(fheader.num_networks);
    for (unsigned int nnet = 0; nnet < fheader.num_networks; nnet++) {
        gpscache_network cnet;
        wireless_network *wnet = new wireless_network;
        
#ifdef HAVE_LIBZ
        if (gzread(cachefile, &cnet, sizeof(gpscache_network)) < 
            (int) sizeof(gpscache_network)) {
            gzclose(cachefile);
            return -1;
        }
#else
        if ((fread(&cnet, sizeof(gpscache_network), 1, cachefile)) < 
                (int) sizeof(gpscache_network)) {
            fclose(cachefile);
            return -1;
        }
#endif

        wnet->type = (wireless_network_type) cnet.type;
        wnet->bssid = mac_addr((uint8_t *) cnet.bssid);
        wnet->ssid = cnet.ssid;
        wnet->beacon_info = cnet.beacon_info;
        wnet->llc_packets = cnet.llc_packets;
        wnet->data_packets = cnet.data_packets;
        wnet->crypt_packets = cnet.crypt_packets;
        wnet->interesting_packets = cnet.interesting_packets;
        wnet->channel = cnet.channel;
        wnet->crypt_set = cnet.wep;
        wnet->last_time = cnet.last_time;
        wnet->first_time = cnet.first_time;
        wnet->beacon = cnet.beacon;
        wnet->carrier_set = cnet.carrier_set;
        wnet->encoding_set = cnet.encoding_set;
        wnet->datasize = cnet.data_size;
        wnet->ipdata.range_ip[0] = cnet.range_ip[0];
        wnet->ipdata.range_ip[1] = cnet.range_ip[1];
        wnet->ipdata.range_ip[2] = cnet.range_ip[2];
        wnet->ipdata.range_ip[3] = cnet.range_ip[3];

        in_networklist->push_back(wnet);
    }

    // Now read all the points
    int point_id = 0;
    in_points->reserve(fheader.num_points);
    for (unsigned int nsam = 0; nsam < fheader.num_points; nsam++) {
        gpscache_point cpt;
        gps_point *pt = new gps_point;
        
#ifdef HAVE_LIBZ
        if (gzread(cachefile, &cpt, sizeof(gpscache_point)) < 
            (int) sizeof(gpscache_point)) {
            gzclose(cachefile);
            return -1;
        }
#else
        if ((fread(&cpt, sizeof(gpscache_point), 1, cachefile)) < 
                (int) sizeof(gpscache_point)) {
            fclose(cachefile);
            return -1;
        }
#endif

        strncpy(pt->bssid, cpt.bssid, MAC_STR_LEN);
        strncpy(pt->source, cpt.source, MAC_STR_LEN);
	pt->bssid[MAC_STR_LEN-1]  = '\0';
	pt->source[MAC_STR_LEN-1] = '\0';
        pt->tv_sec = cpt.tv_sec;
        pt->tv_usec = cpt.tv_usec;
        pt->lat = cpt.lat;
        pt->lon = cpt.lon;
        pt->spd = cpt.spd;
        pt->alt = cpt.alt;
        pt->heading = cpt.heading;
        pt->fix = cpt.fix;
        pt->signal = cpt.signal;
        pt->noise = cpt.noise;
        pt->id = point_id++;

        in_points->push_back(pt);
    }

#ifdef HAVE_LIBZ
    gzclose(cachefile);
#else
    fclose(cachefile);
#endif
    
    return 1;

}

// Cache gps data to a file
int WriteGpsCacheFile(const char *in_gpsfname, 
                      vector<wireless_network *> *in_networklist,
                      vector<gps_point *> *in_points) {

    struct stat fstat;
    time_t gpsmod;
    int slashpos;
    char cachefname[1024];
    struct passwd *pw;

#ifdef HAVE_LIBZ
    gzFile cachefile;
#else
    FILE *cachefile;
#endif
   
    // Get home dir
    pw = getpwuid(getuid());
    if (pw == NULL) {
        fprintf(stderr, "ERROR:  Could not find home directory path for gpscache, "
                "getpwuid() failed, %s\n", strerror(errno));
        return -1;
    }

    // Get gps and net xml timestamps 
    if (stat(in_gpsfname, &fstat) == -1) {
        fprintf(stderr, "ERROR: Could not stat gpsxml file %s\n",
                in_gpsfname);
        return -1;
    }
    gpsmod = fstat.st_mtime;

    // Find out if the cache dir exists, try to make it if it doesn't.
    snprintf(cachefname, 1024, "%s/%s/", pw->pw_dir, GPSCACHE_DIR);
    if (stat(cachefname, &fstat) == -1) {
        fprintf(stderr, "NOTICE: Config dir %s doesn't exist, making it...\n",
                cachefname);
        if (mkdir(cachefname, S_IRUSR | S_IWUSR | S_IXUSR) < 0) {
            fprintf(stderr, "FATAL: Could not make cache dir, %s\n",
                    strerror(errno));
            return -1;
        }
    }
    
    // Find the file name of the gps file
    for (slashpos = strlen(in_gpsfname); slashpos >= 0; slashpos--) {
        if (in_gpsfname[slashpos] == '/')
            break;
    }
    slashpos++;

    snprintf(cachefname, 1024, "%s/%s/%s%s", pw->pw_dir, GPSCACHE_DIR,
             in_gpsfname + slashpos, GPSCACHE_SUFFIX);

    // Open the cache file for writing
#ifdef HAVE_LIBZ
    if ((cachefile = gzopen(cachefname, "wb")) == NULL) {
#else
    if ((cachefile = fopen(cachefname, "w")) == NULL) {
#endif
        fprintf(stderr, "WARNING: Could not open gps cache file %s for writing (%s)\n",
                cachefname, strerror(errno));
        return -1;
    }

    gpscache_header fheader;
    fheader.cache_magic = GPSCACHE_MAGIC;
    fheader.cache_version = GPSCACHE_VERSION;
    fheader.gps_last_mod = gpsmod;
    fheader.num_networks = in_networklist->size();
    fheader.num_points = in_points->size();

#ifdef HAVE_LIBZ
    if (gzwrite(cachefile, &fheader, sizeof(gpscache_header)) < 
        (int) sizeof(gpscache_header)) {
        gzclose(cachefile);
        fprintf(stderr, "FATAL:  Error writing to cache %s: %s\n",
                cachefname, strerror(errno));
        unlink(cachefname);
        return -1;
    }
#else
    if (fwrite(&fheader, sizeof(gpscache_header), 1, cachefile) < 
        (int) sizeof(gpscache_header)) {
        fclose(cachefile);
        fprintf(stderr, "FATAL:  Error writing to cache %s: %s\n",
                cachefname, strerror(errno));
        unlink(cachefname);
        return -1;
    }
#endif

    // Write the networks out
    for (unsigned int nnet = 0; nnet < fheader.num_networks; nnet++) {
        gpscache_network cnet;
        wireless_network *wnet = (*in_networklist)[nnet];
      
        cnet.type = wnet->type;
        for (unsigned int m = 0; m < 6; m++)
            cnet.bssid[m] = wnet->bssid[m];
        snprintf(cnet.ssid, 32, "%s", wnet->ssid.c_str());
        snprintf(cnet.beacon_info, 256, "%s", wnet->beacon_info.c_str());
        cnet.llc_packets = wnet->llc_packets;
        cnet.data_packets = wnet->data_packets;
        cnet.crypt_packets = wnet->crypt_packets;
        cnet.interesting_packets = wnet->interesting_packets;
        cnet.channel = wnet->channel;
        cnet.wep = wnet->crypt_set;
        cnet.last_time = wnet->last_time;
        cnet.first_time = wnet->first_time;
        cnet.beacon = wnet->beacon;
        cnet.carrier_set = wnet->carrier_set;
        cnet.encoding_set = wnet->encoding_set;
        cnet.data_size = wnet->datasize;
        cnet.range_ip[0] = wnet->ipdata.range_ip[0];
        cnet.range_ip[1] = wnet->ipdata.range_ip[1];
        cnet.range_ip[2] = wnet->ipdata.range_ip[2];
        cnet.range_ip[3] = wnet->ipdata.range_ip[3];

#ifdef HAVE_LIBZ
        if (gzwrite(cachefile, &cnet, sizeof(gpscache_network)) < 
            (int) sizeof(gpscache_network)) {
            gzclose(cachefile);
            fprintf(stderr, "FATAL:  Error writing to cache %s: %s\n",
                    cachefname, strerror(errno));
            unlink(cachefname);
            return -1;
        }
#else
        if ((fwrite(&cnet, sizeof(gpscache_network), 1, cachefile)) < 
            (int) sizeof(gpscache_network)) {
            fclose(cachefile);
            fprintf(stderr, "FATAL:  Error writing to cache %s: %s\n",
                    cachefname, strerror(errno));
            unlink(cachefname);
            return -1;
        }
#endif
    }

    // Now read all the points
    for (unsigned int nsam = 0; nsam < fheader.num_points; nsam++) {
        gpscache_point cpt;
        gps_point *pt = (*in_points)[nsam];

	memset(&cpt, 0, sizeof cpt);
        strncpy(cpt.bssid, pt->bssid, sizeof(cpt.bssid)-1);
        strncpy(cpt.source, pt->source, sizeof(cpt.source)-1);
        cpt.tv_sec = pt->tv_sec;
        cpt.tv_usec = pt->tv_usec;
        cpt.lat = pt->lat;
        cpt.lon = pt->lon;
        cpt.spd = pt->spd;
        cpt.alt = pt->alt;
        cpt.heading = pt->heading;
        cpt.fix = pt->fix;
        cpt.signal = pt->signal;
        cpt.noise = pt->noise;

#ifdef HAVE_LIBZ
        if (gzwrite(cachefile, &cpt, sizeof(gpscache_point)) < 
            (int) sizeof(gpscache_point)) {
            gzclose(cachefile);
            fprintf(stderr, "FATAL:  Error writing to cache %s: %s\n",
                    cachefname, strerror(errno));
            unlink(cachefname);
            return -1;
        }
#else
        if ((fwrite(&cpt, sizeof(gpscache_point), 1, cachefile)) < 
            (int) sizeof(gpscache_point)) {
            fclose(cachefile);
            fprintf(stderr, "FATAL:  Error writing to cache %s: %s\n",
                    cachefname, strerror(errno));
            unlink(cachefname);
            return -1;
        }
#endif

    }

#ifdef HAVE_LIBZ
    gzclose(cachefile);
#else
    fclose(cachefile);
#endif
    
    return 1;
}


