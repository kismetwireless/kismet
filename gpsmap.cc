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

// Extract a GPS coordinates dump and list it

// Map fetcher
// Map: http://www.mapblast.com/gif?&CT=41.711632:-73.932541:25000&IC=&W=1280&H=1024&FAM=mblast&LB=
// lat, lon, zoom

#include "config.h"

// Prevent make dep warnings
#if (defined(HAVE_IMAGEMAGICK) && defined(HAVE_GPS))

#include <stdio.h>
#include <pthread.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <math.h>
#include <time.h>
#include "getopt.h"
#include <unistd.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <deque>
#include <zlib.h>
#include <magick/api.h>
#include "configfile.h"

#include "gpsdump.h"
#include "expat.h"
#include "manuf.h"

#define MAJOR 2
#define MINOR 5

// looky looky, image magick changed their api!
#if MagickLibVersion < 0x0545
#define OldMagickLib
#endif

const char *config_base = "kismet.conf";

//const char url_template[] = "http://www.mapblast.com/gif?&CT=%f:%f:%ld&IC=&W=%d&H=%d&FAM=myblast&LB=%s";
// &L = USA for the USA, EUR appears to be generic for Europe, EUR0809 for other parts of Europe.. if you get it wrong your map will be very bland =)
// default to USA, probably want to change this. -- poptix
const char url_template[] = "http://msrvmaps.mappoint.net/isapi/MSMap.dll?ID=3XNsF.&C=%f,%f&L=USA&CV=1&A=%ld&S=%d,%d&O=0.000000,0.000000&MS=0&P=|5748|";
const char download_template[] = "wget \"%s\" -O %s";

// Decay from absolute blue for multiple tracks
const uint8_t track_decay = 0x1F;
// Width of the track
const unsigned int track_width = 3;

// distance (in feet) before we throttle a network and discard it
const unsigned int horiz_throttle = 75000;
//const unsigned int horiz_throttle = 850;

// Image scales we use
long int scales[] = { 1000, 2000, 5000, 10000, 20000, 30000, 50000, 60000, 70000, 75000, 80000,
85000, 90000, 95000, 100000, 125000, 150000, 200000, 300000, 500000, 750000, 1000000, 2000000,
3000000, 4000000, 5000000, 6000000, 7000000, 8000000, 9000000, 10000000, 15000000,
20000000, 25000000, 30000000, 35000000, 40000000, 0 };

// Image colors
const char *netcolors[] = {
    "#000000",
    "#FF0000", "#FF0072", "#FF00E5", "#D400FF",
    "#5D00FF", "#0087FF", "#00F2FF", "#00FF94",
    "#00FF2E", "#BBFF00", "#FFB200", "#FF6E00",
    "#FF6500", "#960000", "#96005F", "#640096",
    "#001E96", "#008E96", "#00963E", "#529600",
    "#968C00", "#963700", NULL
};

// strength colors
char **powercolors;
int power_steps;

// Channel colors
char *channelcolors[] = {
    "#FF0000", "#FF8000", "#FFFF00",
    "#80FF00", "#00FF00", "#00FF80",
    "#00FFFF", "#0080FF", "#0000FF",
    "#8000FF", "#FF00FF", "#FF0080",
    "#808080", "#000000"
};

// Origional
char *powercolors_Orig[] = {
    "#FF0000", "#FFD500", "#FFCC00",
    "#F2FF00", "#7BFF00", "#00FFB6",
    "#00FFFF", "#005DFF", "#A100FF",
    "#FA00FF"
};
const int power_steps_Orig = 10;

// Math progression
char *powercolors_Math[] = {
    "#FF0000", "#FF8000", "#FFFF00",
    "#80FF00", "#00FF00", "#00FF80",
    "#00FFFF", "#0080FF", "#0000FF",
    "#8000FF", "#FF00FF", "#FF0080"
};
const int power_steps_Math = 12;

// Weather Radar
char *powercolors_Radar[] = {
    "#50E350", "#39C339", "#208420",
    "#145A14", "#C8C832", "#DC961E",
    "#E61E1E", "#B31A17", "#811610",
};
const int power_steps_Radar = 9;

const int power_max = 255;
//const double power_constant = -2;
unsigned int map_width = 1280;
unsigned int map_height = 1024;

int draw_opacity, draw_track, draw_bounds, draw_range, draw_interpolated, draw_hull, draw_scatter,
    draw_legend, convert_greyscale, keep_gif, draw_center, center_dot, verbose, interpolation_res;

int sample_points;

// points .. replaced by gpspoint
/*
struct point {
	double x, y, z;
        };
        */

// don't ask
struct hullPoint {
	int x, y;
	double angle;
	string xy;
	bool operator< (const hullPoint&) const;
	bool operator() (const hullPoint&, const hullPoint&) const;
};

bool hullPoint::operator< (const hullPoint& op) const {
	if (y == op.y) {
		return x < op.x;
	}
	return y < op.y;
}

bool hullPoint::operator() (const hullPoint& a, const hullPoint& b) const { /*FOLD00*/
	if (a.angle == b.angle) {
		if (a.x == b.x) {
			return a.y < b.y;
		}
		return a.x < b.x;
	}
	return a.angle < b.angle;
}

typedef struct gps_network {

    gps_network() {
        wnet = NULL;
        max_lat = min_lat = max_lon = min_lon = max_alt = min_alt = 0;
        count = 0;
        avg_lat = avg_lon = avg_alt = avg_spd = 0;
        diagonal_distance = altitude_distance = 0;
    };

    // Wireless network w/ full details, loaded from the associated netfile xml
    wireless_network *wnet;

    string bssid;

    float max_lat;
    float min_lat;
    float max_lon;
    float min_lon;
    float max_alt;
    float min_alt;

    int count;

    float avg_lat, avg_lon, avg_alt, avg_spd;

    float diagonal_distance, altitude_distance;

    vector<gps_point *> points;

    // Points w/in this network
    // vector<point> net_point;

    // Index to the netcolors table
    string color_index;
};

// All networks we know about
map<mac_addr, wireless_network *> bssid_net_map;

// All the networks we know about for drawing
map<string, gps_network *> bssid_gpsnet_map;

typedef struct {
    int version;

    float lat;
    float lon;
    float alt;
    float spd;

    int power;
    int quality;
    int noise;

    unsigned int x, y;
} track_data;

// Array of network track arrays
unsigned int num_tracks = 0;
vector< vector<track_data> > track_vec;
// Global average for map scaling
gps_network global_map_avg;
// Mapquest map scale
long scale;
// Expedia scale =/
long scale2;
// Center lat/lon for map
double map_avg_lat, map_avg_lon;
// Do we have any power data?
int power_data;

// Threads, locks, and graphs to hold the power
pthread_t *mapthread;
pthread_mutex_t power_lock;
pthread_mutex_t print_lock;
unsigned int numthreads = 1;
unsigned int *power_map;
unsigned int power_pos = 0;
pthread_mutex_t power_pos_lock;
int *power_input_map;

// Filtered MAC's
string filter;
int invert_filter = 0;

// color by wep instead of random
int color_wep = 0;
// Color by channel instead of random
int color_channel = 0;

 /*FOLD00*/
// Forward prototypes
string Mac2String(uint8_t *mac, char seperator);
double rad2deg(double x);
double earth_distance(double lat1, double lon1, double lat2, double lon2);
double calcR (double lat);
void calcxy (double *posx, double *posy, double lat, double lon, double pixelfact, /*FOLD00*/
             double zero_lat, double zero_long);
long int BestMapScale(double tlat, double tlon, double blat, double blon);
int ProcessGPSFile(char *in_fname);
void AssignNetColors();
void MergeNetData(vector<wireless_network *> in_netdata);
void ProcessNetData(int in_printstats);
void DrawNetTracks(Image *in_img, DrawInfo *in_di);
void DrawNetCircles(Image *in_img, DrawInfo *in_di);
void DrawNetBoundRects(Image *in_img, DrawInfo *in_di, int in_fill);
void DrawLegend(Image *in_img, DrawInfo *in_di);
void DrawNetCenterDot(Image *in_img, DrawInfo *in_di, int in_dotsize);
int InverseWeight(int in_x, int in_y, int in_fuzz, double in_scale);
void DrawNetPower(Image *in_img, DrawInfo *in_di);
void DrawNetHull(Image *in_img, DrawInfo *in_di);
void DrawNetScatterPlot(Image *in_img, DrawInfo *in_di, int in_dotsize);

//forward here

string Mac2String(uint8_t *mac, char seperator) { /*FOLD00*/
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
 /*FOLD00*/

// Faust Code to convert rad to deg and find the distance between two points
// on the globe.  Thanks, Faust.
//const float M_PI = 3.14159;
double rad2deg(double x) { /*FOLD00*/
     return x*M_PI/180.0;
}

double earth_distance(double lat1, double lon1, double lat2, double lon2) { /*FOLD00*/
    /*
    const double radius = 6378150.0; //meters

    //convert to rads
    double x1 = radius * cos(rad2deg(lon1)) * sin(rad2deg(90-lat1));
    double x2 = radius * cos(rad2deg(lon2)) * sin(rad2deg(90-lat2));
    double y1 = radius * sin(rad2deg(lon1)) * sin(rad2deg(90-lat1));
    double y2 = radius * sin(rad2deg(lon2)) * sin(rad2deg(90-lat2));
    double z1 = radius * cos(rad2deg(90-lat1));
    double z2 = radius * cos(rad2deg(90-lat2));
    double a = acos((x1*x2 + y1*y2 + z1*z2)/pow(radius,2));
    return radius * a;
    */

    double x1 = calcR(lat1) * cos(rad2deg(lon1)) * sin(rad2deg(90-lat1));
    double x2 = calcR(lat2) * cos(rad2deg(lon2)) * sin(rad2deg(90-lat2));
    double y1 = calcR(lat1) * sin(rad2deg(lon1)) * sin(rad2deg(90-lat1));
    double y2 = calcR(lat2) * sin(rad2deg(lon2)) * sin(rad2deg(90-lat2));
    double z1 = calcR(lat1) * cos(rad2deg(90-lat1));
    double z2 = calcR(lat2) * cos(rad2deg(90-lat2));
    double a = acos((x1*x2 + y1*y2 + z1*z2)/pow(calcR((double) (lat1+lat2)/2),2));
    return calcR((double) (lat1+lat2) / 2) * a;
}

//#ifdef 0
// I'm still working on this...

// Lifted from gpsdrive 1.7
// CalcR gets the radius of the earth at a particular latitude
// calcxy finds the x and y positions on a 1280x1024 image of a certian scale
//  centered on a given lat/lon.

// This pulls the "real radius" of a lat, instead of a global guesstimate
double calcR (double lat) /*FOLD00*/
{
    double a = 6378.137, r, sc, x, y, z;
    double e2 = 0.081082 * 0.081082;
    /*
     the radius of curvature of an ellipsoidal Earth in the plane of the
     meridian is given by

     R' = a * (1 - e^2) / (1 - e^2 * (sin(lat))^2)^(3/2)

     where a is the equatorial radius,
     b is the polar radius, and
     e is the eccentricity of the ellipsoid = sqrt(1 - b^2/a^2)

     a = 6378 km (3963 mi) Equatorial radius (surface to center distance)
     b = 6356.752 km (3950 mi) Polar radius (surface to center distance)
     e = 0.081082 Eccentricity
     */

    lat = lat * M_PI / 180.0;
    sc = sin (lat);
    x = a * (1.0 - e2);
    z = 1.0 - e2 * sc * sc;
    y = pow (z, 1.5);
    r = x / y;

    r = r * 1000.0;
    return r;
}

/* Mapscale / pixelfact is meter / pixel */
#define PIXELFACT 2817.947378

void calcxy (double *posx, double *posy, double lat, double lon, double pixelfact, /*FOLD00*/
        double zero_lat, double zero_long)
{
    double dif;

    *posx = (calcR(lat) * M_PI / 180.0) * cos (M_PI * lat / 180.0) * (lon - zero_long);

    *posx = (map_width/2) + *posx / pixelfact;
    //*posx = *posx - xoff;

    *posy = (calcR(lat) * M_PI / 180.0) * (lat - zero_lat);

    dif = calcR(lat) * (1 - (cos ((M_PI * (lon - zero_long)) / 180.0)));

    *posy = *posy + dif / 1.85;
    *posy = (map_height/2) - *posy / pixelfact;
    //*posy = *posy - yoff;
}
//#endif

// Find the best map scale for the 'rectangle' tlat,tlon blat,blon
long int BestMapScale(double tlat, double tlon, double blat, double blon) { /*FOLD00*/
    for (int x = 0; scales[x] != 0; x++) {
        /*
        if (((double) (scales[x] / PIXELFACT) * map_width > width) &&
            ((double) (scales[x] / PIXELFACT) * map_height > height))
            return scales[x];
            */

        double mapx, mapy;
        calcxy (&mapx, &mapy, global_map_avg.max_lat, global_map_avg.max_lon,
                (double) scales[x]/PIXELFACT, map_avg_lat, map_avg_lon);

        if (mapx < 0 || mapx > map_width || mapy < 0 || mapy > map_height)
            continue;
        else {
            // Fudge the scale by 10% for extreme ranges
            if (scales[x] >= 1000000 && scales[x] < 20000000)
                return (long) (scales[x] + (scales[x] * 0.10));
            if (scales[x] >= 20000000)
                return (long) (scales[x] + (scales[x] * 0.15));

            return scales[x];
        }
    }

    return 0;
}

#define geom_distance(a, b, x, y) sqrt(pow((double) (a) - (double) (x), 2) + pow((double) (b) - (double) (y), 2))

// Frank and Nielson's improved weighting algorithm
double WeightAlgo(int start_x, int start_y, int in_x, int in_y, double in_fuzz, double in_scale) { /*FOLD00*/

    // Step 1:  Find 'r', the distance to the farthest interpolation point
    int min_x = 0, min_y = 0;
    int max_x = map_width, max_y = map_height;
    int offset = (int) (in_fuzz/in_scale);

    if (start_x - offset > min_x)
        min_x = start_x - offset;
    if (start_y - offset > min_y)
        min_y = start_y - offset;
    if (start_x + offset < max_x)
        max_x = start_x + offset;
    if (start_y + offset < max_y)
        max_y = start_y + offset;


    printf("startx %d starty %d inx %d iny %d\n", start_x, start_y, in_x, in_y);

    // Find the farthest sample point in this set
    double r = 0;
    for (int cury = min_y; cury < max_y; cury++) {
        for (int curx = min_x; curx < max_x; curx++) {
            if (power_input_map[(map_width * cury) + curx] < 0)
                continue;

//            printf("power map at %d,%d has val %d max %d,%d\n", cury, curx,
//                   power_input_map[(map_width * cury) + curx], max_x, max_y);

            double h = geom_distance(start_x, start_y, curx, cury);
            if (h > r)
                r = h;
        }
    }

    // Construct the 'top half' of the weight function:
    double hi = geom_distance(start_x, start_y, in_x, in_y);
    double top_func = pow( ((r - hi)/(r * hi)), 2);

    double bot_sum = 0;
    // Construct the 'bottom half' of the weight function
    for (int cury = min_y; cury < max_y; cury++) {
        for (int curx = min_x; curx < max_x; curx++) {
            if (power_input_map[(map_width * cury) + curx] < 0)
                continue;

            double hj = geom_distance(start_x, start_y, curx, cury) * 1.8;

            bot_sum += pow( ((r - hj)/(r * hj)), 2);
        }
    }

    // Put it all together and return the influence
    double weight = top_func/bot_sum;

    return weight;
}
 /*FOLD00*/

// Inverse weight calculations -- Shepard's with Frank and Nielson's improved weight
// algorithm
int InverseWeight(int in_x, int in_y, int in_fuzz, double in_scale) { /*FOLD00*/

//    fprintf(stderr, "Getting power on %d %d\n", in_x, in_y);


    int min_x = 0, min_y = 0;
    int max_x = map_width, max_y = map_height;
    int offset = (int) (in_fuzz/in_scale);

    if (in_x - offset > min_x)
        min_x = in_x - offset;
    if (in_y - offset > min_y)
        min_y = in_y - offset;
    if (in_x + offset < max_x)
        max_x = in_x + offset;
    if (in_y + offset < max_y)
        max_y = in_y + offset;

    /*
    fprintf(stderr, "influenced by %d range, %d %d from %d %d to %d %d\n",
            offset, in_x, in_y, min_x, min_y, max_x, max_y);
            */

    if (offset == 0)
        return 0;

    double power_sum = 0;

    for (int cury = min_y; cury < max_y; cury++) {
        for (int curx = min_x; curx < max_x; curx++) {

            if (power_input_map[(map_width * cury) + curx] < 0)
                continue;

            power_sum += WeightAlgo(in_x, in_y, curx, cury, in_fuzz, in_scale) *
                power_input_map[(map_width * cury) + curx];

        }
    }

    return (int) power_sum;

}

void MergeNetData(vector<wireless_network *> in_netdata) {
    for (unsigned int x = 0; x < in_netdata.size(); x++) {
        wireless_network *inet = in_netdata[x];

        if (bssid_net_map.find(inet->bssid) != bssid_net_map.end()) {
            wireless_network *onet = bssid_net_map[inet->bssid];

            if (onet->last_time < inet->last_time) {
                // Update stuff if it's better in the newer data
                onet->last_time = inet->last_time;

                if (onet->type > inet->type)
                    onet->type = inet->type;
                if (inet->ssid != "")
                    onet->ssid = inet->ssid;
                onet->channel = inet->channel;
                if (inet->beacon_info != "")
                    onet->beacon_info = inet->beacon_info;
                if (onet->ipdata.atype < inet->ipdata.atype)
                    memcpy(&onet->ipdata, &inet->ipdata, sizeof(net_ip_data));
                onet->cloaked = inet->cloaked;
                onet->wep = inet->wep;
            }

            if (onet->first_time < inet->first_time)
                onet->first_time = inet->first_time;

            onet->llc_packets += inet->llc_packets;
            onet->data_packets += inet->data_packets;
            onet->crypt_packets += inet->crypt_packets;
            onet->interesting_packets += inet->interesting_packets;
        } else {
            bssid_net_map[inet->bssid] = inet;
        }
    }
}

int ProcessGPSFile(char *in_fname) { /*FOLD00*/
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

    // We have the file correctly, so add to our gps track count
    vector<track_data> trak;
    track_vec.push_back(trak);
    num_tracks++;

    // We have all our gps points loaded into the local struct now, so if they had a
    // network file specified, load the networks from that and mesh it with the network
    // data we already (may) have from ther files.

    int foundnetfile = 0;

    if (XMLFetchGpsNetfile() != "") {
        fprintf(stderr, "NOTICE:  Reading associated network file, '%s'\n", XMLFetchGpsNetfile().c_str());
#ifdef HAVE_LIBZ
        if ((gpsfz = gzopen(XMLFetchGpsNetfile().c_str(), "r")) == NULL) {
            fprintf(stderr, "WARNING:  Could not open associated network xml file '%s', trying compressed...\n",
                    XMLFetchGpsNetfile().c_str());

            string comp = XMLFetchGpsNetfile();
            comp += ".gz";

            if ((gpsfz = gzopen(comp.c_str(), "r")) == NULL) {
                fprintf(stderr, "WARNING:  Could not open associated network xml file '%s' even with .gz suffix.\n",
                        XMLFetchGpsNetfile().c_str());
            } else {
                fprintf(stderr, "NOTICE:  Opened associated network xml file '%s'\n",
                        comp.c_str());
                foundnetfile = 1;
            }
#else
        if ((gpsf = fopen(XMLFetchGpsNetfile().c_str(), "r")) == NULL) {
            fprintf(stderr, "WARNING:  Could not open associated network xml file '%s'\n",
                    XMLFetchGpsNetfile().c_str());

#endif

        }

        if (foundnetfile) {
            fprintf(stderr, "NOTICE:  Processing network XML file.\n");

            vector<wireless_network *> file_networks;
#ifdef HAVE_LIBZ
            file_networks = XMLFetchNetworkList(gpsfz);
#else
            file_networks = XMLFetchNetworkList(gpsf);
#endif
            if (file_networks.size() != 0) {
                // Do something with the networks
                MergeNetData(file_networks);
            } else {
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

    // Now that we have the network data (hopefully) loaded, we'll load the points and
    // reference the networks for them.
    int last_power = 0;
    int power_count = 0;

    for (unsigned int i = 0; i < file_points.size(); i++) {
        // All we have to do here is push the points into the network (and make them
        // one if it doesn't exist).  We crunch all the data points in ProcessNetData
        gps_network *gnet = NULL;

        // Don't process filtered networks at all.
        if ((invert_filter == 0 && filter.find(file_points[i]->bssid) != string::npos) ||
            (invert_filter == 1 && filter.find(file_points[i]->bssid) == string::npos))
            continue;

        // Don't process unfixed points at all
        if (file_points[i]->fix < 2)
            continue;

        double lat, lon, alt, spd;
        int fix;

        lat = file_points[i]->lat;
        lon = file_points[i]->lon;
        alt = file_points[i]->alt;
        spd = file_points[i]->spd;
        fix = file_points[i]->fix;

        global_map_avg.avg_lat += lat;
        global_map_avg.avg_lon += lon;
        global_map_avg.avg_alt += alt;
        global_map_avg.avg_spd += spd;
        global_map_avg.count++;

        if (lat > global_map_avg.max_lat || global_map_avg.max_lat == 0)
            global_map_avg.max_lat = lat;
        if (lat < global_map_avg.min_lat || global_map_avg.min_lat == 0)
            global_map_avg.min_lat = lat;

        if (lon > global_map_avg.max_lon || global_map_avg.max_lon == 0)
            global_map_avg.max_lon = lon;
        if (lon < global_map_avg.min_lon || global_map_avg.min_lon == 0)
            global_map_avg.min_lon = lon;

        if (alt > global_map_avg.max_alt || global_map_avg.max_alt == 0)
            global_map_avg.max_alt = alt;
        if (alt < global_map_avg.min_alt || global_map_avg.min_alt == 0)
            global_map_avg.min_alt = alt;

        if (strncmp(file_points[i]->bssid, gps_track_bssid, MAC_STR_LEN) == 0) {
            track_data tdat;

            tdat.x = 0;
            tdat.y = 0;

            tdat.lat = lat;
            tdat.lon = lon;
            tdat.alt = alt;
            tdat.spd = spd;

            tdat.version = (int) XMLFetchGpsVersion();

            // Filter power ratings
            if (file_points[i]->signal == last_power) {
                if (power_count < 3) {
                    tdat.power = file_points[i]->signal;
                    tdat.quality = file_points[i]->quality;
                    tdat.noise = file_points[i]->noise;
                } else {
                    tdat.power = 0;
                    tdat.quality = 0;
                    tdat.noise = 0;
                }
                power_count++;
            } else {
                last_power = file_points[i]->signal;
                power_count = 0;
                tdat.power = file_points[i]->signal;
                tdat.quality = file_points[i]->quality;
                tdat.noise = file_points[i]->noise;
            }

            if (tdat.power != 0)
                power_data = 1;

            track_vec[num_tracks-1].push_back(tdat);
        } else if (bssid_gpsnet_map.find(file_points[i]->bssid) == bssid_gpsnet_map.end()) {
            //printf("making new netork: %s\n", file_points[i]->bssid);
            gnet = new gps_network;

            gnet->bssid = file_points[i]->bssid;

            if (bssid_net_map.find(file_points[i]->bssid) != bssid_net_map.end())
                gnet->wnet = bssid_net_map[file_points[i]->bssid];
            else
                gnet->wnet = NULL;

            gnet->points.push_back(file_points[i]);

            bssid_gpsnet_map[file_points[i]->bssid] = gnet;

        } else {
            gnet = bssid_gpsnet_map[file_points[i]->bssid];

            gnet->points.push_back(file_points[i]);
        }
    }

    if (verbose)
        fprintf(stderr, "%s contains %d samples.\n", in_fname, file_samples);

    sample_points += file_samples;

    return 1;
}

// Do all the math
void ProcessNetData(int in_printstats) { /*FOLD00*/
    // Convert the tracks to x,y
    if (draw_track != 0 || draw_interpolated != 0) {
        for (unsigned int vec = 0; vec < track_vec.size(); vec++) {
            for (unsigned int x = 0; x < track_vec[vec].size(); x++) {
                double track_tx, track_ty;
                calcxy(&track_tx, &track_ty, track_vec[vec][x].lat, track_vec[vec][x].lon,
                       (double) scale/PIXELFACT, map_avg_lat, map_avg_lon);

                track_vec[vec][x].x = (int) track_tx;
                track_vec[vec][x].y = (int) track_ty;
            }

            if (in_printstats)
                printf("Track %d: %d samples.\n", vec, track_vec[vec].size());
        }
    }

    printf("Processing %d networks.\n", bssid_gpsnet_map.size());

    for (map<string, gps_network *>::const_iterator x = bssid_gpsnet_map.begin();
         x != bssid_gpsnet_map.end(); ++x) {

        gps_network *map_iter = x->second;


        if (map_iter->points.size() <= 1) {
           // printf("net %s only had <= 1 point.\n", map_iter->bssid.c_str());
            continue;
        }

        // Calculate the min/max and average sizes of this network
        for (unsigned int y = 0; y < map_iter->points.size(); y++) {
            float lat = map_iter->points[y]->lat;
            float lon = map_iter->points[y]->lon;
            float alt = map_iter->points[y]->alt;
            float spd = map_iter->points[y]->spd;

            //printf("Got %f %f %f %f\n", lat, lon, alt, spd);

            map_iter->avg_lat += lat;
            map_iter->avg_lon += lon;
            map_iter->avg_alt += alt;
            map_iter->avg_spd += spd;
            map_iter->count++;

            // Enter the max/min values
            if (lat > map_iter->max_lat || map_iter->max_lat == 0)
                map_iter->max_lat = lat;

            if (lat < map_iter->min_lat || map_iter->min_lat == 0)
                map_iter->min_lat = lat;

            if (lon > map_iter->max_lon || map_iter->max_lon == 0)
                map_iter->max_lon = lon;

            if (lon < map_iter->min_lon || map_iter->min_lon == 0)
                map_iter->min_lon = lon;

            if (alt > map_iter->max_alt || map_iter->max_alt == 0)
                map_iter->max_alt = alt;

            if (alt < map_iter->min_alt || map_iter->min_alt == 0)
                map_iter->min_alt = alt;
        }

        map_iter->diagonal_distance = earth_distance(map_iter->max_lat, map_iter->max_lon,
                                                    map_iter->min_lat, map_iter->min_lon);

        map_iter->altitude_distance = map_iter->max_alt - map_iter->min_alt;

        double avg_lat = (double) map_iter->avg_lat / map_iter->count;
        double avg_lon = (double) map_iter->avg_lon / map_iter->count;
        double avg_alt = (double) map_iter->avg_alt / map_iter->count;
        double avg_spd = (double) map_iter->avg_spd / map_iter->count;

        map_iter->avg_lat = avg_lat;
        map_iter->avg_lon = avg_lon;
        map_iter->avg_alt = avg_alt;
        map_iter->avg_spd = avg_spd;

        if (in_printstats)
            printf("Net:     %s [%s]\n"
                   "  Samples : %d\n"
                   "  Min lat : %f\n"
                   "  Min lon : %f\n"
                   "  Max lat : %f\n"
                   "  Max lon : %f\n"
                   "  Min alt : %f\n"
                   "  Max Alt : %f\n"
                   "  Avg Lat : %f\n"
                   "  Avg Lon : %f\n"
                   "  Avg Alt : %f\n"
                   "  Avg Spd : %f\n"
                   "  H. Range: %f ft\n"
                   "  V. Range: %f ft\n",
                   map_iter->wnet == NULL ? "Unknown" : map_iter->wnet->ssid.c_str(),
                   map_iter->bssid.c_str(),
                   map_iter->count,
                   map_iter->min_lat, map_iter->min_lon,
                   map_iter->max_lat, map_iter->max_lon,
                   map_iter->min_alt, map_iter->max_alt,
                   map_iter->avg_lat, map_iter->avg_lon,
                   map_iter->avg_alt, map_iter->avg_spd,
                   map_iter->diagonal_distance * 3.3, map_iter->altitude_distance);
    }
}

void AssignNetColors() { /*FOLD00*/
    int base_color = 1;

    for (map<string, gps_network *>::const_iterator x = bssid_gpsnet_map.begin();
         x != bssid_gpsnet_map.end(); ++x) {

        gps_network *map_iter = x->second;

        if (color_wep) {
            if (map_iter->wnet != NULL) {
                if (MatchBestManuf(map_iter->wnet, 0) == manuf_max_score) {
                    map_iter->color_index = "#0000FF";
                } else if (map_iter->wnet->wep) {
                    map_iter->color_index = "#FF0000";
                } else {
                    map_iter->color_index = "#00FF00";
                }
            } else {
                map_iter->color_index = "#00FF00";
            }
        } else if (color_channel) {
            if (map_iter->wnet != NULL) {
                if (map_iter->wnet->channel < 1 || map_iter->wnet->channel > 14) {
                    map_iter->color_index = "#000000";
                } else {
                    map_iter->color_index = channelcolors[map_iter->wnet->channel - 1];
                }
            }
        } else {
            if (netcolors[base_color] == NULL)
                base_color = 1;

            map_iter->color_index = netcolors[base_color];

            base_color++;
        }
    }
}

void DrawNetTracks(Image *in_img, DrawInfo *in_di) { /*FOLD00*/
    // Our track color
    uint8_t track_r = 0x00, track_g = 0x00, track_b = 0xFF;
    char color_str[8];
    PixelPacket track_clr;

    // Draw each track
    for (unsigned int vec = 0; vec < track_vec.size(); vec++) {
        if (track_vec[vec].size() == 0)
            continue;

        // Generate the color we're drawing with
        snprintf(color_str, 8, "#%02X%02X%02X", track_r, track_g, track_b);

#ifdef OldMagickLib
	QueryColorDatabase(color_str, &track_clr);
#else
	{
	ExceptionInfo excep;
	QueryColorDatabase(color_str, &track_clr, &excep);
	}
#endif

        in_di->stroke = track_clr;

        // Dim the color
        track_b -= track_decay;

        // Reset it if we're "too dark"
        if (track_b < 0x50)
            track_b = 0xFF;

        // Initialize the previous track location vars

        int prev_tx, prev_ty;
        prev_tx = track_vec[vec][0].x;
        prev_ty = track_vec[vec][0].y;

        for (unsigned int x = 1; x < track_vec[vec].size(); x++) {
            char prim[1024];

            // If we don't have a previous vector (ie, the map data failed), set it
            // and continue
            if (prev_tx == -1 || prev_ty == -1) {
                prev_tx = track_vec[vec][x].x;
                prev_ty = track_vec[vec][x].y;
                continue;
            }

            // Scrap dupes
            if (track_vec[vec][x].x == (unsigned int) prev_tx &&
                track_vec[vec][x].y == (unsigned int) prev_ty)
                continue;

            // Scrap stuff entirely off-screen to save on speed
            if (((unsigned int) prev_tx > map_width && (unsigned int) prev_ty > map_height &&
                 track_vec[vec][x].x > map_width && track_vec[vec][x].y > map_height) ||
                (prev_tx < 0 && prev_ty < 0 &&
                 track_vec[vec][x].x < 0 && track_vec[vec][x].y < 0))
                continue;

            // If the track jumps more than 50 meters in 1 second, assume we had a
            // problem and restart the track at the next position
            double distance;
            if ((distance = geom_distance(track_vec[vec][x].x, track_vec[vec][x].y,
                                          prev_tx, prev_ty)) > 50) {
                prev_tx = -1;
                prev_ty = -1;
                continue;
            }

            /* Don't whine about track jumps (for now)
            if (sqrt(pow(track_vec[vec][x].x - prev_tx, 2) + pow(track_vec[vec][x].y - prev_ty, 2)) > 20) {
                printf("Suspicious track record: %dx%d (%fx%f)\n"
                       "Prev: %dx%d (%fx%f)\n",
                       track_vec[vec][x].x, track_vec[vec][x].y,
                       track_vec[vec][x].lat, track_vec[vec][x].lon,
                       prev_tx, prev_ty,
                       track_vec[vec][x-1].lat, track_vec[vec][x-1].lon);
                       }
                       */

            snprintf(prim, 1024, "stroke-width %d line %d,%d %d,%d",
                     track_width,
                     prev_tx, prev_ty, track_vec[vec][x].x, track_vec[vec][x].y);

            in_di->primitive = strdup(prim);
            DrawImage(in_img, in_di);

            prev_tx = track_vec[vec][x].x;
            prev_ty = track_vec[vec][x].y;
        }
    }
}

void DrawNetCircles(Image *in_img, DrawInfo *in_di) { /*FOLD00*/
    for (map<string, gps_network *>::const_iterator x = bssid_gpsnet_map.begin();
         x != bssid_gpsnet_map.end(); ++x) {

        gps_network *map_iter = x->second;

        // Skip networks w/ no determined coordinates
        if (map_iter->max_lat == 0)
            continue;

        if (map_iter->diagonal_distance > horiz_throttle)
            continue;

        // Figure x, y of min on our hypothetical map
        double mapx, mapy;

        calcxy (&mapx, &mapy, map_iter->avg_lat, map_iter->avg_lon,
                (double) scale/PIXELFACT, map_avg_lat, map_avg_lon);

        double end_lat, end_lon;

        // Find the nearest corner of the bounding rectangle, this will determine
        // the size of our network circle
        if (((map_iter->min_lat + map_iter->max_lat) / 2) < map_iter->avg_lat)
            end_lat = map_iter->max_lat;
        else
            end_lat = map_iter->min_lat;
        if (((map_iter->min_lon + map_iter->max_lon)/ 2) < map_iter->avg_lon)
            end_lon = map_iter->max_lon;
        else
            end_lon = map_iter->min_lon;

        double endx, endy;
        calcxy(&endx, &endy, end_lat, end_lon,
               (double) scale/PIXELFACT, map_avg_lat, map_avg_lon);

        // printf("  Endpt   : %dx%d\n", (int) endx, (int) endy);

        PixelPacket netclr;

#ifdef OldMagickLib
        QueryColorDatabase(map_iter->color_index.c_str(), &netclr);
#else
	{
	ExceptionInfo excep;
        QueryColorDatabase(map_iter->color_index.c_str(), &netclr, &excep);
	}
#endif

        in_di->fill = netclr;
        in_di->stroke = netclr;

        char prim[1024];

        snprintf(prim, 1024, "fill-opacity %d%% stroke-opacity %d%% circle %d,%d %d,%d",
                 draw_opacity, draw_opacity, (int) mapx, (int) mapy, (int) endx, (int) endy);

        in_di->primitive = strdup(prim);
        DrawImage(in_img, in_di);
    }
}

double clockwize( int x0, int y0, int x1, int y1, int x2, int y2) { /*FOLD00*/
	return ( x2 - x0 ) * ( y1 - y0 ) - ( x1 - x0 ) * ( y2 - y0 );
}

void DrawNetHull(Image *in_img, DrawInfo *in_di) { /*FOLD00*/
    for (map<string, gps_network *>::const_iterator x = bssid_gpsnet_map.begin();
         x != bssid_gpsnet_map.end(); ++x) {

        gps_network *map_iter = x->second;

        // Skip networks w/ no determined coordinates
        if (map_iter->max_lat == 0)
            continue;

        if (map_iter->diagonal_distance > horiz_throttle)
            continue;

        map<string, hullPoint> dim;
        for (unsigned int x = 0; x < map_iter->points.size(); x++) {
            gps_point *pt = map_iter->points[x];
            double mapx, mapy;

            calcxy (&mapx, &mapy, pt->lat, pt->lon,
                    (double) scale/PIXELFACT, map_avg_lat, map_avg_lon);

            char mm1[64];
            snprintf(mm1, 64, "%d,%d", (int) mapx, (int) mapy);
            string a = mm1;
            hullPoint b;
            b.x = (int) mapx;
            b.y = (int) mapy;
            b.angle = 0.0;
            b.xy = a;
            dim[a] = b;
	}

	// need at least 3 points for a hull

	//printf("\nPts: %d\n", dim.size());
	if (dim.size() < 3)
		continue;

	// got the unique points, now we need to sort em
        deque<hullPoint> pts;
	for (map<string, hullPoint>::const_iterator i = dim.begin(); i != dim.end(); ++i) {
		pts.push_back(i->second);
	}
	sort(pts.begin(), pts.end());

	//start point for the hull
	hullPoint start = pts[0];
	pts.pop_front();

	//compute angles for pts
	for (deque<hullPoint>::iterator j = pts.begin(); j != pts.end(); ++j) {
		j->angle = atan2( j->y - start.y, j->x - start.x );
	}

	//sort against angle
	sort(pts.begin(), pts.end(), hullPoint() );

	//build the hull
	vector<hullPoint> hull;
	hull.push_back(start);
	hullPoint tmp = pts[0];
	hull.push_back(tmp);
	pts.push_front(start);

        for (unsigned int k = 2; k < pts.size() ; k++) {
            while (clockwize(hull[hull.size()-2].x,
                             hull[hull.size()-2].y,
                             hull[hull.size()-1].x,
                             hull[hull.size()-1].y,
                             pts[k].x,
                             pts[k].y) >= 0
                   && hull.size() >= 2) {
                hull.pop_back();
            }
            hull.push_back(pts[k]);
        }

        if (hull.size() < 3)
            continue;
			
	//wheh
        /*
         printf("Hull:\n");
         for(vector<hullPoint>::const_iterator l = hull.begin(); l != hull.end(); ++l) {
         printf("x: %d y: %d a: %f\n", l->x, l->y, l->angle);
         }
         printf("orig:\n");
         for(deque<hullPoint>::const_iterator l = pts.begin(); l != pts.end(); ++l) {
         printf("x: %d y: %d a: %f\n", l->x, l->y, l->angle);
         }
         */

        PixelPacket netclr;

#ifdef OldMagickLib
	QueryColorDatabase(map_iter->color_index.c_str(), &netclr);
#else
	{
	ExceptionInfo excep;
 	QueryColorDatabase(map_iter->color_index.c_str(), &netclr, &excep);
	}
#endif

        in_di->fill = netclr;

        string sep = ", ";
        string pstr = "";
        for(vector<hullPoint>::const_iterator l = hull.begin(); l != hull.end(); ++l) {
            pstr = pstr + l->xy + sep;
	}
        pstr = pstr + start.xy;

        char pstr2[2048];
        memset(pstr2, 0, sizeof(char)*2048);
	pstr.copy(pstr2, string::npos);

	char prim[2048];
        snprintf(prim, 1024, "fill-opacity %d%% stroke-opacity %d%% polygon %s",
                 draw_opacity, draw_opacity, pstr2);

	//printf("%s\n", prim);
	
        in_di->primitive = strdup(prim);
        DrawImage(in_img, in_di);
    }

}

void DrawNetBoundRects(Image *in_img, DrawInfo *in_di, int in_fill) { /*FOLD00*/
    for (map<string, gps_network *>::const_iterator x = bssid_gpsnet_map.begin();
         x != bssid_gpsnet_map.end(); ++x) {

        gps_network *map_iter = x->second;

        // Skip networks w/ no determined coordinates
        if (map_iter->max_lat == 0)
            continue;

        if (map_iter->diagonal_distance == 0 || map_iter->diagonal_distance > horiz_throttle)
            continue;

        // Figure x, y of min on our hypothetical map
        double mapx, mapy;
        calcxy (&mapx, &mapy, map_iter->max_lat, map_iter->max_lon,
                (double) scale/PIXELFACT, map_avg_lat, map_avg_lon);

        double endx, endy;
        calcxy(&endx, &endy, map_iter->min_lat, map_iter->min_lon,
               (double) scale/PIXELFACT, map_avg_lat, map_avg_lon);

        double tlx, tly, brx, bry;

        if (mapx < endx) {
            tlx = mapx;
            brx = endx;
        } else {
            tlx = endx;
            brx = mapx;
        }

        if (mapy < endy) {
            tly = mapy;
            bry = endy;
        } else {
            tly = endy;
            bry = mapy;
        }

        if (in_fill) {
            PixelPacket netclr;
#ifdef OldMagickLib
	QueryColorDatabase(map_iter->color_index.c_str(), &netclr);
#else
	{
	ExceptionInfo excep;
	QueryColorDatabase(map_iter->color_index.c_str(), &netclr, &excep);
	}
#endif
            in_di->fill = netclr;
        }

        char prim[1024];

        snprintf(prim, 1024, "stroke black fill-opacity %d%% rectangle %d,%d %d,%d",
                 in_fill, (int) mapx, (int) mapy, (int) endx, (int) endy);

        //snprintf(prim, 1024, "fill-opacity %d%% rectangle %d,%d %d,%d",
        //in_fill, (int) tlx, (int) tly, (int) brx, (int) bry);


        in_di->primitive = strdup(prim);
        DrawImage(in_img, in_di);

        /*
        //d = sqrt[(x1-x2)^2 + (y1-y2)^2]
        printf("  Px RLen : %d\n", (int) sqrt(pow((int) mapx - endx, 2) + pow((int) mapy - endy, 2)));
        */

    }
}

void DrawLegend(Image *in_img, DrawInfo *in_di) { /*FOLD00*/



}

// Thread function to compute a line of interpolated data

typedef struct powerline_arg {
//    unsigned int y;
//    unsigned int y_max;
    unsigned int in_res;
    unsigned int threadno;
};

void *PowerLine(void *arg) { /*FOLD00*/
    powerline_arg *parg = (powerline_arg *) arg;
    time_t startline;

//    unsigned int y_offset = parg->y;
//    unsigned int y_max = parg->y_max;
    unsigned int in_res = parg->in_res;
    unsigned int y = 0;

    while (y < map_height) {
        pthread_mutex_lock(&power_pos_lock);
        y = power_pos * in_res;
        power_pos++;
        pthread_mutex_unlock(&power_pos_lock);

        if (y >= map_height)
            break;

        //    for (unsigned int y = y_offset; y < map_height; y+= (in_res * numthreads)) {
        startline = time(0);

        pthread_mutex_lock(&print_lock);
        fprintf(stderr, "Thread %d: crunching interpolation image line %d\n", parg->threadno, y);
        pthread_mutex_unlock(&print_lock);

        for (unsigned int x = 0; x < map_width; x+= in_res) {
            unsigned int powr = InverseWeight(x, y, (int) (scale/100), (double) scale/PIXELFACT);

            pthread_mutex_lock(&power_lock);
            power_map[(map_width * y) + x] = powr;

            pthread_mutex_unlock(&power_lock);
        }

        if (verbose) {
            pthread_mutex_lock(&print_lock);
            int elapsed = time(0) - startline;
            int complet = elapsed * ((map_height - y) / in_res);

            fprintf(stderr, "Completed in %d seconds.  (Estimated: %dh %dm %ds to completion)\n",
                    elapsed, (complet/60)/60, (complet/60) % 60, complet % 60);
            pthread_mutex_unlock(&print_lock);
        }

    }

    pthread_exit((void *) 0);
}

void DrawNetPower(Image *in_img, DrawInfo *in_di, int in_res) { /*FOLD00*/
    PixelPacket point_clr;
    pthread_attr_t attr;

    power_map = (unsigned int *) malloc(sizeof(unsigned int) * (map_width * map_height));
    memset(power_map, 0, sizeof(unsigned int) * (map_width * map_height));

    power_input_map = (int *) malloc(sizeof(int) * (map_width * map_height));
    memset(power_input_map, -1, sizeof(int) * (map_width * map_height));

    // Convert the power data in the tracks into a 2d map
    fprintf(stderr, "Converting track power data to coordinate mesh...\n");
    for (unsigned int vec = 0; vec < track_vec.size(); vec++) {
        for(unsigned int i = 0; i < track_vec[vec].size(); i++) {

            if (track_vec[vec][i].version < 2)
                continue;

            unsigned int curx = track_vec[vec][i].x, cury = track_vec[vec][i].y;

            if (curx >= map_width || cury >= map_height || curx < 0 || cury < 0)
                continue;

            /*
            printf("comparing map %d,%d val %d to %d\n", curx, cury,
            power_input_map[(map_width * cury) + curx], track_vec[vec][i].power);
            */

            if (power_input_map[(map_width * cury) + curx] < track_vec[vec][i].power &&
                track_vec[vec][i].power != 0) {
                power_input_map[(map_width * cury) + curx] = track_vec[vec][i].power;
            }

        }
    }

    fprintf(stderr, "Interpolating power into graph points.\n");
    // Slice the map into pieces and assign it to the threads, averaging high - if it's
    // not evenly divisible the last thread may get less work to do than the others.
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    powerline_arg *pargs = new powerline_arg[numthreads];
    for (unsigned int t = 0; t < numthreads; t++) {
        pargs[t].in_res = in_res;
        pargs[t].threadno = t;

        pthread_create(&mapthread[t], &attr, PowerLine, (void *) &pargs[t]);
    }

    pthread_attr_destroy(&attr);

    // Now wait for the threads to complete and come back
    int thread_status;
    for (unsigned int t = 0; t < numthreads; t++) {
        pthread_join(mapthread[t], (void **) &thread_status);
    }

    fprintf(stderr, "Drawing interpolated power levels to map.\n");
    for (unsigned int y = 0; y < map_height; y += in_res) {
        for (unsigned int x = 0; x < map_width; x += in_res) {
            //            int powr = InverseWeight(x, y, 200, (double) scale/PIXELFACT);
            int powr = power_map[(map_width * y) + x];

            //printf("Got weight %d for pixel %d,%d\n", powr, x, y);

            if (powr > 0) {

                int power_index = powr / (power_max / power_steps);
                if (powr < (power_max / power_steps) / 2)
                    continue;

                if (power_index >= power_steps)
                    power_index = power_steps - 1;

#ifdef OldMagickLib
		QueryColorDatabase(powercolors[power_index], &point_clr);
#else
		{
		ExceptionInfo excep;
		QueryColorDatabase(powercolors[power_index], &point_clr, &excep);
		}
#endif

                in_di->stroke = point_clr;
                in_di->fill = point_clr;

                char prim[1024];

                int b, r;

                if (in_res == 1) {
                    snprintf(prim, 1024, "fill-opacity %d%% stroke-opacity %d%% stroke-width 0 point %d,%d",
                         draw_opacity, draw_opacity, x, y);
                } else {
                    r = x + in_res - 1;
                    b = y + in_res - 1;
                    snprintf(prim, 1024, "fill-opacity %d%% stroke-opacity %d%% stroke-width 0 rectangle %d,%d %d,%d",
                         draw_opacity, draw_opacity, x, y, r, b);
                }

                //printf("%d,%d power %d\n", x, y, powr);
                //snprintf(prim, 1024, "fill-opacity %d%% stroke-opacity %d%% stroke-width 1 rectangle %d,%d %d,%d",
                //         draw_opacity, draw_opacity, x, y, r, b);

                in_di->primitive = strdup(prim);
                DrawImage(in_img, in_di);

            }
        }

    }

    delete power_map;
}

void DrawNetCenterDot(Image *in_img, DrawInfo *in_di, int in_dotsize) {
    for (map<string, gps_network *>::const_iterator x = bssid_gpsnet_map.begin();
         x != bssid_gpsnet_map.end(); ++x) {

        gps_network *map_iter = x->second;

        // Skip networks w/ no determined coordinates
        if (map_iter->max_lat == 0)
            continue;

        if (map_iter->diagonal_distance > horiz_throttle)
            continue;


        // Figure x, y of min on our hypothetical map
        double mapx, mapy;

        calcxy (&mapx, &mapy, map_iter->avg_lat, map_iter->avg_lon,
                (double) scale/PIXELFACT, map_avg_lat, map_avg_lon);

        double endx, endy;
        endx = mapx + in_dotsize;
        endy = mapy + in_dotsize;

        // printf("  Endpt   : %dx%d\n", (int) endx, (int) endy);

        PixelPacket netclr;
#ifdef OldMagickLib
	QueryColorDatabase(map_iter->color_index.c_str(), &netclr);
#else
	{
            ExceptionInfo excep;
            QueryColorDatabase(map_iter->color_index.c_str(), &netclr, &excep);
	}
#endif
        in_di->fill = netclr;
        in_di->stroke = netclr;

        char prim[1024];

        snprintf(prim, 1024, "fill-opacity 100%% stroke-opacity 100%% circle %d,%d %d,%d",
                 (int) mapx, (int) mapy, (int) endx, (int) endy);
        in_di->primitive = strdup(prim);
        DrawImage(in_img, in_di);
    }
}

void DrawNetCenterText(Image *in_img, DrawInfo *in_di, int in_textmode) {
    for (map<string, gps_network *>::const_iterator x = bssid_gpsnet_map.begin();
         x != bssid_gpsnet_map.end(); ++x) {

        gps_network *map_iter = x->second;

        // Skip networks w/ no determined coordinates
        if (map_iter->max_lat == 0)
            continue;

        if (map_iter->diagonal_distance > horiz_throttle)
            continue;

        // Figure x, y of min on our hypothetical map
        double mapx, mapy;

        calcxy (&mapx, &mapy, map_iter->avg_lat, map_iter->avg_lon,
                (double) scale/PIXELFACT, map_avg_lat, map_avg_lon);

        PixelPacket netclr;

        char prim[1024];

#ifdef OldMagickLib
        QueryColorDatabase("#000000", &netclr);
#else
        {
            ExceptionInfo excep;
            QueryColorDatabase("#000000", &netclr, &excep);
        }
#endif

        in_di->fill = netclr;
        in_di->stroke = netclr;

        snprintf(prim, 1024, "gravity center fill-opacity 100%% stroke-opacity 100%% text %d,%d \"%s%s\"",
                 (int) mapx, (int) mapy + 8,
                 in_textmode & 1 ? map_iter->bssid.c_str() : "",
                 (in_textmode & 2 && map_iter->wnet != NULL) ? map_iter->wnet->ssid.c_str() : "");
        in_di->primitive = strdup(prim);
        DrawImage(in_img, in_di);

    }
}


void DrawNetScatterPlot(Image *in_img, DrawInfo *in_di, int in_dotsize) { /*FOLD00*/
    for (map<string, gps_network *>::const_iterator x = bssid_gpsnet_map.begin();
         x != bssid_gpsnet_map.end(); ++x) {

        gps_network *map_iter = x->second;

        // Skip networks w/ no determined coordinates
        if (map_iter->max_lat == 0)
            continue;

        if (map_iter->diagonal_distance > horiz_throttle)
            continue;

	// hehe, cheating with a hash
        map<string, string> dim;
        for (unsigned int y = 0; y < map_iter->points.size(); y++) {
            gps_point *pt = map_iter->points[y];

            double mapx, mapy;
            calcxy (&mapx, &mapy, pt->lat, pt->lon, (double) scale/PIXELFACT, map_avg_lat, map_avg_lon);

            double endx, endy;
            endx = mapx + in_dotsize;
            endy = mapy + in_dotsize;

            char mm1[64];
            snprintf(mm1, 64, "%d,%d", (int) mapx, (int) mapy);
            char mm2[64];
            snprintf(mm2, 64, "%d,%d", (int) endx, (int) endy);
            string a = mm1;
            string b = mm2;
            dim[a] = b;
        }

        PixelPacket netclr;

#ifdef OldMagickLib
	QueryColorDatabase(map_iter->color_index.c_str(), &netclr);
#else
	{
	ExceptionInfo excep;
	QueryColorDatabase(map_iter->color_index.c_str(), &netclr, &excep);
	}
#endif

	in_di->fill = netclr;

	for (map<string, string>::const_iterator y = dim.begin(); y != dim.end(); ++y) {
	       char mm1[64];
	       memset(mm1, 0, sizeof(char)*64);
	       char mm2[64];
	       memset(mm2, 0, sizeof(char)*64);
	       y->first.copy(mm1, string::npos);
	       y->second.copy(mm2, string::npos);

		char prim[1024];

		snprintf(prim, 1024, "fill-opacity %d%% stroke-opacity %d%% circle %s %s", 
			draw_opacity, draw_opacity, mm1, mm2);

		in_di->primitive = strdup(prim);
		DrawImage(in_img, in_di);
	       
	}

    }

}


int Usage(char *argv, int ec = 1) { /*FOLD00*/
    printf("Usage: %s [OPTION] <GPS files>\n", argv);
    printf(
           "  -c, --coords <x,y,s>         Force map center at x,y of scale s\n"
	   "  -S, --scale <s>              Force scale to be s\n"
           "  -u, --user-image-size <x,y>  Custom map size\n"
           "  -m, --user-map <map>         Use custom map instead of downloading\n"
           "  -t, --disable-draw-track     Disable drawing travel track\n"
           "  -b, --draw-bounds            Draw bounding rectangles\n"
           "  -r, --disable-draw-range     Disable drawing estimated range circles\n"
           "  -w, --color-wep              Color based on WEP instead of progressive\n"
           "  -N, --color-channel          Color based on network channel\n"
           "  -H, --draw-hull              Draw hull of data points\n"
           "  -p, --draw-scatter-plot      Draw network data points\n"
           "  -i, --draw-interpolated      Draw interpolated power\n"
           "  -s, --interpolated-size      Resolution to interpolate with\n"
           "  -C, --interpolated-color     Alternate interpolated power color set\n"
           "                               1 is a gradiant though RGB colorspace (12 colors)\n"
           "                               2 is weathermap radar style (9 colors)\n"
           "  -d, --draw-center-dot        Draw a dot at the center of the network range\n"
           "  -D, --dot-size <size>        Point size for center dot and scatter plot\n"
           "                               [Default: 3]\n"
           "  -L, --label <types>          Label points.  Comma seperated list of label data,\n"
           "                                (bssid, ssid)\n"
           "  -O, --opacity <num>          Opacity of drawn elements [Default: 70]\n"
           "  -g, --no-greyscale           Don't convert map to greyscale\n"
           "  -k, --keep-gif               Keep the downloaded GIF\n"
           "  -T, --threads <num>          Number of simultaneous threads used for complex\n"
           "                               operations\n"
           "  -M, --metric                 Fetch metric-titled map\n"
           "  -F, --filter <MAC list>      Comma-seperated ALL CAPS list of MAC's to filter\n"
           "  -I, --invert-filter          Invert filtering (ONLY draw filtered MAC's)\n"
           "  -v, --verbose                Verbose output while running\n"
           "  -o, --output <filename>      Output .png file\n"
           "  -f, --config-file <file>     Alternate config file\n"
           "  -V, --version                GPSMap version\n"
           "  -h, --help                   What do you think you're reading?\n");
    exit(ec);
}

char *exec_name;

int main(int argc, char *argv[]) { /*FOLD00*/
    exec_name = argv[0];

    char mapname[1024];
    char mapoutname[1024];

    unsigned int metric = 0;

    static struct option long_options[] = {   /* options table */
        { "disable-draw-track", no_argument, 0, 't' },
        { "scale", required_argument, 0, 'S' },
        { "draw-bounds", no_argument, 0, 'b' },
        { "disable-draw-range", no_argument, 0, 'r' },
        { "draw-interpolated", no_argument, 0, 'i' },
        { "interpolated-size", required_argument, 0, 's' },
        { "disable-draw-legend", no_argument, 0, 'l' },
        { "net-colors", required_argument, 0, 'c' },
        { "output", required_argument, 0, 'o' },
        { "opacity", required_argument, 0, 'O' },
        { "no-greyscale", no_argument, 0, 'g' },
        { "keep-gif", no_argument, 0, 'k' },
        { "user-image-size", required_argument, 0, 'u' },
        { "user-map", required_argument, 0, 'm' },
        { "quiet", no_argument, 0, 'q' },
        { "threads", required_argument, 0, 'T' },
        { "help", no_argument, 0, 'h' },
        { "verbose", no_argument, 0, 'v' },
        { "version", no_argument, 0, 'V' },
        { "draw-center-dot", no_argument, 0, 'd' },
        { "interpolated-color", required_argument, 0, 'C' },
        { "metric", no_argument, 0, 'M' },
        { "draw-hull", no_argument, 0, 'H' },
        { "draw-scatter-plot", no_argument, 0, 'p' },
        { "dot-size", required_argument, 0, 'D' },
        { "filter", required_argument, 0, 'F' },
        { "invert-filter", no_argument, 0, 'I' },
        { "config-file", required_argument, 0, 'f' },
        { "color-wep", no_argument, 0, 'w' },
        { "color-channel", no_argument, 0, 'N' },
        { "label", required_argument, 0, 'L' },
        { 0, 0, 0, 0 }
    };
    int option_index;

    int usermap = 0;
    memset(mapname, 0, 1024);
    memset(mapoutname, 0, 1024);

    draw_track = 1;
    draw_bounds = 0;
    draw_range = 1;
    draw_interpolated = 0;
    draw_legend = 1;
    convert_greyscale = 1;
    keep_gif = 0;
    draw_center = 0;
    center_dot = 3;
    draw_opacity = 70;
    verbose = 0;
    power_data = 0;
    interpolation_res = 2;
    power_steps = power_steps_Orig;
    powercolors = powercolors_Orig;
    draw_hull = 0;

    float user_lat, user_lon;
    long user_scale = 0;

    user_lat = user_lon = 0;

    sample_points = 0;

    char *configfile = NULL;

    int label = 0;

    while(1) {
        int r = getopt_long(argc, argv, "S:T:tbrils:c:o:m:O:gqu:hvdkC:MHVpD:f:IwL:N",
                            long_options, &option_index);

        if (r < 0) break;

        switch(r) {
        case 't':
            draw_track = 0;
            break;
        case 'b':
            draw_bounds = 1;
            break;
        case 'r':
            draw_range = 0;
            break;
        case 'i':
            draw_interpolated = 1;
            break;
        case 's':
            if (sscanf(optarg, "%d", &interpolation_res) != 1) {
                fprintf(stderr, "Invalid interpolation resolution.\n");
                Usage(argv[0]);
            }

            if (interpolation_res <= 0) {
                fprintf(stderr, "Interpolation resolution must be 1 or higher.  Setting to 2.\n");
                interpolation_res = 2;
            }

            break;
        case 'l':
            draw_legend = 0;
            break;
	case 'S':
	    if (sscanf(optarg, "%ld", &user_scale) != 1) {
		    fprintf(stderr, "Invalid custom scale.\n");
		    Usage(argv[0]);
	    }
	    break;
	case 'c':
            if (sscanf(optarg, "%f,%f,%ld", &user_lat, &user_lon,
                       &user_scale) != 3) {
                fprintf(stderr, "Invalid custom map coordinates.\n");
                Usage(argv[0]);
            }
            break;
        case 'u':
            if (sscanf(optarg, "%d,%d", &map_width, &map_height) != 2) {
                fprintf(stderr, "Invalid custom map size.\n");
                Usage(argv[0]);
            }
            break;
        case 'm':
            snprintf(mapname, 1024, "%s", optarg);
            usermap = 1;
            break;
        case 'M':
            metric = 1;
            break;
        case 'o':
            snprintf(mapoutname, 1024, "%s", optarg);
            break;
        case 'T':
            if (sscanf(optarg, "%d", &numthreads) != 1) {
                fprintf(stderr, "Invalid number of threads.\n");
                Usage(argv[0]);
            }
            break;
        case 'O':
            if (sscanf(optarg, "%d", &draw_opacity) != 1) {
                fprintf(stderr, "Invalid opacity.\n");
                Usage(argv[0]);
            }
            break;
        case 'D':
            if (sscanf(optarg, "%d", &center_dot) != 1) {
                fprintf(stderr, "Invalid center dot size.\n");
                Usage(argv[0]);
            }
            break;
        case 'd':
            draw_center = 1;
            break;
        case 'g':
            convert_greyscale = 0;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'k':
            keep_gif = 1;
            break;
        case 'C':
            {
            int icolor;
            if (sscanf(optarg, "%d", &icolor) !=1) {
                fprintf(stderr, "Invalid interpolation color set\n");
                Usage(argv[0]);
            }
            if (icolor == 1) {
   		power_steps = power_steps_Math;
    		powercolors = powercolors_Math;
            } else if (icolor == 2) {
   		power_steps = power_steps_Radar;
    		powercolors = powercolors_Radar;
            }
            }
            break;
        case 'H':
            draw_hull = 1;
            break;
        case 'F':
            filter = optarg;
            printf("NOTICE:  Filtering MAC addresses: %s\n", optarg);
            break;
        case 'I':
            invert_filter = 1;
            printf("NOTICE:  Inverting MAC address filter.\n");
            break;
        case 'f':
            configfile = optarg;
            printf("NOTICE:  Using alternate config file %s\n", optarg);
            break;
        case 'p':
            draw_scatter = 1;
            break;
        case 'w':
            printf("NOTICE:  Coloring based on WEP/Default\n");
            color_wep = 1;
            break;
        case 'N':
            printf("NOTICE:  Coloring based on network channel\n");
            color_channel = 1;
            break;
        case 'L':
            if (strstr(optarg, "bssid"))
                label |= 1;
            if (strstr(optarg, "ssid"))
                label |= 2;
            break;
        case 'h':
            Usage(argv[0], 0);
            break;
        case 'V':
            printf("GPSMap v%i.%i\n", MAJOR, MINOR);
            exit(0);
            break;
        default:
            Usage(argv[0]);
            break;
        }
    }

    ConfigFile conf;

    // If we haven't gotten a command line config option...
    if (configfile == NULL) {
        configfile = (char *) malloc(1024*sizeof(char));
        snprintf(configfile, 1024, "%s/%s", SYSCONF_LOC, config_base);
    }

    // Parse the config and load all the values from it and/or our command
    // line options.  This is a little soupy but it does the trick.
    if (conf.ParseConfig(configfile) < 0) {
        fprintf(stderr, "WARNING:  Couldn't open config file '%s'.  Will continue anyway.\n",
                configfile);
        configfile = NULL;
    }

    if (configfile != NULL) {
        if (filter.length() == 0) {
            if (conf.FetchOpt("macfilter") != "") {
                filter = conf.FetchOpt("macfilter");
                printf("NOTICE:  Filtering MAC addresses: %s\n", filter.c_str());
            }
        }
    }

    // Catch a null-draw condition
    if (invert_filter == 1 && filter.length() == 0) {
        fprintf(stderr, "FATAL:  Inverse filtering requested but no MAC's given to draw.\n");
        exit(1);
    }

    // Initialize stuff
    num_tracks = 0;
//    memset(&global_map_avg, 0, sizeof(gps_network));

    // Build the threads
    mapthread = (pthread_t *) malloc(sizeof(pthread_t) * numthreads);
    pthread_mutex_init(&power_lock, NULL);
    pthread_mutex_init(&print_lock, NULL);
    pthread_mutex_init(&power_pos_lock, NULL);

    // Imagemagick stuff
    Image *img = NULL;
    ImageInfo *img_info;
    ExceptionInfo exception;
    DrawInfo *di;

    InitializeMagick(*argv);
    GetExceptionInfo(&exception);
    img_info = CloneImageInfo((ImageInfo *) NULL);

    if (optind == argc) {
        fprintf(stderr, "FATAL:  Must provide at least one dump file.\n");
        Usage(argv[0]);
    }

    for (int x = optind; x < argc; x++) {
        if (ProcessGPSFile(argv[x]) < 0) {
            fprintf(stderr, "WARNING:  Unrecoverable error processing GPS data file \"%s\", skipping.\n",
                    argv[x]);
            //exit(1);
        }
    }

    fprintf(stderr, "Processing %d sample points.\n",
            sample_points);

    map_avg_lat = (double) (global_map_avg.min_lat + global_map_avg.max_lat) / 2;
    map_avg_lon = (double) (global_map_avg.min_lon + global_map_avg.max_lon) / 2;

    // Fit the whole map
    scale = BestMapScale(global_map_avg.min_lat, global_map_avg.min_lon,
                         global_map_avg.max_lat, global_map_avg.max_lon);

    fprintf(stderr, "Map image scale: %ld\n", scale);
    fprintf(stderr, "Minimum Corner (lat/lon): %f x %f\n", global_map_avg.min_lat,
            global_map_avg.min_lon);
    fprintf(stderr, "Maximum Corner (lat/lon): %f x %f\n", global_map_avg.max_lat,
            global_map_avg.max_lon);
    fprintf(stderr, "Map center (lat/lon): %f x %f\n", map_avg_lat, map_avg_lon);

    if (user_scale != 0) {
        fprintf(stderr, "Overriding with user scale: %ld\n", user_scale);
        
	scale = user_scale;
    }

    if (user_lat != 0) {
        fprintf(stderr, "Overriding with user map center (lat/lon): %f x %f\n", user_lat, user_lon);

        map_avg_lat = user_lat;
        map_avg_lon = user_lon;
    }

    if (scale == 0) {
        fprintf(stderr, "Unable to find a map at any scale to fit the data.\n");
        exit(0);
    }

    if (!usermap) {
        snprintf(mapname, 1024, "map_%f_%f_%ld_%d_%d.gif", map_avg_lat, map_avg_lon,
                 scale, map_width, map_height);
    }

    if (mapoutname[0] == '\0')
        snprintf(mapoutname, 1024, "map_%f_%f_%ld_%d_%d.png", map_avg_lat, map_avg_lon,
                 scale, map_width, map_height);

    printf("Loading map into Imagemagick structures.\n");
    strcpy(img_info->filename, mapname);
    img = ReadImage(img_info, &exception);

    if (img == (Image *) NULL) {
        if (usermap) {
            printf("Unable to load '%s'\n", mapname);
            exit(1);
        }

        char url[1024];

        scale2 = (long) (scale / 1378.6);

        snprintf(url, 1024, url_template, map_avg_lat, map_avg_lon, scale2,
                 map_width, map_height);
//                 metric ? "&DU=KM" : ""); // poptix -- there is no scale on mappoint

        printf("Map url: %s\n", url);
        printf("Fetching map...\n");

        char geturl[1024];
        snprintf(geturl, 1024, download_template, url, mapname);
        system(geturl);

        printf("Loading map into Imagemagick structures.\n");
        strcpy(img_info->filename, mapname);
        img = ReadImage(img_info, &exception);
    }

    if (img == (Image *) NULL) {
        fprintf(stderr, "FATAL:  ImageMagick error:\n");
        MagickError(exception.severity,exception.reason,exception.description);
        exit(0);
    }

    strcpy(img_info->filename, mapoutname);
    strcpy(img->filename, mapoutname);

    di = CloneDrawInfo(img_info, NULL);

    // Convert it to greyscale and then back to color
    if (convert_greyscale) {
        fprintf(stderr, "Converting map to greyscale.\n");
        SetImageType(img, GrayscaleType);
        SetImageType(img, TrueColorType);
    }

    fprintf(stderr, "Calculating network coordinates and statistics...\n");
    ProcessNetData(verbose);

    fprintf(stderr, "Assigning network colors...\n");
    AssignNetColors();

    if (draw_track) {
        fprintf(stderr, "Drawing track coordinates...\n");
        DrawNetTracks(img, di);
    }

    if (draw_scatter) {
        fprintf(stderr, "Drawing scatter plot, dot size %d...\n", center_dot);
        DrawNetScatterPlot(img, di, center_dot);
    }

    if (draw_interpolated && power_data == 0) {
        fprintf(stderr, "ERROR:  Interpolated power drawing requested, but none of the GPS datafiles being\n"
                "processed have power data.  Not doing interpolated graphing.\n");
    } else if (draw_interpolated) {
        fprintf(stderr, "Drawing network power interpolations...\n");

        DrawNetPower(img, di, interpolation_res);
    }

    if (draw_range) {
        fprintf(stderr, "Calculating and drawing network circles...\n");
        DrawNetCircles(img, di);
    }

    if (draw_hull) {
	fprintf(stderr, "Calculating and drawing network hulls...\n");
	DrawNetHull(img, di);
    }

    if (draw_bounds) {
        fprintf(stderr, "Calculating and drawing bounding rectangles...\n");
        DrawNetBoundRects(img, di, 0);
    }

    if (draw_center) {
        fprintf(stderr, "Drawing center dot, size %d...\n", center_dot);
        DrawNetCenterDot(img, di, center_dot);
    }

    if (label) {
        fprintf(stderr, "Labeling networks...\n");
        DrawNetCenterText(img, di, label);
    }

    WriteImage(img_info, img);

    DestroyDrawInfo(di);
    DestroyImage(img);

    DestroyMagick();

    delete mapthread;

    if (!keep_gif && !usermap) {
        fprintf(stderr, "Unlinking downloaded map.\n");
        unlink(mapname);
    }

}

#endif

