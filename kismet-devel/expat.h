#ifndef __EXPAT_H__
#define __EXPAT_H__

#include "config.h"

#include <stdio.h>
#include <vector>
#include <string>
#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#include "tracktypes.h"
#include "gpsdump.h"

#ifdef HAVE_LIBZ
vector<wireless_network *> XMLFetchNetworkList(gzFile in_file);
#else
vector<wireless_network *> XMLFetchNetworkList(FILE *in_file);
#endif
time_t XMLFetchNetworkStart();
time_t XMLFetchNetworkEnd();
double XMLFetchNetworkVersion();

#ifdef HAVE_LIBZ
vector<gps_point *> XMLFetchGpsList(gzFile in_file);
#else
vector<gps_point *> XMLFetchGpsList(FILE *in_file);
#endif
double XMLFetchGpsVersion();
string XMLFetchGpsNetfile();
time_t XMLFetchGpsStart();

#endif
