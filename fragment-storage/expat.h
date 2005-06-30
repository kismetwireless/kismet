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

#ifndef __EXPAT_H__
#define __EXPAT_H__

#include "config.h"

#ifdef HAVE_EXPAT

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
char *XMLFetchNetworkVersion();

#ifdef HAVE_LIBZ
vector<gps_point *> XMLFetchGpsList(gzFile in_file);
#else
vector<gps_point *> XMLFetchGpsList(FILE *in_file);
#endif
double XMLFetchGpsVersion();
string XMLFetchGpsNetfile();
time_t XMLFetchGpsStart();
#endif

#endif

