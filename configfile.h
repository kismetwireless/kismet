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

#ifndef __CONFIGFILE_H__
#define __CONFIGFILE_H__

#include "config.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <pwd.h>

#include <string>
#include <map>
#include <vector>

#include "globalregistry.h"
#include "macaddr.h"
#include "alertracker.h"

class ConfigFile {
public:
    int ParseConfig(const char *in_fname);
    string FetchOpt(string in_key);
    vector<string> FetchOptVec(string in_key);

    static string ExpandLogPath(string path, string logname, string type, 
								int start, int overwrite = 0);
    static int ParseFilterLine(string filter_str, macmap<int> *bssid_map,
                               macmap<int> *source_map,
                               macmap<int> *dest_map,
                               int *bssid_invert, int *source_invert, 
							   int *dest_invert);
    static int ParseAlertLine(string alert_str, string *ret_name, 
							  alert_time_unit *ret_limit_unit,
                              int *ret_limit_rate, int *ret_limit_burst);

protected:
    map<string, vector<string> > config_map;
};

#endif

