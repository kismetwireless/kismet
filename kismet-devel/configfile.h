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

void MungeToShell(char *in_data, int max);
string StrLower(string in_str);
string StrStrip(string in_str);

class ConfigFile {
public:

    int ParseConfig(const char *in_fname);
    string FetchOpt(string in_key);

    string ExpandLogPath(string path, string logname, string type, int start, int overwrite = 0);

protected:
    map<string, string> config_map;
};

#endif

