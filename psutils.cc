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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <string>
#include <vector>
#include <sys/types.h>
#include <dirent.h>

int FindProcess(string in_proc, string in_option) {
#ifdef SYS_LINUX
	DIR *procdir;
	struct dirent *pid;
	FILE *pfile;
	string path, targ;
	int c;
	vector<string> parsed;

	if ((procdir = opendir("/proc")) == NULL)
		return 0;

	while ((pid = readdir(procdir)) != NULL) {
		path = string("/proc/") + pid->d_name + string("/cmdline");

		if ((pfile = fopen(path.c_str(), "r")) != NULL) {
			targ = "";
			parsed.clear();

			// this sucks
			while ((c = fgetc(pfile)) != EOF) {
				if (c == '\0') {
					parsed.push_back(targ);
					targ = "";
					continue;
				}
					
				targ += c;
			}

			fclose(pfile);

			if (parsed.size() <= 0)
				continue;

			if (parsed[0].find(in_proc) != string::npos) {
				for (unsigned int x = 1; x < parsed.size(); x++) {
					if (parsed[x].find(in_option) != string::npos) {
						closedir(procdir);
						return 1;
					}
				}
			}
		}
	}

	closedir(procdir);
#endif
	return 0;
}

