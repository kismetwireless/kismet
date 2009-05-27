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

#ifdef SYS_LINUX

#include "madwifing_control.h"

#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <getopt.h>
#include <err.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>

#include "ifcontrol.h"

int madwifing_list_vaps(const char *ifname, vector<string> *retvec) {
	DIR *devdir;
	struct dirent *devfile;
	string dirpath;
	int kern24model = 0;
	FILE *pf = NULL;

	dirpath = "/sys/class/net/" + string(ifname) + "/device/";

	if ((devdir = opendir(dirpath.c_str())) == NULL) {
		dirpath = "/proc/sys/net/";
		if ((devdir = opendir(dirpath.c_str())) == NULL) {
			return -1;
		}
		kern24model = 1;
	}

	while ((devfile = readdir(devdir)) != NULL) {
		if (kern24model) {
			string pfname = dirpath + devfile->d_name + "/%parent";
			char pname[64];

			if ((pf = fopen(pfname.c_str(), "r")) == NULL) {
				continue;
			} else {
				if (fscanf(pf, "%s", pname) != 1) {
					fclose(pf);
					continue;
				} else {
					retvec->push_back(devfile->d_name);
				}

				fclose(pf);
			}
		} else {
			string ownername = "net:" + string(ifname);

			if (strncmp("net:", devfile->d_name, 4) == 0)
				retvec->push_back(devfile->d_name + 4);
		}
	}

	closedir(devdir);

	return retvec->size();
}

int madwifing_find_parent(vector<string> *vaplist) {
	for (unsigned int x = 0; x < vaplist->size(); x++) {
		if ((*vaplist)[x].find("wifi") != string::npos)
			return x;
	}

	return -1;
}

int madwifing_destroy_vap(const char *ifname, char *errstr) {
	struct ifreq ifr;
	int sock;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, 1024, "Failed to create socket to madwifi: %s",
				 strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sock, SIOC80211IFDESTROY, &ifr) < 0) {
		snprintf(errstr, 1024, "Failed to destroy VAP: %s", strerror(errno));
		close(sock);
		return -1;
	}

	close(sock);

	return 1;
}

int madwifing_build_vap(const char *ifname, char *errstr, const char *vapname, 
						char *retvapname, int vapmode, int vapflags) {
	struct ieee80211_clone_params {
		char icp_name[IFNAMSIZ];
		uint16_t icp_opmode;
		uint16_t icp_flags;
	};
	struct ieee80211_clone_params cp;
	struct ifreq ifr;
	int sock;
	char tnam[IFNAMSIZ];

	// Find a numbered vapname which is useable
	for (unsigned int n = 0; n < 10; n++) {
		int fl;
		snprintf(tnam, IFNAMSIZ, "%s%d", vapname, n);
		if (Ifconfig_Get_Flags(tnam, errstr, &fl) < 0)
			break;

		// Default to no temp name as error
		tnam[0] = '\0';
	}

	if (tnam[0] == '\0') {
		snprintf(errstr, 1024, "Unable to find free slot for VAP %s", vapname);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	memset(&cp, 0, sizeof(cp));

	strncpy(cp.icp_name, tnam, IFNAMSIZ);
	cp.icp_opmode = vapmode;
	cp.icp_flags = vapflags;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_data = (caddr_t) &cp;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, 1024, "Unable to create socket to madwifi-ng: %s",
				 strerror(errno));
		return -1;
	}

	if (ioctl(sock, SIOC80211IFCREATE, &ifr) < 0) {
		snprintf(errstr, 1024, "Unable to create VAP: %s", strerror(errno));
		close(sock);
		return -1;
	}

	strncpy(retvapname, ifr.ifr_name, IFNAMSIZ);
	close(sock);

	return 1;
}

#endif

