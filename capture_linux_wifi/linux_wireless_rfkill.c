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

#include "../config.h"
#include "linux_wireless_rfkill.h"

#ifdef SYS_LINUX

#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>

int linux_sys_get_rfkill(const char *interface, unsigned int rfkill_type) {
    DIR *devdir;
    struct dirent *devfile;
    char dirpath[2048];

    const char *rfkill_key = "rfkill";
    const char *hard_key = "hard";
    const char *soft_key = "soft";

    FILE *killf;

    int r;

    snprintf(dirpath, 2048, "/sys/class/net/%s/phy80211/", interface);

    if ((devdir = opendir(dirpath)) == NULL)
        return -1;

    while ((devfile = readdir(devdir)) != NULL) {
        if (strlen(devfile->d_name) < strlen(rfkill_key))
            continue;

        if (strncmp(devfile->d_name, rfkill_key, strlen(rfkill_key)) == 0) {
            snprintf(dirpath, 2048, "/sys/class/net/%s/phy80211/%s/%s",
                    interface, devfile->d_name, 
                    rfkill_type == 0 ? hard_key : soft_key);

            if ((killf = fopen(dirpath, "r")) == NULL) {
                closedir(devdir);
                return -1;
            }

            if ((fscanf(killf, "%d", &r)) != 1) {
                closedir(devdir);
                fclose(killf);
                return -1;
            }

            closedir(devdir);
            fclose(killf);

            return r;
        }
    }

    return -1;
}

int linux_sys_clear_rfkill(const char *interface) {
    DIR *devdir;
    struct dirent *devfile;
    char dirpath[2048];

    const char *rfkill_key = "rfkill";

    FILE *killf;

    snprintf(dirpath, 2048, "/sys/class/net/%s/phy80211/", interface);

    if ((devdir = opendir(dirpath)) == NULL)
        return -1;

    while ((devfile = readdir(devdir)) != NULL) {
        if (strlen(devfile->d_name) < strlen(rfkill_key))
            continue;

        if (strncmp(devfile->d_name, rfkill_key, strlen(rfkill_key)) == 0) {
            snprintf(dirpath, 2048, "/sys/class/net/%s/phy80211/%s/soft",
                    interface, devfile->d_name);

            if ((killf = fopen(dirpath, "w")) == NULL) {
                closedir(devdir);
                return -1;
            }

            if (fprintf(killf, "%d\n", 0) < 0) {
                closedir(devdir);
                fclose(killf);
                return -1;
            }

            closedir(devdir);
            fclose(killf);

            return 0;
        }
    }

    return -1;
}


#endif
