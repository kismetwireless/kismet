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

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <string.h>

#include <sys/types.h>
#include <dirent.h>

#ifdef SYS_LINUX
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#if defined(SYS_OPENBSD) && defined(HAVE_MACHINE_APMVAR_H)
#include <machine/apmvar.h>
#endif

#if 0
#ifdef SYS_DARWIN
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/ps/IOPowerSources.h>
#include <IOKit/ps/IOPSKeys.h>

#define LCDP_BATT_ABSENT 1
#define LCDP_AC_ON 2
#define LCDP_BATT_UNKNOWN 3
#define LCDP_AC_OFF 4
#define LCDP_BATT_CHARGING 5
#define LCDP_BATT_HIGH 6
#define LCDP_BATT_LOW 7
#define LCDP_BATT_CRITICAL 8
#endif
#endif

#ifdef SYS_NETBSD
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/envsys.h>
#include <fcntl.h>
#include <paths.h>
#endif

#include "battery.h"
#include "fmt.h"

int Fetch_Battery_Linux_ACPI(kis_battery_info *out __attribute__((unused))) {
#ifdef SYS_LINUX
	char buf[128];
	FILE *bfile;

	DIR *adir;
	struct dirent *ent;
	int rate = 0, cap = 0, remain = 0, tint = 0;
    std::string bpath;

	adir = opendir("/proc/acpi/battery");

	if (adir == NULL) {
		// No batteries, assume we're on AC
		out->percentage = 0;
		out->charging = 0;
		out->remaining_sec = 0;
		out->ac = 1;
		return 0;
	}

	while ((ent = readdir(adir)) != NULL) {
		bpath = "/proc/acpi/battery/" + std::string(ent->d_name) + "/state";

		if ((bfile = fopen(bpath.c_str(), "r")) == NULL)
			continue;
		while (fgets(buf, 128, bfile)) {
			if (strlen(buf) < 26)
				continue;

			if (strstr(buf, "charging state:") == buf) {
				// Only reset charging if no batteries are charging
				if (strstr(buf + 25, "charged") == (buf + 25) && out->charging != 1) {
					out->charging = 2;
				} else if (strstr(buf + 25, "discharging") == (buf + 25)) {
					out->charging = 0;
					out->ac = 0;
				} else if (strstr(buf + 25, "charging") == (buf + 25)) {
					out->charging = 1;
					out->ac = 1;
				}
			} else if (strstr(buf, "present rate:") == buf) {
				// Add discharge rates across all batteries
				if (sscanf(buf + 25, "%d", &tint) == 1) {
					rate += tint;
				}
			} else if (strstr(buf, "remaining capacity:") == buf) {
				// Add remaining across all batteries
				if (sscanf(buf + 25, "%d", &tint) == 1)
					remain += tint;
			}
		}
		fclose(bfile);

		bpath = "/proc/acpi/battery/" + std::string(ent->d_name) + "/info";
		if ((bfile = fopen(bpath.c_str(), "r")) == NULL) {
			continue;
		}

		while (fgets(buf, 128, bfile)) {
			if (strlen(buf) < 26)
				continue;

			// Add the last fulls
			if (strstr(buf, "last full capacity:") == buf) {
				if (sscanf(buf + 25, "%d", &tint) == 1) {
					cap += tint;
				}
			}
		}
		fclose(bfile);
	}

	closedir(adir);

	out->percentage = (float) ((float) remain / cap) * 100;

	if (rate > 0)
		out->remaining_sec = (float) ((float) remain / rate) * 60 * 60;

    return 1;
#endif

    return 0;
}

int Fetch_Battery_Linux_Sys(kis_battery_info *out __attribute__((unused))) {
    /* sys battery handling strongly derived from the ACPI code by
     * 
     *      Grahame Bowland <grahame@angrygoats.net>
     *      and
     *      Michael Meskes  <meskes@debian.org>
     */
#ifdef SYS_LINUX
    // Default to being on AC; if we lack battery info we're probably
    // not a laptop
    out->ac = 1;

    FILE *f;
    struct stat statbuf;

    const char *base_dir = "/sys/class/power_supply/";
    std::string bdir, fpath;

    char *line;
    size_t linesz;

    int itr;

    int on_ac = 0;
    int charging = 0;

    struct _long_file_pairs {
        const char *filename;
        long *target;
    };

    long power_now;
    long current_now;
    long charge_now;
    long energy_now;
    long voltage_now;
    long charge_full;
    long energy_full;

    long present_rate = -1;
    long remaining_capacity = -1;
    long remaining_energy = -1;
    long last_capacity = -1;
    long last_capacity_unit = -1;
    long voltage = -1;
    long seconds_remaining = -1;

    int percentage = 0;

    struct _long_file_pairs filepairs[] = {
        { "power_now", &power_now },
        { "current_now", &current_now },
        { "charge_now", &charge_now },
        { "energy_now", &energy_now },
        { "voltage_now", &voltage_now },
        { "charge_full", &charge_full },
        { "energy_full", &energy_full },
        { "end", NULL }
    };

    // Are we indexed as bat0 or bat1
    bdir = fmt::format("{}/BAT0", base_dir);
    if (stat(bdir.c_str(), &statbuf) < 0) {
        bdir = fmt::format("{}/BAT1", base_dir);
        if (stat(bdir.c_str(), &statbuf) < 0) {
            return -1;
        }
    }

    fpath = fmt::format("{}/status", bdir);
    if ((f = fopen(fpath.c_str(), "r")) == NULL) {
        return -1;
    } 

    ssize_t glsz __attribute__((unused));
    line = NULL;
    linesz = 0;
    glsz = getline(&line, &linesz, f);
    fclose(f);

    if (strcasestr(line, "discharging") == line) {
        on_ac = 0;
    } else if (strcasestr(line, "charging") == line) {
        on_ac = 1;
        charging = 1;
    }

    free(line);

    itr = 0;
    while (filepairs[itr].target != NULL) {
        fpath = fmt::format("{}/{}", bdir, filepairs[itr].filename);

        if ((f = fopen(fpath.c_str(), "r")) != NULL) {
            if (fscanf(f, "%lu", filepairs[itr].target) != 1) {
                *(filepairs[itr].target) = -1L;
            }

            fclose(f);
        } else {
            *(filepairs[itr].target) = -1L;
        }

        itr++;
    }

    if (charge_now != -1) {
        remaining_capacity = charge_now / 1000L; 
    } else if (energy_now != -1) {
        remaining_energy = energy_now / 1000L;
    }

    if (current_now != -1) {
        present_rate = current_now / 1000L;
    } else if (power_now != -1) {
        present_rate = power_now / 1000L;
    }

    if (charge_full != -1) {
        last_capacity = charge_full / 1000L;
    } else if (energy_full != -1) {
        last_capacity_unit = energy_full / 1000L;
    }

    if (voltage_now != -1) {
        voltage = voltage_now / 1000L;
    }


    if (last_capacity_unit != -1 && last_capacity == -1) {
        if (voltage == 0) {
            last_capacity = 0;
        } else if (voltage != -1) {
            last_capacity = last_capacity_unit * 1000L / voltage;
        } else {
            last_capacity = last_capacity_unit;
        }
    }

    if (remaining_energy != -1 && remaining_capacity == -1) {
        if (voltage == 0) {
            remaining_capacity = 0;
        } else if (voltage != -1) {
            remaining_capacity = remaining_energy * 1000 / voltage;
            present_rate = present_rate * 1000 / voltage;
        } else {
            remaining_capacity = remaining_energy;
        }
    }

    if (last_capacity <= 0)
        percentage = 0;
    else
        percentage = remaining_capacity * 100 / last_capacity;

    if (present_rate <= 0)
        seconds_remaining = 0;
    else
        seconds_remaining = 3600 * remaining_capacity / present_rate;

    out->percentage = percentage;
    out->charging = charging;
    out->ac = on_ac;
    out->remaining_sec = seconds_remaining;

    return 1;
#endif

    return 0;
}

int Fetch_Battery_Darwin(kis_battery_info *out __attribute__((unused))) {
    // This seems to no longer work?  Disabling for now, will revisit
#if 0
#ifdef SYS_DARWIN
	// Battery handling code from Kevin Finisterre & Apple specs
	CFTypeRef blob = IOPSCopyPowerSourcesInfo();
	CFArrayRef sources = IOPSCopyPowerSourcesList(blob);

	int i, bat_available = 0;
	CFDictionaryRef pSource = NULL;
	const void *psValue;

	int acstat = 0, battflag = LCDP_BATT_ABSENT;

	if (CFArrayGetCount(sources) != 0) {
		for (i = 0; i < CFArrayGetCount(sources); i++) {
			pSource = IOPSGetPowerSourceDescription(blob, 
													CFArrayGetValueAtIndex(sources, i));
			if (pSource == NULL)
				break;

			psValue = (CFStringRef) CFDictionaryGetValue(pSource, 
														 CFSTR(kIOPSNameKey));

			if (CFDictionaryGetValueIfPresent(pSource, CFSTR(kIOPSIsPresentKey),
											  &psValue) && 
				(CFBooleanGetValue((CFBooleanRef) psValue))) {
				psValue = 
					(CFStringRef) CFDictionaryGetValue(pSource, 
													   CFSTR(kIOPSPowerSourceStateKey));

				if (CFStringCompare((CFStringRef) psValue, 
								CFSTR(kIOPSBatteryPowerValue), 0) == kCFCompareEqualTo) {
					battflag = LCDP_BATT_UNKNOWN;
					acstat = LCDP_AC_OFF;
					out->charging = 0;
				} else if (CFDictionaryGetValueIfPresent(pSource, 
											 CFSTR(kIOPSIsChargingKey), &psValue)) {
					if (CFBooleanGetValue((CFBooleanRef) psValue) > 0) {
						battflag = LCDP_BATT_CHARGING;
						out->charging = 1;
					} else {
						battflag = LCDP_BATT_UNKNOWN;
					}
				}

				if (battflag != LCDP_BATT_ABSENT) {
					int curCapacity = 0;
					int maxCapacity = 0;
					int remainingTime = 0;
					int timeToCharge = 0;

					bat_available = 1;

					psValue = CFDictionaryGetValue(pSource, 
												   CFSTR(kIOPSCurrentCapacityKey));
					CFNumberGetValue((CFNumberRef) psValue, kCFNumberSInt32Type, 
									 &curCapacity);

					psValue = CFDictionaryGetValue(pSource, 
												   CFSTR(kIOPSMaxCapacityKey));
					CFNumberGetValue((CFNumberRef) psValue, kCFNumberSInt32Type, 
									 &maxCapacity);

					out->percentage = (maxCapacity / curCapacity) * 100;

					// If this is 0 we are on AC, if it's a negative we are 
					// "calculating",
					psValue = CFDictionaryGetValue(pSource, 
												   CFSTR(kIOPSTimeToEmptyKey));
					CFNumberGetValue((CFNumberRef) psValue, 
									 kCFNumberSInt32Type, &remainingTime);

					if (remainingTime == 0)
						out->ac = 1;
					else
						out->ac = 0;

					psValue = CFDictionaryGetValue(pSource, 
												   CFSTR(kIOPSTimeToFullChargeKey));
					CFNumberGetValue((CFNumberRef) psValue, 
									 kCFNumberSInt32Type, &timeToCharge);

					if (out->charging && timeToCharge > 0) {
						out->charging = 1;
					} else if (remainingTime > 0) {
						out->remaining_sec = remainingTime * 60;
						out->charging = 0;
						out->ac = 0;
					}

                    return 1;
				}
			}
		}
	}

#endif
#endif

    return 0;
}

int Fetch_Battery_OpenBSD(kis_battery_info *out __attribute__((unused))) {
#if defined(SYS_OPENBSD) && defined(HAVE_MACHINE_APMVAR_H)
	struct apm_power_info api;
	int apmfd;

	if ((apmfd = open("/dev/apm", O_RDONLY)) < 0) {
		return 1;
	} else if (ioctl(apmfd, APM_IOC_GETPOWER, &api) < 0) {
		close(apmfd);
		return 1;
	} else {
		close(apmfd);
		switch(api.battery_state) {
			case APM_BATT_UNKNOWN:
			case APM_BATTERY_ABSENT:
				return 1;
		}

		out->percentage = (int) api.battery_life;
		out->remaining_sec = (int) api.minutes_left * 60;

		if (api.battery_state == APM_BATT_CHARGING) {
			out->ac = 1;
			out->charging = 1;
		} else {
			switch (api.ac_state) {
				case APM_AC_ON:
					out->ac = 1;
					if (bat_percentage < 100) {
						out->charging = 1;
					} else {
						out->charging = 0;
					}
					break;
				default:
					out->ac = 0;
					out->charging = 0;
			}
		}

        return 1;
	}

#endif

    return 0;
}

int Fetch_Battery_NetBSD(kis_battery_info *out __attribute__((unused))) {
#ifdef SYS_NETBSD
	static int fd = -1;
	int i;
	envsys_basic_info_t info;
	envsys_tre_data_t data;
	unsigned int charge = 0;
	unsigned int maxcharge = 0;
	unsigned int rate = 0;

	if (fd < 0 && (fd = open(_PATH_SYSMON, O_RDONLY)) < 0) 
		return 1;

	for (i = 0; i >= 0; i++) {
		memset(&info, 0, sizeof(info));
		info.sensor = i;

		if (ioctl(fd, ENVSYS_GTREINFO, &info) == -1) {
			close(fd);
			return 1;
		}

		if (!(info.validflags & ENVSYS_FVALID))
			break;

		memset(&data, 0, sizeof(data));
		data.sensor = i;

		if(ioctl(fd, ENVSYS_GTREDATA, &data) == -1) {
			close(fd);
			return 1;
		}

		if (!(data.validflags & ENVSYS_FVALID))
			continue;

		if (strcmp("acpiacad0 connected", info.desc) == 0) {
			out->ac = data.cur.data_us;
		} else if (strcmp("acpibat0 charge", info.desc) == 0) {
			out->percentage = (unsigned int) ((data.cur.data_us * 100.0) / 
											  data.max.data_us);
			charge = data.cur.data_us;
			maxcharge = data.max.data_us;
		} else if (strcmp("acpibat0 charging", info.desc) == 0) {
			out->charging = data.cur.data_us > 0 ? 1 : 0;
		} else if (strcmp("acpibat0 discharge rate", info.desc) == 0) {
			rate = data.cur.data_us;
		}
	}

	if (out->charging != 0)
		out->remaining_sec = rate ? (unsigned int) ((maxcharge - charge) * 3600.0 / 
	else
		out->remaining_sec = rate ? (unsigned int) ((charge * 3600.0) / rate) : 0;

    return 1;

#endif

    return 0;
}

int fetch_battery_info(kis_battery_info *out) {
	out->percentage = 0;
	out->charging = 0;
	out->remaining_sec = 0;
	out->ac = 1;

#ifdef SYS_LINUX
    if (Fetch_Battery_Linux_ACPI(out))
        return 1;

    if (Fetch_Battery_Linux_Sys(out))
        return 1;

    return 0;

#elif defined(SYS_DARWIN)
    return Fetch_Battery_Darwin(out);
#elif defined(SYS_OPENBSD) && defined(HAVE_MACHINE_APMVAR_H)
    return Fetch_Battery_OpenBSD(out);
#elif defined(SYS_NETBSD)
	static int fd = -1;
	int i;
	envsys_basic_info_t info;
	envsys_tre_data_t data;
	unsigned int charge = 0;
	unsigned int maxcharge = 0;
	unsigned int rate = 0;

	if (fd < 0 && (fd = open(_PATH_SYSMON, O_RDONLY)) < 0) 
		return 1;

	for (i = 0; i >= 0; i++) {
		memset(&info, 0, sizeof(info));
		info.sensor = i;

		if (ioctl(fd, ENVSYS_GTREINFO, &info) == -1) {
			close(fd);
			return 1;
		}

		if (!(info.validflags & ENVSYS_FVALID))
			break;

		memset(&data, 0, sizeof(data));
		data.sensor = i;

		if(ioctl(fd, ENVSYS_GTREDATA, &data) == -1) {
			close(fd);
			return 1;
		}

		if (!(data.validflags & ENVSYS_FVALID))
			continue;

		if (strcmp("acpiacad0 connected", info.desc) == 0) {
			out->ac = data.cur.data_us;
		} else if (strcmp("acpibat0 charge", info.desc) == 0) {
			out->percentage = (unsigned int) ((data.cur.data_us * 100.0) / 
											  data.max.data_us);
			charge = data.cur.data_us;
			maxcharge = data.max.data_us;
		} else if (strcmp("acpibat0 charging", info.desc) == 0) {
			out->charging = data.cur.data_us > 0 ? 1 : 0;
		} else if (strcmp("acpibat0 discharge rate", info.desc) == 0) {
			rate = data.cur.data_us;
		}
	}

	if (out->charging != 0)
		out->remaining_sec = rate ? (unsigned int) ((maxcharge - charge) * 3600.0 / 
													rate) : 0;
	else
		out->remaining_sec = rate ? (unsigned int) ((charge * 3600.0) / rate) : 0;

#endif

	return 1;
}

