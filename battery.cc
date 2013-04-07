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

#if defined(SYS_OPENBSD) && defined(HAVE_MACHINE_APMVAR_H)
#include <machine/apmvar.h>
#endif

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

#ifdef SYS_NETBSD
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/envsys.h>
#include <fcntl.h>
#include <paths.h>
#endif

#include "battery.h"

int Fetch_Battery_Info(kis_battery_info *out) {
	out->percentage = 0;
	out->charging = 0;
	out->remaining_sec = 0;
	out->ac = 1;

#ifdef SYS_LINUX
	char buf[128];
	FILE *bfile;
	char units[32];

	if ((bfile = fopen("/proc/apm", "r")) != NULL) {
		int line_status, bat_status, flag, perc, apm_time;

		if (fgets(buf, 128, bfile) == NULL) {
			fclose(bfile);
			goto apmfail;
		}


		if (sscanf(buf, "%*s %*d.%*d %*x %x %x %x %d%% %d %32s\n", &line_status,
				   &bat_status, &flag, &perc, &apm_time, units) != 6) {
			fclose(bfile);
			goto apmfail;
		}

		if ((flag & 0x80) == 0 && bat_status != 0xFF) {
			out->percentage = perc;
		}

		if (line_status == 1)
			out->ac = 1;
		else
			out->ac = 0;

		if (bat_status == 3)
			out->charging = 1;
		else
			out->charging = 0;

		if (apm_time < 0)
			out->remaining_sec = 0;
		else
			out->remaining_sec = apm_time;

		if (!strncmp(units, "min", 4))
			out->remaining_sec *= 60;

		fclose(bfile);

		return 1;
	}

	// Fail to trying to read ACPI
apmfail:
	DIR *adir;
	struct dirent *ent;
	int rate = 0, cap = 0, remain = 0, tint = 0;
	string bpath;

	adir = opendir("/proc/acpi/battery");

	if (adir == NULL) {
		// No batteries, assume we're on AC
		out->percentage = 0;
		out->charging = 0;
		out->remaining_sec = 0;
		out->ac = 1;
		return 1;
	}

	while ((ent = readdir(adir)) != NULL) {
		bpath = "/proc/acpi/battery/" + string(ent->d_name) + "/state";

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

		bpath = "/proc/acpi/battery/" + string(ent->d_name) + "/info";
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

#elif defined(SYS_DARWIN)
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
				}
			}
		}
	}

#elif defined(SYS_OPENBSD) && defined(HAVE_MACHINE_APMVAR_H)

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
	}

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

