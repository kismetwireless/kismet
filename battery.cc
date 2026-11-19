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
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>

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

	// Clamped before the cast; an out of range float to int conversion is undefined
	if (cap > 0)
		out->percentage = (int) std::clamp(((float) remain / cap) * 100, 0.0f, 100.0f);

	if (rate > 0)
		out->remaining_sec = (int) std::clamp(((float) remain / rate) * 60 * 60, 0.0f, 2147483520.0f);

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
    std::vector<kis_battery_reading> batteries;
    int ext_online;

    fetch_linux_power_supplies("/sys/class/power_supply", batteries, ext_online);
    aggregate_battery_info(batteries, ext_online, out);

    return 1;
#endif

    return 0;
}

const char *kis_battery_state_str(kis_battery_state s) {
    switch (s) {
        case kis_battery_state::charging:
            return "charging";
        case kis_battery_state::discharging:
            return "discharging";
        case kis_battery_state::full:
            return "full";
        case kis_battery_state::not_charging:
            return "not_charging";
        default:
            return "unknown";
    }
}

namespace {
    // Larger sysfs values are garbage; the cap keeps the int64 unit math below in range
    constexpr int64_t ps_max_value = 1000000000000LL;
    constexpr int64_t ps_max_seconds = 2147483647LL;
    constexpr size_t ps_max_supplies = 32;
    constexpr size_t ps_max_name = 32;

    bool ps_valid_name(const char *n) {
        size_t len = strlen(n);

        if (len == 0 || len > ps_max_name || n[0] == '.')
            return false;

        for (size_t i = 0; i < len; i++) {
            const auto c = static_cast<unsigned char>(n[i]);
            if (!isalnum(c) && c != '_' && c != '.' && c != '-')
                return false;
        }

        return true;
    }

    // First line of a small sysfs file, without the newline
    bool ps_read_line(const std::string& path, std::string& out) {
        char buf[64];
        FILE *f = fopen(path.c_str(), "r");

        if (f == nullptr)
            return false;

        bool ok = fgets(buf, sizeof(buf), f) != nullptr;
        fclose(f);

        if (!ok)
            return false;

        buf[strcspn(buf, "\r\n")] = 0;
        out = buf;
        return true;
    }

    // A decimal sysfs value; -1 when missing, unparseable or out of range.  Rates
    // are signed on some drivers (negative while discharging), so keep the magnitude.
    int64_t ps_read_long(const std::string& path, bool magnitude = false) {
        std::string line;

        if (!ps_read_line(path, line) || line.empty())
            return -1;

        errno = 0;
        char *end = nullptr;
        long long v = strtoll(line.c_str(), &end, 10);

        if (errno != 0 || end == line.c_str() || (*end != 0 && !isspace(static_cast<unsigned char>(*end))))
            return -1;

        if (v < 0 && magnitude && v > -ps_max_value)
            v = -v;

        if (v < 0 || v > ps_max_value)
            return -1;

        return static_cast<int64_t>(v);
    }

    kis_battery_state ps_parse_status(const std::string& s) {
        if (strcasecmp(s.c_str(), "Charging") == 0)
            return kis_battery_state::charging;
        if (strcasecmp(s.c_str(), "Discharging") == 0)
            return kis_battery_state::discharging;
        if (strcasecmp(s.c_str(), "Full") == 0)
            return kis_battery_state::full;
        if (strcasecmp(s.c_str(), "Not charging") == 0)
            return kis_battery_state::not_charging;
        return kis_battery_state::unknown;
    }

    // Charge and rate in mA(h), converting energy readings with the voltage; the
    // same math as the original single-battery code
    void ps_read_battery(const std::string& bdir, kis_battery_reading& b) {
        std::string status;

        if (ps_read_line(bdir + "/status", status))
            b.state = ps_parse_status(status);

        const int64_t power_now = ps_read_long(bdir + "/power_now", true);
        const int64_t current_now = ps_read_long(bdir + "/current_now", true);
        const int64_t charge_now = ps_read_long(bdir + "/charge_now");
        const int64_t energy_now = ps_read_long(bdir + "/energy_now");
        const int64_t voltage_now = ps_read_long(bdir + "/voltage_now");
        const int64_t charge_full = ps_read_long(bdir + "/charge_full");
        const int64_t energy_full = ps_read_long(bdir + "/energy_full");
        const int64_t capacity = ps_read_long(bdir + "/capacity");

        int64_t present_rate = -1;
        int64_t remaining_capacity = -1;
        int64_t remaining_energy = -1;
        int64_t last_capacity = -1;
        int64_t last_capacity_unit = -1;
        int64_t voltage = -1;

        if (charge_now != -1)
            remaining_capacity = charge_now / 1000;
        else if (energy_now != -1)
            remaining_energy = energy_now / 1000;

        if (current_now != -1)
            present_rate = current_now / 1000;
        else if (power_now != -1)
            present_rate = power_now / 1000;

        if (charge_full != -1)
            last_capacity = charge_full / 1000;
        else if (energy_full != -1)
            last_capacity_unit = energy_full / 1000;

        if (voltage_now != -1) {
            voltage = voltage_now / 1000;
            b.voltage = voltage_now / 1000000.0;
        }

        if (last_capacity_unit != -1 && last_capacity == -1) {
            if (voltage == 0)
                last_capacity = 0;
            else if (voltage != -1)
                last_capacity = last_capacity_unit * 1000 / voltage;
            else
                last_capacity = last_capacity_unit;
        }

        if (remaining_energy != -1 && remaining_capacity == -1) {
            if (voltage == 0) {
                remaining_capacity = 0;
            } else if (voltage != -1) {
                remaining_capacity = remaining_energy * 1000 / voltage;
                if (present_rate != -1)
                    present_rate = present_rate * 1000 / voltage;
            } else {
                remaining_capacity = remaining_energy;
            }
        }

        b.remaining_capacity = remaining_capacity;
        b.last_capacity = last_capacity;
        b.present_rate = present_rate;

        if (remaining_capacity >= 0 && last_capacity > 0)
            b.percentage = static_cast<int>(std::clamp<int64_t>(remaining_capacity * 100 / last_capacity, 0, 100));
        else if (capacity >= 0)
            b.percentage = static_cast<int>(std::min<int64_t>(capacity, 100));

        if (remaining_capacity >= 0 && present_rate > 0)
            b.remaining_sec = std::min<int64_t>(3600 * remaining_capacity / present_rate, ps_max_seconds);
    }
}

void fetch_linux_power_supplies(const std::string& root, std::vector<kis_battery_reading>& batteries,
        int& ext_online) {
    batteries.clear();
    ext_online = -1;

    DIR *d = opendir(root.c_str());

    if (d == nullptr)
        return;

    std::vector<std::string> names;
    struct dirent *ent;

    while ((ent = readdir(d)) != nullptr && names.size() < ps_max_supplies) {
        if (ps_valid_name(ent->d_name))
            names.push_back(ent->d_name);
    }

    closedir(d);

    std::sort(names.begin(), names.end());

    for (const auto& n : names) {
        const auto dir = fmt::format("{}/{}", root, n);
        std::string type, scope;

        if (!ps_read_line(dir + "/type", type))
            continue;

        // Peripheral batteries and chargers (mice, headsets) aren't the system's
        if (ps_read_line(dir + "/scope", scope) && strcasecmp(scope.c_str(), "Device") == 0)
            continue;

        if (strcasecmp(type.c_str(), "Battery") != 0) {
            const int64_t online = ps_read_long(dir + "/online");

            if (online > 0)
                ext_online = 1;
            else if (online == 0 && ext_online < 0)
                ext_online = 0;

            continue;
        }

        if (ps_read_long(dir + "/present") == 0)
            continue;

        kis_battery_reading b;
        b.name = n;
        ps_read_battery(dir, b);
        batteries.push_back(b);
    }
}

void aggregate_battery_info(const std::vector<kis_battery_reading>& batteries, int ext_online,
        kis_battery_info *out) {
    // No battery: probably not a laptop, so on AC
    out->percentage = 0;
    out->charging = 0;
    out->ac = 1;
    out->remaining_sec = 0;

    if (batteries.empty())
        return;

    bool any_charging = false, any_external = false, any_discharging = false;
    int64_t sum_remaining = 0, sum_last = 0, sum_rate = 0, sum_rate_remaining = 0;
    int64_t sum_perc = 0, num_perc = 0;

    for (const auto& b : batteries) {
        any_charging |= b.state == kis_battery_state::charging;
        any_external |= b.state == kis_battery_state::charging || b.state == kis_battery_state::full ||
            b.state == kis_battery_state::not_charging;
        any_discharging |= b.state == kis_battery_state::discharging;

        if (b.remaining_capacity >= 0 && b.last_capacity > 0) {
            sum_remaining += b.remaining_capacity;
            sum_last += b.last_capacity;
        }

        if (b.remaining_capacity >= 0 && b.present_rate > 0) {
            sum_rate_remaining += b.remaining_capacity;
            sum_rate += b.present_rate;
        }

        if (b.percentage >= 0) {
            sum_perc += b.percentage;
            num_perc++;
        }
    }

    if (sum_last > 0)
        out->percentage = static_cast<int>(std::clamp<int64_t>(sum_remaining * 100 / sum_last, 0, 100));
    else if (num_perc > 0)
        out->percentage = static_cast<int>(sum_perc / num_perc);

    if (sum_rate > 0)
        out->remaining_sec = static_cast<int>(std::min<int64_t>(3600 * sum_rate_remaining / sum_rate, ps_max_seconds));

    out->charging = any_charging;

    // A battery draining while a supply is online (a weak USB-C charger) still reads
    // as discharging, like the original code; full and not-charging batteries are on
    // external power
    if (any_discharging && !any_charging)
        out->ac = 0;
    else if (ext_online == 1 || any_external)
        out->ac = 1;
    else if (ext_online == 0)
        out->ac = 0;
    else
        out->ac = !any_discharging;
}

int Fetch_Battery_Darwin(kis_battery_info *out __attribute__((unused))) {
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

