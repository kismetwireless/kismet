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
#include "configfile.h"
#include "messagebus.h"
#include "util.h"
#include "manuf.h"

Manuf::Manuf(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  Manuf called before kismet_config\n");
		exit(1);
	}

	vector<string> fname = globalreg->kismet_config->FetchOptVec("ouifile");
	if (fname.size() == 0) {
		_MSG("Missing 'ouifile' option in config, will not resolve manufacturer "
			 "names for MAC addresses", MSGFLAG_ERROR);
		return;
	}

	for (unsigned int x = 0; x < fname.size(); x++) {
		if ((mfile = fopen(fname[x].c_str(), "r")) != NULL) {
			_MSG("Opened OUI file '" + fname[x], MSGFLAG_INFO);
			break;
		}

		_MSG("Could not open OUI file '" + fname[x] + "': " +
			 string(strerror(errno)), MSGFLAG_ERROR);
	}

	if (mfile == NULL) {
		_MSG("No OUI files were available, will not resolve manufacturer "
			 "names for MAC addresses", MSGFLAG_ERROR);
		return;
	}

	IndexOUI();
}

void Manuf::IndexOUI() {
	char buf[1024];
	int line = 0;
	fpos_t prev_pos;
	short int m[3];

	if (mfile == NULL)
		return;

	_MSG("Indexing manufacturer db", MSGFLAG_INFO);

	fgetpos(mfile, &prev_pos);

	while (!feof(mfile)) {
		if (fgets(buf, 1024, mfile) == NULL || feof(mfile))
			break;

		if ((line % 50) == 0) {
			if (sscanf(buf, "%hx:%hx:%hx",
					   &(m[0]), &(m[1]), &(m[2])) == 3) {

				// Log a position at the previous pos - which is the line before
				// this one, so we're inclusive
				index_pos ip;
				uint32_t oui;

				oui = 0;
				oui |= (uint32_t) m[0] << 16;
				oui |= (uint32_t) m[1] << 8;
				oui |= (uint32_t) m[2];

				ip.oui = oui;
				ip.pos = prev_pos;

				index_vec.push_back(ip);
			} else {
				// Compensate for not getting a reasonable line (probably a
				// comment) by decrementing here so we keep trying at each
				// index point until we get info we're looking for
				line--;
			}
		}

		fgetpos(mfile, &prev_pos);
		line++;
	}

	_MSG("Completed indexing manufacturer db, " + IntToString(line) + " lines " +
		 IntToString(index_vec.size()) + " indexes", MSGFLAG_INFO);
}

string Manuf::LookupOUI(mac_addr in_mac) {
	uint32_t soui = in_mac.OUI(), toui;
	int matched = -1;
	char buf[1024];
	short int m[3];
	char manuf[16];

	if (mfile == NULL)
		return "Unknown";

	// Use the cache first
	if (oui_map.find(soui) != oui_map.end()) {
		return oui_map[soui].manuf;
	}

	for (unsigned int x = 0; x < index_vec.size(); x++) {
		if (soui > index_vec[x].oui)
			continue;

		matched = x - 1;
		break;
	}

	// Cache unknown to save us effort in the future
	if (matched < 0) {
		manuf_data md;
		md.oui = soui;
		md.manuf = "Unknown";
		oui_map[soui] = md;

		return md.manuf;
	}

	fsetpos(mfile, &(index_vec[matched].pos));

	while (!feof(mfile)) {
		if (fgets(buf, 1024, mfile) == NULL || feof(mfile))
			break;

		if (sscanf(buf, "%hx:%hx:%hx\t%10s",
				   &(m[0]), &(m[1]), &(m[2]), manuf) == 4) {

			// Log a position at the previous pos - which is the line before
			// this one, so we're inclusive
			toui = 0;
			toui |= (uint32_t) m[0] << 16;
			toui |= (uint32_t) m[1] << 8;
			toui |= (uint32_t) m[2];

			if (toui == soui) {
				manuf_data md;
				md.oui = soui;
				md.manuf = MungeToPrintable(string(manuf));
				oui_map[soui] = md;

				return md.manuf;
			}

			if (toui > soui) {
				manuf_data md;
				md.oui = soui;
				md.manuf = "Unknown";
				oui_map[soui] = md;

				return md.manuf;
			}
		}
	}

	return "Unknown";
}


