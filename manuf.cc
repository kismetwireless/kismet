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
#include "entrytracker.h"
#include "messagebus.h"
#include "util.h"
#include "manuf.h"

Manuf::Manuf() {
    auto entrytracker = Globalreg::FetchMandatoryGlobalAs<EntryTracker>();

    manuf_id = 
        entrytracker->RegisterField("kismet.device.base.manuf", 
                TrackerElementFactory<TrackerElementString>(), "manufacturer name");

    unknown_manuf = std::make_shared<TrackerElementString>(manuf_id);
    unknown_manuf->set("Unknown");

    if (Globalreg::globalreg->kismet_config->FetchOptBoolean("manuf_lookup", true) == false) {
        _MSG("Disabling OUI lookup.", MSGFLAG_INFO);
        return;
    }

    auto fname = Globalreg::globalreg->kismet_config->FetchOptVec("ouifile");
    if (fname.size() == 0) {
        _MSG("Missing 'ouifile' option in config, will not resolve manufacturer "
             "names for MAC addresses", MSGFLAG_ERROR);
        return;
    }

    for (auto f : fname) {
        auto expanded = Globalreg::globalreg->kismet_config->ExpandLogPath(f, "", "", 0, 1);

        if ((mfile = fopen(expanded.c_str(), "r")) != NULL) {
            _MSG("Opened OUI file '" + expanded, MSGFLAG_INFO);
            break;
        }

        _MSG("Could not open OUI file '" + expanded + "': " + std::string(strerror(errno)), MSGFLAG_INFO);
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
    uint32_t last_oui = 0;

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

                if (oui < last_oui) {
                    _MSG("Warning:  Manuf file appears to be out of order, expected "
                            "sorted manuf OUI data", MSGFLAG_ERROR);
                }

                ip.oui = oui;
                ip.pos = prev_pos;

                last_oui = oui;

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

std::shared_ptr<TrackerElementString> Manuf::LookupOUI(mac_addr in_mac) {
    uint32_t soui = in_mac.OUI(), toui;
    int matched = -1;
    char buf[1024];
    short int m[3];

    if (mfile == NULL)
        return unknown_manuf;

    // Use the cache first
    if (oui_map.find(soui) != oui_map.end()) {
        return oui_map[soui].manuf;
    }

    for (unsigned int x = 0; x < index_vec.size(); x++) {
        if (soui > index_vec[x].oui) {
            matched = x;
            continue;
        }

        break;
    }

    // Cache unknown to save us effort in the future
    if (matched < 0) {
        manuf_data md;
        md.oui = soui;
        md.manuf = unknown_manuf;
        oui_map[soui] = md;

        return md.manuf;
    }

    // Jump backwards one index in the matching unless we're in the first block
    if (matched > 0)
        matched -= 1;

    fsetpos(mfile, &(index_vec[matched].pos));

    while (!feof(mfile)) {
        if (fgets(buf, 1024, mfile) == NULL || feof(mfile))
            break;

        if (strlen(buf) < 10)
            continue;

        // Trim \n
        auto mlen = strlen(buf + 9) - 1;

        if (mlen == 0)
            continue;


        if (sscanf(buf, "%hx:%hx:%hx\t", &(m[0]), &(m[1]), &(m[2])) == 3) {

            // Log a position at the previous pos - which is the line before
            // this one, so we're inclusive
            toui = mac_addr::OUI(m);

            if (toui == soui) {
                manuf_data md;
                md.oui = soui;

                md.manuf = std::make_shared<TrackerElementString>(manuf_id);
                md.manuf->set(MungeToPrintable(std::string(buf + 9, mlen)));
                oui_map[soui] = md;
                return md.manuf;
            }

            if (toui > soui) {
                manuf_data md;
                md.oui = soui;
                md.manuf = unknown_manuf;
                oui_map[soui] = md;
                return md.manuf;
            }
        }
    }

    return unknown_manuf;
}

std::shared_ptr<TrackerElementString> Manuf::MakeManuf(const std::string& in_manuf) {
    auto manuf = std::make_shared<TrackerElementString>(manuf_id);
    manuf->set(in_manuf);
    return manuf;
}

bool Manuf::IsUnknownManuf(std::shared_ptr<TrackerElementString> in_manuf) {
    return in_manuf == unknown_manuf;
}

