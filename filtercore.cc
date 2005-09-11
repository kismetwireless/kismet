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

#include "filtercore.h"

FilterCore::FilterCore() {
	fprintf(stderr, "FATAL OOPS:  FilterCore() called w/ no globalreg\n");
	exit(1);
}

FilterCore::FilterCore(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;
	bssid_invert = -1;
	source_invert = -1;
	dest_invert = -1;
	bssid_hit = 0;
	source_hit = 0;
	dest_hit = 0;
}

int FilterCore::AddFilterLine(string filter_str) {
    // Break it into filter terms
    size_t parse_pos = 0;
    size_t parse_error = 0;

    while (parse_pos < filter_str.length()) {
        size_t addr_term_end;
        size_t address_target = 0; // 1=bssid 2=source 4=dest 7=any

        if (filter_str[parse_pos] == ',' || filter_str[parse_pos] == ' ') {
            parse_pos++;
            continue;
        }

        if ((addr_term_end = filter_str.find('(', parse_pos + 1)) == string::npos) {
			_MSG("Couldn't parse filter line '" + filter_str + "' no '(' found",
				 MSGFLAG_ERROR);
            parse_error = 1;
            break;
        }

        string addr_term = StrLower(filter_str.substr(parse_pos, 
													  addr_term_end - parse_pos));

        parse_pos = addr_term_end + 1;

        if (addr_term.length() == 0) {
			_MSG("Couldn't parse filter line '" + filter_str + "' no address type "
				 "given.", MSGFLAG_ERROR);
            parse_error = 1;
            break;
        }

        if (addr_term == "any") {
            address_target = 7;
        } else if (addr_term == "bssid") {
            address_target = 1;
        } else if (addr_term == "source") {
            address_target = 2;
        } else if (addr_term == "dest") {
            address_target = 4;
        } else {
			_MSG("Couldn't parse filter line '" + filter_str + "' unknown address "
				 "type '" + addr_term + "' (expected 'any', 'bssid', 'source', "
				 "'dest'", MSGFLAG_ERROR);
            parse_error = 1;
            break;
        }

        if ((addr_term_end = filter_str.find(')', parse_pos + 1)) == string::npos) {
			_MSG("Couldn't parse filter line '" + filter_str + "', no ')' found",
				 MSGFLAG_ERROR);
            parse_error = 1;
            break;
        }

        string term_contents = filter_str.substr(parse_pos, 
												 addr_term_end - parse_pos);

        parse_pos = addr_term_end + 1;

        if (term_contents.length() == 0) {
			_MSG("Couldn't parse filter line '" + filter_str + "' no addresses "
				 "listed after address type", MSGFLAG_ERROR);
            parse_error = 1;
            break;
        }

        size_t term_parse_pos = 0;
        while (term_parse_pos < term_contents.length()) {
            size_t term_end;
            int invert = 0;

            if (term_contents[term_parse_pos] == ' ' || 
				term_contents[term_parse_pos] == ',') {
                term_parse_pos++;
                continue;
            }

            if (term_contents[term_parse_pos] == '!') {
                invert = 1;
                term_parse_pos++;
            }

            if ((term_end = term_contents.find(',', 
											   term_parse_pos + 1)) == string::npos)
                term_end = term_contents.length();

            string single_addr = term_contents.substr(term_parse_pos, 
													  term_end - term_parse_pos);

            mac_addr mac = single_addr.c_str();
            if (mac.error != 0) {
				_MSG("Couldn't parse filter string '" + filter_str + "' MAC "
					 "address '" + single_addr + "'", MSGFLAG_ERROR);
                parse_error = 1;
                break;
            }

            // Catch non-inverted 'ANY'
            if (address_target == 7 && invert == 0) {
				_MSG("Filtering address type 'ANY' will discard all packets.  The "
					 "'ANY' address type can only be used on inverted matches to "
					 "discard any packets not matching the specified.", 
					 MSGFLAG_ERROR);
                parse_error = 1;
                break;
            }

			// Do an insert check for mismatched inversion flags, set it,
			// and set the inversion for future address types
            if (address_target & 0x01) {
				if (bssid_invert != -1 && invert != bssid_invert) {
					_MSG("BSSID filter '" + filter_str + "' has an illegal mix of "
						 "normal and inverted addresses.  A filter must be either "
						 "all inverted addresses or all standard addresses.", 
						 MSGFLAG_ERROR);
					return -1;
				}
                bssid_map.insert(mac, invert);
				bssid_invert = invert;
            } if (address_target & 0x02) {
				if (source_invert != -1 && invert != source_invert) {
					_MSG("SOURCE filter '" + filter_str + "' has an illegal mix of "
						 "normal and inverted addresses.  A filter must be either "
						 "all inverted addresses or all standard addresses.", 
						 MSGFLAG_ERROR);
					return -1;
				}
                source_map.insert(mac, invert);
				source_invert = invert;
            } if (address_target & 0x04) {
				if (dest_invert != -1 && invert != dest_invert) {
					_MSG("DEST filter '" + filter_str + "' has an illegal mix of "
						 "normal and inverted addresses.  A filter must be either "
						 "all inverted addresses or all standard addresses.", 
						 MSGFLAG_ERROR);
					return -1;
				}
                dest_map.insert(mac, invert);
				dest_invert = invert;
            }

            term_parse_pos = term_end + 1;
        }

    }

    if (parse_error == 1)
        return -1;

    return 1;
}

