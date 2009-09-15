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

#include <sstream>

#include "util.h"
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
#ifdef HAVE_LIBPCRE
	pcre_invert = -1;
	pcre_hit = 0;
#endif
}

#define _filter_stacker_none	0
#define _filter_stacker_mac		1
#define _filter_stacker_pcre	2

#define _filter_type_none		-1
#define _filter_type_bssid		0
#define _filter_type_source		1
#define _filter_type_dest		2
#define _filter_type_any		3
#define _filter_type_pcre		4

int FilterCore::AddFilterLine(string filter_str) {
	_kis_lex_rec ltop;
	int type = _filter_stacker_none;
	int mtype = _filter_type_none;
	int negate = -1;
	string errstr;

	// Local copies to add so we can error out cleanly...  This is a cheap
	// hack but it lets us avoid a bunch of if's
	map<int, vector<mac_addr> > local_maps;
	map<int, int> local_inverts;
#ifdef HAVE_LIBPCRE
	vector<pcre_filter *> local_pcre;
#endif
	vector<mac_addr> macvec;

	local_inverts[_filter_type_bssid] = -1;
	local_inverts[_filter_type_source] = -1;
	local_inverts[_filter_type_dest] = -1;
	local_inverts[_filter_type_any] = -1;
	local_inverts[_filter_type_pcre] = -1;

	list<_kis_lex_rec> precs = LexString(filter_str, errstr);

	if (precs.size() == 0) {
		_MSG(errstr, MSGFLAG_ERROR);
		return -1;
	}

	while (precs.size() > 0) {
		// Grab the top of the stack, pop the lexer
		ltop = precs.front();
		precs.pop_front();

		// Ignore 'none'
		if (ltop.type == _kis_lex_none) {
			continue;
		}

		// If we don't have anything in the stack...
		if (type == _filter_stacker_none) {
			// Ignore delimiters, they just break up mac addresses
			if (ltop.type == _kis_lex_delim)
				continue;

			if (ltop.type != _kis_lex_string) {
				_MSG("Couldn't parse filter line '" + filter_str + "', expected an "
					 "unquoted string", MSGFLAG_ERROR);
#ifdef HAVE_LIBPCRE
				for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
					pcre_free(local_pcre[zed]->re);
					pcre_free(local_pcre[zed]->study);
					delete(local_pcre[zed]);
				}
#endif
				return -1;
			}

			string uqstr = StrLower(ltop.data);

			if (uqstr == "bssid") {
				type = _filter_stacker_mac;
				mtype = _filter_type_bssid;
			} else if (uqstr == "source") {
				type = _filter_stacker_mac;
				mtype = _filter_type_source;
			} else if (uqstr == "dest") {
				type = _filter_stacker_mac;
				mtype = _filter_type_dest;
			} else if (uqstr == "any") {
				type = _filter_stacker_mac;
				mtype = _filter_type_any;
			} else if (uqstr == "pcre") {
				type = _filter_stacker_pcre;
			} else {
				_MSG("Couldn't parse filter line '" + filter_str + "', expected one "
					 "of BSSID, SOURCE, DEST, ANY, PCRE", MSGFLAG_ERROR);
#ifdef HAVE_LIBPCRE
				for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
					pcre_free(local_pcre[zed]->re);
					pcre_free(local_pcre[zed]->study);
					delete(local_pcre[zed]);
				}
#endif
				return -1;
			}

			// check for a '('
			if (precs.size() <= 0) {
				_MSG("Couldn't parse filter line '" + filter_str + "', expected (",
					 MSGFLAG_ERROR);
#ifdef HAVE_LIBPCRE
				for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
					pcre_free(local_pcre[zed]->re);
					pcre_free(local_pcre[zed]->study);
					delete(local_pcre[zed]);
				}
#endif
				return -1;
			}

			ltop = precs.front();
			precs.pop_front();

			if (ltop.type != _kis_lex_popen) {
				_MSG("Couldn't parse filter line '" + filter_str + "', expected (",
					 MSGFLAG_ERROR);
#ifdef HAVE_LIBPCRE
				for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
					pcre_free(local_pcre[zed]->re);
					pcre_free(local_pcre[zed]->study);
					delete(local_pcre[zed]);
				}
#endif
				return -1;
			}

			// Peek for a negation
			if (precs.size() <= 0) {
				_MSG("Couldn't parse filter line '" + filter_str + "', expected "
					 "contents", MSGFLAG_ERROR);
#ifdef HAVE_LIBPCRE
				for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
					pcre_free(local_pcre[zed]->re);
					pcre_free(local_pcre[zed]->study);
					delete(local_pcre[zed]);
				}
#endif
				return -1;
			}

			continue;
		}

		if (type == _filter_stacker_mac) {
			int addr_loc_negate = 0;

			if (ltop.type == _kis_lex_negate) {
				if (negate == 0) {
					_MSG("Couldn't parse filter line '" + filter_str + "', cannot "
						 "mix negated and non-negated MAC addresses on the same "
						 "filter", MSGFLAG_ERROR);
#ifdef HAVE_LIBPCRE
					for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
						pcre_free(local_pcre[zed]->re);
						pcre_free(local_pcre[zed]->study);
						delete(local_pcre[zed]);
					}
#endif
				}

				// Double-hop on negates
				negate = 1;
				addr_loc_negate = 1;

				ltop = precs.front();
				precs.pop_front();
			}

			// Look for an address as a string
			if (ltop.type != _kis_lex_string) {
				_MSG("Couldn't parse filter line '" + filter_str + "', expected "
					 "MAC address", MSGFLAG_ERROR);
#ifdef HAVE_LIBPCRE
				for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
					pcre_free(local_pcre[zed]->re);
					pcre_free(local_pcre[zed]->study);
					delete(local_pcre[zed]);
				}
#endif
				return -1;
			}

			if (negate == 1 && addr_loc_negate != 1) {
				_MSG("Couldn't parse filter line '" + filter_str + "', cannot "
					 "mix inverted and non-inverted MAC addresses on the same "
					 "filter", MSGFLAG_ERROR);
#ifdef HAVE_LIBPCRE
				for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
					pcre_free(local_pcre[zed]->re);
					pcre_free(local_pcre[zed]->study);
					delete(local_pcre[zed]);
				}
#endif
				return -1;
			}


			mac_addr mymac = ltop.data.c_str();

			if (mymac.error) {
				_MSG("Couldn't parse filter line '" + filter_str + "', expected "
					 "MAC address and could not interpret '" + ltop.data + "'",
					 MSGFLAG_ERROR);
#ifdef HAVE_LIBPCRE
				for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
					pcre_free(local_pcre[zed]->re);
					pcre_free(local_pcre[zed]->study);
					delete(local_pcre[zed]);
				}
#endif
				return -1;
			}

			// Add it to the local map for this type
			(local_maps[mtype]).push_back(mymac);

			// Peek at the next item
			if (precs.size() <= 0) {
				_MSG("Couldn't parse filter line '" + filter_str + "', expected ',' "
					 "or ')'", MSGFLAG_ERROR);
#ifdef HAVE_LIBPCRE
				for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
					pcre_free(local_pcre[zed]->re);
					pcre_free(local_pcre[zed]->study);
					delete(local_pcre[zed]);
				}
#endif
				return -1;
			}

			ltop = precs.front();
			precs.pop_front();

			// If it's a delimiter, skip over it and continue
			if (ltop.type == _kis_lex_delim)
				continue;

			// if it's a close paren, close down and save/errorcheck the negation
			if (ltop.type == _kis_lex_pclose) {
				if (local_inverts[mtype] != -1 && local_inverts[mtype] != negate) {
					_MSG("Couldn't parse filter line '" + filter_str + "', filter "
						 "has an illegal mix of normal and inverted addresses. "
						 "A filter type must be either all inverted addresses or all "
						 "standard addresses.", MSGFLAG_ERROR);
#ifdef HAVE_LIBPCRE
					for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
						pcre_free(local_pcre[zed]->re);
						pcre_free(local_pcre[zed]->study);
						delete(local_pcre[zed]);
					}
#endif
					return -1;
				}

				if (negate < 0)
					negate = 0;

				local_inverts[mtype] = negate;
				type = _filter_stacker_none;
				mtype = _filter_type_none;
				negate = 0;
				continue;
			}

			// Fall through and hit errors about anything else
			_MSG("Couldn't parse filter line '" + filter_str + "', expected ',' "
				 "or ')'", MSGFLAG_ERROR);
#ifdef HAVE_LIBPCRE
			for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
				pcre_free(local_pcre[zed]->re);
				pcre_free(local_pcre[zed]->study);
				delete(local_pcre[zed]);
			}
#endif
			return -1;
		}

		if (type == _filter_stacker_pcre) {
#ifndef HAVE_LIBPCRE
			// Catch libpcre not being here
			_MSG("Couldn't parse filter line '" + filter_str + "', filter "
				 "uses PCRE regular expressions and this instance of Kismet "
				 "was not compiled with libpcre support.", MSGFLAG_ERROR);
			return -1;
#else
			// Look for a quoted string
			if (ltop.type != _kis_lex_quotestring) {
				_MSG("Couldn't parse filter line '" + filter_str + "', expected "
					 "quoted string", MSGFLAG_ERROR);
				for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
					pcre_free(local_pcre[zed]->re);
					pcre_free(local_pcre[zed]->study);
					delete(local_pcre[zed]);
				}
				return -1;
			}

			// local_pcre.push_back(ltop.data);
			// Try to parse and study the PCRE
			pcre_filter *filt = new pcre_filter;
			const char *error, *study_err;
			int erroffset;
			ostringstream osstr;

			filt->re = 
				pcre_compile(ltop.data.c_str(), 0, &error, &erroffset, NULL);
			if (filt->re == NULL) {
				osstr << "Couldn't parse filter line '" << filter_str << "', PCRE "
					"compilation failure '" << error << "' at offset " << erroffset;
				_MSG(osstr.str(), MSGFLAG_ERROR);
				delete(filt);
				for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
					pcre_free(local_pcre[zed]->re);
					pcre_free(local_pcre[zed]->study);
					delete(local_pcre[zed]);
				}
				return -1;
			}

			filt->study = pcre_study(filt->re, 0, &study_err);
			if (filt->study != NULL) {
				osstr << "Couldn't parse filter line '" << filter_str << "', PCRE "
					"study/optimization failure '" << study_err << "'";
				_MSG(osstr.str(), MSGFLAG_ERROR);
				pcre_free(filt->re);
				delete(filt);
				for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
					pcre_free(local_pcre[zed]->re);
					pcre_free(local_pcre[zed]->study);
					delete(local_pcre[zed]);
				}
				return -1;
			}

			filt->filter = ltop.data;
			local_pcre.push_back(filt);

			// Peek at the next item
			if (precs.size() <= 0) {
				_MSG("Couldn't parse filter line '" + filter_str + "', expected ',' "
					 "or ')'", MSGFLAG_ERROR);
				for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
					pcre_free(local_pcre[zed]->re);
					pcre_free(local_pcre[zed]->study);
					delete(local_pcre[zed]);
				}
				return -1;
			}

			ltop = precs.front();
			precs.pop_front();

			// If it's a delimiter, skip over it and continue
			if (ltop.type == _kis_lex_delim) {
				continue;
			}

			// If it's a close paren, close down
			if (ltop.type == _kis_lex_pclose) {
				if (local_inverts[_filter_type_pcre] != -1 && 
					local_inverts[_filter_type_pcre] != negate) {
					_MSG("Couldn't parse filter line '" + filter_str + "', filter "
						 "has an illegal mix of normal and inverted PCRE filters. "
						 "A filter type must be either all inverted addresses or all "
						 "standard addresses.", MSGFLAG_ERROR);
					for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
						pcre_free(local_pcre[zed]->re);
						pcre_free(local_pcre[zed]->study);
						delete(local_pcre[zed]);
					}
					return -1;
				}
				local_inverts[_filter_type_pcre] = negate;
				type = _filter_stacker_none;
				mtype = _filter_type_none;
				negate = 0;
				continue;
			}

			// Fall through and hit errors about anything else
			_MSG("Couldn't parse filter line '" + filter_str + "', expected ',' "
				 "or ')'", MSGFLAG_ERROR);
			for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
				pcre_free(local_pcre[zed]->re);
				pcre_free(local_pcre[zed]->study);
				delete(local_pcre[zed]);
			}
			return -1;
#endif
		}

	}

	// Check all the negate joins before we edit anything
	int negfail = 0;
	negate = local_inverts[_filter_type_bssid];
	if (negate != -1) {
		macvec = local_maps[_filter_type_bssid];
		if (bssid_invert != -1 && negate != bssid_invert) {
			negfail = 1;
		}
	}
	negate = local_inverts[_filter_type_source];
	if (negate != -1) {
		macvec = local_maps[_filter_type_source];
		if (source_invert != -1 && negate != source_invert) {
			negfail = 1;
		}
	}
	negate = local_inverts[_filter_type_dest];
	if (negate != -1) {
		macvec = local_maps[_filter_type_dest];
		if (dest_invert != -1 && negate != dest_invert) {
			negfail = 1;
		}
	}
	negate = local_inverts[_filter_type_any];
	if (negate != -1) {
		macvec = local_maps[_filter_type_any];
		if ((dest_invert != 1 && negate != dest_invert) ||
			(source_invert != 1 && negate != source_invert) ||
			(bssid_invert != 1 && negate != bssid_invert)) {
			_MSG("Couldn't parse filter line '" + filter_str + "', filter uses the "
				 "ANY filter term.  The ANY filter can only be used on inverted "
				 "matches to discard any packets not matching the specified address, "
				 "and the DEST, SOURCE, and BSSID filter terms must contain only "
				 "inverted matches.", MSGFLAG_ERROR);
			negfail = 1;
		}
	}
#ifdef HAVE_LIBPCRE
	negate = local_inverts[_filter_type_pcre];
	if (negate != -1) {
		macvec = local_maps[_filter_type_pcre];
		if (pcre_invert != -1 && negate != pcre_invert) {
			negfail = 1;
		}
	}
#endif

	if (negfail != 0) {
		_MSG("Couldn't parse filter line '" + filter_str + "', filter "
			 "has an illegal mix of normal and inverted addresses. "
			 "A filter type must be either all inverted addresses or all "
			 "standard addresses.", MSGFLAG_ERROR);
#ifdef HAVE_LIBPCRE
		for (unsigned zed = 0; zed < local_pcre.size(); zed++) {
			pcre_free(local_pcre[zed]->re);
			pcre_free(local_pcre[zed]->study);
			delete(local_pcre[zed]);
		}
#endif
		return -1;
	}

	// Join all the maps back up with the real filters
	negate = local_inverts[_filter_type_bssid];
	if (negate != -1) {
		macvec = local_maps[_filter_type_bssid];
		bssid_invert = negate;
		for (unsigned int x = 0; x < macvec.size(); x++) {
			bssid_map.insert(macvec[x], 1);
		}
	}

	negate = local_inverts[_filter_type_source];
	if (negate != -1) {
		macvec = local_maps[_filter_type_source];
		source_invert = negate;
		for (unsigned int x = 0; x < macvec.size(); x++) {
			source_map.insert(macvec[x], 1);
		}
	}

	negate = local_inverts[_filter_type_dest];
	if (negate != -1) {
		macvec = local_maps[_filter_type_dest];
		dest_invert = negate;
		for (unsigned int x = 0; x < macvec.size(); x++) {
			dest_map.insert(macvec[x], 1);
		}
	}

	negate = local_inverts[_filter_type_any];
	if (negate != -1) {
		macvec = local_maps[_filter_type_any];
		for (unsigned int x = 0; x < macvec.size(); x++) {
			dest_map.insert(macvec[x], 1);
			source_map.insert(macvec[x], 1);
			bssid_map.insert(macvec[x], 1);
		}
	}

#ifdef HAVE_LIBPCRE
	negate = local_inverts[_filter_type_pcre];
	if (negate != -1) {
		pcre_invert = negate;
		for (unsigned int x = 0; x < local_pcre.size(); x++) {
			pcre_vec.push_back(local_pcre[x]);
		}
	}
#endif

	return 1;
	
#if 0
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
#endif
}

int FilterCore::RunFilter(mac_addr bssidmac, mac_addr sourcemac,
						  mac_addr destmac) {
	int hit = 0;
	// Clumsy artifact of how iters are defined for macmap currently, must
	// be defined as an assign
	macmap<int>::iterator fitr = bssid_map.find(bssidmac);
	
	if ((fitr != bssid_map.end() && bssid_invert == 1) ||
		(fitr == bssid_map.end() && bssid_invert == 0)) {
		bssid_hit++;
		hit = 1;
	}

	fitr = source_map.find(sourcemac);
	if ((fitr != source_map.end() && source_invert == 1) ||
		(fitr == source_map.end() && source_invert == 0)) {
		source_hit++;
		hit = 1;
	}

	fitr = dest_map.find(destmac);
	if ((fitr != dest_map.end() && dest_invert == 1) ||
		(fitr == dest_map.end() && dest_invert == 0)) {
		dest_hit++;
		hit = 1;
	}

	return hit;
}

int FilterCore::FetchPCREHits() {
#ifndef HAVE_LIBPCRE
	return 0;
#else
	return pcre_hit;
#endif
}

int FilterCore::RunPcreFilter(string in_text) {
#ifndef HAVE_LIBPCRE
	return 0;
#else
	int ovector[128];
	int rc;

	for (unsigned int x = 0; x < pcre_vec.size(); x++) {
		rc = pcre_exec(pcre_vec[x]->re, pcre_vec[x]->study, in_text.c_str(),
					   in_text.length(), 0, 0, ovector, 128);
		if ((rc >= 0 && pcre_invert == 0) || (rc < 0 && pcre_invert == 1))
			return 1;
	}
#endif
	return 0;
}

