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

#include "configfile.h"
#include "capturesourceutil.h"

map<string, int> ParseEnableLine(string in_named) {
    map<string, int> retmap;

    unsigned int begin = 0;
    unsigned int end = in_named.find(",");
    int done = 0;

    while (done == 0) {
        if (end == string::npos) {
            end = in_named.length();
            done = 1;
        }

        string ensrc = in_named.substr(begin, end-begin);
        begin = end+1;
        end = in_named.find(",", begin);

        retmap[StrLower(ensrc)] = 0;
    }

    return retmap;
}

int ParseCardLines(vector<string> *in_lines, vector<capturesource *> *in_sources) {
    string sourceopt;
    unsigned int begin, end;

    // Now tokenize the sources
    for (unsigned int x = 0; x < in_lines->size(); x++) {
        sourceopt = (*in_lines)[x];

        begin = 0;
        end = sourceopt.find(",");
        vector<string> optlist;

        while (end != string::npos) {
            string subopt = sourceopt.substr(begin, end-begin);
            begin = end+1;
            end = sourceopt.find(",", begin);
            optlist.push_back(subopt);
        }
        optlist.push_back(sourceopt.substr(begin, sourceopt.size() - begin));

        if (optlist.size() < 3) {
            return (-1) * (x + 1);
        }

        capturesource *newsource = new capturesource;
        newsource->source = NULL;
        newsource->scardtype = optlist[0];
        newsource->interface = optlist[1];
        newsource->name = optlist[2];
        memset(&newsource->packparm, 0, sizeof(packet_parm));

        in_sources->push_back(newsource);
    }

    return 1;
}

int BindRootSources(vector<capturesource *> *in_capsources, map<string, int> *in_enable,
                   int filter_enable) {
    // Now loop through each of the sources - parse the engines, interfaces, types.
    // Open any that need to be opened as root.
    for (unsigned int src = 0; src < in_capsources->size(); src++) {
        capturesource *csrc = (*in_capsources)[src];

        // If we didn't get sources on the command line or if we have a forced enable
        // on the command line, check to see if we should enable this source.  If we just
        // skip it it keeps a NULL capturesource pointer and gets ignored in the code.
        if (filter_enable) {
            if (in_enable->find(StrLower(csrc->name)) == in_enable->end() &&
                in_enable->size() != 0)
            continue;
        }

        (*in_enable)[StrLower(csrc->name)] = 1;

        // Figure out the card type
        const char *sctype = csrc->scardtype.c_str();

        if (!strcasecmp(sctype, "cisco"))
            csrc->cardtype = card_cisco;
        else if (!strcasecmp(sctype, "cisco_cvs"))
            csrc->cardtype = card_cisco_cvs;
        else if (!strcasecmp(sctype, "cisco_bsd"))
            csrc->cardtype = card_cisco_bsd;
        else if (!strcasecmp(sctype, "prism2"))
            csrc->cardtype = card_prism2;
        else if (!strcasecmp(sctype, "prism2_legacy"))
            csrc->cardtype = card_prism2_legacy;
        else if (!strcasecmp(sctype, "prism2_bsd"))
            csrc->cardtype = card_prism2_bsd;
        else if (!strcasecmp(sctype, "prism2_hostap"))
            csrc->cardtype = card_prism2_hostap;
        else if (!strcasecmp(sctype, "orinoco"))
            csrc->cardtype = card_orinoco;
        else if (!strcasecmp(sctype, "generic"))
            csrc->cardtype = card_generic;
        else if (!strcasecmp(sctype, "wsp100"))
            csrc->cardtype = card_wsp100;
        else if (!strcasecmp(sctype, "wtapfile"))
            csrc->cardtype = card_wtapfile;
        else if (!strcasecmp(sctype, "viha"))
            csrc->cardtype = card_viha;
        else if (!strcasecmp(sctype, "ar5k"))
            csrc->cardtype = card_ar5k;
        else if (!strcasecmp(sctype, "drone"))
            csrc->cardtype= card_drone;
        else {
            fprintf(stderr, "FATAL:  Source %d (%s):  Unknown card type '%s'\n", src, csrc->name.c_str(), sctype);
            exit(1);
        }

        // Open it if it needs to be opened as root
        card_type ctype = csrc->cardtype;

        if (ctype == card_prism2_legacy) {
#ifdef HAVE_LINUX_NETLINK
            fprintf(stderr, "Source %d (%s): Using prism2 to capture packets.\n", src, csrc->name.c_str());

            csrc->source = new Prism2Source;
#else
            fprintf(stderr, "FATAL:  Source %d (%s): Linux netlink support was not compiled in.\n", src, csrc->name.c_str());
            exit(1);
#endif
        } else if (ctype == card_cisco || ctype == card_cisco_cvs || ctype == card_cisco_bsd ||
                   ctype == card_prism2 || ctype == card_prism2_bsd || ctype == card_prism2_hostap ||
                   ctype == card_orinoco || ctype == card_generic || ctype == card_ar5k) {
#ifdef HAVE_LIBPCAP
            if (csrc->interface == "") {
                fprintf(stderr, "FATAL:  Source %d (%s): No capture device specified.\n", src, csrc->name.c_str());
                exit(1);
            }

            fprintf(stderr, "Source %d (%s): Using pcap to capture packets from %s\n",
                    src, csrc->name.c_str(), csrc->interface.c_str());

            csrc->source = new PcapSource;
#else
            fprintf(stderr, "FATAL:  Source %d (%s): Pcap support was not compiled in.\n", src, csrc->name.c_str());
            exit(1);
#endif
        } else if (ctype == card_wtapfile) {
#ifdef HAVE_LIBWIRETAP
            if (csrc->interface == "") {
                fprintf(stderr, "FATAL:  Source %d (%s): No capture device specified.\n", src, csrc->name.c_str());
                exit(1);
            }

            fprintf(stderr, "Source %d (%s): Defering wtapfile open until priv drop.\n", src, csrc->name.c_str());
#else
            fprintf(stderr, "FATAL:  Source %d (%s): libwiretap support was not compiled in.\n", src, csrc->name.c_str());
            exit(1);
#endif
        } else if (ctype == card_drone) {
            if (csrc->interface == "") {
                fprintf(stderr, "FATAL:  Source %d (%s): No capture device specified.\n", src, csrc->name.c_str());
                exit(1);
            }

            fprintf(stderr, "Source %d (%s): Defering drone open until priv drop.\n", src, csrc->name.c_str());

        } else if (ctype == card_wsp100) {
#ifdef HAVE_WSP100
            if (csrc->interface == "") {
                fprintf(stderr, "FATAL:  Source %d (%s): No capture device specified.\n", src, csrc->name.c_str());
                exit(1);
            }

            fprintf(stderr, "Source %d (%s): Using WSP100 to capture packets from %s.\n",
                   src, csrc->name.c_str(), csrc->interface.c_str());

            csrc->source = new Wsp100Source;
#else
            fprintf(stderr, "FATAL:  Source %d (%s): WSP100 support was not compiled in.\n", src, csrc->name.c_str());
            exit(1);
#endif
        } else if (ctype == card_viha) {
#ifdef HAVE_VIHAHEADERS
            fprintf(stderr, "Source %d (%s): Using Viha to capture packets.\n",
                    src, csrc->name.c_str());

            csrc->source = new VihaSource;
#else
            fprintf(stderr, "FATAL:  Source %d (%s): Viha support was not compiled in.\n", src, csrc->name.c_str());
            exit(1);
#endif
        } else {
            fprintf(stderr, "FATAL:  Source %d (%s): Unhandled card type %s\n", src, csrc->name.c_str(), csrc->scardtype.c_str());
            exit(1);
        }

        // Open the packet source
        if (csrc->source != NULL)
            if (csrc->source->OpenSource(csrc->interface.c_str(), csrc->cardtype) < 0) {
                fprintf(stderr, "FATAL: Source %d (%s): %s\n", src, csrc->name.c_str(), csrc->source->FetchError());
                exit(1);
            }
    }


    return 1;
}

int BindUserSources(vector<capturesource *> *in_capsources, map<string, int> *in_enable,
                   int filter_enable) {
    for (unsigned int src = 0; src < in_capsources->size(); src++) {
        capturesource *csrc = (*in_capsources)[src];

        card_type ctype = csrc->cardtype;

        // For any unopened sources...
        if (csrc->source == NULL) {

            if (filter_enable) {
                if (in_enable->find(StrLower(csrc->name)) == in_enable->end() &&
                    in_enable->size() != 0)
                    continue;
            }

            (*in_enable)[StrLower(csrc->name)] = 1;

            if (ctype == card_wtapfile) {
#ifdef HAVE_LIBWIRETAP
                fprintf(stderr, "Source %d (%s): Loading packets from dump file %s\n",
                       src, csrc->name.c_str(), csrc->interface.c_str());

                csrc->source = new WtapFileSource;
#else
                fprintf(stderr, "FATAL: Source %d (%s): Wtapfile support was not compiled in.\n", src, csrc->name.c_str());
                exit(1);
#endif
            } else if (ctype == card_drone) {
                fprintf(stderr, "Source %d (%s): Capturing packets from Drone %s.\n",
                        src, csrc->name.c_str(), csrc->interface.c_str());

                csrc->source = new DroneSource;
            }

            // Open the packet source
            if (csrc->source != NULL)
                if (csrc->source->OpenSource(csrc->interface.c_str(), csrc->cardtype) < 0) {
                    fprintf(stderr, "FATAL: Source %d (%s): %s\n", src, csrc->name.c_str(), csrc->source->FetchError());
                    exit(1);
                }
        }
    }


    return 1;
}

