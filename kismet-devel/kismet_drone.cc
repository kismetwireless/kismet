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

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "getopt.h"
#include <stdlib.h>
#include <signal.h>
#include <pwd.h>
#include <string>
#include <vector>

#include "packet.h"

#include "packetsource.h"
#include "prism2source.h"
#include "pcapsource.h"
#include "wtapfilesource.h"
#include "wsp100source.h"
#include "vihasource.h"

#include "gpsd.h"
#include "tcpstreamer.h"
#include "configfile.h"

#ifndef exec_name
char *exec_name;
#endif

const char *config_base = "kismet_drone.conf";

typedef struct capturesource {
    KisPacketSource *source;
    string name;
    string interface;
    string scardtype;
    card_type cardtype;
    packet_parm packparm;
};

// Capture sources
vector<capturesource *> packet_sources;

// Catch our interrupt
void CatchShutdown(int sig) {
    for (unsigned int x = 0; x < packet_sources.size(); x++) {
        if (packet_sources[x]->source != NULL) {
            packet_sources[x]->source->CloseSource();
            delete packet_sources[x]->source;
            delete packet_sources[x];
        }
    }

    fprintf(stderr, "Kismet drone terminating.\n");

    exit(0);
}

int Usage(char *argv) {
    printf("Usage: %s [OPTION]\n", argv);
    printf("Most (or all) of these options can (and should) be configured via the\n"
           "kismet_drone.conf global config file, but can be overridden here.\n");
    printf(
           "  -f, --config-file <file>     Use alternate config file\n"
           "  -c, --capture-source <src>   Packet capture source line (type,interface,name)\n"
           "  -C, --enable-capture-sources Comma separated list of named packet sources to use.\n"
           "  -p, --port <port>            TCPIP server port for stream connections\n"
           "  -a, --allowed-hosts <hosts>  Comma separated list of hosts allowed to connect\n"
           "  -s, --silent                 Don't send any output to console.\n"
           "  -N, --server-name            Server name\n"
           "  -v, --version                Kismet version\n"
           "  -h, --help                   What do you think you're reading?\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    exec_name = argv[0];

    char *configfile = NULL;
    char *servername = NULL;

    string allowed_hosts;
    int tcpport = -1;
    int tcpmax;

    int silent = 0;

    TcpStreamer streamer;

    // For commandline and file sources
    string named_sources;
    vector<string> source_input_vec;
    int source_from_cmd = 0;
    int enable_from_cmd = 0;

    vector<client_ipblock *> legal_ipblock_vec;

    static struct option long_options[] = {   /* options table */
        { "config-file", required_argument, 0, 'f' },
        { "capture-source", required_argument, 0, 'c' },
        { "enable-capture-sources", required_argument, 0, 'C' },
        { "port", required_argument, 0, 'p' },
        { "allowed-hosts", required_argument, 0, 'a' },
        { "server-name", required_argument, 0, 'N' },
        { "help", no_argument, 0, 'h' },
        { "version", no_argument, 0, 'v' },
        { "silent", no_argument, 0, 's' },
        { 0, 0, 0, 0 }
    };
    int option_index;

    // Catch the interrupt handler to shut down
    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGPIPE, SIG_IGN);

    while(1) {
        int r = getopt_long(argc, argv, "f:c:C:p:a:N:hvs",
                            long_options, &option_index);
        if (r < 0) break;
        switch(r) {
        case 's':
            // Silent
            silent = 1;
            break;
        case 'f':
            // Config path
            configfile = optarg;
            fprintf(stderr, "Using alternate config file: %s\n", configfile);
            break;
        case 'c':
            // Capture type
            source_input_vec.push_back(optarg);
            source_from_cmd = 1;
            break;
        case 'C':
            // Named sources
            named_sources = optarg;
            enable_from_cmd = 1;
            fprintf(stderr, "Using specified capture sources: %s\n", named_sources.c_str());
            break;
        case 'p':
            // Port
            if (sscanf(optarg, "%d", &tcpport) != 1) {
                fprintf(stderr, "Invalid port number.\n");
                Usage(argv[0]);
            }
            break;
        case 'a':
            // Allowed
            allowed_hosts = optarg;
            break;
        case 'N':
            // Servername
            servername = optarg;
            break;
        case 'v':
            // version
            fprintf(stderr, "Kismet Drone %d.%d.%d\n", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY);
            exit(0);
            break;
        default:
            Usage(argv[0]);
            break;
        }
    }

    // If we haven't gotten a command line config option...
    int freeconf = 0;
    if (configfile == NULL) {
        configfile = (char *) malloc(1024*sizeof(char));
        snprintf(configfile, 1024, "%s/%s", SYSCONF_LOC, config_base);
        freeconf = 1;
    }

    ConfigFile *conf = new ConfigFile;

    // Parse the config and load all the values from it and/or our command
    // line options.  This is a little soupy but it does the trick.
    if (conf->ParseConfig(configfile) < 0) {
        exit(1);
    }

    if (freeconf)
        free(configfile);

#ifdef HAVE_SUID
    struct passwd *pwordent;
    const char *suid_user;
    uid_t suid_id, real_uid;

    real_uid = getuid();

    if (conf->FetchOpt("suiduser") != "") {
        suid_user = strdup(conf->FetchOpt("suiduser").c_str());
        if ((pwordent = getpwnam(suid_user)) == NULL) {
            fprintf(stderr, "FATAL:  Could not find user '%s' for dropping priviledges.\n", suid_user);
            fprintf(stderr, "        Make sure you have a valid user set for 'suiduser' in your config.\n");
            exit(1);
        } else {
            suid_id = pwordent->pw_uid;

            if (suid_id == 0) {
                // If we're suiding to root...
                fprintf(stderr, "FATAL:  Specifying a uid-0 user for the priv drop is pointless.  Recompile\n");
                fprintf(stderr, "        with --disable-setuid if you really want this.\n");
                exit(1);
            } else if (suid_id != real_uid && real_uid != 0) {
                // If we're not running as root (ie, we've suid'd to root)
                // and if we're not switching to the user that ran us
                // then we don't like it and we bail.
                fprintf(stderr, "FATAL:  kismet_server must be started as root or as the suid-target user.\n");
                exit(1);
            }


            fprintf(stderr, "Will drop privs to %s (%d)\n", suid_user, suid_id);
        }
    } else {
        fprintf(stderr, "FATAL:  No 'suiduser' option in the config file.\n");
        exit(1);
    }
#else
    fprintf(stderr, "Suid priv-dropping disabled.  This may not be secure.\n");
#endif

    // Read all of our packet sources, tokenize the input and then start opening
    // them.

    if (named_sources.length() == 0) {
        named_sources = conf->FetchOpt("enablesources");
    }

    // Parse the enabled sources into a map
    map<string, int> enable_name_map;

    unsigned int begin = 0;
    unsigned int end = named_sources.find(",");
    int done = 0;

    // Tell them if we're enabling everything
    if (named_sources.length() == 0)
        fprintf(stderr, "No enable sources specified, all sources will be enabled.\n");

    // Command line sources override the enable line, unless we also got an enable line
    // from the command line too.
    if ((source_from_cmd == 0 || enable_from_cmd == 1) && named_sources.length() > 0) {
        while (done == 0) {
            if (end == string::npos) {
                end = named_sources.length();
                done = 1;
            }

            string ensrc = named_sources.substr(begin, end-begin);
            begin = end+1;
            end = named_sources.find(",", begin);

            enable_name_map[StrLower(ensrc)] = 0;
        }
    }

    string sourceopt;

    // Read the config file if we didn't get any sources on the command line
    if (source_input_vec.size() == 0)
        source_input_vec = conf->FetchOptVec("source");

    if (source_input_vec.size() == 0) {
        fprintf(stderr, "FATAL:  No valid packet sources defined in config or passed on command line.\n");
        exit(1);
    }

    // Now tokenize the sources
    for (unsigned int x = 0; x < source_input_vec.size(); x++) {
        sourceopt = source_input_vec[x];

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
            fprintf(stderr, "FATAL:  Invalid source line '%s'\n", sourceopt.c_str());
            exit(1);
        }

        capturesource *newsource = new capturesource;
        newsource->source = NULL;
        newsource->scardtype = optlist[0];
        newsource->interface = optlist[1];
        newsource->name = optlist[2];
        memset(&newsource->packparm, 0, sizeof(packet_parm));

        packet_sources.push_back(newsource);
    }

    source_input_vec.clear();

    // Now loop through each of the sources - parse the engines, interfaces, types.
    // Open any that need to be opened as root.
    for (unsigned int src = 0; src < packet_sources.size(); src++) {
        capturesource *csrc = packet_sources[src];

        // If we didn't get sources on the command line or if we have a forced enable
        // on the command line, check to see if we should enable this source.  If we just
        // skip it it keeps a NULL capturesource pointer and gets ignored in the code.
        if ((source_from_cmd == 0 || enable_from_cmd == 1) &&
            (enable_name_map.find(StrLower(csrc->name)) == enable_name_map.end() &&
             named_sources.length() != 0)) {
            continue;
        }

        enable_name_map[StrLower(csrc->name)] = 1;

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

    // Once the packet source is opened, we shouldn't need special privileges anymore
    // so lets drop to a normal user.  We also don't want to open our logfiles as root
    // if we can avoid it.  Once we've dropped, we'll investigate our sources again and
    // open any defered
#ifdef HAVE_SUID
    if (setuid(suid_id) < 0) {
        fprintf(stderr, "FATAL:  setuid() to %s (%d) failed.\n", suid_user, suid_id);
        exit(1);
    } else {
        fprintf(stderr, "Dropped privs to %s (%d)\n", suid_user, suid_id);
    }
#endif

    // WE ARE NOW RUNNING AS THE TARGET UID

    for (unsigned int src = 0; src < packet_sources.size(); src++) {
        capturesource *csrc = packet_sources[src];

        card_type ctype = csrc->cardtype;

        // For any unopened soruces...
        if (csrc->source == NULL) {

            // Again, see if we should enable anything
            if ((source_from_cmd == 0 || enable_from_cmd == 1) &&
                (enable_name_map.find(StrLower(csrc->name)) == enable_name_map.end() &&
                 named_sources.length() != 0)) {
                continue;
            }

            enable_name_map[StrLower(csrc->name)] = 1;

            if (ctype == card_wtapfile) {
#ifdef HAVE_LIBWIRETAP
                fprintf(stderr, "Source %d (%s): Loading packets from dump file %s\n",
                       src, csrc->name.c_str(), csrc->interface.c_str());

                csrc->source = new WtapFileSource;
#else
                fprintf(stderr, "FATAL: Source %d (%s): Wtapfile support was not compiled in.\n", src, csrc->name.c_str());
                exit(1);
#endif
            }

            // Open the packet source
            if (csrc->source != NULL)
                if (csrc->source->OpenSource(csrc->interface.c_str(), csrc->cardtype) < 0) {
                    fprintf(stderr, "FATAL: Source %d (%s): %s\n", src, csrc->name.c_str(), csrc->source->FetchError());
                    exit(1);
                }
        }
    }

    // See if we tried to enable something that didn't exist
    if (enable_name_map.size() == 0) {
        fprintf(stderr, "FATAL:  No sources were enabled.  Check your source lines in your config file\n"
                "        and on the command line.\n");
        exit(1);
    }

    for (map<string, int>::iterator enmitr = enable_name_map.begin();
         enmitr != enable_name_map.end(); ++enmitr) {
        if (enmitr->second == 0) {
            fprintf(stderr, "FATAL:  No source with the name '%s' was found.  Check your source and enable\n"
                    "        lines in your configfile and on the command line.\n", enmitr->first.c_str());
            exit(1);
        }
    }


    // Now parse the rest of our options
    // ---------------

    if (servername == NULL) {
        if (conf->FetchOpt("servername") != "") {
            servername = strdup(conf->FetchOpt("servername").c_str());
        } else {
            servername = strdup("Unnamed");
        }
    }

    if (tcpport == -1) {
        if (conf->FetchOpt("tcpport") == "") {
            fprintf(stderr, "FATAL:  No tcp port given to listen for stream connections.\n");
            exit(1);
        } else if (sscanf(conf->FetchOpt("tcpport").c_str(), "%d", &tcpport) != 1) {
            fprintf(stderr, "FATAL:  Invalid config file value for tcp port.\n");
            exit(1);
        }
    }

    if (conf->FetchOpt("maxclients") == "") {
        fprintf(stderr, "FATAL:  No maximum number of clients given.\n");
        exit(1);
    } else if (sscanf(conf->FetchOpt("maxclients").c_str(), "%d", &tcpmax) != 1) {
        fprintf(stderr, "FATAL:  Invalid config file option for max clients.\n");
        exit(1);
    }

    if (allowed_hosts.length() == 0) {
        if (conf->FetchOpt("allowedhosts") == "") {
            fprintf(stderr, "FATAL:  No list of allowed hosts.\n");
            exit(1);
        }

        allowed_hosts = conf->FetchOpt("allowedhosts");
    }

    // Parse the allowed hosts into the vector
    unsigned int ahstart = 0;
    unsigned int ahend = allowed_hosts.find(",");

    int ahdone = 0;
    while (ahdone == 0) {
        string hoststr;

        if (ahend == string::npos) {
            ahend = allowed_hosts.length();
            ahdone = 1;
        }

        hoststr = allowed_hosts.substr(ahstart, ahend - ahstart);
        ahstart = ahend + 1;
        ahend = allowed_hosts.find(",", ahstart);

        client_ipblock *ipb = new client_ipblock;

        // Find the netmask divider, if one exists
        unsigned int masksplit = hoststr.find("/");
        if (masksplit == string::npos) {
            // Handle hosts with no netmask - they're treated as single hosts
            inet_aton("255.255.255.255", &(ipb->mask));

            if (inet_aton(hoststr.c_str(), &(ipb->network)) == 0) {
                fprintf(stderr, "FATAL:  Illegal IP address '%s' in allowed hosts list.\n",
                        hoststr.c_str());
                exit(1);
            }
        } else {
            // Handle pairs
            string hosthalf = hoststr.substr(0, masksplit);
            string maskhalf = hoststr.substr(masksplit + 1, hoststr.length() - (masksplit + 1));

            if (inet_aton(hosthalf.c_str(), &(ipb->network)) == 0) {
                fprintf(stderr, "FATAL:  Illegal IP address '%s' in allowed hosts list.\n",
                        hosthalf.c_str());
                exit(1);
            }

            int validmask = 1;
            if (maskhalf.find(".") == string::npos) {
                // If we have a single number (ie, /24) calculate it and put it into
                // the mask.
                long masklong = strtol(maskhalf.c_str(), (char **) NULL, 10);

                if (masklong < 0 || masklong > 32) {
                    validmask = 0;
                } else {
                    if (masklong == 0)
                        masklong = 32;

                    ipb->mask.s_addr = htonl((-1 << (32 - masklong)));
                }
            } else {
                // We have a dotted quad mask (ie, 255.255.255.0), convert it
                if (inet_aton(maskhalf.c_str(), &(ipb->mask)) == 0)
                    validmask = 0;
            }

            if (validmask == 0) {
                fprintf(stderr, "FATAL:  Illegal netmask '%s' in allowed hosts list.\n",
                        maskhalf.c_str());
                exit(1);
            }
        }

        // Catch 'network' addresses that aren't network addresses.
        if ((ipb->network.s_addr & ipb->mask.s_addr) != ipb->network.s_addr) {
            fprintf(stderr, "FATAL:  Invalid network '%s' in allowed hosts list.\n",
                    inet_ntoa(ipb->network));
            exit(1);
        }

        // Add it to our vector
        legal_ipblock_vec.push_back(ipb);
    }

    // Now we can start doing things...
    fprintf(stderr, "Kismet %d.%d.%d (%s)\n",
            VERSION_MAJOR, VERSION_MINOR, VERSION_TINY, servername);

    for (unsigned int x = 0; x < packet_sources.size(); x++) {
        if (packet_sources[x]->source == NULL)
            continue;

        fprintf(stderr, "Source %d (%s): Capturing packets from %s\n",
                 x, packet_sources[x]->name.c_str(), packet_sources[x]->source->FetchType());
    }

    fprintf(stderr, "Listening on port %d.\n", tcpport);
    for (unsigned int ipvi = 0; ipvi < legal_ipblock_vec.size(); ipvi++) {
        char *netaddr = strdup(inet_ntoa(legal_ipblock_vec[ipvi]->network));
        char *maskaddr = strdup(inet_ntoa(legal_ipblock_vec[ipvi]->mask));

        fprintf(stderr, "Allowing connections from %s/%s\n", netaddr, maskaddr);

        free(netaddr);
        free(maskaddr);
    }

    if (streamer.Setup(tcpmax, tcpport, &legal_ipblock_vec) < 0) {
        fprintf(stderr, "Failed to set up stream server: %s\n", streamer.FetchError());
        CatchShutdown(-1);
    }

    fd_set read_set;
    int max_fd = 0;

    FD_ZERO(&read_set);

    // We want to remember all our FD's so we don't have to keep calling functions which
    // call functions and so on.  Fill in our descriptors while we're at it.
    int stream_descrip = streamer.FetchDescriptor();
    if (stream_descrip > max_fd && stream_descrip > 0)
        max_fd = stream_descrip;
    FD_SET(stream_descrip, &read_set);

    for (unsigned int x = 0; x < packet_sources.size(); x++) {
        if (packet_sources[x]->source == NULL)
            continue;

        int source_descrip = packet_sources[x]->source->FetchDescriptor();
        if (source_descrip > 0) {
            FD_SET(source_descrip, &read_set);
            if (source_descrip > max_fd)
                max_fd = source_descrip;
        }
    }

    while (1) {
        fd_set rset, wset;

        max_fd = streamer.MergeSet(read_set, max_fd, &rset, &wset);

        struct timeval tm;
        tm.tv_sec = 0;
        tm.tv_usec = 100000;

        if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
            if (errno != EINTR) {
                fprintf(stderr, "FATAL:  select() error %d (%s)\n", errno, strerror(errno));
                CatchShutdown(-1);
            }
        }

        // We can pass the results of this select to the UI handler without incurring a
        // a delay since it will bail nicely if there aren't any new connections.
        int accept_fd = 0;
        accept_fd = streamer.Poll(rset, wset);
        if (accept_fd < 0) {
            if (!silent)
                fprintf(stderr, "TCP streamer error: %s\n", streamer.FetchError());
        } else if (accept_fd > 0) {
            if (!silent)
                fprintf(stderr, "Accepted streamer connection from %s\n",
                        streamer.FetchError());

            if (accept_fd > max_fd)
                max_fd = accept_fd;
        }

        for (unsigned int src = 0; src < packet_sources.size(); src++) {
            if (packet_sources[src]->source == NULL)
                continue;

            KisPacketSource *psrc = packet_sources[src]->source;

            // Jump through hoops to handle generic packet source
            int process_packet_source = 0;
            if (psrc->FetchDescriptor() < 0) {
                process_packet_source = 1;
            } else {
                if (FD_ISSET(psrc->FetchDescriptor(), &rset)) {
                    process_packet_source = 1;
                }
            }

            if (process_packet_source) {
                kis_packet packet;

                int len;

                // Capture the packet from whatever device
                len = psrc->FetchPacket(&packet);

                // Handle a packet
                if (len > 0) {
                    if (streamer.WritePacket(&packet) < 0) {
                        fprintf(stderr, "FATAL:  Error writing packet to streamer: %s\n",
                                streamer.FetchError());
                        CatchShutdown(-1);
                    }

                    if (packet.data != NULL)
                        delete[] packet.data;
                    // Should always be null, but just in case...
                    if (packet.moddata != NULL)
                        delete[] packet.data;
                }
            }
        }

        // Handle scheduled events
        struct timeval cur_tm;
        gettimeofday(&cur_tm, NULL);
        for (map<int, server_timer_event *>::iterator evtitr = timer_map.begin();
             evtitr != timer_map.end(); ++evtitr) {
            server_timer_event *evt = evtitr->second;

            if ((evt->trigger_tm.tv_sec < cur_tm.tv_sec) ||
                (evt->trigger_tm.tv_sec == cur_tm.tv_sec &&
                 evt->trigger_tm.tv_usec < cur_tm.tv_usec)) {

                // Call the function with the given parameters
                int ret;
                ret = (*evt->callback)(evt, evt->callback_parm);

                if (ret > 0 && evt->timeslices != -1 && evt->recurring) {
                    evt->schedule_tm.tv_sec = cur_tm.tv_sec;
                    evt->schedule_tm.tv_usec = cur_tm.tv_usec;
                    evt->trigger_tm.tv_sec = evt->schedule_tm.tv_sec + (evt->timeslices / 10);
                    evt->trigger_tm.tv_usec = evt->schedule_tm.tv_usec + (evt->timeslices % 10);
                } else {
                    delete evt;
                    timer_map.erase(evtitr);
                }

            }

        }

    }

}
