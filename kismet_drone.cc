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
#include "dronesource.h"
#include "packetsourcetracker.h"
#include "kis_packsources.h"

#include "gpsd.h"
#include "tcpstreamer.h"
#include "configfile.h"

#include "timetracker.h"

#ifndef exec_name
char *exec_name;
#endif

const char *config_base = "kismet_drone.conf";

GPSD *gps = NULL;
#ifdef HAVE_GPS
int gpsmode = 0;
int gps_enable = 0;
#endif

// Timetracker
Timetracker timetracker;

// Source trcker
Packetsourcetracker sourcetracker;

// Catch a fast error shutdown
void ErrorShutdown() {
    sourcetracker.CloseSources();
    sourcetracker.ShutdownChannelChild();

    fprintf(stderr, "Kismet drone exiting.\n");
    exit(1);
}

// Catch our interrupt
void CatchShutdown(int sig) {
    sourcetracker.CloseSources();
    sourcetracker.ShutdownChannelChild();

    fprintf(stderr, "Kismet drone exiting.\n");
    exit(0);
}

int GpsEvent(Timetracker::timer_event *evt, void *parm) {
#ifdef HAVE_GPS
    // The GPS only provides us a new update once per second we might
    // as well only update it here once a second
    if (gps_enable) {
        int gpsret;
        gpsret = gps->Scan();
        if (gpsret < 0) {
            if (!silent)
                fprintf(stderr, "GPS error fetching data: %s\n",
                        gps->FetchError());

            gps_enable = 0;
        }

    }

    // We want to be rescheduled
    return 1;
#endif
    return 0;
}

// Handle channel hopping... this is actually really simple.
int ChannelHopEvent(Timetracker::timer_event *evt, void *parm) {
    sourcetracker.AdvanceChannel();

    return 1;
}

int Usage(char *argv) {
    printf("Usage: %s [OPTION]\n", argv);
    printf("Most (or all) of these options can (and should) be configured via the\n"
           "kismet_drone.conf global config file, but can be overridden here.\n");
    printf("  -I, --initial-channel <n:c>  Initial channel to monitor on (default: 6)\n"
           "                                Format capname:channel\n"
           "  -x, --force-channel-hop      Forcibly enable the channel hopper\n"
           "  -X, --force-no-channel-hop   Forcibly disable the channel hopper\n"
           "  -f, --config-file <file>     Use alternate config file\n"
           "  -c, --capture-source <src>   Packet capture source line (type,interface,name)\n"
           "  -C, --enable-capture-sources Comma separated list of named packet sources to use.\n"
           "  -p, --port <port>            TCPIP server port for stream connections\n"
           "  -a, --allowed-hosts <hosts>  Comma separated list of hosts allowed to connect\n"
           "  -b, --bind-address <address>    Bind to this address. Default INADDR_ANY.\n"
           "  -s, --silent                 Don't send any output to console.\n"
           "  -N, --server-name            Server name\n"
           "  -v, --version                Kismet version\n"
           "  -h, --help                   What do you think you're reading?\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    exec_name = argv[0];

    // Packet and contents
    kis_packet packet;
    uint8_t data[MAX_PACKET_LEN];
    uint8_t moddata[MAX_PACKET_LEN];

    char *configfile = NULL;
    char *servername = NULL;

    char status[STATUS_MAX];
    
    string allowed_hosts, bind_addr;
    int tcpport = -1;
    int tcpmax;

    TcpStreamer streamer;

#ifdef HAVE_GPS
    char gpshost[1024];
    int gpsport = -1;
#endif

    int channel_hop = -1;
    int channel_velocity = 1;
    int channel_dwell = 0;
    int channel_split = 0;

    // Default channels
    vector<string> defaultchannel_vec;
    vector<string> src_initchannel_vec;
    vector<string> src_customchannel_vec;
    
    // We don't actually use this but we need it for calls
    map<mac_addr, wep_key_info *> bssid_wep_map;

    // For commandline and file sources
    string named_sources;
    vector<string> source_input_vec;
    int source_from_cmd = 0;

    vector<client_ipblock *> legal_ipblock_vec;

    int microsleep = 0;

    static struct option long_options[] = {   /* options table */
        { "config-file", required_argument, 0, 'f' },
        { "capture-source", required_argument, 0, 'c' },
        { "enable-capture-sources", required_argument, 0, 'C' },
        { "port", required_argument, 0, 'p' },
        { "allowed-hosts", required_argument, 0, 'a' },
        { "bind-address", required_argument, 0, 'b'},
        { "server-name", required_argument, 0, 'N' },
        { "help", no_argument, 0, 'h' },
        { "version", no_argument, 0, 'v' },
        { "silent", no_argument, 0, 's' },
        { "initial-channel", required_argument, 0, 'I' },
        { "force-channel-hop", no_argument, 0, 'x' },
        { "force-no-channel-hop", no_argument, 0, 'X' },
        { "microsleep", required_argument, 0, 'M' },
        { 0, 0, 0, 0 }
    };
    int option_index;

    // Catch the interrupt handler to shut down
    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGPIPE, SIG_IGN);

    while(1) {
        int r = getopt_long(argc, argv, "f:c:C:p:a:b:N:hvsI:xXM:",
                            long_options, &option_index);
        if (r < 0) break;
        switch(r) {
        case 'M':
            // Microsleep
            if (sscanf(optarg, "%d", &microsleep) != 1) {
                fprintf(stderr, "Invalid microsleep\n");
                Usage(argv[0]);
            }
            break;
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
            named_sources = string(optarg);
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
            allowed_hosts = string(optarg);
            break;
        case 'b':
            bind_addr = string(optarg);
            break;
        case 'N':
            // Servername
            servername = optarg;
            break;
        case 'v':
            // version
            fprintf(stderr, "Kismet Drone %s.%s.%s\n", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY);
            exit(0);
            break;
        case 'x':
            // force channel hop
            channel_hop = 1;
            fprintf(stderr, "Ignoring config file and enabling channel hopping.\n");
            break;
        case 'X':
            // Force channel hop off
            channel_hop = 0;
            fprintf(stderr, "Ignoring config file and disabling channel hopping.\n");
            break;
        case 'I':
            // Initial channel
            src_initchannel_vec.push_back(optarg);
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
        snprintf(configfile, 1024, "%s/%s", getenv("KISMET_CONF") != NULL ? getenv("KISMET_CONF") : SYSCONF_LOC, config_base);
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

    // Catch old configs and yell about them
    if (conf->FetchOpt("cardtype") != "" || conf->FetchOpt("captype") != "" ||
        conf->FetchOpt("capinterface") != "") {
        fprintf(stderr, "FATAL:  Your config file uses the old capture type "
                "definitions.  These have been changed to support multiple captures "
                "and other new features.  You need to install the latest configuration "
                "files.  See the troubleshooting section of the README for more "
                "information.\n");
        exit(1);
    }

    if (conf->FetchOpt("80211achannels") != "" || 
        conf->FetchOpt("80211bchannels") != "") {
        fprintf(stderr, "FATAL:  Your config file uses the old default channel "
                "configuration lines.  You need to install the latest configuration "
                "files.  See the troubleshooting section of the README for more "
                "information.\n");
        exit(1);
    }

#ifdef HAVE_GPS
    if (conf->FetchOpt("gps") == "true") {
        if (sscanf(conf->FetchOpt("gpshost").c_str(), "%1023[^:]:%d", gpshost, &gpsport) != 2) {
            fprintf(stderr, "Invalid GPS host in config (host:port required)\n");
            exit(1);
        }

        gps_enable = 1;
    } else {
            gps_enable = 0;
    }

    if (gps_enable == 1) {
        // Open the GPS
        gps = new GPSD(gpshost, gpsport);

        // Lock GPS position
        if (conf->FetchOpt("gpsmodelock") == "true") {
            fprintf(stderr, "Enabling GPS position lock override (broken GPS unit reports 0 always)\n");
            gps->SetOptions(GPSD_OPT_FORCEMODE);
        }

        if (gps->OpenGPSD() < 0) {
            fprintf(stderr, "%s\n", gps->FetchError());

            gps_enable = 0;
        } else {
            fprintf(stderr, "Opened GPS connection to %s port %d\n",
                    gpshost, gpsport);

        }
    }

    // Update GPS coordinates and handle signal loss if defined
    timetracker.RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, &GpsEvent, NULL);

#endif

    // Register the gps and timetracker with the sourcetracker
    sourcetracker.AddGpstracker(gps);
    sourcetracker.AddTimetracker(&timetracker);

    // Register the sources
    RegisterKismetSources(&sourcetracker);

    // Read all of our packet sources, tokenize the input and then start opening
    // them.

    if (named_sources.length() == 0) {
        named_sources = conf->FetchOpt("enablesources");
    }

    // Tell them if we're enabling everything
    if (named_sources.length() == 0)
        fprintf(stderr, "No specific sources given to be enabled, all will be enabled.\n");

    // Read the config file if we didn't get any sources on the command line
    if (source_input_vec.size() == 0)
        source_input_vec = conf->FetchOptVec("source");

    // Now look at our channel options
    if (channel_hop == -1) {
        if (conf->FetchOpt("channelhop") == "true") {
            fprintf(stderr, "Enabling channel hopping.\n");
            channel_hop = 1;
        } else {
            fprintf(stderr, "Disabling channel hopping.\n");
            channel_hop = 0;
        }
    }

    if (channel_hop == 1) {
        if (conf->FetchOpt("channelsplit") == "true") {
            fprintf(stderr, "Enabling channel splitting.\n");
            channel_split = 1;
        } else {
            fprintf(stderr, "Disabling channel splitting.\n");
            channel_split = 0;
        }

        if (conf->FetchOpt("channelvelocity") != "") {
            if (sscanf(conf->FetchOpt("channelvelocity").c_str(), "%d", 
                       &channel_velocity) != 1) {
                fprintf(stderr, "FATAL:  Illegal config file value for "
                        "channelvelocity.\n");
                exit(1);
            }

            if (channel_velocity < 1 || channel_velocity > 10) {
                fprintf(stderr, "FATAL:  Illegal value for channelvelocity, must "
                        "be between 1 and 10.\n");
                exit(1);
            }
        }

        if (conf->FetchOpt("channeldwell") != "") {
            if (sscanf(conf->FetchOpt("channeldwell").c_str(), "%d",
                       &channel_dwell) != 1) {
                fprintf(stderr, "FATAL: Illegal config file value for "
                        "channeldwell.\n");
                exit(1);
            }
        }

        // Fetch the vector of default channels
        defaultchannel_vec = conf->FetchOptVec("defaultchannels");
        if (defaultchannel_vec.size() == 0) {
            fprintf(stderr, "FATAL:  Could not find any defaultchannels config lines "
                    "and channel hopping was requested.");
            exit(1);
        }

        // Fetch custom channels for individual sources
        src_customchannel_vec = conf->FetchOptVec("sourcechannels");
    }

    // Register our default channels
    if (sourcetracker.RegisterDefaultChannels(&defaultchannel_vec) < 0) {
        fprintf(stderr, "FATAL:  %s\n", sourcetracker.FetchError());
        exit(1);
    }

    // Turn all our config data into meta packsources, or fail...  If we're
    // passing the sources from the command line, we enable them all, so we
    // null the named_sources string
    int old_chhop = channel_hop;
    if (sourcetracker.ProcessCardList(source_from_cmd ? "" : named_sources, 
                                      &source_input_vec, &src_customchannel_vec, 
                                      &src_initchannel_vec,
                                      channel_hop, channel_split) < 0) {
        fprintf(stderr, "FATAL: %s\n", sourcetracker.FetchError());
        exit(1);
    }
        
    // This would only change if we're channel hopping and processcardlist had
    // to turn it off because nothing supports it, so print a notice...
    if (old_chhop != channel_hop)
        fprintf(stderr, "NOTICE: Disabling channel hopping, no enabled sources "
                "are able to change channel.\n");
    
    // Now enable root sources...
    setreuid(0, 0);

    // Bind the root sources
    if (sourcetracker.BindSources(1) < 0) {
        fprintf(stderr, "FATAL: %s\n", sourcetracker.FetchError());
        exit(1);
    }

    // Spawn the channel control source.  All future exits must now call the real
    // exit function to terminate the channel hopper!
    if (sourcetracker.SpawnChannelChild() < 0) {
        fprintf(stderr, "FATAL: %s\n", sourcetracker.FetchError());
        exit(1);
    }


    // Once the packet source and channel control is opened, we shouldn't need special
    // privileges anymore so lets drop to a normal user.  We also don't want to open our
    // logfiles as root if we can avoid it.  Once we've dropped, we'll investigate our
    // sources again and open any defered
#ifdef HAVE_SUID
    if (setuid(suid_id) < 0) {
        fprintf(stderr, "FATAL:  setuid() to %s (%d) failed.\n", suid_user, suid_id);
        exit(1);
    } else {
        fprintf(stderr, "Dropped privs to %s (%d)\n", suid_user, suid_id);
    }
#endif

    // WE ARE NOW RUNNING AS THE TARGET UID

    // Bind the user sources
    if (sourcetracker.BindSources(0) < 0) {
        fprintf(stderr, "FATAL: %s\n", sourcetracker.FetchError());
        ErrorShutdown();
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
            ErrorShutdown();
        } else if (sscanf(conf->FetchOpt("tcpport").c_str(), "%d", &tcpport) != 1) {
            fprintf(stderr, "FATAL:  Invalid config file value for tcp port.\n");
            ErrorShutdown();
        }
    }

    if (conf->FetchOpt("maxclients") == "") {
        fprintf(stderr, "FATAL:  No maximum number of clients given.\n");
        ErrorShutdown();
    } else if (sscanf(conf->FetchOpt("maxclients").c_str(), "%d", &tcpmax) != 1) {
        fprintf(stderr, "FATAL:  Invalid config file option for max clients.\n");
        ErrorShutdown();
    }

    if (allowed_hosts.length() == 0) {
        if (conf->FetchOpt("allowedhosts") == "") {
            fprintf(stderr, "FATAL:  No list of allowed hosts.\n");
            ErrorShutdown();
        }

        allowed_hosts = conf->FetchOpt("allowedhosts");
    }

    if (bind_addr.length() == 0) {
        if (conf->FetchOpt("bindaddress") == "") {
            fprintf(stderr, "NOTICE: bind address not specified, using INADDR_ANY.\n");
        }

        bind_addr = conf->FetchOpt("bindaddress");
    }
        
    

    // Parse the allowed hosts into the vector
    size_t ahstart = 0;
    size_t ahend = allowed_hosts.find(",");

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
        size_t masksplit = hoststr.find("/");
        if (masksplit == string::npos) {
            // Handle hosts with no netmask - they're treated as single hosts
            inet_aton("255.255.255.255", &(ipb->mask));

            if (inet_aton(hoststr.c_str(), &(ipb->network)) == 0) {
                fprintf(stderr, "FATAL:  Illegal IP address '%s' in allowed hosts list.\n",
                        hoststr.c_str());
                ErrorShutdown();
            }
        } else {
            // Handle pairs
            string hosthalf = hoststr.substr(0, masksplit);
            string maskhalf = hoststr.substr(masksplit + 1, hoststr.length() - (masksplit + 1));

            if (inet_aton(hosthalf.c_str(), &(ipb->network)) == 0) {
                fprintf(stderr, "FATAL:  Illegal IP address '%s' in allowed hosts list.\n",
                        hosthalf.c_str());
                ErrorShutdown();
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
                ErrorShutdown();
            }
        }

        // Catch 'network' addresses that aren't network addresses.
        if ((ipb->network.s_addr & ipb->mask.s_addr) != ipb->network.s_addr) {
            fprintf(stderr, "FATAL:  Invalid network '%s' in allowed hosts list.\n",
                    inet_ntoa(ipb->network));
            ErrorShutdown();
        }

        // Add it to our vector
        legal_ipblock_vec.push_back(ipb);
    }

    // Channel hop if requested
    if (channel_hop) {
        if (channel_dwell)
            timetracker.RegisterTimer(SERVER_TIMESLICES_SEC * channel_dwell, NULL, 1, &ChannelHopEvent, NULL);
        else
            timetracker.RegisterTimer(SERVER_TIMESLICES_SEC / channel_velocity, NULL, 1, &ChannelHopEvent, NULL);
    }

    // Now we can start doing things...
    fprintf(stderr, "Kismet Drone %s.%s.%s (%s)\n",
            VERSION_MAJOR, VERSION_MINOR, VERSION_TINY, servername);

    fprintf(stderr, "Listening on port %d (protocol %d).\n", tcpport, STREAM_DRONE_VERSION);
    for (unsigned int ipvi = 0; ipvi < legal_ipblock_vec.size(); ipvi++) {
        char *netaddr = strdup(inet_ntoa(legal_ipblock_vec[ipvi]->network));
        char *maskaddr = strdup(inet_ntoa(legal_ipblock_vec[ipvi]->mask));

        fprintf(stderr, "Allowing connections from %s/%s\n", netaddr, maskaddr);

        free(netaddr);
        free(maskaddr);
    }

    if (streamer.Setup(tcpmax, bind_addr, tcpport, &legal_ipblock_vec) < 0) {
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

    while (1) {
        fd_set rset, wset;

        max_fd = streamer.MergeSet(read_set, max_fd, &rset, &wset);
        max_fd = sourcetracker.MergeSet(&rset, &wset, max_fd);

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


        // Process sourcetracker-level stuff... This should someday handle packetpath
        // stuff, and should someday be the same argument format as uiserver.poll...
        int ret;
        ret = sourcetracker.Poll(&rset, &wset);
        if (ret < 0) {
            snprintf(status, STATUS_MAX, "FATAL: %s", sourcetracker.FetchError());
            if (!silent) {
                fprintf(stderr, "%s\n", status);
                fprintf(stderr, "Terminating.\n");
            }

            CatchShutdown(-1);
        } else if (ret > 0) {
            if (!silent) {
                fprintf(stderr, "%s\n", sourcetracker.FetchError());
            }
        }
      
        // This is ugly, come up with a better way to do it someday
        vector<KisPacketSource *> packet_sources = sourcetracker.FetchSourceVec();
        
        for (unsigned int src = 0; src < packet_sources.size(); src++) {
            if (FD_ISSET(packet_sources[src]->FetchDescriptor(), &rset)) {
                // Capture the packet from whatever device
                // len = psrc->FetchPacket(&packet, data, moddata);

                ret = packet_sources[src]->FetchPacket(&packet, data, moddata);
                
                if (ret > 0) {
                    if (streamer.WritePacket(&packet) < 0) {
                        fprintf(stderr, "FATAL:  Error writing packet to streamer: %s\n",
                                streamer.FetchError());
                        CatchShutdown(-1);
                    }
                } else if (ret < 0) {
                    // Fail on error
                    snprintf(status, STATUS_MAX, "FATAL: %s",
                             packet_sources[src]->FetchError());
                    if (!silent) {
                        fprintf(stderr, "%s\n", status);
                        fprintf(stderr, "Terminating.\n");
                    }

                    CatchShutdown(-1);
                }
            } // End processing new packets

        }

        timetracker.Tick();

        if (microsleep != 0)
            usleep(microsleep);

    }

}
