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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <vector>
#include "getopt.h"
#include "configfile.h"

#ifndef exec_name
char *exec_name;
#endif

typedef struct capturesource {
    char *interface;
    int chanpos;
    char *cardtype;
    const char *cmd_template;
};

#define prism2 "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true"
#define prism2_pcap "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true prismheader=true"
#define prism2_bsd "prism2ctl %s -f %d"
#define prism2_hostap "iwconfig %s channel %d"
#define orinoco "iwpriv %s monitor 1 %d"

#define pidpath "/var/run/kismet_hopper.pid"
#define conpath "/tmp/kismet_hopper.control"

const char *config_base = "kismet.conf";

// Channel rotations to maximize hopping for US and international frequencies
int us_channels[] = {1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, -1};
int intl_channels[] = {1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, -1};

int *parse_hopseq(char* param) {
    int *result;
    char *pos;
    char *nextpos;

    vector<int> assemble;

    //    result = (int*)malloc(sizeof(int)*15);

    pos = param;

    int res;

    while ((nextpos=strchr(pos,',')) != NULL) {
        *nextpos = 0;
        nextpos++;

        if (sscanf(pos, "%d", &res) < 1) {
            fprintf(stderr, "Illegal custom channel sequence %s\n", param);
            exit(1);
        }

        assemble.push_back(res);
        pos = nextpos;
    }

    // Catch the last one
    if (sscanf(pos, "%d", &res) < 1) {
        fprintf(stderr, "Illegal custom channel sequence %s\n", param);
        exit(1);
    }
    assemble.push_back(res);

    result = (int *) malloc(sizeof(int) * (assemble.size() + 1));

    for (unsigned int x = 0; x < assemble.size(); x++) {
        if (assemble[x] < 1 || assemble[x] > 14) {
            fprintf(stderr, "Illegal custom channel %d - valid channels are 1-14.\n",
                    assemble[x]);
            exit(1);
        }
        result[x] = assemble[x];
    }

    result[assemble.size()] = -1;

    return result;
}

int Usage(char *argv) {
    printf("Usage: %s [OPTION]\n", argv);
    printf(
           "  -f, --config-file <file>     Use alternate config file\n"
           "  -d, --divide-channels        Divide channels across multiple cards when possible\n"
           "  -c, --capture-source <src>   Packet capture source line (engine,interface,type,name)\n"
           "  -n, --international          Use international channels (1-14)\n"
           "  -s, --hopsequence            Use given hop sequence\n"
           "  -v, --velocity               Hopping velocity (hops per second)\n"
           "  -h, --help                   What do you think you're reading?\n");
    exit(1);
}

void CatchShutdown(int sig) {
    fprintf(stderr, "kismet_hopper shutting down.\n");
    unlink(pidpath);
    exit(0);
}

int main(int argc, char *argv[]) {
    int *chanlist;
    FILE *pgsock;
    char *configfile = NULL;
    char *channame = "United States";
    struct stat fstat;

    FILE *pidfile;
    int pid;

    exec_name = argv[0];

    unsigned long interval;
    int freq = 3;

    if (stat(pidpath, &fstat) == 0) {
        fprintf(stderr, "Detected pid file '%s'.  Make sure another instance of kismet_hopper\n"
                "isn't running, and remove this file.", pidpath);
        CatchShutdown(-1);
    }

    static struct option long_options[] = {   /* options table */
        { "config-file", required_argument, 0, 'f' },
        { "international", no_argument, 0, 'n' },
        { "capture-source", required_argument, 0, 'c' },
        { "hopsequence", required_argument, 0, 's' },
        { "velocity", required_argument, 0, 'v' },
        { "divide-channels", no_argument, 0, 'd' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0}
    };

    vector<string> source_input_vec;
    int divide = 0;
    int divisions = 0;

    chanlist = us_channels;
    int option_index;
    while(1) {
        int r = getopt_long(argc, argv, "fnc:s:v:hd",
                            long_options, &option_index);
        if (r < 0) break;

        switch(r) {
        case 'f':
            configfile = optarg;
            break;
        case 'n':
            chanlist = intl_channels;
	    channame = "International";
            break;
        case 'v':
            if (sscanf(optarg, "%d", &freq) != 1) {
                fprintf(stderr, "Invalid number for channels-per-second\n");
                Usage(argv[0]);
            }
            break;
	case 's':
            chanlist = parse_hopseq(optarg);
            channame = "Custom channels";
            if (!chanlist)
                exit(1);
            break;
        case 'c':
            // Capture type
            source_input_vec.push_back(optarg);
            break;
        case 'd':
            // Divide channels
            divide = 1;
            break;
        default:
            Usage(argv[0]);
            break;
        }
    }

    ConfigFile *conf = new ConfigFile;

    // If we haven't gotten a command line config option...
    if (configfile == NULL) {
        configfile = (char *) malloc(1024*sizeof(char));
        snprintf(configfile, 1024, "%s/%s", SYSCONF_LOC, config_base);
    }

    // Parse the config and load all the values from it and/or our command
    // line options.  This is a little soupy but it does the trick.
    if (conf->ParseConfig(configfile) < 0) {
        exit(1);
    }

    // Catch old configs and yell about them
    if (conf->FetchOpt("cardtype") != "" || conf->FetchOpt("captype") != "" ||
        conf->FetchOpt("capinterface") != "") {
        fprintf(stderr, "FATAL:  Old config file options found.  To support multiple sources, Kismet now\n"
                "uses a new config file format.  Please consult the example config file in your Kismet\n"
                "source directory, OR do 'make forceinstall' and reconfigure Kismet.\n");
        exit(1);
    }

    // Read all of our packet sources, tokenize the input and then start opening
    // them.

    vector<capturesource *> packet_sources;

    string sourceopt;

    // Read the config file if we didn't get any sources on the command line
    if (source_input_vec.size() == 0) {
        int sourcenum = 0;
        char sourcestr[16];

        while (snprintf(sourcestr, 16, "source%d", sourcenum++) &&
               (sourceopt = conf->FetchOpt(sourcestr)) != "") {
            source_input_vec.push_back(sourceopt);
        }
    }

    if (source_input_vec.size() == 0) {
        fprintf(stderr, "FATAL:  No valid packet sources defined in config or passed on command line.\n");
        exit(1);
    }

    // Now tokenize the sources
    for (unsigned int x = 0; x < source_input_vec.size(); x++) {
        sourceopt = source_input_vec[x];

        unsigned int begin = 0;
        unsigned int end = sourceopt.find(",");
        vector<string> optlist;

        while (end != string::npos) {
            string subopt = sourceopt.substr(begin, end-begin);
            begin = end+1;
            end = sourceopt.find(",", begin);
            optlist.push_back(subopt);
        }
        optlist.push_back(sourceopt.substr(begin, sourceopt.size() - begin));

        if (optlist.size() < 4) {
            fprintf(stderr, "FATAL:  Invalid source line '%s'\n", sourceopt.c_str());
            exit(1);
        }

        capturesource *newsource = new capturesource;
        newsource->interface = strdup(optlist[1].c_str());
        newsource->cardtype = strdup(optlist[2].c_str());
        newsource->chanpos = 0;

        packet_sources.push_back(newsource);
    }

    for (unsigned int src = 0; src < packet_sources.size(); src++) {
        char *type = packet_sources[src]->cardtype;

        if ((!strcasecmp(type, "cisco") || !strcasecmp(type, "cisco_bsd")) &&
            packet_sources.size() == 1) {
            fprintf(stderr, "FATAL:  Cisco cards don't need to channel hop.\n");
            exit(1);
        } else if (!strcasecmp(type, "prism2")) {
            packet_sources[src]->cmd_template = prism2;
            divisions++;
        } else if (!strcasecmp(type, "prism2_pcap")) {
            packet_sources[src]->cmd_template = prism2_pcap;
            divisions++;
        } else if (!strcasecmp(type, "prism2_bsd")) {
            packet_sources[src]->cmd_template = prism2_bsd;
            divisions++;
        } else if (!strcasecmp(type, "prism2_hostap")) {
            packet_sources[src]->cmd_template = prism2_hostap;
            divisions++;
        } else if (!strcasecmp(type, "orinoco")) {
            packet_sources[src]->cmd_template = orinoco;
            divisions++;
        } else {
            fprintf(stderr, "FATAL: Source %d: Unknown card type '%s'.\n", src, type);
            exit(1);
        }

        free(type);
    }

    // Free up the memory
    delete conf;


    if ((pidfile = fopen(pidpath, "w")) == NULL) {
        fprintf(stderr, "FATAL:  Could not open PID file '%s' for writing.\n", pidpath);
        exit(1);
    }

    pid = getpid();
    fprintf(pidfile, "%d\n", pid);
    fclose(pidfile);

    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGPIPE, SIG_IGN);

    if (freq == 0) {
        fprintf(stderr, "No point in hopping 0 channels.  Setting velocity to 1.\n");
        freq = 3;
    } else if (freq > 10) {
        if (freq > 100) {
            fprintf(stderr, "Cannot hop more than 100 channels per second, setting velocity to 100\n");
            freq = 100;
        } else {
            fprintf(stderr, "WARNING: Velocities over 10 are not reccomended and may cause problems.\n");
        }
    }

    interval = 1000000 / freq;
    fprintf(stderr, "Hopping %d channel%sper second (%ld microseconds per channel)\n",
            freq, freq > 1 ? "s " : " ", interval);

    if (divide && divisions > 1) {
        int nchannels = 0;
        while (chanlist[nchannels++] != -1) ;
        fprintf(stderr, "Dividing %d channels into %d segments.\n", nchannels, divisions);
        for (unsigned int ofst = 0; ofst < packet_sources.size(); ofst++) {
            packet_sources[ofst]->chanpos = (nchannels / divisions) * ofst;
            printf("Source %d starting at offset %d\n", ofst, packet_sources[ofst]->chanpos);
        }
    }

    for (unsigned int src = 0; src < packet_sources.size(); src++)
        fprintf(stderr, "%s - Source %d - Channel hopping (%s) on interface %s\n",
                argv[0], src, channame, packet_sources[src]->interface);

    char cmd[1024];
    int statime = 0;
    while (1) {
        if (statime++ > 5) {
            statime = 0;
            if (stat(conpath, &fstat) == 0) {
                fprintf(stderr, "Detected killfile %s\n", conpath);
                CatchShutdown(-1);
            }
        }

        for (unsigned int src = 0; src < packet_sources.size(); src++) {
            capturesource *csrc = packet_sources[src];
            snprintf(cmd, 1024, csrc->cmd_template, csrc->interface, chanlist[csrc->chanpos++]);

            if (chanlist[csrc->chanpos] == -1)
                csrc->chanpos = 0;

            if ((pgsock = popen(cmd, "r")) < 0) {
                fprintf(stderr, "Could not popen ``%s''.  Aborting.\n", cmd);
                exit(0);
            }

            pclose(pgsock);
        }

        usleep(interval);

    }

}
