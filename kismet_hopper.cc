// Simple app to progress through all of the prism2 channels

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

#define prism2 "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true"
#define prism2_pcap "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true prismheader=true"
#define prism2_bsd "prism2ctl %s -f %d"
#define orinoco "iwpriv %s monitor 1 %d"

#define pidpath "/var/run/kismet_hopper.pid"
#define conpath "/tmp/kismet_hopper.control"

const char *config_base = "kismet.conf";

// Channel rotations to maximize hopping for US and international frequencies
int us_channels[] = {1, 6, 11, 2, 7, 3, 8, 4, 12, 9, 5, 10, -1};
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
           "  -i, --interface <if>         Interface to place in monitor mode (eth0, wlan0, etc)\n"
           "  -t, --type <type>            Use alternate card type\n"
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
    const char *interface = NULL;
    char *channame = "United States";
    const char *type = NULL;
    const char *cmd_template = NULL;
    const char *label = NULL;
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
        { "international", no_argument, 0, 'n'},
        { "interface", required_argument, 0, 'i' },
        { "type", required_argument, 0, 't' },
        { "hopsequence", required_argument, 0, 's' },
        { "velocity", required_argument, 0, 'v' },
        { 0, 0, 0, 0}
    };

    chanlist = us_channels;
    int option_index;
    while(1) {
        int r = getopt_long(argc, argv, "f:ni:s:t:v:",
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
        case 'i':
            interface = optarg;
            break;
        case 't':
            type = optarg;
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
        default:
            Usage(argv[0]);
            break;
        }
    }

    ConfigFile conf;

    // If we haven't gotten a command line config option...
    if (configfile == NULL) {
        configfile = (char *) malloc(1024*sizeof(char));
        snprintf(configfile, 1024, "%s/%s", SYSCONF_LOC, config_base);
    }

    // Parse the config and load all the values from it and/or our command
    // line options.  This is a little soupy but it does the trick.
    if (conf.ParseConfig(configfile) < 0) {
        exit(1);
    }

    if (interface == NULL) {
        if (conf.FetchOpt("capinterface") == "") {
            fprintf(stderr, "FATAL:  No interface specified on the command line or in the config file.\n");
            exit(1);
        }

        interface = conf.FetchOpt("capinterface").c_str();
    }

    if (type == NULL) {
        if (conf.FetchOpt("cardtype") == "") {
            fprintf(stderr, "FATAL:  No card type specified on the command line or in the config file.\n");
        }

        type = conf.FetchOpt("cardtype").c_str();
    }

    if (!strcasecmp(type, "cisco") || !strcasecmp("cardtype", "cisco_bsd")) {
        fprintf(stderr, "FATAL:  Cisco cards don't need to channel hop.\n");
        exit(1);
    } else if (!strcasecmp(type, "prism2")) {
        label = "prism2";
        cmd_template = prism2;
    } else if (!strcasecmp(type, "prism2_pcap")) {
        label = "prism2 pcap";
        cmd_template = prism2_pcap;
    } else if (!strcasecmp(type, "prism2_bsd")) {
        label = "prism2 BSD";
        cmd_template = prism2_bsd;
    } else if (!strcasecmp(type, "orinoco")) {
        label = "orinoco";
        cmd_template = orinoco;
    } else if (!strcasecmp(type, "orinoco_bsd")) {
        fprintf(stderr, "FATAL:  No monitor/hopper code for Orinoco on BSD yet.\n");
        exit(1);
    } else {
        fprintf(stderr, "FATAL:  Unknown card type '%s'.\n", type);
        exit(1);
    }

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


    fprintf(stderr, "%s - Channel hopping (%s) on interface %s as a %s card.\n",
            argv[0], channame, interface, label);

    int chpos = 0;
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


        snprintf(cmd, 1024, cmd_template, interface, chanlist[chpos++]);

        if (chanlist[chpos] == -1)
            chpos = 0;

        if ((pgsock = popen(cmd, "r")) < 0) {
            fprintf(stderr, "Could not popen ``%s''.  Aborting.\n", cmd);
            exit(0);
        }

        pclose(pgsock);

        usleep(interval);

    }

}
