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
#include "genericsource.h"

#include "dumpfile.h"
#include "wtapdump.h"
#include "wtaplocaldump.h"
#include "airsnortdump.h"
#include "gpsd.h"
#include "gpsdump.h"
#include "packetracker.h"
#include "configfile.h"
#include "speech.h"
#include "tcpserver.h"
#include "kismet_server.h"

#ifndef exec_name
char *exec_name;
#endif


const char *config_base = "kismet.conf";

// Some globals for command line options
char *configfile = NULL;
int no_log = 0, noise_log = 0, data_log = 0, net_log = 0, crypt_log = 0, cisco_log = 0,
    gps_log = 0, gps_enable = 1, csv_log = 0, xml_log = 0, ssid_cloak_track = 0, ip_track = 0,
    waypoint = 0;
string logname, dumplogfile, netlogfile, cryptlogfile, ciscologfile,
    gpslogfile, csvlogfile, xmllogfile, ssidtrackfile, configdir, iptrackfile, waypointfile;
FILE *ssid_file = NULL, *ip_file = NULL, *waypoint_file = NULL;
/* *net_file = NULL, *cisco_file = NULL, *csv_file = NULL,
    *xml_file = NULL, */

DumpFile *dumpfile, *cryptfile;
PacketSource *packsource;
int packnum = 0, localdropnum = 0;
//Frontend *gui = NULL;
Packetracker tracker;
packet_parm pack_parm;
#ifdef HAVE_GPS
GPSD gps;
GPSDump gpsdump;
#endif
TcpServer ui_server;
int silent;
time_t start_time;
packet_info last_info;
int decay;
unsigned int metric;
channel_power channel_graph[CHANNEL_MAX];

fd_set read_set;

// Number of clients with string printing on
int numstringclients = 0;
// Number of clients with packtype printing on
int numpackclients = 0;

// Pipe file descriptor pairs and fd's
int soundpair[2];
int speechpair[2];
pid_t soundpid = -1, speechpid = -1;

// Past alerts
vector<string> past_alerts;
unsigned int max_alerts = 50;

// Handle writing all the files out and optionally unlinking the empties
void WriteDatafiles(int in_shutdown) {
    if (ssid_cloak_track) {
        if (ssid_file)
            tracker.WriteSSIDMap(ssid_file);

        if (in_shutdown)
            fclose(ssid_file);
    }

    if (ip_track) {
        if (ip_file)
            tracker.WriteIPMap(ip_file);

        if (in_shutdown)
            fclose(ip_file);
    }

    char alert[2048];

    if (net_log) {
        if (tracker.FetchNumNetworks() != 0) {
            if (tracker.WriteNetworks(netlogfile) == -1) {
                snprintf(alert, 2048, "WARNING: %s", tracker.FetchError());
                NetWriteAlert(alert);
                if (!silent)
                    fprintf(stderr, "%s\n", alert);
            }
        } else if (in_shutdown) {
            fprintf(stderr, "NOTICE: Didn't detect any networks, unlinking network list.\n");
            unlink(netlogfile.c_str());
        }
    }

    if (csv_log) {
        if (tracker.FetchNumNetworks() != 0) {
            if (tracker.WriteCSVNetworks(csvlogfile) == -1) {
                snprintf(alert, 2048, "WARNING: %s", tracker.FetchError());
                NetWriteAlert(alert);
                if (!silent)
                    fprintf(stderr, "%s\n", alert);
            }
        } else if (in_shutdown) {
            fprintf(stderr, "NOTICE: Didn't detect any networks, unlinking CSV network list.\n");
            unlink(csvlogfile.c_str());
        }
    }

    if (xml_log) {
        if (tracker.FetchNumNetworks() != 0) {
            if (tracker.WriteXMLNetworks(xmllogfile) == -1) {
                snprintf(alert, 2048, "WARNING: %s", tracker.FetchError());
                NetWriteAlert(alert);
                if (!silent)
                    fprintf(stderr, "%s\n", alert);
            }
        } else if (in_shutdown) {
            fprintf(stderr, "NOTICE: Didn't detect any networks, unlinking XML network list.\n");
            unlink(xmllogfile.c_str());
        }
    }

    if (cisco_log) {
        if (tracker.FetchNumCisco() != 0) {
            if (tracker.WriteCisco(ciscologfile) == -1) {
                snprintf(alert, 2048, "WARNING: %s", tracker.FetchError());
                NetWriteAlert(alert);
                if (!silent)
                    fprintf(stderr, "%s\n", alert);
            }
        } else if (in_shutdown) {
            fprintf(stderr, "NOTICE: Didn't detect any Cisco Discovery Packets, unlinking cisco dump\n");
            unlink(ciscologfile.c_str());
        }
    }

    sync();

}

// Catch our interrupt
void CatchShutdown(int sig) {
    // If we're sighuping ignore the gui entirely
    /*
    if (gui != NULL && sig != SIGHUP)
    gui->EndDisplay();
    */

    if (packsource != NULL) {
        packsource->CloseSource();
        delete packsource;
    }

    ui_server.SendToAll("*TERMINATE: Kismet server terminating.\n");

    ui_server.Shutdown();

    // Write the data file, closing the files and unlinking them
    WriteDatafiles(1);

    if (data_log) {
        dumpfile->CloseDump();

        if (dumpfile->FetchDumped() == 0) {
            fprintf(stderr, "NOTICE: Didn't capture any packets, unlinking dump file\n");
            unlink(dumpfile->FetchFilename());
        }

        // delete dumpfile;
    }

    if (crypt_log) {
        cryptfile->CloseDump();

        if (cryptfile->FetchDumped() == 0) {
            fprintf(stderr, "NOTICE: Didn't see any weak encryption packets, unlinking weak file\n");
            unlink(cryptlogfile.c_str());
        }

        // delete cryptfile;
    }

#ifdef HAVE_GPS
    if (gps_log) {
        if (gpsdump.CloseDump(1) < 0)
            fprintf(stderr, "NOTICE:  Didn't log any GPS coordinates, unlinking gps file\n");
    }

#endif

    // Kill our sound players
    if (soundpid > 0)
        kill(soundpid, 9);
    if (speechpid > 0)
        kill(speechpid, 9);

    exit(0);
}

// Subprocess sound handler
void SoundHandler(int *fds, const char *player, map<string, string> soundmap) {
    int read_sock = fds[0];
    close(fds[1]);

    fd_set rset;

    char data[1024];

    pid_t sndpid = -1;
    int harvested = 1;

    while (1) {
        FD_ZERO(&rset);
        FD_SET(read_sock, &rset);
        char *end;

        memset(data, 0, 1024);

        struct timeval tm;
        tm.tv_sec = 1;
        tm.tv_usec = 0;

        if (select(read_sock + 1, &rset, NULL, NULL, &tm) < 0) {
            if (errno != EINTR) {
                exit(1);
            }
        }

        if (harvested == 0) {
            // We consider a wait error to be a sign that the child pid died
            // so we flag it as harvested and keep on going
            pid_t harvestpid = waitpid(sndpid, NULL, WNOHANG);
            if (harvestpid == -1 || harvestpid == sndpid)
                harvested = 1;
        }

        if (FD_ISSET(read_sock, &rset)) {
            int ret;
            ret = read(read_sock, data, 1024);

            // We'll die off if we get a read error, and we'll let kismet on the
            // other side detact that it died
            if (ret < 0)
                exit(1);

            if ((end = strstr(data, "\n")) == NULL)
                continue;

            end[0] = '\0';
        }

        if (data[0] == '\0')
            continue;


        // If we've harvested the process, spawn a new one and watch it
        // instead.  Otherwise, we just let go of the data we read
        if (harvested == 1) {
            char snd[1024];

            if (soundmap.size() == 0)
                snprintf(snd, 1024, "%s", data);
            if (soundmap.find(data) != soundmap.end())
                snprintf(snd, 1024, "%s", soundmap[data].c_str());
            else
                continue;

            char plr[1024];
            snprintf(plr, 1024, "%s", player);

            harvested = 0;
            if ((sndpid = fork()) == 0) {
                // Suppress errors
                if (silent) {
                    fclose(stdout);
                    fclose(stderr);
                }

                char * const echoarg[] = { plr, snd, NULL };
                execve(echoarg[0], echoarg, NULL);
            }
        }
        data[0] = '\0';
    }
}

// Subprocess speech handler
void SpeechHandler(int *fds, const char *player) {
    int read_sock = fds[0];
    close(fds[1]);

    fd_set rset;

    char data[1024];

    pid_t sndpid = -1;
    int harvested = 1;

    while (1) {
        FD_ZERO(&rset);
        FD_SET(read_sock, &rset);
        //char *end;

        memset(data, 0, 1024);

        if (harvested == 0) {
            // We consider a wait error to be a sign that the child pid died
            // so we flag it as harvested and keep on going
            pid_t harvestpid = waitpid(sndpid, NULL, WNOHANG);
            if (harvestpid == -1 || harvestpid == sndpid)
                harvested = 1;
        }

        struct timeval tm;
        tm.tv_sec = 1;
        tm.tv_usec = 0;

        if (select(read_sock + 1, &rset, NULL, NULL, &tm) < 0) {
            if (errno != EINTR) {
                exit(1);
            }
        }

        if (FD_ISSET(read_sock, &rset)) {
            int ret;
            ret = read(read_sock, data, 1024);

            // We'll die off if we get a read error, and we'll let kismet on the
            // other side detact that it died
            if (ret < 0)
                exit(1);

            data[ret] = '\0';
        }

        if (data[0] == '\0')
            continue;

        // If we've harvested the process, spawn a new one and watch it
        // instead.  Otherwise, we just let go of the data we read
        if (harvested == 1) {
            harvested = 0;
            if ((sndpid = fork()) == 0) {
                char spk_call[1024];
                snprintf(spk_call, 1024, "echo \"(SayText \\\"%s\\\")\" | %s >/dev/null 2>/dev/null",
                         data, player);
                system(spk_call);

                exit(0);
            }
        }

        data[0] = '\0';
    }
}


// Fork and run a system call to play a sound
int PlaySound(string in_sound) {

    char snd[1024];

    snprintf(snd, 1024, "%s\n", in_sound.c_str());

    if (write(soundpair[1], snd, strlen(snd)) < 0) {
        char status[STATUS_MAX];
        if (!silent)
            fprintf(stderr, "ERROR:  Write error, closing sound pipe.\n");
        snprintf(status, STATUS_MAX, "ERROR:  Write error on sound pipe, closing sound connection");
        NetWriteStatus(status);

        return 0;
    }

    return 1;
}

int SayText(string in_text) {

    char snd[1024];

    snprintf(snd, 1024, "%s\n", in_text.c_str());
    MungeToShell(snd, 1024);

    if (write(speechpair[1], snd, strlen(snd)) < 0) {
        char status[STATUS_MAX];
        if (!silent)
            fprintf(stderr, "ERROR:  Write error, closing speech pipe.\n");
        snprintf(status, STATUS_MAX, "ERROR:  Write error on speech pipe, closing speech connection");
        NetWriteStatus(status);

        return 0;
    }

    return 1;
}


void NetWriteInfo() {
    static time_t last_write = time(0);
    static int last_packnum = tracker.FetchNumPackets();
    vector<wireless_network *> tracked;
    char output[2048];

    snprintf(output, 2048, "*TIME: %d\n", (int) time(0));
    ui_server.SendToAll(output);

#ifdef HAVE_GPS
    if (gps_enable) {
        float lat, lon, alt, spd;
        int mode;

        gps.FetchLoc(&lat, &lon, &alt, &spd, &mode);

        // lat, lon, alt, spd, mode
        snprintf(output, 2048, "*GPS: %f %f %f %f %d\n",
                 lat, lon, alt, spd, mode);

        ui_server.SendToAll(output);
    } else {
        snprintf(output, 2048, "*GPS: 0.0 0.0 0.0 0.0 0\n");
        ui_server.SendToAll(output);
    }
#endif

    // Build power output and channel power output
    char power_output[16];

    if (time(0) - last_info.time < decay && last_info.quality != -1)
        snprintf(power_output, 16, "%d %d %d", last_info.quality,
                 last_info.signal, last_info.noise);
    else if (last_info.quality == -1)
        snprintf(power_output, 16, "-1 -1 -1");
    else
        snprintf(power_output, 16, "0 0 0");

    snprintf(output, 2048, "*INFO: %d %d %d %d %d %d %d %s %d",
             tracker.FetchNumNetworks(), tracker.FetchNumPackets(),
             tracker.FetchNumCrypt(), tracker.FetchNumInteresting(),
             tracker.FetchNumNoise(), tracker.FetchNumDropped() + localdropnum,
             tracker.FetchNumPackets() - last_packnum,
             power_output, CHANNEL_MAX);

    last_packnum = tracker.FetchNumPackets();

    char munge[2048];
    for (unsigned int x = 0; x < CHANNEL_MAX; x++) {
        snprintf(munge, 2048, "%s %d",
                 output,
                 (time(0) - channel_graph[x].last_time) < decay ? channel_graph[x].signal : -1);
        strncpy(output, munge, 2048);
    }
    snprintf(munge, 2048, "%s\n", output);
    strncpy(output, munge, 2048);

    ui_server.SendToAll(output);

    tracked = tracker.FetchNetworks();

    for (unsigned int x = 0; x < tracked.size(); x++) {
        // Only send new networks
        if (tracked[x]->last_time < last_write)
            continue;

        if (tracked[x]->type == network_remove) {
            snprintf(output, 2048, "*REMOVE: %s\n", tracked[x]->bssid.Mac2String().c_str());

            ui_server.SendToAll(output);

            tracker.RemoveNetwork(tracked[x]->bssid);

            continue;
        }

        snprintf(output, 2048, "*NETWORK: %.2000s\n", Packetracker::Net2String(tracked[x]).c_str());
        ui_server.SendToAll(output);

        for (map<mac_addr, wireless_client *>::const_iterator y = tracked[x]->client_map.begin();
             y != tracked[x]->client_map.end(); ++y) {
            if (y->second->last_time < last_write)
                continue;

                snprintf(output, 2048, "*CLIENT: %.2000s\n",
                         Packetracker::Client2String(tracked[x], y->second).c_str());
                ui_server.SendToAll(output);
        }

        for (map<string, cdp_packet>::const_iterator y = tracked[x]->cisco_equip.begin();
             y != tracked[x]->cisco_equip.end(); ++y) {

            cdp_packet cdp = y->second;

            snprintf(output, 2048, "*CISCO %s %.2000s\n",
                     tracked[x]->bssid.Mac2String().c_str(), Packetracker::CDP2String(&cdp).c_str());

            ui_server.SendToAll(output);
        }
    }

    last_write = time(0);
}


void NetWriteStatus(char *in_status) {
    char out_stat[1024];
    snprintf(out_stat, 1024, "*STATUS: %s\n", in_status);
    ui_server.SendToAll(out_stat);
}

void NetWriteAlert(char *in_alert) {
    char out_alert[1024];
    timeval ts;
    gettimeofday(&ts, NULL);

    snprintf(out_alert, 1024, "*ALERT: %ld %ld %s\n", (long int) ts.tv_sec,
             (long int) ts.tv_usec, in_alert);

    past_alerts.push_back(out_alert);
    if (past_alerts.size() > max_alerts)
        past_alerts.erase(past_alerts.begin());

    ui_server.SendToAll(out_alert);
}

void NetWriteNew(int in_fd) {
    char output[2048];
    snprintf(output, 2048, "*KISMET: %d.%d.%d %d\n",
             VERSION_MAJOR, VERSION_MINOR, VERSION_TINY, (int) start_time);
    ui_server.Send(in_fd, output);

    vector<wireless_network *> tracked;
    tracked = tracker.FetchNetworks();

    for (unsigned int x = 0; x < tracked.size(); x++) {
        snprintf(output, 2048, "*NETWORK: %.2000s\n", Packetracker::Net2String(tracked[x]).c_str());
        ui_server.Send(in_fd, output);

        for (map<mac_addr, wireless_client *>::const_iterator y = tracked[x]->client_map.begin();
             y != tracked[x]->client_map.end(); ++y) {
            snprintf(output, 2048, "*CLIENT: %.2000s\n", Packetracker::Client2String(tracked[x], y->second).c_str());
            ui_server.Send(in_fd, output);
        }

        for (map<string, cdp_packet>::const_iterator y = tracked[x]->cisco_equip.begin();
             y != tracked[x]->cisco_equip.end(); ++y) {

            cdp_packet cdp = y->second;

            snprintf(output, 2048, "*CISCO %s %.2000s\n",
                     tracked[x]->bssid.Mac2String().c_str(), Packetracker::CDP2String(&cdp).c_str());
            ui_server.Send(in_fd, output);
        }
    }

    for (unsigned int x = 0; x < past_alerts.size(); x++)
        ui_server.Send(in_fd, past_alerts[x].c_str());

}

// Handle a command sent by a client over its TCP connection.
static void handle_command(TcpServer *tcps, client_command *cc) {
    string cmdspace = cc->cmd + " ";
    const char *cmdptr = cmdspace.c_str();
    string resp = "unknown";
    if (!strncmp(cmdptr, "pause ", 6)) {
	if (packsource) {
	    packsource->Pause();
            resp = "ok";
            if (!silent)
                printf("NOTICE:  Pausing packet source per request of client %d\n", cc->client_fd);
	} else {
	    resp = "err";
	}
    } else if (!strncmp(cmdptr, "resume ", 7)) {
	if (packsource) {
	    packsource->Resume();
            resp = "ok";
            if (!silent)
                printf("NOTICE:  Resuming packet source per request of client %d\n", cc->client_fd);

	} else {
	    resp = "err";
	}
    } else if (!strncmp(cmdptr, "strings ", 8)) {
        client_opt opts;
        if (tcps->GetClientOpts(cc->client_fd, &opts) == 1) {
            resp = "ok";
            opts.send_strings = 1;
            tcps->SetClientOpts(cc->client_fd, opts);
            numstringclients++;
            if (!silent)
                printf("NOTICE:  Sending strings to client %d\n", cc->client_fd);
        } else {
            resp = "err";
        }
    } else if (!strncmp(cmdptr, "nostrings ", 10)) {
        client_opt opts;
        if (tcps->GetClientOpts(cc->client_fd, &opts) == 1) {
            resp = "ok";
            opts.send_strings = 0;
            tcps->SetClientOpts(cc->client_fd, opts);
            numstringclients--;
            if (!silent)
                printf("NOTICE:  Stopping strings to client %d\n", cc->client_fd);
        } else {
            resp = "err";
        }
    } else if (!strncmp(cmdptr, "packtypes ", 10)) {
        client_opt opts;
        if (tcps->GetClientOpts(cc->client_fd, &opts) == 1) {
            resp = "ok";
            opts.send_packtype = 1;
            tcps->SetClientOpts(cc->client_fd, opts);
            numpackclients++;
            if (!silent)
                printf("NOTICE:  Sending packet types to client %d\n", cc->client_fd);

        } else {
            resp = "err";
        }
    } else if (!strncmp(cmdptr, "nopacktypes ", 12)) {
        client_opt opts;
        if (tcps->GetClientOpts(cc->client_fd, &opts) == 1) {
            resp = "ok";
            opts.send_packtype = 0;
            tcps->SetClientOpts(cc->client_fd, opts);
            numpackclients--;
            if (!silent)
                printf("NOTICE:  Stopping packet types to client %d\n", cc->client_fd);

        } else {
            resp = "err";
        }
    }

    // Reply to the client if he wants it
    if (cc->stamp != 0) {
	char cliresp[2048];
	sprintf(cliresp, "!%u ", cc->stamp);
	int rlen = strlen(cliresp);
	snprintf(cliresp+rlen, 2046-rlen, "%s\n", resp.c_str());
	tcps->Send(cc->client_fd, cliresp);
    }
}

int Usage(char *argv) {
    printf("Usage: %s [OPTION]\n", argv);
    printf("Most (or all) of these options can (and should) be configured via the\n"
           "kismet.conf global config file, but can be overridden here.\n");
    printf("  -t, --log-title <title>      Custom log file title\n"
           "  -n, --no-logging             No logging (only process packets)\n"
           "  -f, --config-file <file>     Use alternate config file\n"
           "  -c, --capture-type <type>    Type of packet capture device (prism2, pcap, etc)\n"
           "  -i, --capture-interface <if> Packet capture interface (eth0, eth1, etc)\n"
           "  -l, --log-types <types>      Comma seperated list of types to log,\n"
           "                                (ie, dump,cisco,weak,network,gps)\n"
           "  -d, --dump-type <type>       Dumpfile type (wiretap)\n"
           "  -m, --max-packets <num>      Maximum number of packets before starting new dump\n"
           "  -q, --quiet                  Don't play sounds\n"
           "  -g, --gps <host:port>        GPS server (host:port or off)\n"
           "  -p, --port <port>            TCPIP server port for GUI connections\n"
           "  -a, --allowed-hosts <hosts>  Comma seperated list of hosts allowed to connect\n"
           "  -s, --silent                 Don't send any output to console.\n"
           "  -v, --version                Kismet version\n"
           "  -h, --help                   What do you think you're reading?\n");
    exit(1);
}

int main(int argc,char *argv[]) {
    exec_name = argv[0];

    client_command cmd;
    int sleepu = 0;
    time_t last_draw = time(0);
    time_t last_write = time(0);
    int log_packnum = 0;
    int limit_logs = 0;
    char status[STATUS_MAX];

    //const char *sndplay = NULL;
    string sndplay;
    int sound = -1;

    const char *festival = NULL;
    int speech = -1;
    int speech_encoding = 0;
    string speech_sentence_encrypted, speech_sentence_unencrypted;

    map<string, string> wav_map;

    const char *captype = NULL, *capif = NULL, *logtypes = NULL, *dumptype = NULL;

    char gpshost[1024];
    int gpsport = -1;

    const char *allowed_hosts = NULL;
    int tcpport = -1;
    int tcpmax;

    silent = 0;
    metric = 0;

    start_time = time(0);

    int gpsmode = 0;

    string filter;

    int datainterval = 0;

    int beacon_log = 1;

    card_type cardtype = card_unspecified;

    FILE *manuf_data;
    char *client_manuf_name = NULL, *ap_manuf_name = NULL;

    static struct option long_options[] = {   /* options table */
        { "log-title", required_argument, 0, 't' },
        { "no-logging", no_argument, 0, 'n' },
        { "config-file", required_argument, 0, 'f' },
        { "capture-type", required_argument, 0, 'c' },
        { "capture-interface", required_argument, 0, 'i' },
        { "log-types", required_argument, 0, 'l' },
        { "dump-type", required_argument, 0, 'd' },
        { "max-packets", required_argument, 0, 'm' },
        { "quiet", no_argument, 0, 'q' },
        { "gps", required_argument, 0, 'g' },
        { "port", required_argument, 0, 'p' },
        { "allowed-hosts", required_argument, 0, 'a' },
        { "help", no_argument, 0, 'h' },
        { "version", no_argument, 0, 'v' },
        { "silent", no_argument, 0, 's' },
        // No this isn't documented, and no, you shouldn't be screwing with it
        { "microsleep", required_argument, 0, 'M' },
        { 0, 0, 0, 0 }
    };
    int option_index;
    decay = 5;

    // Catch the interrupt handler to shut down
    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGPIPE, SIG_IGN);

    // Some default option masks
    client_opt string_options;
    string_options.send_strings = 1;
    string_options.send_packtype = -1;

    client_opt packtype_options;
    packtype_options.send_strings = -1;
    packtype_options.send_packtype = 1;


    while(1) {
        int r = getopt_long(argc, argv, "d:M:t:nf:c:i:l:m:g:a:p:qhvs",
                            long_options, &option_index);
        if (r < 0) break;
        switch(r) {
        case 's':
            // Silent
            silent = 1;
            break;
        case 'M':
            // Microsleep
            if (sscanf(optarg, "%d", &sleepu) != 1) {
                fprintf(stderr, "Invalid microsleep\n");
                Usage(argv[0]);
            }
            break;
        case 't':
            // Logname
            logname = optarg;
            fprintf(stderr, "Using logname: %s\n", logname.c_str());
            break;
        case 'n':
            // No logging
            no_log = 1;
            fprintf(stderr, "Not logging any data\n");
            break;
        case 'f':
            // Config path
            configfile = optarg;
            fprintf(stderr, "Using alternate config file: %s\n", configfile);
            break;
        case 'c':
            // Capture type
            captype = optarg;
            break;
        case 'i':
            // Capture interface
            capif = optarg;
            break;
        case 'l':
            // Log types
            logtypes = optarg;
            break;
        case 'd':
            // dump type
            dumptype = optarg;
            break;
        case 'm':
            // Maximum log
            if (sscanf(optarg, "%d", &limit_logs) != 1) {
                fprintf(stderr, "Invalid maximum packet number.\n");
                Usage(argv[0]);
            }
            break;
        case 'g':
            // GPS
            if (strcmp(optarg, "off") == 0) {
                gps_enable = 0;
            }
#ifdef HAVE_GPS
            else if (sscanf(optarg, "%1024[^:]:%d", gpshost, &gpsport) < 2) {
                fprintf(stderr, "Invalid GPS host '%s' (host:port or off required)\n",
                       optarg);
                gps_enable = 1;
                Usage(argv[0]);
            }
#else
            else {
                fprintf(stderr, "WARNING:  GPS requested but gps support was not included.  GPS\n"
                        "          logging will be disabled.\n");
                gps_enable = 0;
                exit(1);
            }
#endif
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
        case 'q':
            // Quiet
            sound = 0;
            break;
        case 'v':
            // version
            fprintf(stderr, "Kismet %d.%d.%d\n", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY);
            exit(0);
            break;
        default:
            Usage(argv[0]);
            break;
        }
    }

    memset(channel_graph, 0, sizeof(channel_power) * CHANNEL_MAX);

    // If we haven't gotten a command line config option...
    int freeconf = 0;
    if (configfile == NULL) {
        configfile = (char *) malloc(1024*sizeof(char));
        snprintf(configfile, 1024, "%s/%s", SYSCONF_LOC, config_base);
        freeconf = 1;
    }

    ConfigFile conf;

    // Parse the config and load all the values from it and/or our command
    // line options.  This is a little soupy but it does the trick.
    if (conf.ParseConfig(configfile) < 0) {
        exit(1);
    }

    if (freeconf)
        free(configfile);

#ifdef HAVE_SUID
    struct passwd *pwordent;
    const char *suid_user;
    uid_t suid_id, real_uid;

    real_uid = getuid();

    if (conf.FetchOpt("suiduser") != "") {
        suid_user = conf.FetchOpt("suiduser").c_str();
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


            fprintf(stderr, "NOTICE:  Will drop privs to %s (%d)\n", suid_user, suid_id);
        }
    } else {
        fprintf(stderr, "FATAL:  No 'suiduser' option in the config file.\n");
        exit(1);
    }
#else
    fprintf(stderr, "NOTICE:  Suid priv-dropping disabled.  This may not be secure.\n");
#endif

    // Find out what kind of card we are.
    if (conf.FetchOpt("cardtype") != "") {
        const char *sctype = conf.FetchOpt("cardtype").c_str();

        if (!strcasecmp(sctype, "cisco"))
            cardtype = card_cisco;
        else if (!strcasecmp(sctype, "cisco_cvs"))
            cardtype = card_cisco_cvs;
        else if (!strcasecmp(sctype, "cisco_bsd"))
            cardtype = card_cisco_bsd;
        else if (!strcasecmp(sctype, "prism2"))
            cardtype = card_prism2;
        else if (!strcasecmp(sctype, "prism2_pcap"))
            cardtype = card_prism2_pcap;
        else if (!strcasecmp(sctype, "prism2_bsd"))
            cardtype = card_prism2_bsd;
        else if (!strcasecmp(sctype, "prism2_hostap"))
            cardtype = card_prism2_hostap;
        else if (!strcasecmp(sctype, "orinoco"))
            cardtype = card_orinoco;
        else if (!strcasecmp(sctype, "orinoco_bsd"))
            cardtype = card_orinoco_bsd;
        else if (!strcasecmp(sctype, "generic"))
            cardtype = card_generic;
        else
            fprintf(stderr, "WARNING:  Unknown card type '%s'\n", sctype);
    }

    // Open the captype
    if (captype == NULL) {
        if (conf.FetchOpt("captype") == "") {
            fprintf(stderr, "FATAL:  No capture type specified.");
            exit(1);
        }
        captype = conf.FetchOpt("captype").c_str();
    }

    // Create a capture source
    if (!strcasecmp(captype, "prism2")) {
#ifdef HAVE_LINUX_NETLINK
        fprintf(stderr, "Using prism2 to capture packets.\n");

        packsource = new Prism2Source;
#else
        fprintf(stderr, "FATAL:  Linux netlink support was not compiled in.\n");
        exit(1);
#endif
    } else if (!strcasecmp(captype, "pcap")) {
#ifdef HAVE_LIBPCAP
        if (capif == NULL) {
            if (conf.FetchOpt("capinterface") == "") {
                fprintf(stderr, "FATAL:  No capture device specified.\n");
                exit(1);
            }
            capif = conf.FetchOpt("capinterface").c_str();
        }

        fprintf(stderr, "Using pcap to capture packets from %s\n", capif);

        packsource = new PcapSource;
#else
        fprintf(stderr, "FATAL: Pcap support was not compiled in.\n");
        exit(1);
#endif
    } else if (!strcasecmp(captype, "generic")) {
#ifdef HAVE_LINUX_WIRELESS
        if (capif == NULL) {
            if (conf.FetchOpt("capinterface") == "") {
                fprintf(stderr, "FATAL:  No capture device specified.\n");
                exit(1);
            }
            capif = conf.FetchOpt("capinterface").c_str();
        }

        fprintf(stderr, "Using generic kernel extentions to capture SSIDs from %s\n", capif);

        fprintf(stderr, "Generic capture does not support cisco, weak, or dump logs.\n");
        cisco_log = crypt_log = data_log = 0;

        fprintf(stderr, "**WARNING** Generic capture will generate packets which may be observable.\n");

        if (getuid() != 0) {
            fprintf(stderr, "FATAL: Generic kernel capture will ONLY work as root.  Kismet must be run as\n"
                    "root, not suid, for this to function.\n");
            exit(1);
        }

        packsource = new GenericSource;
#else
        fprintf(stderr, "FATAL: Kernel wireless (wavelan/generic) support was not compiled in.\n");
        exit(1);
#endif
    } else if (!strcasecmp(captype, "wtapfile")) {
        if (capif == NULL) {
            if (conf.FetchOpt("capinterface") == "") {
                fprintf(stderr, "FATAL:  No capture file specified.\n");
                exit(1);
            }
            capif = conf.FetchOpt("capinterface").c_str();
        }
#ifdef HAVE_LIBWIRETAP
        fprintf(stderr, "Loading packets from dump file %s\n", capif);

        // Drop root privs NOW, because we don't want them reading any
        // files in the system they shouldn't be.
#ifdef HAVE_SUID
        if (setuid(suid_id) < 0) {
            fprintf(stderr, "FATAL:  setuid() to %s (%d) failed.\n", suid_user, suid_id);
            exit(1);
        }

        fprintf(stderr, "NOTICE:  Dropped privs to %s (%d)\n", suid_user, suid_id);
#endif

        packsource = new WtapFileSource;
#else
        fprintf(stderr, "FATAL: Wtap support was not compiled in.\n");
        exit(1);
#endif
    } else if (!strcasecmp(captype, "wsp100")) {
#ifdef HAVE_WSP100
        if (capif == NULL) {
            if (conf.FetchOpt("capinterface") == "") {
                fprintf(stderr, "FATAL:  No capture device specified.\n");
                exit(1);
            }
            capif = conf.FetchOpt("capinterface").c_str();
        }

        fprintf(stderr, "Using WSP100 to capture packets.\n");

        packsource = new Wsp100Source;
#else
        fprintf(stderr, "FATAL:  WSP100 support was not compiled in.\n");
        exit(1);
#endif
    } else {
        fprintf(stderr, "FATAL: Unknown capture type '%s'\n", captype);
        exit(1);
    }

    // Open the packet source
    if (packsource->OpenSource(capif, cardtype) < 0) {
        fprintf(stderr, "FATAL: %s\n", packsource->FetchError());
        exit(1);
    }

    // Once the packet source is opened, we shouldn't need special privileges anymore
    // so lets drop to a normal user.  We also don't want to open our logfiles as root
    // if we can avoid it.
#ifdef HAVE_SUID
    if (setuid(suid_id) < 0) {
        fprintf(stderr, "FATAL:  setuid() to %s (%d) failed.\n", suid_user, suid_id);
        exit(1);
    }
#endif

    // Now parse the rest of our options

    if (conf.FetchOpt("configdir") != "") {
        configdir = conf.ExpandLogPath(conf.FetchOpt("configdir"), "", "", 0, 1);
    } else {
        fprintf(stderr, "FATAL:  No 'configdir' option in the config file.\n");
        exit(1);
    }

    if (conf.FetchOpt("ssidmap") != "") {
        // Explode the map file path
        ssidtrackfile = conf.ExpandLogPath(configdir + conf.FetchOpt("ssidmap"), "", "", 0, 1);
        ssid_cloak_track = 1;
    }

    if (conf.FetchOpt("ipmap") != "") {
        // Explode the IP file path
        iptrackfile = conf.ExpandLogPath(configdir + conf.FetchOpt("ipmap"), "", "", 0, 1);
        ip_track = 1;
    }


#ifdef HAVE_GPS
    if (conf.FetchOpt("waypoints") == "true") {
        if(conf.FetchOpt("waypointdata") == "") {
            fprintf(stderr, "WARNING:  Waypoint logging requested but no waypoint data file given.\n"
                    "Waypoint logging will be disabled.\n");
            waypoint = 0;
        } else {
            waypointfile = conf.ExpandLogPath(conf.FetchOpt("waypointdata"), "", "", 0, 1);
            waypoint = 1;
        }

    }
#endif

    if (conf.FetchOpt("metric") == "true") {
        fprintf(stderr, "NOTICE:  Using metric measurements.\n");
        metric = 1;
    }

    if (!no_log) {
        if (logname == "") {
            if (conf.FetchOpt("logdefault") == "") {
                fprintf(stderr, "FATAL:  No default log name in config and no log name provided on the command line.\n");
                exit(1);
            }
            logname = conf.FetchOpt("logdefault").c_str();
        }

        if (logtypes == NULL) {
            if (conf.FetchOpt("logtypes") == "") {
                fprintf(stderr, "FATAL:  No log types in config and none provided on the command line.\n");
                exit(1);
            }
            logtypes = conf.FetchOpt("logtypes").c_str();
        }

        if (conf.FetchOpt("noiselog") == "true")
            noise_log = 1;

        if (strstr(logtypes, "dump")) {
            data_log = 1;

            if (conf.FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  Logging (network dump) enabled but no logtemplate given in config.\n");
                exit(1);
            }

            if (conf.FetchOpt("dumplimit") != "" || limit_logs != 0) {
                if (limit_logs == 0)
                    if (sscanf(conf.FetchOpt("dumplimit").c_str(), "%d", &limit_logs) != 1) {
                        fprintf(stderr, "FATAL:  Illegal config file value for dumplimit.\n");
                        exit(1);
                    }

                if (limit_logs != 0)
                    fprintf(stderr, "Limiting dumpfile to %d packets each.\n",
                            limit_logs);
            }

            if (conf.FetchOpt("dumptype") == "" && dumptype == NULL) {
                fprintf(stderr, "FATAL: Dump file logging requested but no dump type given.\n");
                exit(1);
            }

            if (conf.FetchOpt("dumptype") != "" && dumptype == NULL)
                dumptype = conf.FetchOpt("dumptype").c_str();

            if (!strcasecmp(dumptype, "wiretap")) {
                dumpfile = new WtapDumpFile;
            } else {
                fprintf(stderr, "FATAL:  Unknown dump file type '%s'\n", dumptype);
                exit(1);
            }
        }

        if (strstr(logtypes, "network")) {
            net_log = 1;

            if (conf.FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  Logging (network list) enabled but no logtemplate given in config.\n");
                exit(1);
            }

        }

        if (strstr(logtypes, "weak")) {
            crypt_log = 1;

            if (conf.FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  Logging (weak packets) enabled but no logtemplate given in config.\n");
                exit(1);
            }

        }

        if (strstr(logtypes, "csv")) {
            csv_log = 1;

            if (conf.FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  CSV Logging (network list) enabled but no logtemplate given in config.\n");
                exit(1);
            }

        }

        if (strstr(logtypes, "xml")) {
            xml_log = 1;

            if (conf.FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  XML Logging (network list) enabled but no logtemplate given in config.\n");
                exit(1);
            }
        }

        if (strstr(logtypes, "cisco")) {
            cisco_log = 1;

            if (conf.FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL: Logging (cisco packets) enabled but no logtemplate given in config.\n");
                exit(1);
            }

        }

        if (strstr(logtypes, "gps")) {
#ifdef HAVE_GPS

            gps_log = 1;

            if (conf.FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  Logging (gps coordinates) enabled but no logtemplate given in config.\n");
                exit(1);
            }
#else

            fprintf(stderr, "WARNING:  GPS logging requested but GPS support was not included.\n"
                    "          GPS logging will be disabled.\n");
            gps_log = 0;
#endif

        }

        if (gps_log && !net_log) {
            fprintf(stderr, "WARNING:  Logging (gps coordinates) enabled but XML logging (networks) was not.\n"
                    "It will be enabled now.\n");
            xml_log = 1;
        }
    }

    if (conf.FetchOpt("decay") != "") {
        if (sscanf(conf.FetchOpt("decay").c_str(), "%d", &decay) != 1) {
            fprintf(stderr, "FATAL:  Illegal config file value for decay.\n");
            exit(1);
        }
    }

    if (conf.FetchOpt("alertbacklog") != "") {
        if (sscanf(conf.FetchOpt("alertbacklog").c_str(), "%d", &max_alerts) != 1) {
            fprintf(stderr, "FATAL:  Illegal config file value for alert backlog.\n");
            exit(1);
        }
    }

    if (tcpport == -1) {
        if (conf.FetchOpt("tcpport") == "") {
            fprintf(stderr, "FATAL:  No tcp port given to listen for GUI connections.\n");
            exit(1);
        } else if (sscanf(conf.FetchOpt("tcpport").c_str(), "%d", &tcpport) != 1) {
            fprintf(stderr, "FATAL:  Invalid config file value for tcp port.\n");
            exit(1);
        }
    }

    if (conf.FetchOpt("maxclients") == "") {
        fprintf(stderr, "FATAL:  No maximum number of clients given.\n");
        exit(1);
    } else if (sscanf(conf.FetchOpt("maxclients").c_str(), "%d", &tcpmax) != 1) {
        fprintf(stderr, "FATAL:  Invalid config file option for max clients.\n");
        exit(1);
    }

    if (allowed_hosts == NULL) {
        if (conf.FetchOpt("allowedhosts") == "") {
            fprintf(stderr, "FATAL:  No list of allowed hosts.\n");
            exit(1);
        }

        allowed_hosts = conf.FetchOpt("allowedhosts").c_str();
    }

    // Make sure allowed hosts is valid
    for (unsigned int x = 0; x < strlen(allowed_hosts); x++) {
        if (!isdigit(allowed_hosts[x]) && allowed_hosts[x] != '.' &&
            allowed_hosts[x] != ',') {
            fprintf(stderr, "FATAL:  Allowed hosts list should be a list of comma seperated IPs.\n");
            exit(1);
        }
    }

    // Process sound stuff
    if (conf.FetchOpt("sound") == "true" && sound == -1) {
        if (conf.FetchOpt("soundplay") != "") {
            sndplay = conf.FetchOpt("soundplay");

            if (conf.FetchOpt("soundopts") != "")
                sndplay += " " + conf.FetchOpt("soundopts");

            sound = 1;

            if (conf.FetchOpt("sound_new") != "")
                wav_map["new"] = conf.FetchOpt("sound_new");
            if (conf.FetchOpt("sound_traffic") != "")
                wav_map["traffic"] = conf.FetchOpt("sound_traffic");
            if (conf.FetchOpt("sound_junktraffic") != "")
                wav_map["junktraffic"] = conf.FetchOpt("sound_traffic");
            if (conf.FetchOpt("sound_gpslock") != "")
                wav_map["gpslock"] = conf.FetchOpt("sound_gpslock");
            if (conf.FetchOpt("sound_gpslost") != "")
                wav_map["gpslost"] = conf.FetchOpt("sound_gpslost");
            if (conf.FetchOpt("sound_alert") != "")
                wav_map["alert"] = conf.FetchOpt("sound_alert");

        } else {
            fprintf(stderr, "ERROR:  Sound alerts enabled but no sound playing binary specified.\n");
            sound = 0;
        }
    } else if (sound == -1)
        sound = 0;

    /* Added by Shaw Innes 17/2/02 */
    /* Modified by Andrew Etter 15/9/02 */
    if (conf.FetchOpt("speech") == "true" && speech == -1) {
        if (conf.FetchOpt("festival") != "") {
            festival = conf.FetchOpt("festival").c_str();
            speech = 1;

            string speechtype = conf.FetchOpt("speech_type");

            if (!strcasecmp(speechtype.c_str(), "nato"))
                speech_encoding = SPEECH_ENCODING_NATO;
            else if (!strcasecmp(speechtype.c_str(), "spell"))
                speech_encoding = SPEECH_ENCODING_SPELL;
            else
                speech_encoding = SPEECH_ENCODING_NORMAL;

            // Make sure we have encrypted text lines
            if (conf.FetchOpt("speech_encrypted") == "" || conf.FetchOpt("speech_unencrypted") == "") {
                fprintf(stderr, "ERROR:  Speech request but speech_encrypted or speech_unencrypted line missing.\n");
                speech = 0;
            }

            speech_sentence_encrypted = conf.FetchOpt("speech_encrypted");
            speech_sentence_unencrypted = conf.FetchOpt("speech_unencrypted");
        } else {
            fprintf(stderr, "ERROR: Speech alerts enabled but no path to festival has been specified.\n");
            speech = 0;
        }
    } else if (speech == -1)
        speech = 0;

    if (conf.FetchOpt("writeinterval") != "") {
        if (sscanf(conf.FetchOpt("writeinterval").c_str(), "%d", &datainterval) != 1) {
            fprintf(stderr, "FATAL:  Illegal config file value for data interval.\n");
            exit(1);
        }
    }

    if (conf.FetchOpt("ap_manuf") != "") {
        ap_manuf_name = strdup(conf.FetchOpt("ap_manuf").c_str());
    } else {
        fprintf(stderr, "WARNING:  No ap_manuf file specified, AP manufacturers and defaults will not be detected.\n");
    }

    if (conf.FetchOpt("client_manuf") != "") {
        client_manuf_name = strdup(conf.FetchOpt("client_manuf").c_str());
    } else {
        fprintf(stderr, "WARNING:  No client_manuf file specified.  Client manufacturers will not be detected.\n");
    }

    // Fork and find the sound options
    if (sound) {
        if (pipe(soundpair) == -1) {
            fprintf(stderr, "WARNING:  Unable to create pipe for audio.  Disabling sound.\n");
            sound = 0;
        } else {
            soundpid = fork();

            if (soundpid < 0) {
                fprintf(stderr, "WARNING:  Unable to fork for audio.  Disabling sound.\n");
                sound = 0;
            } else if (soundpid == 0) {
                SoundHandler(soundpair, sndplay.c_str(), wav_map);
                exit(0);
            }

            close(soundpair[0]);
        }
    }

    if (speech) {
        if (pipe(speechpair) == -1) {
            fprintf(stderr, "WARNING:  Unable to create pipe for speech.  Disabling speech.\n");
            speech = 0;
        } else {
            speechpid = fork();

            if (speechpid < 0) {
                fprintf(stderr, "WARNING:  Unable to fork for speech.  Disabling speech.\n");
                speech = 0;
            } else if (speechpid == 0) {
                SpeechHandler(speechpair, festival);
                exit(0);
            }

            close(speechpair[0]);
        }
    }


    // Grab the filtering
    filter = conf.FetchOpt("macfilter");

    // handle the config bits
    struct stat fstat;
    if (stat(configdir.c_str(), &fstat) == -1) {
        fprintf(stderr, "NOTICE: configdir '%s' does not exist, making it.\n",
                configdir.c_str());
        if (mkdir(configdir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) < 0) {
            fprintf(stderr, "FATAL:  Could not make configdir: %s\n",
                    strerror(errno));
            exit(1);
        }
    } else if (! S_ISDIR(fstat.st_mode)) {
        fprintf(stderr, "FATAL: configdir '%s' exists but is not a directory.\n",
                configdir.c_str());
        exit(1);
    }

    if (ssid_cloak_track) {
        if (stat(ssidtrackfile.c_str(), &fstat) == -1) {
            fprintf(stderr, "NOTICE:  SSID cloak file did not exist, it will be created.\n");
        } else {
            if ((ssid_file = fopen(ssidtrackfile.c_str(), "r")) == NULL) {
                fprintf(stderr, "FATAL: Could not open SSID track file '%s': %s\n",
                        ssidtrackfile.c_str(), strerror(errno));
                exit(1);
            }

            tracker.ReadSSIDMap(ssid_file);

            fclose(ssid_file);

        }

        if ((ssid_file = fopen(ssidtrackfile.c_str(), "a")) == NULL) {
            fprintf(stderr, "FATAL: Could not open SSID track file '%s' for writing: %s\n",
                    ssidtrackfile.c_str(), strerror(errno));
            exit(1);
        }

    }

    if (ip_track) {
        if (stat(iptrackfile.c_str(), &fstat) == -1) {
            fprintf(stderr, "NOTICE:  IP track file did not exist, it will be created.\n");

        } else {
            if ((ip_file = fopen(iptrackfile.c_str(), "r")) == NULL) {
                fprintf(stderr, "FATAL: Could not open IP track file '%s': %s\n",
                        iptrackfile.c_str(), strerror(errno));
                exit(1);
            }

            tracker.ReadIPMap(ip_file);

            fclose(ip_file);
        }

        if ((ip_file = fopen(iptrackfile.c_str(), "a")) == NULL) {
            fprintf(stderr, "FATAL: Could not open IP track file '%s' for writing: %s\n",
                    iptrackfile.c_str(), strerror(errno));
            exit(1);
        }

    }

#ifdef HAVE_GPS
    if (waypoint) {
        if ((waypoint_file = fopen(waypointfile.c_str(), "a")) == NULL) {
            fprintf(stderr, "WARNING:  Could not open waypoint file '%s' for writing: %s\n",
                    waypointfile.c_str(), strerror(errno));
            waypoint = 0;
        }
    }
#endif

    // Create all the logs and title/number them appropriately
    int logfile_matched = 0;
    for (int run_num = 1; run_num < 100; run_num++) {
        if (data_log) {
            dumplogfile = conf.ExpandLogPath(conf.FetchOpt("logtemplate"), logname, "dump", run_num);

            if (dumplogfile == "")
                continue;
        }

        if (net_log) {
            netlogfile = conf.ExpandLogPath(conf.FetchOpt("logtemplate"), logname, "network", run_num);

            if (netlogfile == "")
                continue;
        }

        if (crypt_log) {
            cryptlogfile = conf.ExpandLogPath(conf.FetchOpt("logtemplate"), logname, "weak", run_num);

            if (cryptlogfile == "")
                continue;
        }

        if (csv_log) {
            csvlogfile = conf.ExpandLogPath(conf.FetchOpt("logtemplate"), logname, "csv", run_num);

            if (csvlogfile == "")
                continue;
        }

        if (xml_log) {
            xmllogfile = conf.ExpandLogPath(conf.FetchOpt("logtemplate"), logname, "xml", run_num);

            if (xmllogfile == "")
                continue;
        }

        if (cisco_log) {
            ciscologfile = conf.ExpandLogPath(conf.FetchOpt("logtemplate"), logname, "cisco", run_num);

            if (ciscologfile == "")
                continue;
        }

#ifdef HAVE_GPS
        if (gps_log) {
            gpslogfile = conf.ExpandLogPath(conf.FetchOpt("logtemplate"), logname, "gps", run_num);

            if (gpslogfile == "")
                continue;
        }
#endif

        // if we made it this far we're cool -- all the logfiles we're writing to matched
        // this number
        logfile_matched = 1;
        break;
    }

    if (logfile_matched == 0) {
        fprintf(stderr, "ERROR:  Unable to find room for logging files within 100 counts.  If you really are\n"
                "        logging this many times in 1 day, change log title or edit the source.\n");
        exit(1);
    }

    if (net_log)
        fprintf(stderr, "Logging networks to %s\n", netlogfile.c_str());


    if (csv_log)
        fprintf(stderr, "Logging networks in CSV format to %s\n", csvlogfile.c_str());

    if (xml_log)
        fprintf(stderr, "Logging networks in XML format to %s\n", xmllogfile.c_str());

    if (crypt_log)
        fprintf(stderr, "Logging cryptographically weak packets to %s\n", cryptlogfile.c_str());

    if (cisco_log)
        fprintf(stderr, "Logging cisco product information to %s\n", ciscologfile.c_str());

#ifdef HAVE_GPS
    if (gps_log)
        fprintf(stderr, "Logging gps coordinates to %s\n", gpslogfile.c_str());
#endif

    if (data_log)
        fprintf(stderr, "Logging data to %s\n", dumplogfile.c_str());

    if (datainterval != 0 && data_log)
        fprintf(stderr, "Writing data files to disk every %d seconds.\n",
                datainterval);


    // Set the filtering
    if (filter != "") {
        fprintf(stderr, "Filtering MAC addresses: %s\n",
                filter.c_str());
        //tracker.AddFilter(filter);
    }

    if (conf.FetchOpt("beaconlog") == "false") {
        beacon_log = 0;
        fprintf(stderr, "Filtering beacon packets.\n");
    }


    if (ap_manuf_name != NULL) {
        char pathname[1024];

        if (strchr(ap_manuf_name, '/') == NULL)
            snprintf(pathname, 1024, "%s/%s", SYSCONF_LOC, ap_manuf_name);
        else
            snprintf(pathname, 1024, "%s", ap_manuf_name);

        if ((manuf_data = fopen(pathname, "r")) == NULL) {
            fprintf(stderr, "WARNING:  Unable to open '%s' for reading (%s), AP manufacturers and defaults will not be detected.\n",
                    pathname, strerror(errno));
        } else {
            fprintf(stderr, "Reading AP manufacturer data and defaults from %s\n", pathname);
            tracker.ReadAPManufMap(manuf_data);
            fclose(manuf_data);
        }

        free(ap_manuf_name);
    }

    if (client_manuf_name != NULL) {
        char pathname[1024];

        if (strchr(client_manuf_name, '/') == NULL)
            snprintf(pathname, 1024, "%s/%s", SYSCONF_LOC, client_manuf_name);
        else
            snprintf(pathname, 1024, "%s", client_manuf_name);

        if ((manuf_data = fopen(pathname, "r")) == NULL) {
            fprintf(stderr, "WARNING:  Unable to open '%s' for reading (%s), client manufacturers will not be detected.\n",
                    pathname, strerror(errno));
        } else {
            fprintf(stderr, "Reading client manufacturer data and defaults from %s\n", pathname);
            tracker.ReadClientManufMap(manuf_data);
            fclose(manuf_data);
        }

        free(client_manuf_name);
    }

    // Now lets open the GPS host if specified
#ifdef HAVE_GPS
    if (gpsport == -1 && gps_enable) {
        if (conf.FetchOpt("gps") == "true") {
            if (sscanf(conf.FetchOpt("gpshost").c_str(), "%1024[^:]:%d", gpshost, &gpsport) != 2) {
                fprintf(stderr, "Invalid GPS host in config (host:port required)\n");
                exit(1);
            }

            gps_enable = 1;
        } else {
            gps_enable = 0;
            gps_log = 0;
        }
    }

    if (gps_enable == 1) {
        // Open the GPS
        if (gps.OpenGPSD(gpshost, gpsport) < 0) {
            fprintf(stderr, "%s\n", gps.FetchError());

            gps_enable = 0;
            if (gps_log)
                fprintf(stderr, "Disabling GPS logging.\n");
            gps_log = 0;
        } else {
            fprintf(stderr, "Opened GPS connection to %s port %d\n",
                    gpshost, gpsport);

            gpsmode = gps.FetchMode();

            tracker.AddGPS(&gps);
            gpsdump.AddGPS(&gps);

            if (gps_log) {
                if (gpsdump.OpenDump(gpslogfile.c_str(), xmllogfile.c_str()) < 0) {
                    fprintf(stderr, "FATAL: GPS dump error: %s\n", gpsdump.FetchError());
                    exit(1);
                }
            }
        }
    } else {
        if (gps_log)
            fprintf(stderr, "Disabling GPS logging.\n");
        gps_log = 0;
    }
#endif

    if (strstr(conf.FetchOpt("fuzzycrypt").c_str(), captype) || conf.FetchOpt("fuzzycrypt") == "all")
        pack_parm.fuzzy_crypt = 1;
    else
        pack_parm.fuzzy_crypt = 0;

    if (data_log) {
        if (dumpfile->OpenDump(dumplogfile.c_str()) < 0) {
            fprintf(stderr, "FATAL: Dump file error: %s\n", dumpfile->FetchError());
            exit(1);
        }

        dumpfile->SetBeaconLog(beacon_log);

        fprintf(stderr, "Dump file format: %s\n", dumpfile->FetchType());
    }

    // Open our files first to make sure we can, we'll unlink the empties later.
    FILE *testfile = NULL;
    if (net_log) {
        if ((testfile = fopen(netlogfile.c_str(), "w")) == NULL) {
            fprintf(stderr, "FATAL:  Unable to open net file %s: %s\n",
                    netlogfile.c_str(), strerror(errno));
            exit(1);
        }
        fclose(testfile);
    }

    if (csv_log) {
        if ((testfile = fopen(csvlogfile.c_str(), "w")) == NULL) {
            fprintf(stderr, "FATAL:  Unable to open CSV file %s: %s\n",
                    netlogfile.c_str(), strerror(errno));
            exit(1);
        }
        fclose(testfile);
    }

    if (xml_log) {
        if ((testfile = fopen(xmllogfile.c_str(), "w")) == NULL) {
            fprintf(stderr, "FATAL:  Unable to open netxml file %s: %s\n",
                    netlogfile.c_str(), strerror(errno));
            exit(1);
        }
        fclose(testfile);
    }

    if (cisco_log) {
        if ((testfile = fopen(ciscologfile.c_str(), "w")) == NULL) {
            fprintf(stderr, "FATAL:  Unable to open CSV file %s: %s\n",
                    netlogfile.c_str(), strerror(errno));
            exit(1);
        }
        fclose(testfile);
    }

    // Crypt log stays open like the dump log for continual writing
    if (crypt_log) {
        cryptfile = new AirsnortDumpFile;

        if (cryptfile->OpenDump(cryptlogfile.c_str()) < 0) {
            fprintf(stderr, "FATAL: %s\n", cryptfile->FetchError());
            exit(1);
        }

        fprintf(stderr, "Crypt file format: %s\n", cryptfile->FetchType());

    }

    snprintf(status, STATUS_MAX, "Kismet %d.%d.%d", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY);
    fprintf(stderr, "%s\n", status);

    snprintf(status, STATUS_MAX, "Capturing packets from %s",
             packsource->FetchType());
    fprintf(stderr, "%s\n", status);

    if (data_log || net_log || crypt_log) {
        snprintf(status, STATUS_MAX, "Logging%s%s%s%s%s%s%s",
                 data_log ? " data" : "" ,
                 net_log ? " networks" : "" ,
                 csv_log ? " CSV" : "" ,
                 xml_log ? " XML" : "" ,
                 crypt_log ? " weak" : "",
                 cisco_log ? " cisco" : "",
                 gps_log ? " gps" : "");
        fprintf(stderr, "%s\n", status);
    } else if (no_log) {
        snprintf(status, STATUS_MAX, "Not logging any data.");
        fprintf(stderr, "%s\n", status);
    }

    fprintf(stderr, "Listening on port %d, allowing %s to connect.\n",
            tcpport, allowed_hosts);

    if (ui_server.Setup(tcpmax, tcpport, allowed_hosts) < 0) {
        fprintf(stderr, "Failed to set up UI server: %s\n", ui_server.FetchError());
        CatchShutdown(-1);
    }


    time_t last_click = 0;
    time_t last_waypoint = time(0);
    int num_networks = 0, num_packets = 0, num_noise = 0, num_dropped = 0;

    // We're ready to begin the show... Fill in our file descriptors for when
    // to wake up
    FD_ZERO(&read_set);

    int max_fd = 0;

    // We want to remember all our FD's so we don't have to keep calling functions which
    // call functions and so on.  Fill in our descriptors while we're at it.
    int ui_descrip = ui_server.FetchDescriptor();
    if (ui_descrip > max_fd && ui_descrip > 0)
        max_fd = ui_descrip;
    FD_SET(ui_descrip, &read_set);

    int source_descrip = packsource->FetchDescriptor();
    if (source_descrip > 0) {
        FD_SET(source_descrip, &read_set);
        if (source_descrip > max_fd)
            max_fd = source_descrip;
    }

    char netout[2048];
    time_t cur_time = time(0);
    time_t last_time = cur_time;
    while (1) {
        fd_set rset, wset;
        int x;
        cur_time = time(0);

        max_fd = ui_server.MergeSet(read_set, max_fd, &rset, &wset);

        // 1 second idle clock tick on select
        struct timeval tm;
        tm.tv_sec = 1;
        tm.tv_usec = 0;

        if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
            if (errno != EINTR) {
                snprintf(status, STATUS_MAX,
                         "FATAL: select() error %d (%s)", errno, strerror(errno));
                NetWriteStatus(status);
                fprintf(stderr, "%s\n", status);
                CatchShutdown(-1);
            }
        }

	for(x = 0; x <= max_fd; ++x) {
            if (ui_server.isClient(x) && ui_server.HandleClient(x, &cmd, &rset, &wset)) {
                handle_command(&ui_server, &cmd);
            }
	}

        // We can pass the results of this select to the UI handler without incurring a
        // a delay since it will bail nicely if there aren't any new connections.

        int accept_fd = 0;
        accept_fd = ui_server.Poll(rset, wset);
        if (accept_fd < 0) {
            if (!silent)
                fprintf(stderr, "UI error: %s\n", ui_server.FetchError());
        } else if (accept_fd > 0) {
            NetWriteNew(accept_fd);

            if (!silent)
                fprintf(stderr, "Accepted interface connection from %s\n",
                        ui_server.FetchError());

            if (accept_fd > max_fd)
                max_fd = accept_fd;

        }

        // Jump through hoops to handle generic packet source
        int process_packet_source = 0;
        if (source_descrip < 0) {
            process_packet_source = 1;
        } else {
            if (FD_ISSET(source_descrip, &rset))
                process_packet_source = 1;
        }

        if (process_packet_source) {
    
            pkthdr header;
            u_char data[MAX_PACKET_LEN];
    
            int len;
    
            // Capture the packet from whatever device
            len = packsource->FetchPacket(&header, data);
    
            // Handle a packet
            if (len > 0) {
                packnum++;

                static packet_info info;

                GetPacketInfo(&header, data, &pack_parm, &info);

                last_info = info;

                // Discard it if we're filtering it
                if (filter.find(info.bssid_mac.Mac2String().c_str()) != string::npos) {
                    localdropnum++;

                    // don't ever do this.  ever.  (but it really is the most efficient way
                    // of getting from here to there, so....)
                goto last_draw;

                }

                // Handle the per-channel signal power levels
                if (info.channel > 0 && info.channel < CHANNEL_MAX) {
                    channel_graph[info.channel].last_time = info.time;
                    channel_graph[info.channel].signal = info.signal;
                }
    
                int process_ret;
    
#ifdef HAVE_GPS
                if (gps_log && info.type != packet_noise && info.type != packet_unknown) {
                    process_ret = gpsdump.DumpPacket(&info);
                    if (process_ret < 0) {
                        snprintf(status, STATUS_MAX, "%s", gpsdump.FetchError());
                        if (!silent)
                            fprintf(stderr, "%s\n", status);
    
                        NetWriteStatus(status);
                    }
                }
#endif
    
                process_ret = tracker.ProcessPacket(info, status);
                if (process_ret > 0) {
                    if (process_ret == TRACKER_ALERT) {
                        if (!silent)
                            fprintf(stderr, "ALERT %s\n", status);

                        NetWriteAlert(status);
                        if (sound == 1)
                            sound = PlaySound("alert");

                    } else {
                        if (!silent)
                            fprintf(stderr, "%s\n", status);

                        NetWriteStatus(status);
                    }
                }
    
                if (tracker.FetchNumNetworks() != num_networks) {
                    if (sound == 1)
                        sound = PlaySound("new");
                }
    
                if (tracker.FetchNumNetworks() != num_networks && speech == 1) {
                    string text;

                    if (info.wep)
                        text = ExpandSpeechString(speech_sentence_encrypted, &info, speech_encoding);
                    else
                        text = ExpandSpeechString(speech_sentence_unencrypted, &info, speech_encoding);

                    speech = SayText(MungeToShell(text).c_str());
                }
                num_networks = tracker.FetchNumNetworks();
    
                if (tracker.FetchNumPackets() != num_packets) {
                    if (cur_time - last_click >= decay && sound == 1) {
                        if (tracker.FetchNumPackets() - num_packets >
                            tracker.FetchNumDropped() + localdropnum - num_dropped) {
                            sound = PlaySound("traffic");
                        } else {
                            sound = PlaySound("junktraffic");
                        }
    
                        last_click = cur_time;
                    }
    
                    num_packets = tracker.FetchNumPackets();
                    num_noise = tracker.FetchNumNoise();
                    num_dropped = tracker.FetchNumDropped() + localdropnum;
                }

                // Send the packet info
                if (numpackclients > 0) {
                    snprintf(netout, 2048, "*PACKET: %.2000s\n",
                             Packetracker::Packet2String(&info).c_str());
                    ui_server.SendToAllOpts((const char *) netout, packtype_options);
                }

                // Extract the strings from it
                if (info.type == packet_data && info.encrypted == 0 && numstringclients > 0) {
                    vector<string> strlist;
    
                    strlist = GetPacketStrings(&info, &header, data);

                    for (unsigned int y = 0; y < strlist.size(); y++) {
                        snprintf(netout, 2048, "*STRING: %.2000s\n", strlist[y].c_str());
                        ui_server.SendToAllOpts((const char *) netout, string_options);
                    }
    
                }
    
                if (data_log && !(info.type == packet_noise && noise_log == 1)) {
                    if (limit_logs && log_packnum > limit_logs) {
                        dumpfile->CloseDump();

                        dumplogfile = conf.ExpandLogPath(conf.FetchOpt("logtemplate"), logname, "dump", 0);

                        if (dumpfile->OpenDump(dumplogfile.c_str()) < 0) {
                            perror("Unable to open new dump file");
                            CatchShutdown(-1);
                        }

                        dumpfile->SetBeaconLog(beacon_log);

                        snprintf(status, STATUS_MAX, "Opened new packet log file %s",
                                 dumplogfile.c_str());

                        if (!silent)
                            fprintf(stderr, "%s\n", status);

                        NetWriteStatus(status);
                    }

                    dumpfile->DumpPacket(&info, &header, data);
                    log_packnum = dumpfile->FetchDumped();
                }
    
                if (crypt_log) {
                    cryptfile->DumpPacket(&info, &header, data);

                }
    
            } else if (len < 0) {
                // Fail on error
                if (!silent) {
                    fprintf(stderr, "%s\n", packsource->FetchError());
                    fprintf(stderr, "Terminating.\n");
                }
    
                NetWriteStatus(packsource->FetchError());
                CatchShutdown(-1);
            }
        } // End processing new packets

        // Draw if it's time
    last_draw: ;
        if (cur_time != last_draw) {
#ifdef HAVE_GPS
            // The GPS only provides us a new update once per second we might
            // as well only update it here once a second
            if (gps_enable) {
                int gpsret;
                gpsret = gps.Scan();
                if (gpsret < 0) {
                    snprintf(status, STATUS_MAX, "GPS error fetching data: %s",
                             gps.FetchError());

                    if (!silent)
                        fprintf(stderr, "%s\n", gps.FetchError());

                    NetWriteStatus(status);
                    gps_enable = 0;
                }

                if (gpsret == 0 && gpsmode != 0) {
                    if (!silent)
                        fprintf(stderr, "Lost GPS signal.\n");
                    if (sound == 1)
                        sound = PlaySound("gpslost");

                    NetWriteStatus("Lost GPS signal.");
                    gpsmode = 0;
                } else if (gpsret != 0 && gpsmode == 0) {
                    if (!silent)
                        fprintf(stderr, "Aquired GPS signal.\n");
                    if (sound == 1)
                        sound = PlaySound("gpslock");

                    NetWriteStatus("Aquired GPS signal.");
                    gpsmode = 1;
                }
            }

            if (gps_log) {
                gpsdump.DumpPacket(NULL);
            }
#endif

            NetWriteInfo();

            last_draw = cur_time;
        }

        // Write the data files out every x seconds
        if (datainterval > 0) {
            if (cur_time - last_write > datainterval) {
                if (!silent)
                    fprintf(stderr, "Saving data files.\n");
                NetWriteStatus("Saving data files.");
                WriteDatafiles(0);
                last_write = cur_time;
            }
        }

        // Write the waypoints every decay seconds
        if (cur_time - last_waypoint > decay && waypoint) {
            tracker.WriteGpsdriveWaypt(waypoint_file);
            last_waypoint = cur_time;
        }

        // Once per second handle our update event ticks
        if (last_time != cur_time) {
            tracker.Tick();
            last_time = cur_time;
        }

        // Sleep if we have a custom additional sleep time
        if (sleepu > 0)
            usleep(sleepu);
    }

    CatchShutdown(-1);
}
