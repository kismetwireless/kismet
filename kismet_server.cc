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
#include "server_protocols.h"
#include "kismet_server.h"

#ifndef exec_name
char *exec_name;
#endif

void WriteDatafiles(int in_shutdown);
void CatchShutdown(int sig);
int Usage(char *argv);
static void handle_command(TcpServer *tcps, client_command *cc);
void NetWriteAlert(char *in_alert);
void NetWriteStatus(char *in_status);
void NetWriteInfo();
int SayText(string in_text);
int PlaySound(string in_sound);
void SpeechHandler(int *fds, const char *player);
void SoundHandler(int *fds, const char *player, map<string, string> soundmap);
void ProtocolAlertEnable(int in_fd);
void ProtocolNetworkEnable(int in_fd);
void ProtocolClientEnable(int in_fd);

typedef struct capturesource {
    KisPacketSource *source;
    string name;
    string interface;
    string scardtype;
    card_type cardtype;
    packet_parm packparm;
};

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
int packnum = 0, localdropnum = 0;
//Frontend *gui = NULL;
Packetracker tracker;
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
char *servername = NULL;

fd_set read_set;

// Do we allow sending wep keys to the client?
int client_wepkey_allowed = 0;
// Wep keys
map<mac_addr, wep_key_info *> bssid_wep_map;


// Pipe file descriptor pairs and fd's
int soundpair[2];
int speechpair[2];
pid_t soundpid = -1, speechpid = -1;

// Past alerts
vector<ALERT_data *> past_alerts;
unsigned int max_alerts = 50;

// Capture sources
vector<capturesource *> packet_sources;

// Reference numbers for all of our builtin protocols
int kismet_ref = -1, network_ref = -1, client_ref = -1, gps_ref = -1, time_ref = -1, error_ref = -1,
    info_ref = -1, cisco_ref = -1, terminate_ref = -1, remove_ref = -1, capability_ref = -1,
    protocols_ref = -1, status_ref = -1, alert_ref = -1, packet_ref = -1, string_ref = -1,
    ack_ref = -1, wepkey_ref;

// A kismet data record for passing to the protocol
KISMET_data kdata;

// Handle writing all the files out and optionally unlinking the empties
void WriteDatafiles(int in_shutdown) {
    // If we're on our way out make one last write of the network stuff - this
    // has a nice side effect of clearing out any "REMOVE" networks.
    NetWriteInfo();

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
            fprintf(stderr, "Didn't detect any networks, unlinking network list.\n");
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
            fprintf(stderr, "Didn't detect any networks, unlinking CSV network list.\n");
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
            fprintf(stderr, "Didn't detect any networks, unlinking XML network list.\n");
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
            fprintf(stderr, "Didn't detect any Cisco Discovery Packets, unlinking cisco dump\n");
            unlink(ciscologfile.c_str());
        }
    }

    sync();

}

// Catch our interrupt
void CatchShutdown(int sig) {
    for (unsigned int x = 0; x < packet_sources.size(); x++) {
        if (packet_sources[x]->source != NULL) {
            packet_sources[x]->source->CloseSource();
            delete packet_sources[x]->source;
            delete packet_sources[x];
        }
    }

    string termstr = "Kismet server terminating.";
    ui_server.SendToAll(terminate_ref, (void *) &termstr);

    ui_server.Shutdown();

    // Write the data file, closing the files and unlinking them
    WriteDatafiles(1);

    if (data_log) {
        dumpfile->CloseDump();

        if (dumpfile->FetchDumped() == 0) {
            fprintf(stderr, "Didn't capture any packets, unlinking dump file\n");
            unlink(dumpfile->FetchFilename());
        }

        // delete dumpfile;
    }

    if (crypt_log) {
        cryptfile->CloseDump();

        if (cryptfile->FetchDumped() == 0) {
            fprintf(stderr, "Didn't see any weak encryption packets, unlinking weak file\n");
            unlink(cryptlogfile.c_str());
        }

        // delete cryptfile;
    }

#ifdef HAVE_GPS
    if (gps_log) {
        if (gpsdump.CloseDump(1) < 0)
            fprintf(stderr, "Didn't log any GPS coordinates, unlinking gps file\n");
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
            if (ret <= 0 && (errno != EAGAIN && errno != EPIPE))
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
            if (ret <= 0 && (errno != EAGAIN && errno != EPIPE))
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

    int tim = time(0);
    ui_server.SendToAll(time_ref, &tim);

    char tmpstr[32];

#ifdef HAVE_GPS
    GPS_data gdata;

    if (gps_enable) {
        float lat, lon, alt, spd;
        int mode;

        gps.FetchLoc(&lat, &lon, &alt, &spd, &mode);

        snprintf(tmpstr, 32, "%f", lat);
        gdata.lat = tmpstr;
        snprintf(tmpstr, 32, "%f", lon);
        gdata.lon = tmpstr;
        snprintf(tmpstr, 32, "%f", alt);
        gdata.alt = tmpstr;
        snprintf(tmpstr, 32, "%f", spd);
        gdata.spd = tmpstr;
        snprintf(tmpstr, 32, "%d", mode);
        gdata.mode = tmpstr;
    } else {
        gdata.lat = "0.0";
        gdata.lon = "0.0";
        gdata.alt = "0.0";
        gdata.spd = "0.0";
        gdata.mode = "0";
    }

    ui_server.SendToAll(gps_ref, (void *) &gdata);
#endif

    INFO_data idata;
    snprintf(tmpstr, 32, "%d", tracker.FetchNumNetworks());
    idata.networks = tmpstr;
    snprintf(tmpstr, 32, "%d", tracker.FetchNumPackets());
    idata.packets = tmpstr;
    snprintf(tmpstr, 32, "%d", tracker.FetchNumCrypt());
    idata.crypt = tmpstr;
    snprintf(tmpstr, 32, "%d", tracker.FetchNumInteresting());
    idata.weak = tmpstr;
    snprintf(tmpstr, 32, "%d", tracker.FetchNumNoise());
    idata.noise = tmpstr;
    snprintf(tmpstr, 32, "%d", tracker.FetchNumDropped() + localdropnum);
    idata.dropped = tmpstr;
    snprintf(tmpstr, 32, "%d", tracker.FetchNumPackets() - last_packnum);
    idata.rate = tmpstr;

    if (time(0) - last_info.time < decay && last_info.quality != -1)
        snprintf(tmpstr, 16, "%d %d %d", last_info.quality,
                 last_info.signal, last_info.noise);
    else if (last_info.quality == -1)
        snprintf(tmpstr, 16, "-1 -1 -1");
    else
        snprintf(tmpstr, 16, "0 0 0");
    idata.signal = tmpstr;

    last_packnum = tracker.FetchNumPackets();

    ui_server.SendToAll(info_ref, (void *) &idata);

    tracked = tracker.FetchNetworks();

    for (unsigned int x = 0; x < tracked.size(); x++) {
        // Only send new networks
        if (tracked[x]->last_time < last_write)
            continue;

        if (tracked[x]->type == network_remove) {
            string remstr = tracked[x]->bssid.Mac2String();
            ui_server.SendToAll(remove_ref, (void *) &remstr);

            tracker.RemoveNetwork(tracked[x]->bssid);

            continue;
        }

        NETWORK_data ndata;
        Protocol_Network2Data(tracked[x], &ndata);
        ui_server.SendToAll(network_ref, (void *) &ndata);

        for (map<mac_addr, wireless_client *>::const_iterator y = tracked[x]->client_map.begin();
             y != tracked[x]->client_map.end(); ++y) {
            if (y->second->last_time < last_write)
                continue;

            CLIENT_data cdata;
            Protocol_Client2Data(tracked[x], y->second, &cdata);
            ui_server.SendToAll(client_ref, (void *) &cdata);
        }

        /*
        for (map<string, cdp_packet>::const_iterator y = tracked[x]->cisco_equip.begin();
             y != tracked[x]->cisco_equip.end(); ++y) {

            cdp_packet cdp = y->second;

            snprintf(output, 2048, "*CISCO %s %.2000s\n",
                     tracked[x]->bssid.Mac2String().c_str(), Packetracker::CDP2String(&cdp).c_str());

            ui_server.SendToAll(output);
            }
            */
    }

    last_write = time(0);
}

void NetWriteStatus(char *in_status) {
    string str = in_status;
    ui_server.SendToAll(status_ref, (void *) &str);
}

void ProtocolEnableAlert(int in_fd) {
    for (unsigned int x = 0; x < past_alerts.size(); x++)
        ui_server.SendToClient(in_fd, alert_ref, (void *) past_alerts[x]);
}

void NetWriteAlert(char *in_alert) {
    ALERT_data *adata = new ALERT_data;
    char tmpstr[128];
    timeval ts;
    gettimeofday(&ts, NULL);

    snprintf(tmpstr, 128, "%ld", (long int) ts.tv_sec);
    adata->sec = tmpstr;

    snprintf(tmpstr, 128, "%ld", (long int) ts.tv_usec);
    adata->usec = tmpstr;

    adata->text = in_alert;

    past_alerts.push_back(adata);
    if (past_alerts.size() > max_alerts) {
        delete past_alerts[0];
        past_alerts.erase(past_alerts.begin());
    }

    ui_server.SendToAll(alert_ref, (void *) adata);
}

// Called when a client enables the NETWORK protocol, this needs to send all of the
// queued networks.
void ProtocolNetworkEnable(int in_fd) {
    vector<wireless_network *> tracked;
    tracked = tracker.FetchNetworks();

    for (unsigned int x = 0; x < tracked.size(); x++) {
        NETWORK_data ndata;
        Protocol_Network2Data(tracked[x], &ndata);
        ui_server.SendToClient(in_fd, network_ref, (void *) &ndata);
    }

}

// Called when a client enables the CLIENT protocol
void ProtocolClientEnable(int in_fd) {
    vector<wireless_network *> tracked;
    tracked = tracker.FetchNetworks();

    for (unsigned int x = 0; x < tracked.size(); x++) {
        for (map<mac_addr, wireless_client *>::const_iterator y = tracked[x]->client_map.begin();
             y != tracked[x]->client_map.end(); ++y) {
            CLIENT_data cdata;
            Protocol_Client2Data(tracked[x], y->second, &cdata);
            ui_server.SendToClient(in_fd, client_ref, (void *) &cdata);
        }
    }
}

// Handle a command sent by a client over its TCP connection.
static void handle_command(TcpServer *tcps, client_command *cc) {
    char id[12];
    snprintf(id, 12, "%d ", cc->stamp);
    string out_error = string(id);
    char status[1024];

    unsigned int space = cc->cmd.find(" ");

    if (space == string::npos)
        space = cc->cmd.length();

    string cmdword = cc->cmd.substr(0, space);

    if (cmdword == "PAUSE") {
        if (packet_sources.size() > 0) {
            for (unsigned int x = 0; x < packet_sources.size(); x++) {
                if (packet_sources[x]->source != NULL)
                    packet_sources[x]->source->Pause();
            }

            snprintf(status, 1024, "Pausing packet sources per request of client %d", cc->client_fd);
            NetWriteStatus(status);
            if (!silent)
                fprintf(stderr, "%s\n", status);
        }
    } else if (cmdword == "RESUME") {
        if (packet_sources.size() > 0) {
            for (unsigned int x = 0; x < packet_sources.size(); x++) {
                if (packet_sources[x]->source != NULL)
                    packet_sources[x]->source->Resume();
            }

            snprintf(status, 1024, "Resuming packet sources per request of client %d", cc->client_fd);
            NetWriteStatus(status);
            if (!silent)
                fprintf(stderr, "%s\n", status);
        }
    } else if (cmdword == "LISTWEPKEYS") {
        if (client_wepkey_allowed == 0) {
            out_error += "Server does not allow clients to retrieve WEP keys";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        if (bssid_wep_map.size() == 0) {
            out_error += "Server has no WEP keys";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        for (map<mac_addr, wep_key_info *>::iterator wkitr = bssid_wep_map.begin();
             wkitr != bssid_wep_map.end(); ++wkitr) {
            tcps->SendToClient(cc->client_fd, wepkey_ref, (void *) wkitr->second);
        }
    } else if (cmdword == "ADDWEPKEY") {
        // !0 ADDWEPKEY bssid,key
        unsigned int begin = space + 1;
        unsigned int com = cc->cmd.find(",", begin);

        if (com == string::npos) {
            out_error += "Invalid ADDWEPKEY";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        cmdword = cc->cmd.substr(begin, com);

        wep_key_info *winfo = new wep_key_info;
        winfo->fragile = 1;
        winfo->bssid = cmdword.c_str();

        if (winfo->bssid.error) {
            out_error += "Invalid ADDWEPKEY bssid";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        begin = com + 1;
        cmdword = cc->cmd.substr(begin, cc->cmd.length() - begin);

        unsigned char key[WEPKEY_MAX];
        int len = Hex2UChar13((unsigned char *) cmdword.c_str(), key);

        if (len != 5 && len != 13) {
            out_error += "Invalid ADDWEPKEY key";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        winfo->len = len;
        memcpy(winfo->key, key, sizeof(unsigned char) * WEPKEY_MAX);

        // Replace exiting ones
        if (bssid_wep_map.find(winfo->bssid) != bssid_wep_map.end())
            delete bssid_wep_map[winfo->bssid];

        bssid_wep_map[winfo->bssid] = winfo;

        snprintf(status, 1024, "Added key %s length %d for BSSID %s",
                 cmdword.c_str(), len, winfo->bssid.Mac2String().c_str());
        NetWriteStatus(status);
        if (!silent)
            fprintf(stderr, "%s\n", status);

    } else if (cmdword == "DELWEPKEY") {
        // !0 DELWEPKEY bssid
        cmdword = cc->cmd.substr(space + 1, cc->cmd.length() - (space + 1));

        mac_addr bssid_mac = cmdword.c_str();

        if (bssid_mac.error) {
            out_error += "Invalid DELWEPKEY bssid";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        if (bssid_wep_map.find(bssid_mac) == bssid_wep_map.end()) {
            out_error += "Unknown DELWEPKEY bssid";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        delete bssid_wep_map[bssid_mac];
        bssid_wep_map.erase(bssid_mac);

        snprintf(status, 1024, "Deleted key for BSSID %s", bssid_mac.Mac2String().c_str());
        NetWriteStatus(status);
        if (!silent)
            fprintf(stderr, "%s\n", status);

    } else {
        out_error += "Unknown command '" + cmdword + "'";
        tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
        return;
    }

    if (cc->stamp != 0)
        tcps->SendToClient(cc->client_fd, ack_ref, (void *) &cc->stamp);

}

int Usage(char *argv) {
    printf("Usage: %s [OPTION]\n", argv);
    printf("Most (or all) of these options can (and should) be configured via the\n"
           "kismet.conf global config file, but can be overridden here.\n");
    printf("  -t, --log-title <title>      Custom log file title\n"
           "  -n, --no-logging             No logging (only process packets)\n"
           "  -f, --config-file <file>     Use alternate config file\n"
           "  -c, --capture-source <src>   Packet capture source line (type,interface,name)\n"
           "  -C, --enable-capture-sources Comma separated list of named packet sources to use.\n"
           "  -l, --log-types <types>      Comma separated list of types to log,\n"
           "                                (ie, dump,cisco,weak,network,gps)\n"
           "  -d, --dump-type <type>       Dumpfile type (wiretap)\n"
           "  -m, --max-packets <num>      Maximum number of packets before starting new dump\n"
           "  -q, --quiet                  Don't play sounds\n"
           "  -g, --gps <host:port>        GPS server (host:port or off)\n"
           "  -p, --port <port>            TCPIP server port for GUI connections\n"
           "  -a, --allowed-hosts <hosts>  Comma separated list of hosts allowed to connect\n"
           "  -s, --silent                 Don't send any output to console.\n"
           "  -N, --server-name            Server name\n"
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

    const char *logtypes = NULL, *dumptype = NULL;

    char gpshost[1024];
    int gpsport = -1;

    string allowed_hosts;
    int tcpport = -1;
    int tcpmax;

    silent = 0;
    metric = 0;

    start_time = time(0);

    int gpsmode = 0;

    string filter;
    vector<mac_addr> filter_vec;

    unsigned char wep_identity[256];

    // Initialize the identity field
    for (unsigned int wi = 0; wi < 256; wi++)
        wep_identity[wi] = wi;

    int datainterval = 0;

    int beacon_log = 1;
    int phy_log = 1;

    FILE *manuf_data;
    char *client_manuf_name = NULL, *ap_manuf_name = NULL;

    // For commandline and file sources
    string named_sources;
    vector<string> source_input_vec;
    int source_from_cmd = 0;
    int enable_from_cmd = 0;

    vector<client_ipblock *> legal_ipblock_vec;

    static struct option long_options[] = {   /* options table */
        { "log-title", required_argument, 0, 't' },
        { "no-logging", no_argument, 0, 'n' },
        { "config-file", required_argument, 0, 'f' },
        { "capture-source", required_argument, 0, 'c' },
        { "enable-capture-sources", required_argument, 0, 'C' },
        { "log-types", required_argument, 0, 'l' },
        { "dump-type", required_argument, 0, 'd' },
        { "max-packets", required_argument, 0, 'm' },
        { "quiet", no_argument, 0, 'q' },
        { "gps", required_argument, 0, 'g' },
        { "port", required_argument, 0, 'p' },
        { "allowed-hosts", required_argument, 0, 'a' },
        { "server-name", required_argument, 0, 'N' },
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

    while(1) {
        int r = getopt_long(argc, argv, "d:M:t:nf:c:C:l:m:g:a:p:N:qhvs",
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
            source_input_vec.push_back(optarg);
            source_from_cmd = 1;
            break;
        case 'C':
            // Named sources
            named_sources = optarg;
            enable_from_cmd = 1;
            fprintf(stderr, "Using specified capture sources: %s\n", named_sources.c_str());
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
        case 'N':
            // Servername
            servername = optarg;
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
        fprintf(stderr, "FATAL:  Old config file options found.  To support multiple sources, Kismet now\n"
                "uses a new config file format.  Please consult the example config file in your Kismet\n"
                "source directory, OR do 'make forceinstall' and reconfigure Kismet.\n");
        exit(1);
    }

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
                   ctype == card_orinoco || ctype == card_generic) {
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

    // Convert the WEP mappings to our real map
    vector<string> raw_wepmap_vec;
    raw_wepmap_vec = conf->FetchOptVec("wepkey");
    for (unsigned int rwvi = 0; rwvi < raw_wepmap_vec.size(); rwvi++) {
        string wepline = raw_wepmap_vec[rwvi];

        unsigned int rwsplit = wepline.find(",");
        if (rwsplit == string::npos) {
            fprintf(stderr, "FATAL:  Malformed 'wepkey' option in the config file.\n");
            exit(1);
        }

        mac_addr bssid_mac = wepline.substr(0, rwsplit).c_str();

        if (bssid_mac.error == 1) {
            fprintf(stderr, "FATAL:  Malformed 'wepkey' option in the config file.\n");
            exit(1);
        }

        string rawkey = wepline.substr(rwsplit + 1, wepline.length() - (rwsplit + 1));

        unsigned char key[WEPKEY_MAX];
        int len = Hex2UChar13((unsigned char *) rawkey.c_str(), key);

        if (len != 5 && len != 13) {
            fprintf(stderr, "FATAL:  Invalid key '%s' length %d in a wepkey option in the config file.\n",
                    rawkey.c_str(), len);
            exit(1);
        }

        wep_key_info *keyinfo = new wep_key_info;
        keyinfo->bssid = bssid_mac;
        keyinfo->fragile = 0;
        keyinfo->len = len;
        memcpy(keyinfo->key, key, sizeof(unsigned char) * WEPKEY_MAX);

        bssid_wep_map[bssid_mac] = keyinfo;

        fprintf(stderr, "Using key %s length %d for BSSID %s\n",
                rawkey.c_str(), len, bssid_mac.Mac2String().c_str());
    }
    if (conf->FetchOpt("allowkeytransmit") == "true") {
        fprintf(stderr, "Allowing clients to fetch WEP keys.\n");
        client_wepkey_allowed = 1;
    }

    if (servername == NULL) {
        if (conf->FetchOpt("servername") != "") {
            servername = strdup(conf->FetchOpt("servername").c_str());
        } else {
            servername = strdup("Unnamed");
        }
    }

    if (conf->FetchOpt("configdir") != "") {
        configdir = conf->ExpandLogPath(conf->FetchOpt("configdir"), "", "", 0, 1);
    } else {
        fprintf(stderr, "FATAL:  No 'configdir' option in the config file.\n");
        exit(1);
    }

    if (conf->FetchOpt("ssidmap") != "") {
        // Explode the map file path
        ssidtrackfile = conf->ExpandLogPath(configdir + conf->FetchOpt("ssidmap"), "", "", 0, 1);
        ssid_cloak_track = 1;
    }

    if (conf->FetchOpt("ipmap") != "") {
        // Explode the IP file path
        iptrackfile = conf->ExpandLogPath(configdir + conf->FetchOpt("ipmap"), "", "", 0, 1);
        ip_track = 1;
    }


#ifdef HAVE_GPS
    if (conf->FetchOpt("waypoints") == "true") {
        if(conf->FetchOpt("waypointdata") == "") {
            fprintf(stderr, "WARNING:  Waypoint logging requested but no waypoint data file given.\n"
                    "Waypoint logging will be disabled.\n");
            waypoint = 0;
        } else {
            waypointfile = conf->ExpandLogPath(conf->FetchOpt("waypointdata"), "", "", 0, 1);
            waypoint = 1;
        }

    }
#endif

    if (conf->FetchOpt("metric") == "true") {
        fprintf(stderr, "Using metric measurements.\n");
        metric = 1;
    }

    if (!no_log) {
        if (logname == "") {
            if (conf->FetchOpt("logdefault") == "") {
                fprintf(stderr, "FATAL:  No default log name in config and no log name provided on the command line.\n");
                exit(1);
            }
            logname = strdup(conf->FetchOpt("logdefault").c_str());
        }

        if (logtypes == NULL) {
            if (conf->FetchOpt("logtypes") == "") {
                fprintf(stderr, "FATAL:  No log types in config and none provided on the command line.\n");
                exit(1);
            }
            logtypes = strdup(conf->FetchOpt("logtypes").c_str());
        }

        if (conf->FetchOpt("noiselog") == "true")
            noise_log = 1;

        if (strstr(logtypes, "dump")) {
            data_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  Logging (network dump) enabled but no logtemplate given in config.\n");
                exit(1);
            }

            if (conf->FetchOpt("dumplimit") != "" || limit_logs != 0) {
                if (limit_logs == 0)
                    if (sscanf(conf->FetchOpt("dumplimit").c_str(), "%d", &limit_logs) != 1) {
                        fprintf(stderr, "FATAL:  Illegal config file value for dumplimit.\n");
                        exit(1);
                    }

                if (limit_logs != 0)
                    fprintf(stderr, "Limiting dumpfile to %d packets each.\n",
                            limit_logs);
            }

            if (conf->FetchOpt("dumptype") == "" && dumptype == NULL) {
                fprintf(stderr, "FATAL: Dump file logging requested but no dump type given.\n");
                exit(1);
            }

            if (conf->FetchOpt("dumptype") != "" && dumptype == NULL)
                dumptype = strdup(conf->FetchOpt("dumptype").c_str());

            if (!strcasecmp(dumptype, "wiretap")) {
                dumpfile = new WtapDumpFile;
            } else {
                fprintf(stderr, "FATAL:  Unknown dump file type '%s'\n", dumptype);
                exit(1);
            }
        }

        if (strstr(logtypes, "network")) {
            net_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  Logging (network list) enabled but no logtemplate given in config.\n");
                exit(1);
            }

        }

        if (strstr(logtypes, "weak")) {
            crypt_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  Logging (weak packets) enabled but no logtemplate given in config.\n");
                exit(1);
            }

        }

        if (strstr(logtypes, "csv")) {
            csv_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  CSV Logging (network list) enabled but no logtemplate given in config.\n");
                exit(1);
            }

        }

        if (strstr(logtypes, "xml")) {
            xml_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  XML Logging (network list) enabled but no logtemplate given in config.\n");
                exit(1);
            }
        }

        if (strstr(logtypes, "cisco")) {
            cisco_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL: Logging (cisco packets) enabled but no logtemplate given in config.\n");
                exit(1);
            }

        }

        if (strstr(logtypes, "gps")) {
#ifdef HAVE_GPS

            gps_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
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

    if (conf->FetchOpt("decay") != "") {
        if (sscanf(conf->FetchOpt("decay").c_str(), "%d", &decay) != 1) {
            fprintf(stderr, "FATAL:  Illegal config file value for decay.\n");
            exit(1);
        }
    }

    if (conf->FetchOpt("alertbacklog") != "") {
        if (sscanf(conf->FetchOpt("alertbacklog").c_str(), "%d", &max_alerts) != 1) {
            fprintf(stderr, "FATAL:  Illegal config file value for alert backlog.\n");
            exit(1);
        }
    }

    if (tcpport == -1) {
        if (conf->FetchOpt("tcpport") == "") {
            fprintf(stderr, "FATAL:  No tcp port given to listen for GUI connections.\n");
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

    // Process sound stuff
    if (conf->FetchOpt("sound") == "true" && sound == -1) {
        if (conf->FetchOpt("soundplay") != "") {
            sndplay = conf->FetchOpt("soundplay");

            if (conf->FetchOpt("soundopts") != "")
                sndplay += " " + conf->FetchOpt("soundopts");

            sound = 1;

            if (conf->FetchOpt("sound_new") != "")
                wav_map["new"] = conf->FetchOpt("sound_new");
            if (conf->FetchOpt("sound_traffic") != "")
                wav_map["traffic"] = conf->FetchOpt("sound_traffic");
            if (conf->FetchOpt("sound_junktraffic") != "")
                wav_map["junktraffic"] = conf->FetchOpt("sound_traffic");
            if (conf->FetchOpt("sound_gpslock") != "")
                wav_map["gpslock"] = conf->FetchOpt("sound_gpslock");
            if (conf->FetchOpt("sound_gpslost") != "")
                wav_map["gpslost"] = conf->FetchOpt("sound_gpslost");
            if (conf->FetchOpt("sound_alert") != "")
                wav_map["alert"] = conf->FetchOpt("sound_alert");

        } else {
            fprintf(stderr, "ERROR:  Sound alerts enabled but no sound playing binary specified.\n");
            sound = 0;
        }
    } else if (sound == -1)
        sound = 0;

    /* Added by Shaw Innes 17/2/02 */
    /* Modified by Andrew Etter 15/9/02 */
    if (conf->FetchOpt("speech") == "true" && speech == -1) {
        if (conf->FetchOpt("festival") != "") {
            festival = strdup(conf->FetchOpt("festival").c_str());
            speech = 1;

            string speechtype = conf->FetchOpt("speech_type");

            if (!strcasecmp(speechtype.c_str(), "nato"))
                speech_encoding = SPEECH_ENCODING_NATO;
            else if (!strcasecmp(speechtype.c_str(), "spell"))
                speech_encoding = SPEECH_ENCODING_SPELL;
            else
                speech_encoding = SPEECH_ENCODING_NORMAL;

            // Make sure we have encrypted text lines
            if (conf->FetchOpt("speech_encrypted") == "" || conf->FetchOpt("speech_unencrypted") == "") {
                fprintf(stderr, "ERROR:  Speech request but speech_encrypted or speech_unencrypted line missing.\n");
                speech = 0;
            }

            speech_sentence_encrypted = conf->FetchOpt("speech_encrypted");
            speech_sentence_unencrypted = conf->FetchOpt("speech_unencrypted");
        } else {
            fprintf(stderr, "ERROR: Speech alerts enabled but no path to festival has been specified.\n");
            speech = 0;
        }
    } else if (speech == -1)
        speech = 0;

    if (conf->FetchOpt("writeinterval") != "") {
        if (sscanf(conf->FetchOpt("writeinterval").c_str(), "%d", &datainterval) != 1) {
            fprintf(stderr, "FATAL:  Illegal config file value for data interval.\n");
            exit(1);
        }
    }

    if (conf->FetchOpt("ap_manuf") != "") {
        ap_manuf_name = strdup(conf->FetchOpt("ap_manuf").c_str());
    } else {
        fprintf(stderr, "WARNING:  No ap_manuf file specified, AP manufacturers and defaults will not be detected.\n");
    }

    if (conf->FetchOpt("client_manuf") != "") {
        client_manuf_name = strdup(conf->FetchOpt("client_manuf").c_str());
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
    filter = conf->FetchOpt("macfilter");

    // handle the config bits
    struct stat fstat;
    if (stat(configdir.c_str(), &fstat) == -1) {
        fprintf(stderr, "configdir '%s' does not exist, making it.\n",
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
            fprintf(stderr, "SSID cloak file did not exist, it will be created.\n");
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
            fprintf(stderr, "IP track file did not exist, it will be created.\n");

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
    // We need to save this for after we toast the conf record
    string logtemplate;
    int logfile_matched = 0;
    for (int run_num = 1; run_num < 100; run_num++) {
        if (data_log) {
            dumplogfile = conf->ExpandLogPath(conf->FetchOpt("logtemplate"), logname, "dump", run_num);
            logtemplate = conf->FetchOpt("logtemplate");

            if (dumplogfile == "")
                continue;
        }

        if (net_log) {
            netlogfile = conf->ExpandLogPath(conf->FetchOpt("logtemplate"), logname, "network", run_num);

            if (netlogfile == "")
                continue;
        }

        if (crypt_log) {
            cryptlogfile = conf->ExpandLogPath(conf->FetchOpt("logtemplate"), logname, "weak", run_num);

            if (cryptlogfile == "")
                continue;
        }

        if (csv_log) {
            csvlogfile = conf->ExpandLogPath(conf->FetchOpt("logtemplate"), logname, "csv", run_num);

            if (csvlogfile == "")
                continue;
        }

        if (xml_log) {
            xmllogfile = conf->ExpandLogPath(conf->FetchOpt("logtemplate"), logname, "xml", run_num);

            if (xmllogfile == "")
                continue;
        }

        if (cisco_log) {
            ciscologfile = conf->ExpandLogPath(conf->FetchOpt("logtemplate"), logname, "cisco", run_num);

            if (ciscologfile == "")
                continue;
        }

#ifdef HAVE_GPS
        if (gps_log) {
            gpslogfile = conf->ExpandLogPath(conf->FetchOpt("logtemplate"), logname, "gps", run_num);

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

        int fdone = 0;
        unsigned int fstart = 0;
        unsigned int fend = filter.find(",", fstart);
        while (fdone == 0) {
            if (fend == string::npos) {
                fend = filter.length();
                fdone = 1;
            }

            string faddr = filter.substr(fstart, fend-fstart);
            fstart = fend+1;
            fend = filter.find(",", fstart);

            mac_addr fmaddr = faddr.c_str();
            if (fmaddr.error) {
                fprintf(stderr, "FATAL:  Invalid filter address %s.\n", faddr.c_str());
                exit(1);
            }

            filter_vec.push_back(fmaddr);
        }

    }

    if (conf->FetchOpt("beaconlog") == "false") {
        beacon_log = 0;
        fprintf(stderr, "Filtering beacon packets.\n");
    }

    if (conf->FetchOpt("phylog") == "false") {
        phy_log = 0;
        fprintf(stderr, "Filtering PHY layer packets.\n");
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
        if (conf->FetchOpt("gps") == "true") {
            if (sscanf(conf->FetchOpt("gpshost").c_str(), "%1024[^:]:%d", gpshost, &gpsport) != 2) {
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

    char *fuzzengines = strdup(conf->FetchOpt("fuzzycrypt").c_str());
    for (unsigned int x = 0; x < packet_sources.size(); x++) {
        if (packet_sources[x]->source == NULL)
            continue;

        if (strstr(fuzzengines, packet_sources[x]->scardtype.c_str()) ||
            strncmp(fuzzengines, "all", 3) == 0)
            packet_sources[x]->packparm.fuzzy_crypt = 1;
        else
            packet_sources[x]->packparm.fuzzy_crypt = 0;
    }
    free(fuzzengines);

    // Delete the conf stuff
    delete conf;
    conf = NULL;

    if (data_log) {
        if (dumpfile->OpenDump(dumplogfile.c_str()) < 0) {
            fprintf(stderr, "FATAL: Dump file error: %s\n", dumpfile->FetchError());
            exit(1);
        }

        dumpfile->SetBeaconLog(beacon_log);
        dumpfile->SetPhyLog(phy_log);

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

    snprintf(status, STATUS_MAX, "Kismet %d.%d.%d (%s)",
             VERSION_MAJOR, VERSION_MINOR, VERSION_TINY, servername);
    fprintf(stderr, "%s\n", status);

    for (unsigned int x = 0; x < packet_sources.size(); x++) {
        if (packet_sources[x]->source == NULL)
            continue;

        snprintf(status, STATUS_MAX, "Source %d (%s): Capturing packets from %s",
                 x, packet_sources[x]->name.c_str(), packet_sources[x]->source->FetchType());
        fprintf(stderr, "%s\n", status);
    }

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

    fprintf(stderr, "Listening on port %d.\n", tcpport);
    for (unsigned int ipvi = 0; ipvi < legal_ipblock_vec.size(); ipvi++) {
        char *netaddr = strdup(inet_ntoa(legal_ipblock_vec[ipvi]->network));
        char *maskaddr = strdup(inet_ntoa(legal_ipblock_vec[ipvi]->mask));

        fprintf(stderr, "Allowing connections from %s/%s\n", netaddr, maskaddr);

        free(netaddr);
        free(maskaddr);
    }

    if (ui_server.Setup(tcpmax, tcpport, &legal_ipblock_vec) < 0) {
        fprintf(stderr, "Failed to set up UI server: %s\n", ui_server.FetchError());
        CatchShutdown(-1);
    }

    fprintf(stderr, "Registering builtin client/server protocols...\n");
    // Register the required protocols - every client gets these automatically
    // although they can turn them off themselves later
    kismet_ref = ui_server.RegisterProtocol("KISMET", 1, KISMET_fields_text,
                                            &Protocol_KISMET, NULL);
    error_ref = ui_server.RegisterProtocol("ERROR", 1, ERROR_fields_text,
                                           &Protocol_ERROR, NULL);
    ack_ref = ui_server.RegisterProtocol("ACK", 1, ACK_fields_text,
                                         &Protocol_ACK, NULL);
    protocols_ref = ui_server.RegisterProtocol("PROTOCOLS", 1, PROTOCOLS_fields_text,
                                               &Protocol_PROTOCOLS, NULL);
    capability_ref = ui_server.RegisterProtocol("CAPABILITY", 1, CAPABILITY_fields_text,
                                                &Protocol_CAPABILITY, NULL);
    terminate_ref = ui_server.RegisterProtocol("TERMINATE", 1, TERMINATE_fields_text,
                                               &Protocol_TERMINATE, NULL);
    time_ref = ui_server.RegisterProtocol("TIME", 1, TIME_fields_text,
                                          &Protocol_TIME, NULL);
    // register the others
    alert_ref = ui_server.RegisterProtocol("ALERT", 0, ALERT_fields_text,
                                           &Protocol_ALERT, &ProtocolEnableAlert);
    network_ref = ui_server.RegisterProtocol("NETWORK", 0, NETWORK_fields_text,
                                             &Protocol_NETWORK, &ProtocolNetworkEnable);
    client_ref = ui_server.RegisterProtocol("CLIENT", 0, CLIENT_fields_text,
                                            &Protocol_CLIENT, &ProtocolClientEnable);
    gps_ref = ui_server.RegisterProtocol("GPS", 0, GPS_fields_text,
                                         &Protocol_GPS, NULL);
    info_ref = ui_server.RegisterProtocol("INFO", 0, INFO_fields_text,
                                          &Protocol_INFO, NULL);
    remove_ref = ui_server.RegisterProtocol("REMOVE", 0, REMOVE_fields_text,
                                            &Protocol_REMOVE, NULL);
    status_ref = ui_server.RegisterProtocol("STATUS", 0, STATUS_fields_text,
                                            &Protocol_STATUS, NULL);
    packet_ref = ui_server.RegisterProtocol("PACKET", 0, PACKET_fields_text,
                                            &Protocol_PACKET, NULL);
    string_ref = ui_server.RegisterProtocol("STRING", 0, STRING_fields_text,
                                            &Protocol_STRING, NULL);
    wepkey_ref = ui_server.RegisterProtocol("WEPKEY", 0, WEPKEY_fields_text,
                                            &Protocol_WEPKEY, NULL);

    cisco_ref = -1;

    // Hijack the status char* for some temp work and fill in our server data record
    // for sending to new clients.
    snprintf(status, 1024, "%d.%d.%d", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY);
    kdata.version = status;
    snprintf(status, 1024, "%d", (int) start_time);
    kdata.starttime = status;
    snprintf(status, 1024, "\001%s\001", servername);
    kdata.servername = status;
    snprintf(status, 1024, "%s", TIMESTAMP);
    kdata.timestamp = status;

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

    time_t cur_time = time(0);
    time_t last_time = cur_time;
    while (1) {
        fd_set rset, wset;
        cur_time = time(0);

        max_fd = ui_server.MergeSet(read_set, max_fd, &rset, &wset);

        // 0.5 second cycle
        struct timeval tm;
        tm.tv_sec = 0;
        tm.tv_usec = 500000;

        if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
            if (errno != EINTR) {
                snprintf(status, STATUS_MAX,
                         "FATAL: select() error %d (%s)", errno, strerror(errno));
                NetWriteStatus(status);
                fprintf(stderr, "%s\n", status);
                CatchShutdown(-1);
            }
        }

        for (int x = 0; x <= max_fd; ++x) {
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
            if (!silent)
                fprintf(stderr, "Accepted interface connection from %s\n",
                        ui_server.FetchError());

            ui_server.SendToClient(accept_fd, kismet_ref, (void *) &kdata);
            ui_server.SendMainProtocols(accept_fd, protocols_ref);

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
                    packnum++;

                    static packet_info info;

                    GetPacketInfo(&packet, &packet_sources[src]->packparm, &info,
                                  &bssid_wep_map, wep_identity);

                    last_info = info;

                    // Discard it if we're filtering it
                    for (unsigned int fcount = 0; fcount < filter_vec.size(); fcount++) {
                        if (filter_vec[fcount] == info.bssid_mac) {
                            localdropnum++;

                            // don't ever do this.  ever.  (but it really is the most efficient way
                            // of getting from here to there, so....)
                            goto end_packprocess;
                        }
                    }

                    /* We never implemented this doing anything so comment it out,
                       especially since the new server code doesn't use it yet
                    // Handle the per-channel signal power levels
                    if (info.channel > 0 && info.channel < CHANNEL_MAX) {
                        channel_graph[info.channel].last_time = info.time;
                        channel_graph[info.channel].signal = info.signal;
                    }
                    */

                    int process_ret;

#ifdef HAVE_GPS
                    if (gps_log && info.type != packet_noise && info.type != packet_unknown &&
                        info.type != packet_phy) {
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

                    // Send the packet info to clients if any of them are requesting it
                    if (ui_server.FetchNumClientRefs(packet_ref) > 0) {
                        PACKET_data pdata;
                        Protocol_Packet2Data(&info, &pdata);
                        ui_server.SendToAll(packet_ref, (void *) &pdata);
                    }

                    // Extract and send string info to clients if any are requesting it
                    if (info.type == packet_data && (info.encrypted == 0 || info.decoded == 1) &&
                        ui_server.FetchNumClientRefs(string_ref) > 0) {
                        vector<string> strlist;
                        STRING_data sdata;

                        strlist = GetPacketStrings(&info, &packet);
                        sdata.bssid = info.bssid_mac.Mac2String();
                        sdata.sourcemac = info.source_mac.Mac2String();

                        for (unsigned int y = 0; y < strlist.size(); y++) {
                            sdata.text = strlist[y];
                            ui_server.SendToAll(string_ref, (void *) &sdata);
                        }

                    }

                    if (data_log && !(info.type == packet_noise && noise_log == 1)) {
                        if (limit_logs && log_packnum > limit_logs) {
                            dumpfile->CloseDump();

                            dumplogfile = ConfigFile::ExpandLogPath(logtemplate, logname, "dump", 0);

                            if (dumpfile->OpenDump(dumplogfile.c_str()) < 0) {
                                perror("Unable to open new dump file");
                                CatchShutdown(-1);
                            }

                            dumpfile->SetBeaconLog(beacon_log);
                            dumpfile->SetPhyLog(phy_log);

                            snprintf(status, STATUS_MAX, "Opened new packet log file %s",
                                     dumplogfile.c_str());

                            if (!silent)
                                fprintf(stderr, "%s\n", status);

                            NetWriteStatus(status);
                        }

                        int ret = dumpfile->DumpPacket(&info, &packet);
                        if (ret < 0) {
                            NetWriteStatus(dumpfile->FetchError());
                            fprintf(stderr, "FATAL: %s\n", dumpfile->FetchError());
                            CatchShutdown(-1);
                        } else if (ret == 0) {
                            localdropnum++;
                        }

                        log_packnum = dumpfile->FetchDumped();
                    }

                    if (crypt_log) {
                        cryptfile->DumpPacket(&info, &packet);
                    }

                    if (packet.data != NULL)
                        delete[] packet.data;
                    if (packet.moddata != NULL)
                        delete[] packet.moddata;

                } else if (len < 0) {
                    // Fail on error
                    if (!silent) {
                        fprintf(stderr, "Source %d: %s\n", src, psrc->FetchError());
                        fprintf(stderr, "Terminating.\n");
                    }

                    NetWriteStatus(psrc->FetchError());
                    CatchShutdown(-1);
                }
            } // End processing new packets

        end_packprocess: ;

        }

        // Draw if it's time
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
