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

#define KISMET_SERVER

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

#include "util.h"
#include "configfile.h"

#include "packet.h"

#include "packetsource.h"
#include "prism2source.h"
#include "pcapsource.h"
#include "wtapfilesource.h"
#include "wsp100source.h"
#include "vihasource.h"
#include "dronesource.h"
#include "packetsourceutil.h"

#include "dumpfile.h"
#include "wtapdump.h"
#include "wtaplocaldump.h"
#include "airsnortdump.h"
#include "fifodump.h"
#include "gpsdump.h"

#include "gpsd.h"

#include "packetracker.h"
#include "timetracker.h"
#include "alertracker.h"

#include "speech.h"
#include "tcpserver.h"
#include "server_globals.h"
#include "kismet_server.h"

#ifndef exec_name
char *exec_name;
#endif

const char *config_base = "kismet.conf";

// Some globals for command line options
char *configfile = NULL;
int no_log = 0, noise_log = 0, data_log = 0, net_log = 0, crypt_log = 0, cisco_log = 0,
    gps_log = -1, gps_enable = 1, csv_log = 0, xml_log = 0, ssid_cloak_track = 0, ip_track = 0,
    waypoint = 0, fifo = 0, corrupt_log = 0;
string logname, dumplogfile, netlogfile, cryptlogfile, ciscologfile,
    gpslogfile, csvlogfile, xmllogfile, ssidtrackfile, configdir, iptrackfile, waypointfile,
    fifofile;
FILE *ssid_file = NULL, *ip_file = NULL, *waypoint_file = NULL;

DumpFile *dumpfile, *cryptfile;
int packnum = 0, localdropnum = 0;

Packetracker tracker;
Alertracker alertracker;
Timetracker timetracker;

GPSD *gps = NULL;
#ifdef HAVE_GPS
int gpsmode = 0;
GPSDump gpsdump;
#endif

FifoDumpFile fifodump;
TcpServer ui_server;
int sound = -1;
packet_info last_info;
int decay;
channel_power channel_graph[CHANNEL_MAX];
char *servername = NULL;

fd_set read_set;

// Do we allow sending wep keys to the client?
int client_wepkey_allowed = 0;
// Wep keys
macmap<wep_key_info *> bssid_wep_map;

// Pipe file descriptor pairs and fd's
int soundpair[2];
int speechpair[2];
pid_t soundpid = -1, speechpid = -1;

// Past alerts
unsigned int max_alerts = 50;

// Capture sources
vector<capturesource *> packet_sources;

// Reference numbers for all of our builtin protocols
int kismet_ref = -1, network_ref = -1, client_ref = -1, gps_ref = -1, time_ref = -1, error_ref = -1,
    info_ref = -1, cisco_ref = -1, terminate_ref = -1, remove_ref = -1, capability_ref = -1,
    protocols_ref = -1, status_ref = -1, alert_ref = -1, packet_ref = -1, string_ref = -1,
    ack_ref = -1, wepkey_ref = -1, card_ref = -1;

// Reference number for our kismet-server alert
int kissrv_aref = -1;

// A kismet data record for passing to the protocol
KISMET_data kdata;

// Filter maps for the various filter types
int filter_tracker = 0;
macmap<int> filter_tracker_bssid;
macmap<int> filter_tracker_source;
macmap<int> filter_tracker_dest;
int filter_tracker_bssid_invert = -1, filter_tracker_source_invert = -1,
    filter_tracker_dest_invert = -1;

int filter_dump = 0;
macmap<int> filter_dump_bssid;
macmap<int> filter_dump_source;
macmap<int> filter_dump_dest;
int filter_dump_bssid_invert = -1, filter_dump_source_invert = -1,
    filter_dump_dest_invert = -1;

int filter_export = 0;
macmap<int> filter_export_bssid;
macmap<int> filter_export_source;
macmap<int> filter_export_dest;
int filter_export_bssid_invert = -1, filter_export_source_invert = -1,
    filter_export_dest_invert = -1;

// For alert enabling...
typedef struct _alert_enable {
    string alert_name;
    alert_time_unit limit_unit;
    int limit_rate;
    int limit_burst;
};

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
                alertracker.RaiseAlert(kissrv_aref, alert);
                //NetWriteAlert(alert);
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
                alertracker.RaiseAlert(kissrv_aref, alert);
                //NetWriteAlert(alert);
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
                alertracker.RaiseAlert(kissrv_aref, alert);
                //NetWriteAlert(alert);
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
                alertracker.RaiseAlert(kissrv_aref, alert);
                //NetWriteAlert(alert);
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
    if (sig == SIGPIPE)
        fprintf(stderr, "FATAL: Pipe closed unexpectedly, shutting down...\n");

    capchild_packhdr pak;
    pak.sentinel = CAPSENTINEL;
    pak.packtype = CAPPACK_COMMAND;
    pak.flags = CAPFLAG_NONE;
    pak.datalen = 2;
    pak.data = (uint8_t *) malloc(2);
    int16_t cmd = CAPCMD_DIE;

    memcpy(pak.data, &cmd, 2);

    for (unsigned int x = 0; x < packet_sources.size(); x++) {
        if (packet_sources[x]->alive) {
            fprintf(stderr, "Shutting down source %d (%s)...\n", x, packet_sources[x]->name.c_str());

            // Send the death command
            if (send(packet_sources[x]->childpair[1], &pak, sizeof(capchild_packhdr) - sizeof(void *), 0) > 0)
                send(packet_sources[x]->childpair[1], pak.data, pak.datalen, 0);
        }
    }

    free(pak.data);

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
    if (gps_log == 1) {
        if (gpsdump.CloseDump(1) < 0)
            fprintf(stderr, "Didn't log any GPS coordinates, unlinking gps file\n");
    }

#endif

    // Kill our sound players
    if (soundpid > 0)
        kill(soundpid, 9);
    if (speechpid > 0)
        kill(speechpid, 9);

    // Sleep for half a second to give the chilren time to die off from the command
    usleep(500000);

    // Kill any child sniffers still around
    for (unsigned int x = 0; x < packet_sources.size(); x++) {
        if (packet_sources[x]->alive) {
            fprintf(stderr, "Waiting for capture child %d to terminate...\n", packet_sources[x]->childpid);
            wait4(packet_sources[x]->childpid, NULL, 0, NULL);
        }

        delete packet_sources[x];
    }

    fprintf(stderr, "Kismet exiting.\n");
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
            // Only take the first line
            char *nl;
            if ((nl = strchr(data, '\n')) != NULL)
                *nl = '\0';

            // Make sure it's shell-clean

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
                // Only take the first line
                char *nl;
                if ((nl = strchr(data, '\n')) != NULL)
                    *nl = '\0';

                // Make sure it's shell-clean
                MungeToShell(data, strlen(data));
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

void KisLocalAlert(const char *in_text) {
    time_t now = time(0);
    if (!silent)
        fprintf(stderr, "ALERT %.24s %s\n", ctime(&now), in_text);

    if (sound == 1)
        sound = PlaySound("alert");

}

void KisLocalStatus(const char *in_status) {
    time_t now = time(0);
    if (!silent)
        fprintf(stderr, "%.24s %s\n", ctime(&now), in_status);

    NetWriteStatus(in_status);
}

void KisLocalNewnet(const wireless_network *in_net) {
    if (ui_server.FetchNumClients() < 1)
        return;

    NETWORK_data ndata;
    Protocol_Network2Data(in_net, &ndata);
    ui_server.SendToAll(network_ref, (void *) &ndata);
}

void KisLocalNewclient(const wireless_client *in_cli, const wireless_network *in_net) {
    CLIENT_data cdata;
    Protocol_Client2Data(in_net, in_cli, &cdata);
    ui_server.SendToAll(client_ref, (void *) &cdata);
}

void NetWriteInfo() {
    // If we have no clients, don't do this at all, it's expensive
    if (ui_server.FetchNumClients() < 1)
        return;

    // Send card info
    for (unsigned int src = 0; src < packet_sources.size(); src++) {
        if (packet_sources[src]->alive == 0)
            continue;

        ui_server.SendToAll(card_ref, (void *) packet_sources[src]);
    }

    static time_t last_write = time(0);
    static int last_packnum = tracker.FetchNumPackets();
    vector<wireless_network *> tracked;

    int tim = time(0);
    ui_server.SendToAll(time_ref, &tim);

    char tmpstr[32];

#ifdef HAVE_GPS
    GPS_data gdata;

    if (gps_enable) {
        float lat, lon, alt, spd, hed;
        int mode;

        gps->FetchLoc(&lat, &lon, &alt, &spd, &hed, &mode);

        snprintf(tmpstr, 32, "%f", lat);
        gdata.lat = tmpstr;
        snprintf(tmpstr, 32, "%f", lon);
        gdata.lon = tmpstr;
        snprintf(tmpstr, 32, "%f", alt);
        gdata.alt = tmpstr;
        snprintf(tmpstr, 32, "%f", spd);
        gdata.spd = tmpstr;
        snprintf(tmpstr, 32, "%f", hed);
        gdata.heading = tmpstr;
        snprintf(tmpstr, 32, "%d", mode);
        gdata.mode = tmpstr;
    } else {
        gdata.lat = "0.0";
        gdata.lon = "0.0";
        gdata.alt = "0.0";
        gdata.spd = "0.0";
        gdata.heading = "0.0";
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

    if (time(0) - last_info.ts.tv_sec < decay && last_info.quality != -1)
        snprintf(tmpstr, 16, "%d %d %d", last_info.quality,
                 last_info.signal, last_info.noise);
    else if (last_info.quality == -1)
        snprintf(tmpstr, 16, "-1 -1 -1");
    else
        snprintf(tmpstr, 16, "0 0 0");
    idata.signal = tmpstr;

    last_packnum = tracker.FetchNumPackets();

    ui_server.SendToAll(info_ref, (void *) &idata);

    last_write = time(0);

    // Bail out if nobody is listening to networks or packets, building these
    // lists is expensive and if we're headless, don't bother.

    if (ui_server.FetchNumClientRefs(network_ref) < 1 &&
        ui_server.FetchNumClientRefs(client_ref) < 1)
        return;

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

        // Bail if we don't have any client users...
        if (ui_server.FetchNumClientRefs(client_ref) < 1)
            continue;

        for (map<mac_addr, wireless_client *>::const_iterator y = tracked[x]->client_map.begin();
             y != tracked[x]->client_map.end(); ++y) {
            if (y->second->last_time < last_write)
                continue;

            CLIENT_data cdata;
            Protocol_Client2Data(tracked[x], y->second, &cdata);
            ui_server.SendToAll(client_ref, (void *) &cdata);
        }

    }

}

void NetWriteStatus(const char *in_status) {
    string str = in_status;
    ui_server.SendToAll(status_ref, (void *) &str);
}

void ProtocolEnableAlert(int in_fd) {
    alertracker.BlitBacklogged(in_fd);
//    for (unsigned int x = 0; x < past_alerts.size(); x++)
//        ui_server.SendToClient(in_fd, alert_ref, (void *) past_alerts[x]);
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

int GpsEvent(Timetracker::timer_event *evt, void *parm) {
#ifdef HAVE_GPS
    char status[STATUS_MAX];

    // The GPS only provides us a new update once per second we might
    // as well only update it here once a second
    if (gps_enable) {
        int gpsret;
        gpsret = gps->Scan();
        if (gpsret < 0) {
            snprintf(status, STATUS_MAX, "GPS error requesting data: %s",
                     gps->FetchError());

            if (!silent)
                fprintf(stderr, "%s\n", gps->FetchError());

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

    if (gps_log == 1 && gpsmode != 0 && gps != NULL) {
        gpsdump.DumpTrack(gps);
    }

    // We want to be rescheduled
    return 1;
#endif
    return 0;
}

// Simple redirect to the network info drawer.  We don't want to change netwriteinfo to a
// timer event since we call it un-timed too
int NetWriteEvent(Timetracker::timer_event *evt, void *parm) {
    NetWriteInfo();

    // Reschedule us
    return 1;
}

// Handle writing and sync'ing dump files
int ExportSyncEvent(Timetracker::timer_event *evt, void *parm) {
    if (!silent)
        fprintf(stderr, "Saving data files.\n");

    NetWriteStatus("Saving data files.");
    WriteDatafiles(0);

    return 1;
}

// Write the waypoints for gpsdrive
int WaypointSyncEvent(Timetracker::timer_event *evt, void *parm) {
    tracker.WriteGpsdriveWaypt(waypoint_file);

    return 1;
}

// Handle tracker maintenance
int TrackerTickEvent(Timetracker::timer_event *evt, void *parm) {
    tracker.Tick();

    return 1;
}

// Handle channel hopping... this is actually really simple.
int ChannelHopEvent(Timetracker::timer_event *evt, void *parm) {
    for (unsigned int x = 0; x < packet_sources.size(); x++) {
        if (packet_sources[x]->childpid <= 0 || packet_sources[x]->ch_hop == 0)
            continue;

        // Don't hop if a command is pending
        if (packet_sources[x]->cmd_ack == 0)
            continue;

        SendChildCommand(packet_sources[x], packet_sources[x]->channels[packet_sources[x]->ch_pos++]);

        // Wrap the channel sequence
        if ((unsigned int) packet_sources[x]->ch_pos >= packet_sources[x]->channels.size())
            packet_sources[x]->ch_pos = 0;

    }

    return 1;
}

// Handle a command sent by a client over its TCP connection.
void handle_command(TcpServer *tcps, client_command *cc) {
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
                if (packet_sources[x]->alive) {
                    SendChildCommand(packet_sources[x], CAPCMD_PAUSE);

                }
            }

            snprintf(status, 1024, "Pausing packet sources per request of client %d", cc->client_fd);
            NetWriteStatus(status);
            if (!silent)
                fprintf(stderr, "%s\n", status);
        }
    } else if (cmdword == "RESUME") {
        if (packet_sources.size() > 0) {
            for (unsigned int x = 0; x < packet_sources.size(); x++) {
                if (packet_sources[x]->alive) {
                    SendChildCommand(packet_sources[x], CAPCMD_RESUME);
                }

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

        for (macmap<wep_key_info *>::iterator wkitr = bssid_wep_map.begin();
             wkitr != bssid_wep_map.end(); wkitr++) {
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
        int len = Hex2UChar((unsigned char *) cmdword.c_str(), key);

        if (len != 5 && len != 13 && len != 16) {
            out_error += "Invalid ADDWEPKEY key";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        winfo->len = len;
        memcpy(winfo->key, key, sizeof(unsigned char) * WEPKEY_MAX);

        // Replace exiting ones
        if (bssid_wep_map.find(winfo->bssid) != bssid_wep_map.end())
            delete bssid_wep_map[winfo->bssid];

        bssid_wep_map.insert(winfo->bssid, winfo);

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
    printf("  -I, --initial-channel <n:c>  Initial channel to monitor on (default: 6)\n"
           "                                Format capname:channel\n"
           "  -x, --force-channel-hop      Forcibly enable the channel hopper\n"
           "  -X, --force-no-channel-hop   Forcibly disable the channel hopper\n"
           "  -t, --log-title <title>      Custom log file title\n"
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

    // Packet and contents
    kis_packet packet;
    uint8_t data[MAX_PACKET_LEN];
    uint8_t moddata[MAX_PACKET_LEN];


    char *configfile = NULL;

    client_command cmd;
    int sleepu = 0;
    int log_packnum = 0;
    int limit_logs = 0;
    char status[STATUS_MAX];

    //const char *sndplay = NULL;
    string sndplay;

    const char *festival = NULL;
    int speech = -1;
    int speech_encoding = 0;
    string speech_sentence_encrypted, speech_sentence_unencrypted;

    map<string, string> wav_map;

    const char *logtypes = NULL, *dumptype = NULL;

#ifdef HAVE_GPS
    char gpshost[1024];
    int gpsport = -1;
#endif

    string allowed_hosts;
    int tcpport = -1;
    int tcpmax;

    silent = 0;
    metric = 0;

    start_time = time(0);

    unsigned char wep_identity[256];

    // Initialize the identity field
    for (unsigned int wi = 0; wi < 256; wi++)
        wep_identity[wi] = wi;

    int datainterval = 0;

    int channel_hop = -1;
    int channel_velocity = 1;
    int channel_split = 0;
    // capname to initial channel map
    map<string, int> channel_initmap;
    // Default channel hop sequences
    vector<int> channel_def80211b;
    vector<int> channel_def80211a;


    int beacon_log = 1;
    int phy_log = 1;
    int mangle_log = 0;

    FILE *manuf_data;
    char *client_manuf_name = NULL, *ap_manuf_name = NULL;

    // For commandline and file sources
    string named_sources;
    vector<string> source_input_vec;
    int source_from_cmd = 0;
    int enable_from_cmd = 0;

    vector<client_ipblock *> legal_ipblock_vec;

    vector<_alert_enable> alert_enable_vec;

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
        { "initial-channel", required_argument, 0, 'I' },
        { "force-channel-hop", no_argument, 0, 'x' },
        { "force-no-channel-hop", no_argument, 0, 'X' },
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
    signal(SIGPIPE, CatchShutdown);

    while(1) {
        int r = getopt_long(argc, argv, "d:M:t:nf:c:C:l:m:g:a:p:N:I:xXqhvs",
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
            char capname[64];
            int initchan;
            if (sscanf(optarg, "%64[^:]:%d", capname, &initchan) != 2) {
                fprintf(stderr, "FATAL: Unable to process initial channel '%s'.  Format should be capturename:channel\n",
                        optarg);
                Usage(argv[0]);
            }
            channel_initmap[capname] = initchan;
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
        fprintf(stderr, "FATAL:  Old config file options found.  To support multiple sources, Kismet now\n"
                "uses a new config file format.  Please consult the example config file in your Kismet\n"
                "source directory, OR do 'make forceinstall' and reconfigure Kismet.\n");
        exit(1);
    }

#ifdef HAVE_GPS
    // Set up the GPS object to give to the children
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
        gps = new GPSD(gpshost, gpsport);

        // Lock GPS position
        if (conf->FetchOpt("gpsmodelock") == "true") {
            fprintf(stderr, "Enabling GPS position lock override (broken GPS unit reports 0 always)\n");
            gps->SetOptions(GPSD_OPT_FORCEMODE);
        }

    } else {
        gps_log = 0;
    }

#endif

    // Read all of our packet sources, tokenize the input and then start opening
    // them.

    if (named_sources.length() == 0) {
        named_sources = conf->FetchOpt("enablesources");
    }

    // Parse the enabled sources into a map
    map<string, int> enable_name_map;

    // Tell them if we're enabling everything
    if (named_sources.length() == 0)
        fprintf(stderr, "No enable sources specified, all sources will be enabled.\n");

    // Command line sources override the enable line, unless we also got an enable line
    // from the command line too.
    if ((source_from_cmd == 0 || enable_from_cmd == 1) && named_sources.length() > 0) {
        enable_name_map = ParseEnableLine(named_sources);
    }

    // Read the config file if we didn't get any sources on the command line
    if (source_input_vec.size() == 0)
        source_input_vec = conf->FetchOptVec("source");

    if (source_input_vec.size() == 0) {
        fprintf(stderr, "FATAL:  No valid packet sources defined in config or passed on command line.\n");
        exit(1);
    }

    int ret;
    if ((ret = ParseCardLines(&source_input_vec, &packet_sources)) < 0) {
        fprintf(stderr, "FATAL:  Invalid source line '%s'\n",
                source_input_vec[(-1 * ret) - 1].c_str());
        exit(1);
    }

    source_input_vec.clear();

    // Now enable root sources...  BindRoot will terminate if it fails.  We need to set our euid
    // to be root here, we don't care if it fails though.
    setreuid(0, 0);

    BindRootSources(&packet_sources, &enable_name_map,
                    ((source_from_cmd == 0) || (enable_from_cmd == 1)),
                    &timetracker, gps);

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

    BindUserSources(&packet_sources, &enable_name_map,
                    ((source_from_cmd == 0) || (enable_from_cmd == 1)),
                    &timetracker, gps);

    // Set the initial channel
    for (unsigned int x = 0; x < packet_sources.size(); x++) {
        if (channel_initmap.find(packet_sources[x]->name) == channel_initmap.end())
            continue;

        SendChildCommand(packet_sources[x], channel_initmap[packet_sources[x]->name]);

        fprintf(stderr, "Source %d (%s): Setting initial channel %d\n",
                x, packet_sources[x]->name.c_str(), channel_initmap[packet_sources[x]->name]);
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
            if (sscanf(conf->FetchOpt("channelvelocity").c_str(), "%d", &channel_velocity) != 1) {
                fprintf(stderr, "FATAL:  Illegal config file value for channelvelocity.\n");
                exit(1);
            }

            if (channel_velocity < 1 || channel_velocity > 10) {
                fprintf(stderr, "FATAL:  Illegal value for channelvelocity, must be between 1 and 10.\n");
                exit(1);
            }
        }

        if (conf->FetchOpt("80211achannels") == "" || conf->FetchOpt("80211bchannels") == "") {
            fprintf(stderr, "FATAL:  No base channel list (80211achannels or 80211bchannels) in configfile.\n");
            fprintf(stderr, "        Update your config file (make forceinstall).\n");
            exit(1);
        }

        // Parse our default channel listing
        channel_def80211a = ParseChannelLine(conf->FetchOpt("80211achannels"));
        channel_def80211b = ParseChannelLine(conf->FetchOpt("80211bchannels"));

        // Parse and assign our channels
        vector<string> sourcechannellines = conf->FetchOptVec("sourcechannels");
        ParseSetChannels(&sourcechannellines, &packet_sources, channel_split,
                         &channel_def80211a, &channel_def80211b);
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
        int len = Hex2UChar((unsigned char *) rawkey.c_str(), key);

        if (len != 5 && len != 13 && len != 16) {
            fprintf(stderr, "FATAL:  Invalid key '%s' length %d in a wepkey option in the config file.\n",
                    rawkey.c_str(), len);
            exit(1);
        }

        wep_key_info *keyinfo = new wep_key_info;
        keyinfo->bssid = bssid_mac;
        keyinfo->fragile = 0;
        keyinfo->decrypted = 0;
        keyinfo->failed = 0;
        keyinfo->len = len;
        memcpy(keyinfo->key, key, sizeof(unsigned char) * WEPKEY_MAX);

        bssid_wep_map.insert(bssid_mac, keyinfo);

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
        if (conf->FetchOpt("fifo") != "") {
            fifofile = conf->FetchOpt("fifo");
            fifo = 1;
        }

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

        if (conf->FetchOpt("corruptlog") == "true")
            corrupt_log = 1;

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
            if (gps_log == 0) {
                fprintf(stderr, "WARNING:  Disabling GPS logging.\n");
            } else {
                gps_log = 1;

                if (conf->FetchOpt("logtemplate") == "") {
                    fprintf(stderr, "FATAL:  Logging (gps coordinates) enabled but no logtemplate given in config.\n");
                    exit(1);
                }
            }
#else

            fprintf(stderr, "WARNING:  GPS logging requested but GPS support was not included.\n"
                    "          GPS logging will be disabled.\n");
            gps_log = 0;
#endif

        }

        if (gps_log == 1 && !net_log) {
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

    vector<string> hostsvec = StrTokenize(allowed_hosts, ",");

    for (unsigned int hostcomp = 0; hostcomp < hostsvec.size(); hostcomp++) {
        client_ipblock *ipb = new client_ipblock;
        string hoststr = hostsvec[hostcomp];

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
    if (conf->FetchOpt("macfilter") != "") {
        fprintf(stderr, "FATAL:  Old config file options found.  Kismet now supports a much improved\n"
                "filtering scheme.  Please consult the example config file in your Kismet\n"
                "source directory, OR do 'make forceinstall' and reconfigure Kismet.\n");
        exit(1);
    }

    string filter_bit;

    if ((filter_bit = conf->FetchOpt("filter_tracker")) != "") {
        fprintf(stderr, "Enabling tracker filtering.\n");
        filter_tracker = 1;
        if (ConfigFile::ParseFilterLine(filter_bit, &filter_tracker_bssid, &filter_tracker_source,
                                        &filter_tracker_dest, &filter_tracker_bssid_invert,
                                        &filter_tracker_source_invert,
                                        &filter_tracker_dest_invert) < 0)
            exit(1);
    }


    if ((filter_bit = conf->FetchOpt("filter_dump")) != "") {
        fprintf(stderr, "Enabling filtering on dump files.\n");
        filter_dump = 1;
        if (ConfigFile::ParseFilterLine(filter_bit, &filter_dump_bssid, &filter_dump_source,
                                        &filter_dump_dest, &filter_dump_bssid_invert,
                                        &filter_dump_source_invert,
                                        &filter_dump_dest_invert) < 0)
            exit(1);
    }

    if ((filter_bit = conf->FetchOpt("filter_export")) != "") {
        fprintf(stderr, "Enabling filtering on exported (csv, xml, network, gps) files.\n");
        filter_export = 1;
        if (ConfigFile::ParseFilterLine(filter_bit, &filter_export_bssid, &filter_export_source,
                                        &filter_export_dest, &filter_export_bssid_invert,
                                        &filter_export_source_invert,
                                        &filter_export_dest_invert) < 0)
            exit(1);
    }

    // Parse the alert enables.  This is ugly, and maybe should belong in the
    // configfile class with some of the other parsing code.
    for (unsigned int av = 0; av < conf->FetchOptVec("alert").size(); av++) {
        vector<string> tokens = StrTokenize(conf->FetchOptVec("alert")[av], ",");
        _alert_enable aven;

        if (tokens.size() < 2 || tokens.size() > 3) {
            fprintf(stderr, "FATAL:  Invalid alert line: %s\n", conf->FetchOptVec("alert")[av].c_str());
            exit(1);
        }

        aven.alert_name = tokens[0];

        vector<string> units = StrTokenize(tokens[1], "/");

        if (units.size() == 1) {
            aven.limit_unit = sat_minute;
            if (sscanf(units[0].c_str(), "%d", &aven.limit_rate) != 1) {
                fprintf(stderr, "FATAL:  Invalid limit rate: %s\n",
                        conf->FetchOptVec("alert")[av].c_str());
                exit(1);
            }
        } else {
            if (sscanf(units[0].c_str(), "%d", &aven.limit_rate) != 1) {
                fprintf(stderr, "FATAL:  Invalid limit rate: %s\n",
                        conf->FetchOptVec("alert")[av].c_str());
                exit(1);
            }

            if (units[1] == "sec" || units[1] == "second")
                aven.limit_unit = sat_second;
            else if (units[1] == "min" || units[1] == "minute")
                aven.limit_unit = sat_minute;
            else if (units[1] == "hour")
                aven.limit_unit = sat_hour;
            else if (units[1] == "day")
                aven.limit_unit = sat_day;
            else {
                fprintf(stderr, "FATAL:  Invalid time unit in alert line: %s\n",
                        conf->FetchOptVec("alert")[av].c_str());
                exit(1);
            }
        }

        if (tokens.size() == 2) {
            aven.limit_burst = 5;
        } else {
            if (sscanf(tokens[2].c_str(), "%d", &aven.limit_burst) != 1) {
                fprintf(stderr, "FATAL:  Invalid time unit in alert line: %s\n",
                        conf->FetchOptVec("alert")[av].c_str());
                exit(1);
            }

        }

        alert_enable_vec.push_back(aven);
    }

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
        if (gps_log == 1) {
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
    if (gps_log == 1)
        fprintf(stderr, "Logging gps coordinates to %s\n", gpslogfile.c_str());
#endif

    if (data_log)
        fprintf(stderr, "Logging data to %s\n", dumplogfile.c_str());

    if (datainterval != 0 && data_log)
        fprintf(stderr, "Writing data files to disk every %d seconds.\n",
                datainterval);


    if (conf->FetchOpt("beaconlog") == "false") {
        beacon_log = 0;
        fprintf(stderr, "Filtering beacon packets.\n");
    }

    if (conf->FetchOpt("phylog") == "false") {
        phy_log = 0;
        fprintf(stderr, "Filtering PHY layer packets.\n");
    }

    if (conf->FetchOpt("mangledatalog") == "true") {
        mangle_log = 1;
        fprintf(stderr, "Mangling encrypted and fuzzy data packets.\n");
    }

    if (ap_manuf_name != NULL) {
        char pathname[1024];

        if (strchr(ap_manuf_name, '/') == NULL)
            snprintf(pathname, 1024, "%s/%s", getenv("KISMET_CONF") != NULL ? getenv("KISMET_CONF") : SYSCONF_LOC, ap_manuf_name);
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
            snprintf(pathname, 1024, "%s/%s", getenv("KISMET_CONF") != NULL ? getenv("KISMET_CONF") : SYSCONF_LOC, client_manuf_name);
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

    if (filter_export)
        tracker.AddExportFilters(&filter_export_bssid, &filter_export_source, &filter_export_dest,
                                 &filter_export_bssid_invert, &filter_export_source_invert,
                                 &filter_export_dest_invert);

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
        dumpfile->SetMangleLog(mangle_log);

        fprintf(stderr, "Dump file format: %s\n", dumpfile->FetchType());
    }

#ifdef HAVE_GPS
    if (gps_enable && gps_log == 1) {
        if (gpsdump.OpenDump(gpslogfile.c_str(), xmllogfile.c_str()) < 0) {
            fprintf(stderr, "FATAL: GPS dump error: %s\n", gpsdump.FetchError());
            exit(1);
        }
    }
#endif


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

    /*
    for (unsigned int x = 0; x < packet_sources.size(); x++) {
        if (packet_sources[x]->source == NULL)
            continue;

        snprintf(status, STATUS_MAX, "Source %d (%s): Capturing packets from %s",
                 x, packet_sources[x]->name.c_str(), packet_sources[x]->source->FetchType());
        fprintf(stderr, "%s\n", status);
    }
    */

    if (data_log || net_log || crypt_log) {
        snprintf(status, STATUS_MAX, "Logging%s%s%s%s%s%s%s",
                 data_log ? " data" : "" ,
                 net_log ? " networks" : "" ,
                 csv_log ? " CSV" : "" ,
                 xml_log ? " XML" : "" ,
                 crypt_log ? " weak" : "",
                 cisco_log ? " cisco" : "",
                 gps_log == 1 ? " gps" : "");
        fprintf(stderr, "%s\n", status);
    } else if (no_log) {
        snprintf(status, STATUS_MAX, "Not logging any data.");
        fprintf(stderr, "%s\n", status);
    }

    // Open the fifo, if one is requested.  This will block us until something is
    // ready to read from the fifo.
    if (fifo) {
        fprintf(stderr, "Creating and opening named pipe '%s'.  Kismet will now block\n"
                "until another utility opens this pipe.\n", fifofile.c_str());
        if (fifodump.OpenDump(fifofile.c_str()) < 0) {
            fprintf(stderr, "FATAL:  %s\n", fifodump.FetchError());
            CatchShutdown(-1);
        }
    }

#ifdef HAVE_GPS
    if (gps_enable) {
        // Open the GPS
        if (gps->OpenGPSD() < 0) {
            fprintf(stderr, "%s\n", gps->FetchError());

            gps_enable = 0;
            gps_log = 0;
        } else {
            fprintf(stderr, "Opened GPS connection to %s port %d\n",
                    gpshost, gpsport);

            gpsmode = gps->FetchMode();
        }
    }
#endif

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
    card_ref = ui_server.RegisterProtocol("CARD", 0, CARD_fields_text,
                                          &Protocol_CARD, NULL);

    // Register our own alert with no throttling
    kissrv_aref = alertracker.RegisterAlert("KISMET", sat_day, 0, 0);
    // Set the backlog
    alertracker.SetAlertBacklog(max_alerts);
    // Populate the alert engine
    alertracker.AddTcpServer(&ui_server);
    alertracker.AddAlertProtoRef(alert_ref);

    // Tell the packetracker engine where alerts are
    tracker.AddAlertracker(&alertracker);

    // Register alerts with the packetracker
    fprintf(stderr, "Registering requested alerts...\n");
    for (unsigned int alvec = 0; alvec < alert_enable_vec.size(); alvec++) {
        int ret = tracker.EnableAlert(alert_enable_vec[alvec].alert_name,
                                      alert_enable_vec[alvec].limit_unit,
                                      alert_enable_vec[alvec].limit_rate,
                                      alert_enable_vec[alvec].limit_burst);

        // Then process the return value
        if (ret < 0) {
            fprintf(stderr, "FATAL:  Could not enable alert tracking: %s\n",
                    tracker.FetchError());
            CatchShutdown(-1);
        } else if (ret == 0) {
            fprintf(stderr, "%s\n", tracker.FetchError());
        }


    }

    // Schedule our routine events that repeat the entire operational period.  We don't
    // care about their ID's since we're never ever going to cancel them.
    fprintf(stderr, "Registering builtin timer events...\n");

    // Write network info and tick the tracker once per second
    timetracker.RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, &NetWriteEvent, NULL);
    timetracker.RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, &TrackerTickEvent, NULL);
#ifdef HAVE_GPS
    // Update GPS coordinates and handle signal loss if defined
    timetracker.RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, &GpsEvent, NULL);
#endif
    // Sync the data files if requested
    if (datainterval > 0)
        timetracker.RegisterTimer(datainterval * SERVER_TIMESLICES_SEC, NULL, 1, &ExportSyncEvent, NULL);
    // Write waypoints if requested
    if (waypoint)
        timetracker.RegisterTimer(decay * SERVER_TIMESLICES_SEC, NULL, 1, &WaypointSyncEvent, NULL);
    // Channel hop if requested
    if (channel_hop)
        timetracker.RegisterTimer(SERVER_TIMESLICES_SEC / channel_velocity, NULL, 1, &ChannelHopEvent, NULL);

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
        if (packet_sources[x]->childpid <= 0)
            continue;

        FD_SET(packet_sources[x]->childpair[1], &read_set);

        if (packet_sources[x]->childpair[1] > max_fd)
            max_fd = packet_sources[x]->childpair[1];

        if (silent)
            SendChildCommand(packet_sources[x], CAPCMD_SILENT);
#ifdef HAVE_GPS
        if (gps_enable == 1)
            SendChildCommand(packet_sources[x], CAPCMD_GPSENABLE);
#endif
        // Activate the source and gps

        SendChildCommand(packet_sources[x], CAPCMD_ACTIVATE);

        fprintf(stderr, "Enabling packet source %d (%s)...\n", x, packet_sources[x]->name.c_str());

        packet_sources[x]->alive = 1;

    }

    fprintf(stderr, "Gathering packets...\n");

    time_t cur_time;
    while (1) {
        fd_set rset, wset;
        cur_time = time(0);

        max_fd = ui_server.MergeSet(read_set, max_fd, &rset, &wset);

        // Update the write set if we want to send commands
        for (unsigned int x = 0; x < packet_sources.size(); x++) {
            if (packet_sources[x]->childpid <= 0)
                continue;

            if (packet_sources[x]->cmd_buf.size() > 0) {
                FD_SET(packet_sources[x]->childpair[1], &wset);
                if (packet_sources[x]->childpair[1] > max_fd)
                    max_fd = packet_sources[x]->childpair[1];
            }
        }

        struct timeval tm;
        tm.tv_sec = 0;
        tm.tv_usec = 100000;

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
            if (packet_sources[src]->childpid <= 0)
                continue;

            int ret;

            // Handle sending the commands
            if (FD_ISSET(packet_sources[src]->childpair[1], &wset) && packet_sources[src]->cmd_buf.size() > 0) {
                int send_fd = packet_sources[src]->childpair[1];
                capchild_packhdr *pak = packet_sources[src]->cmd_buf.front();
                packet_sources[src]->cmd_buf.pop_front();

                // Send the packet header
                if (send(send_fd, pak, sizeof(capchild_packhdr) - sizeof(void *), 0) < 0) {
                    fprintf(stderr, "FATAL:  capture source %d (%s)send() error sending packhdr %d (%s)\n",
                            src, packet_sources[src]->name.c_str(), errno, strerror(errno));
                    exit(1);
                }

                // Send the data
                if (send(send_fd, pak->data, pak->datalen, 0) < 0) {
                    fprintf(stderr, "FATAL:  capture child %d (%s) send() error sending pack data %d (%s)\n",
                            src, packet_sources[src]->name.c_str(), errno, strerror(errno));
                    exit(1);
                }

                // Delete the data - this needs to be a free because of strdup
                free(pak->data);
                // Delete the packet
                delete pak;
            }

            string chtxt;

            if (FD_ISSET(packet_sources[src]->childpair[1], &rset)) {
                // Capture the packet from whatever device
                // len = psrc->FetchPacket(&packet, data, moddata);

                ret = FetchChildBlock(packet_sources[src]->childpair[1], &packet, data, moddata, &chtxt);

                if (ret == CAPPACK_CMDACK) {
                    packet_sources[src]->cmd_ack = 1;
                    if (data[0] > 0)
                        packet_sources[src]->cur_ch = data[0];
                } else if (ret == CAPPACK_TEXT && chtxt != "") {
                    if (!silent)
                        fprintf(stderr, "%s\n", chtxt.c_str());
                    NetWriteStatus(chtxt.c_str());
                } else if (ret == CAPPACK_PACKET && packet.len > 0) {
                    // Handle a packet
                    packnum++;

                    // Set the channel
                    packet_sources[src]->cur_ch = packet.channel;

                    static packet_info info;

                    GetPacketInfo(&packet, &packet_sources[src]->packparm, &info,
                                  &bssid_wep_map, wep_identity);

                    last_info = info;

                    // Discard it if we're filtering it at the tracker level
                    if (filter_tracker == 1) {
                        int filter_packet = 0;

                        // Look for the attributes of the packet for each filter address
                        // type.  If filtering is inverted, then lack of a match means
                        // allow the packet
                        macmap<int>::iterator fitr = filter_tracker_bssid.find(info.bssid_mac);
                        // In the list and we've got inverted filtering - kill it
                        if (fitr != filter_tracker_bssid.end() &&
                            filter_tracker_bssid_invert == 1)
                            filter_packet = 1;
                        // Not in the list and we've got normal filtering - kill it
                        if (fitr == filter_tracker_bssid.end() &&
                            filter_tracker_bssid_invert == 0)
                            filter_packet = 1;

                        // And continue for the others
                        fitr = filter_tracker_source.find(info.source_mac);
                        if (fitr != filter_tracker_source.end() &&
                            filter_tracker_source_invert == 1)
                            filter_packet = 1;
                        if (fitr == filter_tracker_source.end() &&
                            filter_tracker_source_invert == 0)
                            filter_packet = 1;

                        fitr = filter_tracker_dest.find(info.dest_mac);
                        if (fitr != filter_tracker_dest.end() &&
                            filter_tracker_dest_invert == 1)
                            filter_packet = 1;
                        if (fitr == filter_tracker_dest.end() &&
                            filter_tracker_dest_invert == 0)
                            filter_packet = 1;

                        if (filter_packet == 1) {
                            localdropnum++;

                            // This is bad.
                            goto end_packprocess;
                        }

                    }

#ifdef HAVE_GPS
                    if (gps_log == 1 && info.type != packet_noise && info.type != packet_unknown &&
                        info.type != packet_phy && info.corrupt == 0) {
                        if (gpsdump.DumpPacket(&info) < 0) {
                            snprintf(status, STATUS_MAX, "%s", gpsdump.FetchError());
                            if (!silent)
                                fprintf(stderr, "%s\n", status);

                            NetWriteStatus(status);
                        }
                    }
#endif

                    tracker.ProcessPacket(info);

                    if (tracker.FetchNumNetworks() > num_networks) {
                        if (sound == 1)
                            sound = PlaySound("new");
                    }

                    if (tracker.FetchNumNetworks() > num_networks && speech == 1) {
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

                    if (fifo)
                        fifodump.DumpPacket(&info, &packet);

                    if (data_log && !(info.type == packet_noise && noise_log == 1) &&
                        !(info.corrupt != 0 && corrupt_log == 1)) {
                        if (limit_logs && log_packnum > limit_logs) {
                            dumpfile->CloseDump();

                            dumplogfile = ConfigFile::ExpandLogPath(logtemplate, logname, "dump", 0);

                            if (dumpfile->OpenDump(dumplogfile.c_str()) < 0) {
                                perror("Unable to open new dump file");
                                CatchShutdown(-1);
                            }

                            dumpfile->SetBeaconLog(beacon_log);
                            dumpfile->SetPhyLog(phy_log);
                            dumpfile->SetMangleLog(mangle_log);

                            snprintf(status, STATUS_MAX, "Opened new packet log file %s",
                                     dumplogfile.c_str());

                            if (!silent)
                                fprintf(stderr, "%s\n", status);

                            NetWriteStatus(status);
                        }

                        int log_packet = 1;

                        if (filter_dump == 1) {
                            macmap<int>::iterator fitr = filter_dump_bssid.find(info.bssid_mac);
                            // In the list and we've got inverted filtering - kill it
                            if (fitr != filter_dump_bssid.end() &&
                                filter_dump_bssid_invert == 1)
                                log_packet = 0;
                            // Not in the list and we've got normal filtering - kill it
                            if (fitr == filter_dump_bssid.end() &&
                                filter_dump_bssid_invert == 0)
                                log_packet = 0;

                            // And continue for the others
                            fitr = filter_dump_source.find(info.source_mac);
                            if (fitr != filter_dump_source.end() &&
                                filter_dump_source_invert == 1)
                                log_packet = 0;
                            if (fitr == filter_dump_source.end() &&
                                filter_dump_source_invert == 0)
                                log_packet = 0;

                            fitr = filter_dump_dest.find(info.dest_mac);
                            if (fitr != filter_dump_dest.end() &&
                                filter_dump_dest_invert == 1)
                                log_packet = 0;
                            if (fitr == filter_dump_dest.end() &&
                                filter_dump_dest_invert == 0)
                                log_packet = 0;
                        }

                        if (log_packet == 1) {
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
                    }

                    if (crypt_log) {
                        cryptfile->DumpPacket(&info, &packet);
                    }

                } else if (ret < 0) {
                    // Fail on error
                    if (!silent) {
                        fprintf(stderr, "%s\n", chtxt.c_str());
                        fprintf(stderr, "Terminating.\n");
                    }

                    NetWriteStatus(chtxt.c_str());

                    CatchShutdown(-1);
                }
            } // End processing new packets

        end_packprocess: ;

        }

        timetracker.Tick();

        // Sleep if we have a custom additional sleep time
        if (sleepu > 0)
            usleep(sleepu);
    }

    CatchShutdown(-1);
}
