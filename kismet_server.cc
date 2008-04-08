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

#ifdef HAVE_DBUS
#include <dbus/dbus.h>
#endif

#ifdef HAVE_HILDON
#include <gpsbt.h>
#endif

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
#include "packetsourcetracker.h"
#include "kis_packsources.h"

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
const char *pid_base = "kismet_server.pid";

// Some globals for command line options
char *configfile = NULL;
int no_log = 0, noise_log = 0, data_log = 0, net_log = 0, crypt_log = 0, cisco_log = 0,
    gps_log = -1, gps_enable = 1, csv_log = 0, xml_log = 0, ssid_cloak_track = 0, 
    ip_track = 0, waypoint = 0, waypointformat = 0, fifo = 0, corrupt_log = 0;
int vap_destroy = 0, netmanager_control = 0, track_ivs = 0;
string logname, dumplogfile, netlogfile, cryptlogfile, ciscologfile,
    gpslogfile, csvlogfile, xmllogfile, ssidtrackfile, configdir, iptrackfile, 
    waypointfile, fifofile;
FILE *ssid_file = NULL, *ip_file = NULL, *waypoint_file = NULL, *pid_file = NULL;

#ifdef HAVE_HILDON
gpsbt_t gpsbt_ctx = {0};
#endif

DumpFile *dumpfile, *cryptfile;
int packnum = 0, localdropnum = 0;

Packetsourcetracker sourcetracker;
Packetracker tracker;
Alertracker alertracker;
Timetracker timetracker;

GPSD *gps = NULL;
int gpsmode = 0;
GPSDump gpsdump;

// Last time we tried to reconnect to the gps
time_t last_gpsd_reconnect = 0;
int gpsd_reconnect_attempt = 0;

FifoDumpFile fifodump;
TcpServer ui_server;
int sound = -1;
packet_info last_info;
int decay;
channel_power channel_graph[CHANNEL_MAX];
char *servername = NULL;

pid_t daemon_parent_pid = 0;

fd_set read_set;

// Do we allow sending wep keys to the client?
int client_wepkey_allowed = 0;
// Wep keys
macmap<wep_key_info *> bssid_wep_map;

// Pipe file descriptor pairs and fd's
int soundpair[2];
int speechpair[2];
int chanpair[2];
pid_t soundpid = -1, speechpid = -1, chanpid = -1;

// Past alerts
unsigned int max_alerts = 50;

// Reference numbers for all of our builtin protocols
int kismet_ref = -1, network_ref = -1, client_ref = -1, gps_ref = -1, 
    time_ref = -1, error_ref = -1, info_ref = -1, cisco_ref = -1, terminate_ref = -1, 
    remove_ref = -1, capability_ref = -1, protocols_ref = -1, status_ref = -1, 
    alert_ref = -1, packet_ref = -1, string_ref = -1, ack_ref = -1, wepkey_ref = -1, 
    card_ref = -1;

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
	alert_time_unit burst_unit;
    int limit_rate;
    int limit_burst;
};

// More config-driven globals
const char *logtypes = NULL, *dumptype = NULL;
int limit_logs = 0;
int log_expiry = 0;
int limit_nets = 0;

char gpshost[1024];
int gpsport = -1;

string allowed_hosts;
string bind_addr;
int tcpport = -1;
int tcpmax;

//const char *sndplay = NULL;
string sndplay;

const char *festival = NULL;
int speech = -1;
int flite = 0;
int darwinsay = 0;
string voice;
int speech_encoding = 0;
string speech_sentence_encrypted, speech_sentence_unencrypted;

map<string, string> wav_map;

int beacon_log = 1;
int phy_log = 1;
int mangle_log = 0;

FILE *manuf_data;
char *client_manuf_name = NULL, *ap_manuf_name = NULL;

vector<_alert_enable> alert_enable_vec;
vector<client_ipblock *> legal_ipblock_vec;
int datainterval = 0;

string logtemplate;

int channel_hop;
int retain_monitor;

// More globals!  Sure!  Why not!  This will all go away in newcore anyhow
// Do we use the network classifier to determine if a data frame should be
// tested as encrypted?
int netcryptdetect = 0;

// Shutdown/restore networkmanager (if we can)
int networkmanager_control(char *cmd) {
#ifdef HAVE_DBUS
	DBusMessage* msg;
	DBusConnection* conn;
	DBusError err;

	char *name = "org.freedesktop.NetworkManager";
	char *path = "/org/freedesktop/NetworkManager";

	// initialise the error value
	dbus_error_init(&err);

	// connect to the DBUS system bus, and check for errors
	if ((conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err)) == NULL) {
		fprintf(stderr, "WARNING: Failed to connect to DBUS system, will "
				"not be able to control networkmanager: %s\n", err.message);
		dbus_error_free(&err);
		return -1;
	}

	msg = dbus_message_new_signal(path, name, cmd);

	if (dbus_message_set_destination(msg, name) == 0) {
		fprintf(stderr, "WARNING:  Failed to build DBUS message, will "
				"not be able to control networkmanager.\n");
		dbus_error_free(&err);
		dbus_connection_unref(conn);
		return -1;
	}

	dbus_connection_send(conn, msg, NULL);
	dbus_connection_flush(conn);

	dbus_message_unref(msg);
	dbus_connection_unref(conn);
#endif

	return 1;
}

// Handle writing all the files out and optionally unlinking the empties
void WriteDatafiles(int in_shutdown) {
    // If we're on our way out make one last write of the network stuff - this
    // has a nice side effect of clearing out any "REMOVE" networks.
    NetWriteInfo();

    if (ssid_cloak_track) {
        if (ssid_file)
            tracker.WriteSSIDMap(ssid_file);

        if (in_shutdown && ssid_file)
            fclose(ssid_file);
    }

    if (ip_track) {
        if (ip_file)
            tracker.WriteIPMap(ip_file);

        if (in_shutdown && ip_file)
            fclose(ip_file);
    }

    char alert[2048];

    if (log_expiry)
        tracker.ExpireNetworks(log_expiry);

    if (net_log) {
        if (tracker.WriteNetworks(netlogfile) == -1) {
            snprintf(alert, 2048, "WARNING: %s", tracker.FetchError());
            alertracker.RaiseAlert(kissrv_aref, mac_addr(0), mac_addr(0), 
                                   mac_addr(0), mac_addr(0), 0, alert);
            //NetWriteAlert(alert);
            if (!silent)
                fprintf(stderr, "%s\n", alert);
        }
    }

    if (csv_log) {
        if (tracker.WriteCSVNetworks(csvlogfile) == -1) {
            snprintf(alert, 2048, "WARNING: %s", tracker.FetchError());
            alertracker.RaiseAlert(kissrv_aref, 0, 0, 0, 0, 0, alert);
            //NetWriteAlert(alert);
            if (!silent)
                fprintf(stderr, "%s\n", alert);
        }
    }

    if (xml_log) {
        if (tracker.WriteXMLNetworks(xmllogfile) == -1) {
            snprintf(alert, 2048, "WARNING: %s", tracker.FetchError());
            alertracker.RaiseAlert(kissrv_aref, mac_addr(0), mac_addr(0),
                                   mac_addr(0), mac_addr(0), 0, alert);
            //NetWriteAlert(alert);
            if (!silent)
                fprintf(stderr, "%s\n", alert);
        }
    }

    if (cisco_log) {
        if (tracker.WriteCisco(ciscologfile) == -1) {
            snprintf(alert, 2048, "WARNING: %s", tracker.FetchError());
            alertracker.RaiseAlert(kissrv_aref, mac_addr(0), mac_addr(0),
                                   mac_addr(0), mac_addr(0), 0, alert);
            //NetWriteAlert(alert);
            if (!silent)
                fprintf(stderr, "%s\n", alert);
        }
    }

    sync();
}

// Quick shutdown to clean up from a fatal config after we opened the child
void ErrorShutdown() {
#ifdef HAVE_HILDON
	// Release hildon gps
	gpsbt_stop(&gpsbt_ctx);
#endif

    // Shut down the packet sources
    sourcetracker.CloseSources();

    // Shut down the channel control child
    sourcetracker.ShutdownChannelChild();


	if (netmanager_control) {
		fprintf(stderr, "Trying to wake networkmanager back up...\n");
		if (networkmanager_control("wake") < 0)
			fprintf(stderr, "WARNING: Failed to send 'wake' command to networkmanager "
					"via DBUS, NM may still be inactive.");
	}

    fprintf(stderr, "Kismet exiting.\n");
    exit(1);
}

// Catch our interrupt
void CatchShutdown(int sig) {
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

    if (gps_log == 1) {
        if (gpsdump.CloseDump(1) < 0)
            fprintf(stderr, "Didn't log any GPS coordinates, unlinking gps file\n");
    }

    // Kill our sound players
    if (soundpid > 0)
        kill(soundpid, 9);
    if (speechpid > 0)
        kill(speechpid, 9);

    // Shut down the packet sources
    sourcetracker.CloseSources();

    // Shut down the channel control child
    sourcetracker.ShutdownChannelChild();

#ifdef HAVE_HILDON
	// Release hildon gps
	gpsbt_stop(&gpsbt_ctx);
#endif

	if (netmanager_control) {
		fprintf(stderr, "Trying to wake networkmanager back up...\n");
		if (networkmanager_control("wake") < 0)
			fprintf(stderr, "WARNING: Failed to send 'wake' command to networkmanager "
					"via DBUS, NM may still be inactive.");
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
                    int nulfd = open("/dev/null", O_RDWR);
                    dup2(nulfd, 1);
                    dup2(nulfd, 2);
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
				char voiceopt[128] = "";

				if (voice != "default") {
					if (darwinsay)
						snprintf(voiceopt, 128, "-v %s",
								 MungeToShell(voice).c_str());
				}

                snprintf(spk_call, 1024, "echo \"(%s\\\"%s\\\")\" | %s %s "
						 ">/dev/null 2>/dev/null",
						 (flite || darwinsay) ? "" : "SayText ", data, 
						 player, voiceopt);
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
    vector<meta_packsource *> packet_sources = sourcetracker.FetchMetaSourceVec();
    for (unsigned int src = 0; src < packet_sources.size(); src++) {
        if (packet_sources[src]->valid == 0)
            continue;

        ui_server.SendToAll(card_ref, (void *) packet_sources[src]);
    }

    static time_t last_write = time(0);
    static int last_packnum = tracker.FetchNumPackets();
    vector<wireless_network *> tracked;
	vector<wireless_network *> rem_tracked;

    int tim = time(0);
    ui_server.SendToAll(time_ref, &tim);

    char tmpstr[32];

    GPS_data gdata;

    if (gps_enable && gps != NULL) {
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

    if (time(0) - last_info.ts.tv_sec < decay && last_info.signal != -1)
        snprintf(tmpstr, 16, "%d %d" , last_info.signal, last_info.noise);
    else if (last_info.quality == -1)
        snprintf(tmpstr, 16, "-1 -1");
    else
        snprintf(tmpstr, 16, "0 0");
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
		// Remove networks always get sent
        if (tracked[x]->type == network_remove) {
            string remstr = tracked[x]->bssid.Mac2String();
            ui_server.SendToAll(remove_ref, (void *) &remstr);

			rem_tracked.push_back(tracked[x]);
            // tracker.RemoveNetwork(tracked[x]->bssid);

            continue;
        }

        // Only send new networks
        if (tracked[x]->last_time < last_write)
            continue;

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

	for (unsigned int x = 0; x < rem_tracked.size(); x++) {
		tracker.RemoveNetwork(rem_tracked[x]->bssid);
	}
}

int NetWriteStatus(const char *in_status) {
    string str = in_status;
    return(ui_server.SendToAll(status_ref, (void *) &str));
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
        if (tracked[x]->type == network_remove) 
            continue;

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
    char status[STATUS_MAX];

    // The GPS only provides us a new update once per second we might
    // as well only update it here once a second
	if (gps_enable == 0 || gps == NULL)
		return 0;

    // If we're disconnected, try to reconnect.
    if (gpsd_reconnect_attempt > 0) {
        // Increment the time between connection attempts
        if (last_gpsd_reconnect + ((gpsd_reconnect_attempt - 1) * 2) < time(0)) {
            if (gps->OpenGPSD() < 0) {
                last_gpsd_reconnect = time(0);

                if (gpsd_reconnect_attempt < 20)
                    gpsd_reconnect_attempt++;

                snprintf(status, STATUS_MAX, "Unable to reconnect to GPSD, trying "
                         "again in %d seconds.", ((gpsd_reconnect_attempt - 1) * 2));

				NetWriteStatus(status);
                if (!silent)
                    fprintf(stderr, "WARNING: %s\n", status);

                return 1;
            } else {
                gpsd_reconnect_attempt = 0;

                snprintf(status, STATUS_MAX, "Reopened connection to GPSD");
				NetWriteStatus(status);
                if (!silent)
                    fprintf(stderr, "NOTICE: %s\n", status);
            }
        } else {
            // Don't process more if we haven't woken up yet
            return 1;
        }

    }
    
    if (gps_enable) {
        int gpsret;
        gpsret = gps->FetchMode();

        if (gpsret < 0) {
            snprintf(status, STATUS_MAX, "GPS error requesting data: %s",
                     gps->FetchError());

			NetWriteStatus(status);
			if (!silent)
                fprintf(stderr, "WARNING: %s\n", status);

            gpsd_reconnect_attempt = 1;
        }

        if (gpsret == 0 && gpsmode != 0) {
			NetWriteStatus("Lost GPS signal.");
			if (!silent)
                fprintf(stderr, "Lost GPS signal.\n");
            if (sound == 1)
                sound = PlaySound("gpslost");

            gpsmode = 0;
        } else if (gpsret > 0 && gpsmode == 0) {
			NetWriteStatus("Acquired GPS signal");
			if (!silent)
                fprintf(stderr, "Acquired GPS signal.\n");
            if (sound == 1)
                sound = PlaySound("gpslock");

            gpsmode = 1;
        }

    }

    if (gps_log == 1 && gpsmode != 0 && gps != NULL) {
        gpsdump.DumpTrack(gps);
    }

    // We want to be rescheduled
    return 1;
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
	NetWriteStatus("Saving data files.");
	if (!silent)
        fprintf(stderr, "Saving data files.\n");

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
    // Just call advancechannel
    sourcetracker.AdvanceChannel();
    
    return 1;
}

// Handle a command sent by a client over its TCP connection.
void handle_command(TcpServer *tcps, client_command *cc) {
    char id[12];
    snprintf(id, 12, "%d ", cc->stamp);
    string out_error = string(id);
    char status[1024];

    vector<string> cmdvec = StrTokenize(cc->cmd, " ");

    if (cmdvec.size() == 0) {
        out_error += "invalid command";
        tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
        return;
    }
    
    string cmdword = cmdvec[0];

    if (cmdword == "CHANLOCK") {
        // Lock a metasource to the specified channel
        // ! 0 CHANLOCK SRC CHAN
        if (cmdvec.size() != 3) {
            out_error += "invalid chanlock request";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        int metanum;
        if (sscanf(cmdvec[1].c_str(), "%d", &metanum) != 1) {
            out_error += "invalid chanlock request";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        int chnum;
        if (sscanf(cmdvec[2].c_str(), "%d", &chnum) != 1) {
            out_error += "invalid chanlock request";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        // See if this meta number even exists...
        meta_packsource *meta;
        if ((meta = sourcetracker.FetchMetaID(metanum)) == NULL) {
            out_error += "invalid chanlock request, unknown meta id";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        // See if the meta can control channel
        if (meta->prototype->channelcon == NULL) {
            out_error += "invalid chanlock request, source cannot change channel";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        // See if the requested channel is in the list of valid channels for this
        // source...
        int chvalid = 0;
        for (unsigned int chi = 0; chi < meta->channels.size(); chi++) {
            if (meta->channels[chi] == chnum) {
                chvalid = 1;
                break;
            }
        }

        if (chvalid == 0) {
            out_error += "invalid chanlock request - illegal channel for this source";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);

            snprintf(status, 1024, "WARNING: %d not in channel list for '%s', not "
                     "locking.", chnum, meta->name.c_str());
			NetWriteStatus(status);
			if (!silent)
                fprintf(stderr, "%s\n", status);

            return;
        }

        // Finally if we're valid, stop the source from hopping and lock it to this
        // channel
        sourcetracker.SetHopping(0, meta);
        sourcetracker.SetChannel(chnum, meta);

        snprintf(status, 1024, "Locking source '%s' to channel %d",
                 meta->name.c_str(), chnum);
		NetWriteStatus(status);
		if (!silent)
            fprintf(stderr, "%s\n", status);
    } else if (cmdword == "CHANHOP") {
        // Lock a metasource to the specified channel
        if (cmdvec.size() != 2) {
            out_error += "invalid chanhop request";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        int metanum;
        if (sscanf(cmdvec[1].c_str(), "%d", &metanum) != 1) {
            out_error += "invalid chanhop request";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        // See if this meta number even exists...
        meta_packsource *meta;
        if ((meta = sourcetracker.FetchMetaID(metanum)) == NULL) {
            out_error += "invalid chanhop request, unknown meta id";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        // See if the meta can control channel
        if (meta->prototype->channelcon == NULL) {
            out_error += "invalid chanlock request, source cannot change channel";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        // Set it to hopping.  We con't care if Kismet thinks its hopping or not,
        // we're just saying this source is ALLOWED to hop again.
        sourcetracker.SetHopping(1, meta);

        snprintf(status, 1024, "Allowing source '%s' to hop channels",
                 meta->name.c_str());
		NetWriteStatus(status);
		if (!silent)
            fprintf(stderr, "%s\n", status);

    } else if (cmdword == "PAUSE") {
        sourcetracker.PauseSources();

        snprintf(status, 1024, "Pausing packet sources per request of client %d", 
                 cc->client_fd);
		NetWriteStatus(status);
		if (!silent)
            fprintf(stderr, "%s\n", status);
    } else if (cmdword == "RESUME") {
        sourcetracker.ResumeSources();

        snprintf(status, 1024, "Resuming packet sources per request of client %d", 
                 cc->client_fd);
		NetWriteStatus(status);
		if (!silent)
            fprintf(stderr, "%s\n", status);
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
        if (cmdvec.size() < 2) {
            out_error += "Invalid ADDWEPKEY";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        vector<string> keyvec = StrTokenize(cmdvec[1], ",");
        if (keyvec.size() != 2) {
            out_error += "Invalid ADDWEPKEY";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        wep_key_info *winfo = new wep_key_info;
        winfo->fragile = 1;
        winfo->bssid = keyvec[0].c_str();

        if (winfo->bssid.error) {
            out_error += "Invalid ADDWEPKEY bssid";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        unsigned char key[WEPKEY_MAX];
        int len = Hex2UChar((unsigned char *) keyvec[1].c_str(), key);

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
        if (cmdvec.size() != 2) {
            out_error += "Invalid DELWEPKEY bssid";
            tcps->SendToClient(cc->client_fd, error_ref, (void *) &out_error);
            return;
        }

        mac_addr bssid_mac = cmdvec[1].c_str();

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

        snprintf(status, 1024, "Deleted key for BSSID %s", 
                 bssid_mac.Mac2String().c_str());
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
           "  -b, --bind-address <address>    Bind to this address. Default INADDR_ANY\n"
		   "  -r, --retain-monitor         Leave card in monitor mode on exit\n"
           "  -s, --silent                 Don't send any output to console.\n"
           "  -N, --server-name            Server name\n"
		   "      --daemonize              Background server in daemon mode\n"
           "  -v, --version                Kismet version\n"
           "  -h, --help                   What do you think you're reading?\n");
    exit(1);
}

// Split up a rate/unit string into real values
int ParseAlertRateUnit(string in_ru, alert_time_unit *ret_unit,
					   int *ret_rate) {
	vector<string> units = StrTokenize(in_ru, "/");

	if (units.size() == 1) {
		// Unit is per minute if not specified
		(*ret_unit) = sat_minute;
	} else {
		// Parse the string unit
		if (units[1] == "sec" || units[1] == "second") {
			(*ret_unit) = sat_second;
		} else if (units[1] == "min" || units[1] == "minute") {
			(*ret_unit) = sat_minute;
		} else if (units[1] == "hr" || units[1] == "hour") { 
			(*ret_unit) = sat_hour;
		} else if (units[1] == "day") {
			(*ret_unit) = sat_day;
		} else {
			fprintf(stderr, "Invalid time unit for alert rate '%s'\n",
					units[1].c_str());
			return -1;
		}
	}

	// Get the number
	if (sscanf(units[0].c_str(), "%d", ret_rate) != 1) {
		fprintf(stderr, "Invalid rate '%s' for alert\n", units[0].c_str());
		return -1;
	}

	return 1;
}

// Moved here to make compiling this file take less memory.  Can be broken down more
// in the future.
int ProcessBulkConf(ConfigFile *conf) {
	if (conf->FetchOpt("networkmanagersleep") == "true") {
		netmanager_control = 1;
		fprintf(stderr, "Will attempt to put networkmanager to sleep...\n");
	} 

    // Convert the WEP mappings to our real map
    vector<string> raw_wepmap_vec;
    raw_wepmap_vec = conf->FetchOptVec("wepkey");
    for (size_t rwvi = 0; rwvi < raw_wepmap_vec.size(); rwvi++) {
        string wepline = raw_wepmap_vec[rwvi];

        size_t rwsplit = wepline.find(",");
        if (rwsplit == string::npos) {
            fprintf(stderr, "FATAL:  Malformed 'wepkey' option in the config file.\n");
            ErrorShutdown();
        }

        mac_addr bssid_mac = wepline.substr(0, rwsplit).c_str();

        if (bssid_mac.error == 1) {
            fprintf(stderr, "FATAL:  Malformed 'wepkey' option in the config file.\n");
            ErrorShutdown();
        }

        string rawkey = wepline.substr(rwsplit + 1, wepline.length() - (rwsplit + 1));

        unsigned char key[WEPKEY_MAX];
        int len = Hex2UChar((unsigned char *) rawkey.c_str(), key);

        if (len != 5 && len != 13 && len != 16) {
            fprintf(stderr, "FATAL:  Invalid key '%s' length %d in a wepkey option "
                    "in the config file.\n",
                    rawkey.c_str(), len);
            ErrorShutdown();
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
        ErrorShutdown();
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


    if (conf->FetchOpt("waypoints") == "true") {
        if(conf->FetchOpt("waypointdata") == "") {
            fprintf(stderr, "WARNING:  Waypoint logging requested but no waypoint data file given.\n"
                    "Waypoint logging will be disabled.\n");
            waypoint = 0;
        } else {
            waypointfile = conf->ExpandLogPath(conf->FetchOpt("waypointdata"), "", "", 0, 1);
            waypoint = 1;
        }
        if(conf->FetchOpt("waypoint_essid") == "true") {
            waypointformat = 1;
        } else {
	    waypointformat = 0;
        }
    }

    if (conf->FetchOpt("metric") == "true") {
        fprintf(stderr, "Using metric measurements.\n");
        metric = 1;
    }

    if (conf->FetchOpt("fifo") != "") {
        fifofile = conf->FetchOpt("fifo");
        fifo = 1;
    }

    if (!no_log) {
        if (logname == "") {
            if (conf->FetchOpt("logdefault") == "") {
                fprintf(stderr, "FATAL:  No default log name in config and no log name provided on the command line.\n");
                ErrorShutdown();
            }
            logname = strdup(conf->FetchOpt("logdefault").c_str());
        }

        if (logtypes == NULL) {
            if (conf->FetchOpt("logtypes") == "") {
                fprintf(stderr, "FATAL:  No log types in config and none provided on the command line.\n");
                ErrorShutdown();
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
                ErrorShutdown();
            }

            if (conf->FetchOpt("dumplimit") != "" || limit_logs != 0) {
                if (limit_logs == 0)
                    if (sscanf(conf->FetchOpt("dumplimit").c_str(), "%d", &limit_logs) != 1) {
                        fprintf(stderr, "FATAL:  Illegal config file value for dumplimit.\n");
                        ErrorShutdown();
                    }

                if (limit_logs != 0)
                    fprintf(stderr, "Limiting dumpfile to %d packets each.\n",
                            limit_logs);
            }

            if (conf->FetchOpt("dumptype") == "" && dumptype == NULL) {
                fprintf(stderr, "FATAL: Dump file logging requested but no dump type given.\n");
                ErrorShutdown();
            }

            if (conf->FetchOpt("dumptype") != "" && dumptype == NULL)
                dumptype = strdup(conf->FetchOpt("dumptype").c_str());

            if (!strcasecmp(dumptype, "wiretap")) {
                dumpfile = new WtapDumpFile;
            } else {
                fprintf(stderr, "FATAL:  Unknown dump file type '%s'\n", dumptype);
                ErrorShutdown();
            }
        }

        if (strstr(logtypes, "network")) {
            net_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  Logging (network list) enabled but no logtemplate given in config.\n");
                ErrorShutdown();
            }

        }

        if (strstr(logtypes, "weak")) {
            crypt_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  Logging (weak packets) enabled but no logtemplate given in config.\n");
                ErrorShutdown();
            }

        }

        if (strstr(logtypes, "csv")) {
            csv_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  CSV Logging (network list) enabled but no logtemplate given in config.\n");
                ErrorShutdown();
            }

        }

        if (strstr(logtypes, "xml")) {
            xml_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL:  XML Logging (network list) enabled but no logtemplate given in config.\n");
                ErrorShutdown();
            }
        }

        if (strstr(logtypes, "cisco")) {
            cisco_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                fprintf(stderr, "FATAL: Logging (cisco packets) enabled but no logtemplate given in config.\n");
                ErrorShutdown();
            }

        }

        if (strstr(logtypes, "gps")) {
            if (gps_log == 0) {
                fprintf(stderr, "WARNING:  Disabling GPS logging.\n");
            } else {
                gps_log = 1;

                if (conf->FetchOpt("logtemplate") == "") {
                    fprintf(stderr, "FATAL:  Logging (gps coordinates) enabled but no logtemplate given in config.\n");
                    ErrorShutdown();
                }
            }

        }

        if (gps_log == 1 && !xml_log) {
            fprintf(stderr, "WARNING:  Logging (gps coordinates) enabled but XML logging (networks) was not.\n"
                    "It will be enabled now.\n");
            xml_log = 1;
        }
    }

    if (conf->FetchOpt("decay") != "") {
        if (sscanf(conf->FetchOpt("decay").c_str(), "%d", &decay) != 1) {
            fprintf(stderr, "FATAL:  Illegal config file value for decay.\n");
            ErrorShutdown();
        }
    }

    if (conf->FetchOpt("alertbacklog") != "") {
        int scantmp;
        if (sscanf(conf->FetchOpt("alertbacklog").c_str(), "%d", &scantmp) != 1 ||
            scantmp < 0) {
            fprintf(stderr, "FATAL:  Illegal config file value for alert backlog.\n");
            ErrorShutdown();
        }
        max_alerts = scantmp;
    }

    if (tcpport == -1) {
        if (conf->FetchOpt("tcpport") == "") {
            fprintf(stderr, "FATAL:  No tcp port given to listen for GUI connections.\n");
            exit(1);
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

    vector<string> hostsvec = StrTokenize(allowed_hosts, ",");

    for (size_t hostcomp = 0; hostcomp < hostsvec.size(); hostcomp++) {
        client_ipblock *ipb = new client_ipblock;
        string hoststr = hostsvec[hostcomp];

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

    // Process sound stuff
    if (conf->FetchOpt("sound") == "true" && sound == -1) {
        if (conf->FetchOpt("soundplay") != "") {
            sndplay = conf->FetchOpt("soundplay");

            if (conf->FetchOpt("soundopts") != "")
                sndplay += " " + conf->FetchOpt("soundopts");

            sound = 1;

            if (conf->FetchOpt("sound_new") != "")
                wav_map["new"] = conf->FetchOpt("sound_new");
            if (conf->FetchOpt("sound_new_wep") != "")
                wav_map["new_wep"] = conf->FetchOpt("sound_new_wep");
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
		
			if (conf->FetchOpt("flite") == "true")
				flite = 1;

#ifdef SYS_DARWIN
			if (conf->FetchOpt("darwinsay") == "true") {
				festival = strdup("/usr/bin/say");
				darwinsay = 1;
			}
#endif

			voice = conf->FetchOpt("speech_voice");

			if (voice == "")
				voice = "default";

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
            ErrorShutdown();
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
    string filter_bit;

    if ((filter_bit = conf->FetchOpt("filter_tracker")) != "") {
        fprintf(stderr, "Enabling tracker filtering.\n");
        filter_tracker = 1;
        if (ConfigFile::ParseFilterLine(filter_bit, &filter_tracker_bssid, &filter_tracker_source,
                                        &filter_tracker_dest, &filter_tracker_bssid_invert,
                                        &filter_tracker_source_invert,
                                        &filter_tracker_dest_invert) < 0)
            ErrorShutdown();
    }


    if ((filter_bit = conf->FetchOpt("filter_dump")) != "") {
        fprintf(stderr, "Enabling filtering on dump files.\n");
        filter_dump = 1;
        if (ConfigFile::ParseFilterLine(filter_bit, &filter_dump_bssid, &filter_dump_source,
                                        &filter_dump_dest, &filter_dump_bssid_invert,
                                        &filter_dump_source_invert,
                                        &filter_dump_dest_invert) < 0)
            ErrorShutdown();
    }

    if ((filter_bit = conf->FetchOpt("filter_export")) != "") {
        fprintf(stderr, "Enabling filtering on exported (csv, xml, network, gps) files.\n");
        filter_export = 1;
        if (ConfigFile::ParseFilterLine(filter_bit, &filter_export_bssid, &filter_export_source,
                                        &filter_export_dest, &filter_export_bssid_invert,
                                        &filter_export_source_invert,
                                        &filter_export_dest_invert) < 0)
            ErrorShutdown();
    }

    // Parse the alert enables.  This is ugly, and maybe should belong in the
    // configfile class with some of the other parsing code.
    for (unsigned int av = 0; av < conf->FetchOptVec("alert").size(); av++) {
        vector<string> tokens = StrTokenize(conf->FetchOptVec("alert")[av], ",");
        _alert_enable aven;

		if (tokens.size() != 3) {
			fprintf(stderr, "FATAL: Malformed limits for alert '%s'\n", 
					conf->FetchOptVec("alert")[av].c_str());
			ErrorShutdown();
		}

		aven.alert_name = StrLower(tokens[0]);

		if (ParseAlertRateUnit(StrLower(tokens[1]), 
							   &(aven.limit_unit), &(aven.limit_rate)) != 1 ||
			ParseAlertRateUnit(StrLower(tokens[2]),
							   &(aven.burst_unit), &(aven.limit_burst)) != 1) { 
			fprintf(stderr, "FATAL: Malformed limits for alert '%s'\n",
					conf->FetchOptVec("alert")[av].c_str());
			ErrorShutdown();
		}

		if (aven.burst_unit > aven.limit_unit) {
			fprintf(stderr, "FATAL: Alert burst time unit must be <= alert "
					"limit time unit for alert '%s'\n",
					conf->FetchOptVec("alert")[av].c_str());
			ErrorShutdown();
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
            ErrorShutdown();
        }
    } else if (! S_ISDIR(fstat.st_mode)) {
        fprintf(stderr, "FATAL: configdir '%s' exists but is not a directory.\n",
                configdir.c_str());
        ErrorShutdown();
    }

    if (ssid_cloak_track) {
        if (stat(ssidtrackfile.c_str(), &fstat) == -1) {
            fprintf(stderr, "SSID cloak file did not exist, it will be created.\n");
        } else {
            if ((ssid_file = fopen(ssidtrackfile.c_str(), "r")) == NULL) {
                fprintf(stderr, "FATAL: Could not open SSID track file '%s': %s\n",
                        ssidtrackfile.c_str(), strerror(errno));
                ErrorShutdown();
            }

            tracker.ReadSSIDMap(ssid_file);

            fclose(ssid_file);

        }

        if ((ssid_file = fopen(ssidtrackfile.c_str(), "a")) == NULL) {
            fprintf(stderr, "FATAL: Could not open SSID track file '%s' for writing: %s\n",
                    ssidtrackfile.c_str(), strerror(errno));
            ErrorShutdown();
        }

    }

    if (ip_track) {
        if (stat(iptrackfile.c_str(), &fstat) == -1) {
            fprintf(stderr, "IP track file did not exist, it will be created.\n");

        } else {
            if ((ip_file = fopen(iptrackfile.c_str(), "r")) == NULL) {
                fprintf(stderr, "FATAL: Could not open IP track file '%s': %s\n",
                        iptrackfile.c_str(), strerror(errno));
                ErrorShutdown();
            }

            tracker.ReadIPMap(ip_file);

            fclose(ip_file);
        }

        if ((ip_file = fopen(iptrackfile.c_str(), "a")) == NULL) {
            fprintf(stderr, "FATAL: Could not open IP track file '%s' for writing: %s\n",
                    iptrackfile.c_str(), strerror(errno));
            ErrorShutdown();
        }

    }

    if (waypoint) {
        if ((waypoint_file = fopen(waypointfile.c_str(), "a")) == NULL) {
            fprintf(stderr, "WARNING:  Could not open waypoint file '%s' for writing: %s\n",
                    waypointfile.c_str(), strerror(errno));
            waypoint = 0;
        }
    }

    // Create all the logs and title/number them appropriately
    // We need to save this for after we toast the conf record
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

        if (gps_log == 1) {
            gpslogfile = conf->ExpandLogPath(conf->FetchOpt("logtemplate"), logname, "gps", run_num);

            if (gpslogfile == "")
                continue;
        }

        // if we made it this far we're cool -- all the logfiles we're writing to matched
        // this number
        logfile_matched = 1;
        break;
    }

    if (logfile_matched == 0) {
        fprintf(stderr, "ERROR:  Unable to find room for logging files within 100 counts.  If you really are\n"
                "        logging this many times in 1 day, change log title or edit the source.\n");
        ErrorShutdown();
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

    if (gps_log == 1)
        fprintf(stderr, "Logging gps coordinates to %s\n", gpslogfile.c_str());

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

    if (conf->FetchOpt("trackprobenets") == "false") {
        track_probenets = 0;
        fprintf(stderr, "Not tracking probe responses or associating probe networks.\n");
    } else {
        track_probenets = 1;
        fprintf(stderr, "Tracking probe responses and associating probe networks.\n");
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

	if (conf->FetchOpt("logexpiry") != "" || log_expiry != 0) {
		if (log_expiry == 0)
			if (sscanf(conf->FetchOpt("logexpiry").c_str(), "%d", &log_expiry) != 1) {
				fprintf(stderr, "FATAL:  Illegal config file value for logexpiry.\n");
				ErrorShutdown();
			}

		if (log_expiry != 0)
			fprintf(stderr, "Expiring log entries after %d seconds.\n",
					log_expiry);
	}

	if (conf->FetchOpt("limitnets") != "" || limit_nets != 0) {
		if (limit_nets == 0)
			if (sscanf(conf->FetchOpt("limitnets").c_str(), "%d", &limit_nets) != 1) {
				fprintf(stderr, "FATAL:  Illegal config file value for limitnets.\n");
				ErrorShutdown();
			}

		if (limit_nets != 0)
			fprintf(stderr, "Limiting network number to %d.\n",
					limit_nets);
	}

    if (filter_export)
        tracker.AddExportFilters(&filter_export_bssid, &filter_export_source, 
                                 &filter_export_dest, &filter_export_bssid_invert, 
                                 &filter_export_source_invert,
                                 &filter_export_dest_invert);

    // Push the packparms into each source...
    packet_parm optparms;

	// Set the fuzzy options
    optparms.fuzzy_crypt = 1;
	optparms.fuzzy_decode = -1;

    sourcetracker.SetTypeParms(conf->FetchOpt("fuzzycrypt"), optparms);

	// Set the fuzzy decode to be forgiving on FCS
    optparms.fuzzy_crypt = -1;
	optparms.fuzzy_decode = 1;

    sourcetracker.SetTypeParms(conf->FetchOpt("fuzzydecode"), optparms);

	// Fetch the netcryptdetect value
	if (conf->FetchOpt("netfuzzycrypt") == "true") {
		fprintf(stderr, "Using network-classifier based data encryption detection\n");
		netcryptdetect = 1;
	}

	// Do we track dupe IVs?
	if (conf->FetchOpt("trackivs") == "true") {
		fprintf(stderr, "Tracking IVs for duplicates (may use large amounts of RAM)\n");
		track_ivs = 1;
	} else {
		fprintf(stderr, "Not tracking duplicate IVs\n");
		track_ivs = 0;
	}

    return 1;
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
    char status[STATUS_MAX];

    start_time = time(0);

    unsigned char wep_identity[256];

    // Initialize the identity field
    for (unsigned int wi = 0; wi < 256; wi++)
        wep_identity[wi] = wi;

    channel_hop = -1;
	retain_monitor = 0;
    int channel_velocity = 1;
    int channel_dwell = 0;
    int channel_split = 0;

    // Default channels
    vector<string> defaultchannel_vec;
    // Initial channels for each source
    vector<string> src_initchannel_vec;
    // Custom channel lists for sources
    vector<string> src_customchannel_vec;

    // For commandline and file sources
    string named_sources;
    vector<string> source_input_vec;
    int source_from_cmd = 0;

    silent = 0;
    metric = 0;
    track_probenets = 0;

	// Daemonize?
	int daemonize = 0;

    time_t last_click = 0;
    int num_networks = 0, num_packets = 0, num_noise = 0, num_dropped = 0;

    FILE *testfile = NULL;

    int old_chhop = channel_hop;

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
        { "bind-address", required_argument, 0, 'b'},
        { "server-name", required_argument, 0, 'N' },
        { "help", no_argument, 0, 'h' },
        { "version", no_argument, 0, 'v' },
        { "silent", no_argument, 0, 's' },
        { "initial-channel", required_argument, 0, 'I' },
        { "force-channel-hop", no_argument, 0, 'x' },
        { "force-no-channel-hop", no_argument, 0, 'X' },
		{ "retain-monitor", no_argument, 0, 'r' },
		{ "daemonize", no_argument, 0, 200 },
        // No this isn't documented, and no, you shouldn't be screwing with it
        { "microsleep", required_argument, 0, 'M' },
        { 0, 0, 0, 0 }
    };
    int option_index;
    decay = 5;

    // Catch the interrupt handler to shut down
    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGQUIT, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGPIPE, SIG_IGN);

    while(1) {
        int r = getopt_long(argc, argv, "d:M:t:nf:c:C:l:m:g:a:b:p:N:I:xXqhvsr",
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
            logname = string(optarg);
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
            named_sources = string(optarg);
            fprintf(stderr, "Using specified capture sources: %s\n", 
                    named_sources.c_str());
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
            else if (sscanf(optarg, "%1023[^:]:%d", gpshost, &gpsport) < 2) {
                fprintf(stderr, "Invalid GPS host '%s' (host:port or off required)\n",
                       optarg);
                gps_enable = 1;
                Usage(argv[0]);
            }
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
            // bind address
            bind_addr = string(optarg);
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
            fprintf(stderr, "Kismet %s.%s.%s\n", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY);
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
		case 'r':
			retain_monitor = 1;
			fprintf(stderr, "Retaining monitor mode on exit\n");
			break;
        case 'I':
            // Initial channel
            src_initchannel_vec.push_back(optarg);
            break;
		case 200:
			// Daemonize
			fprintf(stderr, "Backgrounding to daemon mode after startup\n");
			daemonize = 1;
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
    gid_t suid_gid;

    real_uid = getuid();

    if (conf->FetchOpt("suiduser") != "") {
        suid_user = strdup(conf->FetchOpt("suiduser").c_str());
        if ((pwordent = getpwnam(suid_user)) == NULL) {
            fprintf(stderr, "FATAL:  Could not find user '%s' for dropping "
                    "priviledges.  Make sure you have a valid user set for 'suiduser' "
                    "in your config file.  See the 'Installation & Security' and "
                    "'Configuration' sections of the README file for more "
                    "information.\n", suid_user);
            exit(1);
        } else {
            suid_id = pwordent->pw_uid;
            suid_gid = pwordent->pw_gid;

            if (suid_id == 0) {
                // If we're suiding to root...
                fprintf(stderr, "FATAL:  Specifying a uid-0 user for the priv drop "
                        "is pointless.  See the 'Installation & Security' and "
                        "'Configuration' sections of the README file for more "
                        "information.\n");
                exit(1);
            } else if (suid_id != real_uid && real_uid != 0) {
                // If we're not running as root (ie, we've suid'd to root)
                // and if we're not switching to the user that ran us
                // then we don't like it and we bail.
                fprintf(stderr, "FATAL:  kismet_server must be started as root or "
                        "as the suid-target user.\n");
                exit(1);
            }


            fprintf(stderr, "Will drop privs to %s (%d) gid %d\n", suid_user, 
                    suid_id, suid_gid);
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

    if (conf->FetchOpt("macfilter") != "") {
        fprintf(stderr, "FATAL:  Your config file uses the old filtering configuration "
                "settings.  You need to install the latest configuration files.  See "
                "the troubleshooting section of the README for more information.\n");
        exit(1);
    }
       
    // Try to open the pidfile
    string pidfpath;
    if ((pidfpath = conf->FetchOpt("piddir")) == "") {
        fprintf(stderr, "FATAL:  Your config file does not define a 'piddir' setting. "
                "You need to install the latest configuration files.  See the "
                "troubleshooting section of the README for more information.\n");
        exit(1);
    }

    pidfpath += string("/") + pid_base;

    if (unlink(pidfpath.c_str()) < 0 && errno != ENOENT) {
        fprintf(stderr, "FATAL:  Unable to set up pidfile %s, unlink() failed: %s\n",
                pidfpath.c_str(), strerror(errno));
        exit(1);
    }

    if ((pid_file = fopen(pidfpath.c_str(), "w")) == NULL) {
        fprintf(stderr, "FATAL:  Unable to set up pidfile %s, couldn't open for "
                "writing: %s", pidfpath.c_str(), strerror(errno));
        exit(1);
    }

	// Fork off daemon mode and do all the work in the child, write the pid and
	// do nothing else in the parent.  Yes, goto sucks.  Goto: go away
	if (daemonize) {
		daemon_parent_pid = getpid();
		if (fork() != 0)
			goto daemon_parent_cleanup;
	}

	// Deferred writing of pid until now
	fprintf(pid_file, "%d\n", getpid());
	// And we're done
	fclose(pid_file);

    // Set up the GPS object to give to the children
    if (gpsport == -1 && gps_enable) {
        if (conf->FetchOpt("gps") == "true") {
            if (sscanf(conf->FetchOpt("gpshost").c_str(), "%1023[^:]:%d", gpshost, 
                       &gpsport) != 2) {
                fprintf(stderr, "Invalid GPS host in config (host:port required)\n");
                exit(1);
            }

            gps_enable = 1;
        } else {
            gps_enable = 0;
            gps_log = 0;
        }
    }

    if (gps_enable) {
        gps = new GPSD(gpshost, gpsport);

        // Lock GPS position
        if (conf->FetchOpt("gpsmodelock") == "true") {
            fprintf(stderr, "Enabling GPS position lock override (broken GPS unit "
                    "reports 0 always)\n");
            gps->SetOptions(GPSD_OPT_FORCEMODE);
        }

#ifdef HAVE_HILDON
		fprintf(stderr, "Waiting for Hildon gps to enable...\n");
		if (gpsbt_start(NULL, 0, 0, 0 /* default port */, 
						status, STATUS_MAX, 
						0, &gpsbt_ctx) < 0) {
			printf("Hildon BT failed: %s\n", status);
		}
		sleep(1);
#endif

    } else {
        gps_log = 0;
    }

    // Register the gps and timetracker with the sourcetracker
    sourcetracker.AddGpstracker(gps);
    sourcetracker.AddTimetracker(&timetracker);

    // Handle errors here maybe in the future
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

	if (conf->FetchOpt("vapdestroy") == "true") {
		vap_destroy = 1;
		fprintf(stderr, "Non-RFMon VAPs will be destroyed on multi-vap interfaces "
				"(ie, madwifi-ng)\n");
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
    if (setgid(suid_gid) < 0) {
        fprintf(stderr, "FATAL:  setgid() to %d failed.\n", suid_gid);
        exit(1);
    }

    if (setuid(suid_id) < 0) {
        fprintf(stderr, "FATAL:  setuid() to %s (%d) failed.\n", suid_user, suid_id);
        exit(1);
    } 

    fprintf(stderr, "Dropped privs to %s (%d) gid %d\n", suid_user, suid_id, suid_gid);
#endif

    // WE ARE NOW RUNNING AS THE TARGET UID

    // Bind the user sources
    if (sourcetracker.BindSources(0) < 0) {
        fprintf(stderr, "FATAL: %s\n", sourcetracker.FetchError());
        ErrorShutdown();
    }

    // Now parse the rest of our options
    // ---------------

    // Grab the rest of our config options
    ProcessBulkConf(conf);
    
    // Delete the conf stuff
    delete conf;
    conf = NULL;

	// Try to put networkmanager to sleep as unprived
	if (netmanager_control) {
		fprintf(stderr, "Putting networkmanager to sleep...\n");
		if (networkmanager_control("sleep") < 0)
			fprintf(stderr, "WARNING: Failed to send 'sleep' command to networkmanager "
					"via DBUS, NM may try to take control of the interfaces still.");
	}

    if (data_log) {
        if (dumpfile->OpenDump(dumplogfile.c_str()) < 0) {
            fprintf(stderr, "FATAL: Dump file error: %s\n", dumpfile->FetchError());
            ErrorShutdown();
        }

        dumpfile->SetBeaconLog(beacon_log);
        dumpfile->SetPhyLog(phy_log);
        dumpfile->SetMangleLog(mangle_log);

        fprintf(stderr, "Dump file format: %s\n", dumpfile->FetchType());
    }

    if (gps_enable && gps_log == 1) {
        if (gpsdump.OpenDump(gpslogfile.c_str(), xmllogfile.c_str()) < 0) {
            fprintf(stderr, "FATAL: GPS dump error: %s\n", gpsdump.FetchError());
            ErrorShutdown();
        }
    }

    // Open our files first to make sure we can, we'll unlink the empties later.
    if (net_log) {
        if ((testfile = fopen(netlogfile.c_str(), "w")) == NULL) {
            fprintf(stderr, "FATAL:  Unable to open net file %s: %s.  Consult the "
                    "'Troubleshooting' section of the README file for more info.\n",
                    netlogfile.c_str(), strerror(errno));
            ErrorShutdown();
        }
        fclose(testfile);
    }

    if (csv_log) {
        if ((testfile = fopen(csvlogfile.c_str(), "w")) == NULL) {
            fprintf(stderr, "FATAL:  Unable to open CSV file %s: %s.  Consult the "
                    "'Troubleshooting' section of the README file for more info.\n",
                    netlogfile.c_str(), strerror(errno));
            ErrorShutdown();
        }
        fclose(testfile);
    }

    if (xml_log) {
        if ((testfile = fopen(xmllogfile.c_str(), "w")) == NULL) {
            fprintf(stderr, "FATAL:  Unable to open netxml file %s: %s.  Consult the "
                    "'Troubleshooting' section of the README file for more info.\n",
                    netlogfile.c_str(), strerror(errno));
            ErrorShutdown();
        }
        fclose(testfile);
    }

    if (cisco_log) {
        if ((testfile = fopen(ciscologfile.c_str(), "w")) == NULL) {
            fprintf(stderr, "FATAL:  Unable to open CSV file %s: %s.  Consult the "
                    "'Troubleshooting' section of the README file for more info.\n",
                    netlogfile.c_str(), strerror(errno));
            ErrorShutdown();
        }
        fclose(testfile);
    }

    // Crypt log stays open like the dump log for continual writing
    if (crypt_log) {
        cryptfile = new AirsnortDumpFile;

        if (cryptfile->OpenDump(cryptlogfile.c_str()) < 0) {
            fprintf(stderr, "FATAL: %s\n", cryptfile->FetchError());
            ErrorShutdown();
        }

        fprintf(stderr, "Crypt file format: %s\n", cryptfile->FetchType());

    }

    snprintf(status, STATUS_MAX, "Kismet %s.%s.%s (%s)",
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

    if (gps_enable && gps != NULL) {
        // Open the GPS
        if (gps->OpenGPSD() < 0) {
            fprintf(stderr, "%s\n", gps->FetchError());

            gps_enable = 0;
			if (gps_log == 1)
				gpsdump.CloseDump(1);
            gps_log = 0;
        } else {
            fprintf(stderr, "Opened GPS connection to %s port %d\n",
                    gpshost, gpsport);

            gpsmode = gps->FetchMode();

            last_gpsd_reconnect = time(0);
        }
    }

    fprintf(stderr, "Listening on port %d.\n", tcpport);
    for (unsigned int ipvi = 0; ipvi < legal_ipblock_vec.size(); ipvi++) {
        char *netaddr = strdup(inet_ntoa(legal_ipblock_vec[ipvi]->network));
        char *maskaddr = strdup(inet_ntoa(legal_ipblock_vec[ipvi]->mask));

        fprintf(stderr, "Allowing connections from %s/%s\n", netaddr, maskaddr);

        free(netaddr);
        free(maskaddr);
    }

    if (ui_server.Setup(tcpmax, bind_addr, tcpport, &legal_ipblock_vec) < 0) {
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
    kissrv_aref = alertracker.RegisterAlert("KISMET", sat_day, 0, sat_day, 0);
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
									  alert_enable_vec[alvec].burst_unit,
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
    // Update GPS coordinates and handle signal loss if defined
    timetracker.RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, &GpsEvent, NULL);
    // Sync the data files if requested
    if (datainterval > 0 && no_log == 0)
        timetracker.RegisterTimer(datainterval * SERVER_TIMESLICES_SEC, NULL, 1, &ExportSyncEvent, NULL);
    // Write waypoints if requested
    if (waypoint)
        timetracker.RegisterTimer(decay * SERVER_TIMESLICES_SEC, NULL, 1, &WaypointSyncEvent, NULL);
    // Channel hop if requested
    if (channel_hop) {
        if (channel_dwell)
            timetracker.RegisterTimer(SERVER_TIMESLICES_SEC * channel_dwell, NULL, 1, &ChannelHopEvent, NULL);
        else
            timetracker.RegisterTimer(SERVER_TIMESLICES_SEC / channel_velocity, NULL, 1, &ChannelHopEvent, NULL);
    }

    cisco_ref = -1;

    // Hijack the status char* for some temp work and fill in our server data record
    // for sending to new clients.
    // Fill in the old version so we don't break other clients
    kdata.version = "0.0.0";
    snprintf(status, 1024, "%s.%s.%s", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY);
    kdata.newversion = status;
    snprintf(status, 1024, "%d", (int) start_time);
    kdata.starttime = status;
    snprintf(status, 1024, "\001%s\001", servername);
    kdata.servername = status;
    snprintf(status, 1024, "%s", TIMESTAMP);
    kdata.timestamp = status;

    printf("Gathering packets...\n");
	fflush(stderr);
	fflush(stdout);

	// Drop to daemon mode if we're going to
daemon_parent_cleanup:
	if (daemonize) {
		fprintf(stderr, "Silencing output and entering daemon mode...\n");
		WriteDatafiles(0);
		silent = 1;
		if (getpid() == daemon_parent_pid)
			exit(1);
	}

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

    time_t cur_time;
    while (1) {
        fd_set rset, wset;
        cur_time = time(0);

        // Merge fd's from the server and the packetsources
        max_fd = ui_server.MergeSet(read_set, max_fd, &rset, &wset);
        max_fd = sourcetracker.MergeSet(&rset, &wset, max_fd);
		if (gps_enable && gps != NULL)
			max_fd = gps->MergeSet(&rset, &wset, max_fd);

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

		if (gps_enable && gps != NULL)
			gps->Poll(&rset, &wset);

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

        // Process sourcetracker-level stuff... This should someday handle packetpath
        // stuff, and should someday be the same argument format as uiserver.poll...
        int ret;
        ret = sourcetracker.Poll(&rset, &wset);
        if (ret < 0) {
            snprintf(status, STATUS_MAX, "FATAL: %s", sourcetracker.FetchError());
			NetWriteStatus(status);
			if (!silent) {
                fprintf(stderr, "%s\n", status);
                fprintf(stderr, "Terminating.\n");
            }

            CatchShutdown(-1);
        } else if (ret > 0) {
			NetWriteStatus(status);
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
                    // Handle a packet
                    packnum++;

                    static packet_info info;

                    GetPacketInfo(&packet, &info, &bssid_wep_map, wep_identity);

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

                            continue;
                        }

                    }

                    if (gps_log == 1 && info.type != packet_noise && 
                        info.type != packet_unknown && info.type != packet_phy) {
                        if (gpsdump.DumpPacket(&info) < 0) {
                            snprintf(status, STATUS_MAX, "%s", gpsdump.FetchError());
							NetWriteStatus(status);
							if (!silent)
                                fprintf(stderr, "%s\n", status);
                        }
                    }

                    // tracker.ProcessPacket(info);
                    tracker.ProcessPacket(&packet, &info, &bssid_wep_map, 
										  wep_identity);

                    if (tracker.FetchNumNetworks() > num_networks) {
                        if (sound == 1)
                            if (info.crypt_set && 
								wav_map.find("new_wep") != wav_map.end())
                                sound = PlaySound("new_wep");
                            else
                                sound = PlaySound("new");
                        if (speech == 1) {
                            string text;

                            if (info.crypt_set)
                                text = ExpandSpeechString(speech_sentence_encrypted, &info, 
                                                          speech_encoding);
                            else
                                text = ExpandSpeechString(speech_sentence_unencrypted, 
                                                          &info, speech_encoding);

                            speech = SayText(MungeToShell(text).c_str());
                        }
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
                    if (info.type == packet_data && (info.encrypted == 0 || 
                                                     info.decoded == 1) &&
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

                    if (data_log && !(info.type == packet_noise && noise_log == 0) &&
                        !(info.corrupt != 0 && corrupt_log == 0)) {
                        if (limit_logs && log_packnum > limit_logs) {
                            dumpfile->CloseDump();

                            dumplogfile = ConfigFile::ExpandLogPath(logtemplate, 
                                                                    logname, "dump", 0);

                            if (dumpfile->OpenDump(dumplogfile.c_str()) < 0) {
                                perror("Unable to open new dump file");
                                CatchShutdown(-1);
                            }

                            dumpfile->SetBeaconLog(beacon_log);
                            dumpfile->SetPhyLog(phy_log);
                            dumpfile->SetMangleLog(mangle_log);

                            snprintf(status, STATUS_MAX, "Opened new packet log file %s",
                                     dumplogfile.c_str());

							NetWriteStatus(status);
							if (!silent)
                                fprintf(stderr, "%s\n", status);

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
                                snprintf(status, STATUS_MAX, "FATAL: %s", dumpfile->FetchError());
                                fprintf(stderr, "%s\n", status);
                                NetWriteStatus(status);
                                CatchShutdown(-1);
                            } 
                            
                            /*
                              else if (ret == 0) {
                                localdropnum++;
                            }
                            */

                            log_packnum = dumpfile->FetchDumped();
                        }
                    }

                    if (crypt_log) {
                        cryptfile->DumpPacket(&info, &packet);
                    }

                } else if (ret < 0) {
                    // Fail on error
                    snprintf(status, STATUS_MAX, "FATAL: %s",
                             packet_sources[src]->FetchError());
					NetWriteStatus(status);
					if (!silent) {
                        fprintf(stderr, "%s\n", status);
                        fprintf(stderr, "Terminating.\n");
                    }

                    CatchShutdown(-1);
                }
            } // End processing new packets

        }

        timetracker.Tick();

        // Sleep if we have a custom additional sleep time
        if (sleepu > 0)
            usleep(sleepu);
    }

    CatchShutdown(-1);
}
