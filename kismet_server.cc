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

#include "globalregistry.h"

#include "configfile.h"
#include "messagebus.h"

#include "macaddr.h"
#include "packet.h"

#include "packetsourcetracker.h"

#include "packetracker.h"
#include "timetracker.h"
#include "alertracker.h"

#include "netframework.h"
#include "tcpserver.h"
#include "kis_netframe.h"

#include "dumpfile.h"
#include "wtapdump.h"
#include "wtaplocaldump.h"
#include "airsnortdump.h"
#include "fifodump.h"
#include "gpsdump.h"

#include "gpsd.h"

#include "speech.h"

#ifndef exec_name
char *exec_name;
#endif

// Message clients that are attached at the master level
// Smart standard out client that understands the silence options
class SmartStdoutMessageClient : public MessageClient {
public:
    SmartStdoutMessageClient(GlobalRegistry *in_globalreg) :
        MessageClient(in_globalreg) { }
    virtual ~SmartStdoutMessageClient() { }
    void ProcessMessage(string in_msg, int in_flags);
};

void SmartStdoutMessageClient::ProcessMessage(string in_msg, int in_flags) {
    if ((in_flags & MSGFLAG_DEBUG) && !globalreg->silent)
        fprintf(stdout, "DEBUG: %s\n", in_msg.c_str());
    else if ((in_flags & MSGFLAG_INFO) && !globalreg->silent)
        fprintf(stdout, "NOTICE: %s\n", in_msg.c_str());
    else if ((in_flags & MSGFLAG_ERROR) && !globalreg->silent)
        fprintf(stdout, "ERROR: %s\n", in_msg.c_str());
    else if (in_flags & MSGFLAG_FATAL)
        fprintf(stderr, "FATAL: %s\n", in_msg.c_str());
    
    return;
}

// Queue of fatal alert conditions to spew back out at the end
class FatalQueueMessageClient : public MessageClient {
public:
    FatalQueueMessageClient(GlobalRegistry *in_globalreg) :
        MessageClient(in_globalreg) { }
    virtual ~FatalQueueMessageClient() { }
    void ProcessMessage(string in_msg, int in_flags);
    void DumpFatals();
protected:
    vector<string> fatalqueue;
};

void FatalQueueMessageClient::ProcessMessage(string in_msg, int in_flags) {
    // We only get passed fatal stuff so save a test
    fatalqueue.push_back(in_msg);
}

void FatalQueueMessageClient::DumpFatals() {
    for (unsigned int x = 0; x < fatalqueue.size(); x++) {
        fprintf(stderr, "FATAL: %s\n", fatalqueue[x].c_str());
    }
}

const char *config_base = "kismet.conf";
const char *pid_base = "kismet_server.pid";

// This needs to be a global but nothing outside of this main file will
// use it, so we don't have to worry much about putting it in the globalreg.
FatalQueueMessageClient *fqmescli = NULL;

// Some globals for command line options
char *configfile = NULL;
int no_log = 0, noise_log = 0, data_log = 0, net_log = 0, crypt_log = 0, cisco_log = 0,
    gps_log = -1, gps_enable = 1, csv_log = 0, xml_log = 0, ssid_cloak_track = 0, 
    ip_track = 0, waypoint = 0, fifo = 0, corrupt_log = 0;
string logname, dumplogfile, netlogfile, cryptlogfile, ciscologfile,
    gpslogfile, csvlogfile, xmllogfile, ssidtrackfile, configdir, iptrackfile, 
    waypointfile, fifofile;
FILE *ssid_file = NULL, *ip_file = NULL, *waypoint_file = NULL, *pid_file = NULL;

DumpFile *dumpfile, *cryptfile;
int packnum = 0, localdropnum = 0;


#ifdef HAVE_GPS
int gpsmode = 0;
GPSDump gpsdump;

// Last time we tried to reconnect to the gps
time_t last_gpsd_reconnect = 0;
int gpsd_reconnect_attempt = 0;
#endif

FifoDumpFile fifodump;
int sound = -1;
packet_info last_info;
int decay;
channel_power channel_graph[CHANNEL_MAX];
char *servername = NULL;

fd_set read_set;

// Pipe file descriptor pairs and fd's
int soundpair[2];
int speechpair[2];
int chanpair[2];
pid_t soundpid = -1, speechpid = -1, chanpid = -1;

// Past alerts
unsigned int max_alerts = 50;

// Reference number for our kismet-server alert
int kissrv_aref = -1;

// More config-driven globals
const char *logtypes = NULL, *dumptype = NULL;
int limit_logs = 0;

#ifdef HAVE_GPS
char gpshost[1024];
int gpsport = -1;
#endif

//const char *sndplay = NULL;
string sndplay;

const char *festival = NULL;
int speech = -1;
int speech_encoding = 0;
string speech_sentence_encrypted, speech_sentence_unencrypted;

map<string, string> wav_map;

int beacon_log = 1;
int phy_log = 1;
int mangle_log = 0;

FILE *manuf_data;
char *client_manuf_name = NULL, *ap_manuf_name = NULL;

int datainterval = 0;

string logtemplate;

// Ultimate registry of global components
GlobalRegistry *globalregistry = NULL;

void NetWriteInfo();

// Handle writing all the files out and optionally unlinking the empties
void WriteDatafiles(int in_shutdown) {
    char errstr[STATUS_MAX];

    // If we're on our way out make one last write of the network stuff - this
    // has a nice side effect of clearing out any "REMOVE" networks if we're 
    // not on the way out.
    NetWriteInfo();

    if (ssid_cloak_track) {
        if (ssid_file)
            globalregistry->packetracker->WriteSSIDMap(ssid_file);

        if (in_shutdown)
            fclose(ssid_file);
    }

    if (ip_track) {
        if (ip_file)
            globalregistry->packetracker->WriteIPMap(ip_file);

        if (in_shutdown)
            fclose(ip_file);
    }

    int kissrv_aref = globalregistry->alertracker->FetchAlertRef("KISMET");
    
    if (net_log) {
        if (globalregistry->packetracker->FetchNumNetworks() != 0) {
            if (globalregistry->packetracker->WriteNetworks(netlogfile) == -1) {
                snprintf(errstr, STATUS_MAX, "Failed to write network logfile");
                globalregistry->alertracker->RaiseAlert(kissrv_aref, mac_addr(0), mac_addr(0),
                                                        mac_addr(0), mac_addr(0), 0, errstr);
                globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_LOCAL);
            }
        } else if (in_shutdown) {
            snprintf(errstr, STATUS_MAX, "Didn't detect any networks, unlinking network list.");
            globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_LOCAL);
            unlink(netlogfile.c_str());
        }
    }

    if (csv_log) {
        if (globalregistry->packetracker->FetchNumNetworks() != 0) {
            if (globalregistry->packetracker->WriteCSVNetworks(csvlogfile) == -1) {
                snprintf(errstr, STATUS_MAX, "Failed to write CSV logfile");
                globalregistry->alertracker->RaiseAlert(kissrv_aref, mac_addr(0), mac_addr(0),
                                                        mac_addr(0), mac_addr(0), 0, errstr);
                globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_LOCAL);
            }
        } else if (in_shutdown) {
            snprintf(errstr, STATUS_MAX, "Didn't detect any networks, unlinking CSV logfile.");
            globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_LOCAL);
            unlink(csvlogfile.c_str());
        }
    }

    if (xml_log) {
        if (globalregistry->packetracker->FetchNumNetworks() != 0) {
            if (globalregistry->packetracker->WriteXMLNetworks(xmllogfile) == -1) {
                snprintf(errstr, STATUS_MAX, "Failed to write XML logfile");
                globalregistry->alertracker->RaiseAlert(kissrv_aref, mac_addr(0), mac_addr(0),
                                                        mac_addr(0), mac_addr(0), 0, errstr);
                globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_LOCAL);
            }
        } else if (in_shutdown) {
            snprintf(errstr, STATUS_MAX, "Didn't detect any networks, unlinking CSV logfile.");
            globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_LOCAL);
            unlink(xmllogfile.c_str());
        }
    }

    if (cisco_log) {
        if (globalregistry->packetracker->FetchNumCisco() != 0) {
            if (globalregistry->packetracker->WriteCisco(ciscologfile) == -1) {
                snprintf(errstr, STATUS_MAX, "Failed to write cisco logfile");
                globalregistry->alertracker->RaiseAlert(kissrv_aref, mac_addr(0), mac_addr(0),
                                                        mac_addr(0), mac_addr(0), 0, errstr);
                globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_LOCAL);
            }
        } else if (in_shutdown) {
            snprintf(errstr, STATUS_MAX, "Didn't detect any CDP networks, unlinking cisco logfile.");
            globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_LOCAL);
            unlink(ciscologfile.c_str());
        }
    }

    sync();

}

// Quick shutdown to clean up from a fatal config after we opened the child
void ErrorShutdown() {
    // Shut down the packet sources
    globalregistry->sourcetracker->CloseSources();

    // Shut down the channel control child
    globalregistry->sourcetracker->ShutdownChannelChild();

    // Shouldn't need to requeue fatal errors here since error shutdown means 
    // we just printed something about fatal errors.  Probably.

    fprintf(stderr, "Kismet exiting.\n");
    exit(1);
}

// Catch our interrupt
void CatchShutdown(int sig) {
    if (sig == SIGPIPE)
        fprintf(stderr, "FATAL: A pipe closed unexpectedly, trying to shut down "
                "cleanly...\n");

    string termstr = "Kismet server terminating.";
    globalregistry->kisnetserver->SendToAll(globalregistry->trm_prot_ref, 
                                            (void *) &termstr);

    // globalregistry->kisnetserver->Shutdown();

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

    // Shut down the packet sources
    globalregistry->sourcetracker->CloseSources();

    // Shut down the channel control child
    globalregistry->sourcetracker->ShutdownChannelChild();

    // Dump fatal errors again
    if (fqmescli != NULL) 
        fqmescli->DumpFatals();

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
                if (globalregistry->silent) {
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
        snprintf(status, STATUS_MAX, "ERROR:  Write error on sound pipe, closing sound connection");
        globalregistry->messagebus->InjectMessage(status, MSGFLAG_FATAL);

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
        snprintf(status, STATUS_MAX, "ERROR:  Write error on speech pipe, closing speech connection");
        globalregistry->messagebus->InjectMessage(status, MSGFLAG_FATAL);

        return 0;
    }

    return 1;
}

void KisLocalNewnet(const wireless_network *in_net) {
    if (globalregistry->kisnetserver->FetchNumClients() < 1)
        return;

    NETWORK_data ndata;
    Protocol_Network2Data(in_net, &ndata);
    globalregistry->kisnetserver->SendToAll(globalregistry->net_prot_ref, (void *) &ndata);
}

void NetWriteInfo() {
    // If we have no clients, don't do this at all, it's expensive
    if (globalregistry->kisnetserver->FetchNumClients() < 1)
        return;

    // Send card info
    vector<meta_packsource *> packet_sources = 
        globalregistry->sourcetracker->FetchMetaSourceVec();
    for (unsigned int src = 0; src < packet_sources.size(); src++) {
        if (packet_sources[src]->valid == 0)
            continue;

        globalregistry->kisnetserver->SendToAll(globalregistry->crd_prot_ref, 
                                                (void *) packet_sources[src]);
    }

    static time_t last_write = time(0);
    static int last_packnum = globalregistry->packetracker->FetchNumPackets();
    vector<wireless_network *> tracked;

    int tim = time(0);
    globalregistry->kisnetserver->SendToAll(globalregistry->tim_prot_ref, &tim);

    char tmpstr[32];

#ifdef HAVE_GPS
    GPS_data gdata;

    if (gps_enable) {
        float lat, lon, alt, spd, hed;
        int mode;

        globalregistry->gpsd->FetchLoc(&lat, &lon, &alt, &spd, &hed, &mode);

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

    globalregistry->kisnetserver->SendToAll(globalregistry->gps_prot_ref, 
                                            (void *) &gdata);
#endif

    INFO_data idata;
    snprintf(tmpstr, 32, "%d", 
             globalregistry->packetracker->FetchNumNetworks());
    idata.networks = tmpstr;
    snprintf(tmpstr, 32, "%d", 
             globalregistry->packetracker->FetchNumPackets());
    idata.packets = tmpstr;
    snprintf(tmpstr, 32, "%d", 
             globalregistry->packetracker->FetchNumCrypt());
    idata.crypt = tmpstr;
    snprintf(tmpstr, 32, "%d", 
             globalregistry->packetracker->FetchNumInteresting());
    idata.weak = tmpstr;
    snprintf(tmpstr, 32, "%d", 
             globalregistry->packetracker->FetchNumNoise());
    idata.noise = tmpstr;
    snprintf(tmpstr, 32, "%d", 
             globalregistry->packetracker->FetchNumDropped() + localdropnum);
    idata.dropped = tmpstr;
    snprintf(tmpstr, 32, "%d", 
             globalregistry->packetracker->FetchNumPackets() - last_packnum);
    idata.rate = tmpstr;

    if (time(0) - last_info.ts.tv_sec < decay && last_info.quality != -1)
        snprintf(tmpstr, 16, "%d %d %d", last_info.quality,
                 last_info.signal, last_info.noise);
    else if (last_info.quality == -1)
        snprintf(tmpstr, 16, "-1 -1 -1");
    else
        snprintf(tmpstr, 16, "0 0 0");
    idata.signal = tmpstr;

    last_packnum = globalregistry->packetracker->FetchNumPackets();

    globalregistry->kisnetserver->SendToAll(globalregistry->ifo_prot_ref, 
                                            (void *) &idata);

    last_write = time(0);

    // Bail out if nobody is listening to networks or packets, building these
    // lists is expensive and if we're headless, don't bother.

    if (globalregistry->kisnetserver->FetchNumClientRefs(globalregistry->net_prot_ref) < 1 &&
        globalregistry->kisnetserver->FetchNumClientRefs(globalregistry->cli_prot_ref) < 1)
        return;

    tracked = globalregistry->packetracker->FetchNetworks();

    for (unsigned int x = 0; x < tracked.size(); x++) {
        // Only send new networks
        if (tracked[x]->last_time < last_write)
            continue;

        if (tracked[x]->type == network_remove) {
            string remstr = tracked[x]->bssid.Mac2String();
            globalregistry->kisnetserver->SendToAll(globalregistry->rem_prot_ref, (void *) &remstr);

            globalregistry->packetracker->RemoveNetwork(tracked[x]->bssid);

            continue;
        }

        NETWORK_data ndata;
        Protocol_Network2Data(tracked[x], &ndata);
        globalregistry->kisnetserver->SendToAll(globalregistry->net_prot_ref, (void *) &ndata);

        // Bail if we don't have any client users...
        if (globalregistry->kisnetserver->FetchNumClientRefs(globalregistry->cli_prot_ref) < 1)
            continue;

        for (map<mac_addr, wireless_client *>::const_iterator y = tracked[x]->client_map.begin();
             y != tracked[x]->client_map.end(); ++y) {
            if (y->second->last_time < last_write)
                continue;

            CLIENT_data cdata;
            Protocol_Client2Data(tracked[x], y->second, &cdata);
            globalregistry->kisnetserver->SendToAll(globalregistry->cli_prot_ref, (void *) &cdata);
        }

    }

}

int GpsEvent(Timetracker::timer_event *evt, void *parm, GlobalRegistry *globalreg) {
#ifdef HAVE_GPS
    char status[STATUS_MAX];

    // The GPS only provides us a new update once per second we might
    // as well only update it here once a second

    // If we're disconnected, try to reconnect.
    if (gpsd_reconnect_attempt > 0) {
        // Increment the time between connection attempts
        if (last_gpsd_reconnect + ((gpsd_reconnect_attempt - 1) * 2) < time(0)) {
            if (globalregistry->gpsd->OpenGPSD() < 0) {
                last_gpsd_reconnect = time(0);

                if (gpsd_reconnect_attempt < 11)
                    gpsd_reconnect_attempt++;

                snprintf(status, STATUS_MAX, "Unable to reconnect to GPSD, trying "
                         "again in %d seconds.", ((gpsd_reconnect_attempt - 1) * 2));

                globalregistry->messagebus->InjectMessage(status, MSGFLAG_ERROR);

                return 1;
            } else {
                gpsd_reconnect_attempt = 0;

                snprintf(status, STATUS_MAX, "Reopened connection to GPSD");
                globalregistry->messagebus->InjectMessage(status, MSGFLAG_ERROR);
            }
        } else {
            // Don't process more if we haven't woken up yet
            return 1;
        }

    }
    
    if (gps_enable) {
        int gpsret;
        gpsret = globalregistry->gpsd->Scan();

        if (gpsret < 0) {
            snprintf(status, STATUS_MAX, "GPS error requesting data: %s",
                     globalregistry->gpsd->FetchError());

            globalregistry->messagebus->InjectMessage(status, MSGFLAG_ERROR);

            gpsd_reconnect_attempt = 1;
        }

        if (gpsret == 0 && gpsmode != 0) {
            globalregistry->messagebus->InjectMessage("GPS reciever lost signal", MSGFLAG_INFO);

            if (sound == 1)
                sound = PlaySound("gpslost");

            gpsmode = 0;
        } else if (gpsret != 0 && gpsmode == 0) {
            globalregistry->messagebus->InjectMessage("GPS reciever aquired signal", MSGFLAG_INFO);

            if (sound == 1)
                sound = PlaySound("gpslock");

            gpsmode = 1;
        }
    }

    if (gps_log == 1 && gpsmode != 0 && globalregistry->gpsd != NULL) {
        gpsdump.DumpTrack(globalregistry->gpsd);
    }

    // We want to be rescheduled
    return 1;
#endif
    return 0;
}

// Simple redirect to the network info drawer.  We don't want to change 
// netwriteinfo to a timer event since we call it un-timed too
int NetWriteEvent(Timetracker::timer_event *evt, void *parm, GlobalRegistry *globalreg) {
    NetWriteInfo();

    // Reschedule us
    return 1;
}

// Handle writing and sync'ing dump files
int ExportSyncEvent(Timetracker::timer_event *evt, void *parm, GlobalRegistry *globalreg) {
    globalregistry->messagebus->InjectMessage("Saving data files.", MSGFLAG_INFO);

    WriteDatafiles(0);

    return 1;
}

// Write the waypoints for gpsdrive
int WaypointSyncEvent(Timetracker::timer_event *evt, void *parm, GlobalRegistry *globalreg) {
    globalregistry->packetracker->WriteGpsdriveWaypt(waypoint_file);

    return 1;
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

// Process filtering elements of the config file
int ProcessFilterConf(ConfigFile *conf) {
    // Grab the filtering
    string filter_bit;

    if ((filter_bit = conf->FetchOpt("filter_tracker")) != "") {
        globalregistry->messagebus->InjectMessage("Enabling tracker filtering", 
                                                  MSGFLAG_INFO);
        globalregistry->filter_tracker = 1;
        if (ConfigFile::ParseFilterLine(filter_bit, &(globalregistry->filter_tracker_bssid), 
                                        &(globalregistry->filter_tracker_source),
                                        &(globalregistry->filter_tracker_dest), 
                                        &(globalregistry->filter_tracker_bssid_invert),
                                        &(globalregistry->filter_tracker_source_invert),
                                        &(globalregistry->filter_tracker_dest_invert)) < 0)
            ErrorShutdown();
    }


    if ((filter_bit = conf->FetchOpt("filter_dump")) != "") {
        globalregistry->messagebus->InjectMessage("Enabling dump file filtering", 
                                                  MSGFLAG_INFO);
        globalregistry->filter_dump = 1;
        if (ConfigFile::ParseFilterLine(filter_bit, &(globalregistry->filter_dump_bssid), 
                                        &(globalregistry->filter_dump_source),
                                        &(globalregistry->filter_dump_dest), 
                                        &(globalregistry->filter_dump_bssid_invert),
                                        &(globalregistry->filter_dump_source_invert),
                                        &(globalregistry->filter_dump_dest_invert)) < 0)
            ErrorShutdown();
    }

    if ((filter_bit = conf->FetchOpt("filter_export")) != "") {
        globalregistry->messagebus->InjectMessage("Enabling exported filtering "
                                                  "(CSV, XML, network gps)", MSGFLAG_INFO);
        globalregistry->filter_export = 1;
        if (ConfigFile::ParseFilterLine(filter_bit, &(globalregistry->filter_export_bssid), 
                                        &(globalregistry->filter_export_source),
                                        &(globalregistry->filter_export_dest), 
                                        &(globalregistry->filter_export_bssid_invert),
                                        &(globalregistry->filter_export_source_invert),
                                        &(globalregistry->filter_export_dest_invert)) < 0)
            ErrorShutdown();
    }

    return 1;
}

// Moved here to make compiling this file take less memory.  Can be broken down more
// in the future.
int ProcessBulkConf(ConfigFile *conf) {
    char errstr[STATUS_MAX];

    // Convert the WEP mappings to our real map
    vector<string> raw_wepmap_vec;
    raw_wepmap_vec = conf->FetchOptVec("wepkey");
    for (size_t rwvi = 0; rwvi < raw_wepmap_vec.size(); rwvi++) {
        string wepline = raw_wepmap_vec[rwvi];

        size_t rwsplit = wepline.find(",");
        if (rwsplit == string::npos) {
            globalregistry->messagebus->InjectMessage("Malformed 'wepkey' option in the config file",
                                                      MSGFLAG_FATAL);
            ErrorShutdown();
        }

        mac_addr bssid_mac = wepline.substr(0, rwsplit).c_str();

        if (bssid_mac.error == 1) {
            globalregistry->messagebus->InjectMessage("Malformed 'wepkey' option in the config file",
                                                      MSGFLAG_FATAL);
            ErrorShutdown();
        }

        string rawkey = wepline.substr(rwsplit + 1, wepline.length() - (rwsplit + 1));

        unsigned char key[WEPKEY_MAX];
        int len = Hex2UChar((unsigned char *) rawkey.c_str(), key);

        if (len != 5 && len != 13 && len != 16) {
            snprintf(errstr, STATUS_MAX, "Invalid key '%s' length %d in a wepkey option "
                    "in the config file.\n", rawkey.c_str(), len);
            globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            ErrorShutdown();
        }

        wep_key_info *keyinfo = new wep_key_info;
        keyinfo->bssid = bssid_mac;
        keyinfo->fragile = 0;
        keyinfo->decrypted = 0;
        keyinfo->failed = 0;
        keyinfo->len = len;
        memcpy(keyinfo->key, key, sizeof(unsigned char) * WEPKEY_MAX);

        globalregistry->bssid_wep_map.insert(bssid_mac, keyinfo);

        snprintf(errstr, STATUS_MAX, "Using key %s length %d for BSSID %s",
                rawkey.c_str(), len, bssid_mac.Mac2String().c_str());
        globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    }
    if (conf->FetchOpt("allowkeytransmit") == "true") {
        globalregistry->messagebus->InjectMessage("Allowing clients to fetch WEP keys", MSGFLAG_INFO);
        globalregistry->client_wepkey_allowed = 1;
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
        globalregistry->messagebus->InjectMessage("No 'configdir' option in the config file",
                                                  MSGFLAG_FATAL);
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


#ifdef HAVE_GPS
    if (conf->FetchOpt("waypoints") == "true") {
        if(conf->FetchOpt("waypointdata") == "") {
            globalregistry->messagebus->InjectMessage("Waypoint logging requeted but no waypoint data file "
                                                      "given.  Waypoint logging will be disabled.",
                                                      MSGFLAG_ERROR);
            waypoint = 0;
        } else {
            waypointfile = conf->ExpandLogPath(conf->FetchOpt("waypointdata"), "", "", 0, 1);
            waypoint = 1;
        }

    }
#endif

    if (conf->FetchOpt("metric") == "true") {
        globalregistry->messagebus->InjectMessage("Using metric units for distance", MSGFLAG_INFO);
        globalregistry->metric = 1;
    }

    if (conf->FetchOpt("fifo") != "") {
        fifofile = conf->FetchOpt("fifo");
        fifo = 1;
    }

    if (!no_log) {
        if (logname == "") {
            if (conf->FetchOpt("logdefault") == "") {
                globalregistry->messagebus->InjectMessage("No default log name in config and no "
                                                          "log name provided on the command line",
                                                          MSGFLAG_FATAL);
                ErrorShutdown();
            }
            logname = strdup(conf->FetchOpt("logdefault").c_str());
        }

        if (logtypes == NULL) {
            if (conf->FetchOpt("logtypes") == "") {
                globalregistry->messagebus->InjectMessage("No log types in config and none provided on the command line",
                                                          MSGFLAG_FATAL);
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
                globalregistry->messagebus->InjectMessage("Logging (network dump) enabled but no logtemplate in config",
                                                          MSGFLAG_FATAL);
                ErrorShutdown();
            }

            if (conf->FetchOpt("dumplimit") != "" || limit_logs != 0) {
                if (limit_logs == 0)
                    if (sscanf(conf->FetchOpt("dumplimit").c_str(), "%d", &limit_logs) != 1) {
                        globalregistry->messagebus->InjectMessage("Illegal config file value for dumplimit",
                                                                  MSGFLAG_FATAL);
                        ErrorShutdown();
                    }

                if (limit_logs != 0) {
                    snprintf(errstr, STATUS_MAX, "Limiting dumpfile to %d packets each.",
                            limit_logs);
                    globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
                }
            }

            if (conf->FetchOpt("dumptype") == "" && dumptype == NULL) {
                globalregistry->messagebus->InjectMessage("Dump file logging requested but no dump type given",
                                                          MSGFLAG_FATAL);
                ErrorShutdown();
            }

            if (conf->FetchOpt("dumptype") != "" && dumptype == NULL)
                dumptype = strdup(conf->FetchOpt("dumptype").c_str());

            if (!strcasecmp(dumptype, "wiretap")) {
                dumpfile = new WtapDumpFile;
            } else {
                snprintf(errstr, STATUS_MAX, "Unknown dump file type '%s'", dumptype);
                globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
                ErrorShutdown();
            }
        }

        if (strstr(logtypes, "network")) {
            net_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                globalregistry->messagebus->InjectMessage("Logging (network list) enabled but no template "
                                                          "given in config file", MSGFLAG_FATAL);
                ErrorShutdown();
            }

        }

        if (strstr(logtypes, "weak")) {
            crypt_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                globalregistry->messagebus->InjectMessage("Logging (weak packets) enabled but no template "
                                                          "given in config file", MSGFLAG_FATAL);
                ErrorShutdown();
            }

        }

        if (strstr(logtypes, "csv")) {
            csv_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                globalregistry->messagebus->InjectMessage("Logging (CSV network list) enabled but no template "
                                                          "given in config file", MSGFLAG_FATAL);
                ErrorShutdown();
            }

        }

        if (strstr(logtypes, "xml")) {
            xml_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                globalregistry->messagebus->InjectMessage("Logging (XML network list) enabled but no template "
                                                          "given in config file", MSGFLAG_FATAL);
                ErrorShutdown();
            }
        }

        if (strstr(logtypes, "cisco")) {
            cisco_log = 1;

            if (conf->FetchOpt("logtemplate") == "") {
                globalregistry->messagebus->InjectMessage("Logging (cisco information) enabled but no template "
                                                          "given in config file", MSGFLAG_FATAL);
                ErrorShutdown();
            }

        }

        if (strstr(logtypes, "gps")) {
#ifdef HAVE_GPS
            if (gps_log != 0) {
                gps_log = 1;

                if (conf->FetchOpt("logtemplate") == "") {
                    globalregistry->messagebus->InjectMessage("Logging (GPS) enabled but no template "
                                                              "given in config file", MSGFLAG_FATAL);
                    ErrorShutdown();
                }
            }
#else

            globalregistry->messagebus->InjectMessage("GPS logging but Kismet was compiled without "
                                                      "GPS support.  GPS logging will be disabled",
                                                      MSGFLAG_ERROR);
            gps_log = 0;
#endif

        }

        if (gps_log == 1 && !net_log) {
            globalregistry->messagebus->InjectMessage("Logging (GPS data) was enabled but XML logging was not. "
                                                      "XML logging is needed by gpsmap to correctly plot networks "
                                                      "and will be enabled now.", MSGFLAG_ERROR);
            xml_log = 1;
        }
    }

    if (conf->FetchOpt("decay") != "") {
        if (sscanf(conf->FetchOpt("decay").c_str(), "%d", &decay) != 1) {
            globalregistry->messagebus->InjectMessage("Illegal value for 'decay' in config file", MSGFLAG_FATAL);
            ErrorShutdown();
        }
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
            globalregistry->messagebus->InjectMessage("Sound alerts enabled but no sound player specified, "
                                                      "sound will be disabled", MSGFLAG_ERROR);
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
                globalregistry->messagebus->InjectMessage("Speech requested but no speech templates given "
                                                          "in the config file.  Speech will be disabled.", 
                                                          MSGFLAG_ERROR);
                speech = 0;
            }

            speech_sentence_encrypted = conf->FetchOpt("speech_encrypted");
            speech_sentence_unencrypted = conf->FetchOpt("speech_unencrypted");
        } else {
            globalregistry->messagebus->InjectMessage("Speech requested but no path to festival has been "
                                                      "specified.  Speech will be disabled",
                                                      MSGFLAG_ERROR);
            speech = 0;
        }
    } else if (speech == -1)
        speech = 0;

    if (conf->FetchOpt("writeinterval") != "") {
        if (sscanf(conf->FetchOpt("writeinterval").c_str(), "%d", &datainterval) != 1) {
            globalregistry->messagebus->InjectMessage("Illegal value for 'writeinterval' in config file",
                                                      MSGFLAG_FATAL);
            ErrorShutdown();
        }
    }

    if (conf->FetchOpt("ap_manuf") != "") {
        ap_manuf_name = strdup(conf->FetchOpt("ap_manuf").c_str());
    } else {
        globalregistry->messagebus->InjectMessage("No ap_manuf file specified, AP manufacturers and default "
                                                  "configurations will not be detected", MSGFLAG_ERROR);
    }

    if (conf->FetchOpt("client_manuf") != "") {
        client_manuf_name = strdup(conf->FetchOpt("client_manuf").c_str());
    } else {
        globalregistry->messagebus->InjectMessage("No ap_manuf file specified, client manufacturers "
                                                  "will not be detected", MSGFLAG_ERROR);
    }

    // Fork and find the sound options
    if (sound) {
        if (pipe(soundpair) == -1) {
            globalregistry->messagebus->InjectMessage("Unable to create pipe for audio.  Disabling sound.",
                                                      MSGFLAG_ERROR);
            sound = 0;
        } else {
            soundpid = fork();

            if (soundpid < 0) {
                globalregistry->messagebus->InjectMessage("Unable to fork audio control process.  Disabling sound.",
                                                          MSGFLAG_ERROR);
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
            globalregistry->messagebus->InjectMessage("Unable to create pipe for speech.  Disabling speech.",
                                                      MSGFLAG_ERROR);
            speech = 0;
        } else {
            speechpid = fork();

            if (speechpid < 0) {
                globalregistry->messagebus->InjectMessage("Unable to fork speech control process.  Disabling speech.",
                                                          MSGFLAG_ERROR);
                speech = 0;
            } else if (speechpid == 0) {
                SpeechHandler(speechpair, festival);
                exit(0);
            }

            close(speechpair[0]);
        }
    }

    // Process filter components
    ProcessFilterConf(conf);

    // handle the config bits
    struct stat fstat;
    if (stat(configdir.c_str(), &fstat) == -1) {
        snprintf(errstr, STATUS_MAX, "Local config and cache directory '%s' does not exist, making it",
                 configdir.c_str());
        globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
        if (mkdir(configdir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) < 0) {
            snprintf(errstr, STATUS_MAX, "Could not create config and cache directory: %s",
                     strerror(errno));
            globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            ErrorShutdown();
        }
    } else if (! S_ISDIR(fstat.st_mode)) {
        snprintf(errstr, STATUS_MAX, "Local config and cache directory '%s' exists but is not a directory",
                 configdir.c_str());
        globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        ErrorShutdown();
    }

    if (ssid_cloak_track) {
        if (stat(ssidtrackfile.c_str(), &fstat) == -1) {
            globalregistry->messagebus->InjectMessage("SSID cache file does not exist, it will be created",
                                                      MSGFLAG_INFO);
        } else {
            if ((ssid_file = fopen(ssidtrackfile.c_str(), "r")) == NULL) {
                snprintf(errstr, STATUS_MAX, "Could not open SSID cache file '%s': %s",
                         ssidtrackfile.c_str(), strerror(errno));
                globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
                ErrorShutdown();
            }

            globalregistry->packetracker->ReadSSIDMap(ssid_file);

            fclose(ssid_file);

        }

        if ((ssid_file = fopen(ssidtrackfile.c_str(), "a")) == NULL) {
            snprintf(errstr, STATUS_MAX, "Could not open SSID track file '%s' for writing: %s",
                     ssidtrackfile.c_str(), strerror(errno));
            globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            ErrorShutdown();
        }

    }

    if (ip_track) {
        if (stat(iptrackfile.c_str(), &fstat) == -1) {
            globalregistry->messagebus->InjectMessage("IP cache file does not exist, it will be created",
                                                      MSGFLAG_INFO);

        } else {
            if ((ip_file = fopen(iptrackfile.c_str(), "r")) == NULL) {
                snprintf(errstr, STATUS_MAX, "Could not open IP track file '%s': %s",
                         iptrackfile.c_str(), strerror(errno));
                globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
                ErrorShutdown();
            }

            globalregistry->packetracker->ReadIPMap(ip_file);

            fclose(ip_file);
        }

        if ((ip_file = fopen(iptrackfile.c_str(), "a")) == NULL) {
            snprintf(errstr, STATUS_MAX, "Could not open IP track file '%s' for writing: %s",
                     iptrackfile.c_str(), strerror(errno));
            globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            ErrorShutdown();
        }

    }

#ifdef HAVE_GPS
    if (waypoint) {
        if ((waypoint_file = fopen(waypointfile.c_str(), "a")) == NULL) {
            snprintf(errstr, STATUS_MAX, "Could not open gpsdrive waypoint file '%s' for writing: %s",
                     waypointfile.c_str(), strerror(errno));
            globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
            globalregistry->messagebus->InjectMessage("Waypoint file generation will be disabled",
                                                      MSGFLAG_ERROR);
            waypoint = 0;
        }
    }
#endif

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
        globalregistry->messagebus->InjectMessage("Unable to find a name for the logfiles within 100 "
                                                  "attempts.  If you are really logging more than 100 separate "
                                                  "instances in a single day, edit change the log title or exit "
                                                  "the source, however the most common reason for this failure "
                                                  "is an invalid 'logtemplate' line in the config file.",
                                                  MSGFLAG_FATAL);
        ErrorShutdown();
    }

    if (net_log) {
        snprintf(errstr, STATUS_MAX, "Logging networks to %s", netlogfile.c_str());
        globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    }

    if (csv_log) {
        snprintf(errstr, STATUS_MAX, "Logging CSV data to %s", csvlogfile.c_str());
        globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    }

    if (xml_log) {
        snprintf(errstr, STATUS_MAX, "Logging XML data to %s", xmllogfile.c_str());
        globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    }

    if (crypt_log) {
        snprintf(errstr, STATUS_MAX, "Logging FMS WeakIV data packets to %s", cryptlogfile.c_str());
        globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    }

    if (cisco_log) {
        snprintf(errstr, STATUS_MAX, "Logging Cisco identification info to %s", ciscologfile.c_str());
        globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    }

#ifdef HAVE_GPS
    if (gps_log) {
        snprintf(errstr, STATUS_MAX, "Logging GPS XML data to %s", gpslogfile.c_str());
        globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    }
#endif

    if (data_log) {
        snprintf(errstr, STATUS_MAX, "Logging packets to %s", dumplogfile.c_str());
        globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    }

    if (datainterval != 0 && data_log) {
        snprintf(errstr, STATUS_MAX, "Flushing data files to diskevery %d seconds", 
                 datainterval);
        globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    }


    if (conf->FetchOpt("beaconlog") == "false") {
        beacon_log = 0;
        globalregistry->messagebus->InjectMessage("Filtering beacon packets from the packet dump file",
                                                  MSGFLAG_INFO);
    }

    if (conf->FetchOpt("phylog") == "false") {
        phy_log = 0;
        globalregistry->messagebus->InjectMessage("Filtering PHY-layer packets from the packet dump file",
                                                  MSGFLAG_INFO);
    }

    if (conf->FetchOpt("mangledatalog") == "true") {
        mangle_log = 1;
        globalregistry->messagebus->InjectMessage("Rewriting encrypted and fuzzy-encryption data packets in "
                                                  "the packet dump file",
                                                  MSGFLAG_INFO);
    }

    if (conf->FetchOpt("trackprobenets") == "false") {
        globalregistry->track_probenets = 0;
        globalregistry->messagebus->InjectMessage("Not tracking probe responses or attempting to associate probe networks",
                                                  MSGFLAG_INFO);
    } else {
        globalregistry->track_probenets = 1;
        globalregistry->messagebus->InjectMessage("Will attempt to associate probing clients with networks",
                                                  MSGFLAG_INFO);
    }

    if (ap_manuf_name != NULL) {
        char pathname[1024];

        if (strchr(ap_manuf_name, '/') == NULL)
            snprintf(pathname, 1024, "%s/%s", getenv("KISMET_CONF") != NULL ? 
                     getenv("KISMET_CONF") : SYSCONF_LOC, ap_manuf_name);
        else
            snprintf(pathname, 1024, "%s", ap_manuf_name);

        if ((manuf_data = fopen(pathname, "r")) == NULL) {
            snprintf(errstr, STATUS_MAX, "Unable to open '%s' for reading (%s).  AP manufacturers and "
                     "default configurations will not be detected.", pathname, strerror(errno));
            globalregistry->messagebus->InjectMessage(errstr,
                                                      MSGFLAG_ERROR);
        } else {
            snprintf(errstr, STATUS_MAX, "Reading AP manufacturer data and configuration defaults "
                     "from %s", pathname);
            globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
            globalregistry->packetracker->ReadAPManufMap(manuf_data);
            fclose(manuf_data);
        }

        free(ap_manuf_name);
    }

    if (client_manuf_name != NULL) {
        char pathname[1024];

        if (strchr(client_manuf_name, '/') == NULL)
            snprintf(pathname, 1024, "%s/%s", getenv("KISMET_CONF") != NULL ? 
                     getenv("KISMET_CONF") : SYSCONF_LOC, client_manuf_name);
        else
            snprintf(pathname, 1024, "%s", client_manuf_name);

        if ((manuf_data = fopen(pathname, "r")) == NULL) {
            snprintf(errstr, STATUS_MAX, "Unable to open '%s' for reading(%s), client manufacturer "
                     "will not be detected.", pathname, strerror(errno));
            globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        } else {
            snprintf(errstr, STATUS_MAX, "Reading client manufacturer data from %s", pathname);
            globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
            globalregistry->packetracker->ReadClientManufMap(manuf_data);
            fclose(manuf_data);
        }

        free(client_manuf_name);
    }

    // Push the packparms into each source...
    packet_parm fuzzparms;
    fuzzparms.fuzzy_crypt = 1;

    globalregistry->sourcetracker->SetTypeParms(conf->FetchOpt("fuzzycrypt"), fuzzparms);

    return 1;
}

int CatchOldConfigs(ConfigFile *conf) {
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

    return 1;
}

int main(int argc,char *argv[]) {
    exec_name = argv[0];

    // Start filling in key components of the globalregistry
    globalregistry = new GlobalRegistry;
    // First order - create our message bus and our client for outputting
    globalregistry->messagebus = new MessageBus;
 
    // Create a smart stdout client and allocate the fatal client, add them to the
    // messagebus
    SmartStdoutMessageClient *smartmsgcli = new SmartStdoutMessageClient(globalregistry);
    fqmescli = new FatalQueueMessageClient(globalregistry);

    globalregistry->messagebus->RegisterClient(fqmescli, MSGFLAG_FATAL);
    globalregistry->messagebus->RegisterClient(smartmsgcli, MSGFLAG_ALL);
   
    // Allocate some other critical stuff
    globalregistry->timetracker = new Timetracker(globalregistry);

    // Packet and contents
    kis_packet packet;
    uint8_t data[MAX_PACKET_LEN];
    uint8_t moddata[MAX_PACKET_LEN];

    char *configfile = NULL;

    int sleepu = 0;
    int log_packnum = 0;
    char status[STATUS_MAX];

    globalregistry->start_time = time(0);

    unsigned char wep_identity[256];

    // Initialize the identity field
    for (unsigned int wi = 0; wi < 256; wi++)
        wep_identity[wi] = wi;

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
            globalregistry->silent = 1;
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
            globalregistry->source_input_vec.push_back(string(optarg));
            globalregistry->source_from_cmd = 1;
            break;
        case 'C':
            // Named sources
            globalregistry->named_sources = string(optarg);
            fprintf(stderr, "Using specified capture sources: %s\n", 
                    globalregistry->named_sources.c_str());
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
            if (sscanf(optarg, "%d", &globalregistry->kistcpport) != 1) {
                fprintf(stderr, "Invalid port number.\n");
                Usage(argv[0]);
            }
            break;
        case 'a':
            // Allowed
            globalregistry->kisallowedhosts = string(optarg);
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
            globalregistry->channel_hop = 1;
            fprintf(stderr, "Ignoring config file and enabling channel hopping.\n");
            break;
        case 'X':
            // Force channel hop off
            globalregistry->channel_hop = 0;
            fprintf(stderr, "Ignoring config file and disabling channel hopping.\n");
            break;
        case 'I':
            // Initial channel
            globalregistry->src_initchannel_vec.push_back(string(optarg));
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

    // Register this with the globalreg for other components to use
    globalregistry->kismet_config = conf;

    // This only frees the memory for the filename string
    if (freeconf)
        free(configfile);

    // Register the TCP server cores
    TcpServer *kistcpserver = new TcpServer(globalregistry);
  
    globalregistry->kisnetserver = new KisNetFramework(globalregistry);

    if (globalregistry->fatal_condition)
        CatchShutdown(-1);

    kistcpserver->RegisterServerFramework(globalregistry->kisnetserver);
    globalregistry->kisnetserver->RegisterNetworkServer(kistcpserver);

    // Allocate the alert tracker
    globalregistry->alertracker = new Alertracker(globalregistry);

    // Allocate the packetracker here since we'll need it for parsing
    globalregistry->packetracker = new Packetracker(globalregistry);

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

    // Catch old config file elements that indicate we won't work
    CatchOldConfigs(conf);
       
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

    // Write our pid.  Things calling us need to check and see if we're actually
    // running.
    fprintf(pid_file, "%d\n", getpid());

    // And we're done
    fclose(pid_file);
            

#ifdef HAVE_GPS
    // Set up the GPS object to give to the children
    if (gpsport == -1 && gps_enable) {
        if (conf->FetchOpt("gps") == "true") {
            if (sscanf(conf->FetchOpt("gpshost").c_str(), "%1024[^:]:%d", gpshost, 
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

    if (gps_enable == 1) {
        globalregistry->gpsd = new GPSD(gpshost, gpsport);

        // Lock GPS position
        if (conf->FetchOpt("gpsmodelock") == "true") {
            fprintf(stderr, "Enabling GPS position lock override (broken GPS unit "
                    "reports 0 always)\n");
            globalregistry->gpsd->SetOptions(GPSD_OPT_FORCEMODE);
        }

    } else {
        gps_log = 0;
    }

#endif

    // Build the sourcetracker components
    globalregistry->sourcetracker = new Packetsourcetracker(globalregistry);

    // Now enable root sources...
    setreuid(0, 0);

    // Bind the root sources
    if (globalregistry->sourcetracker->BindSources(1) < 0) {
        CatchShutdown(-1);
    }

    // Spawn the channel control source.  All future exits must now call the real
    // exit function to terminate the channel hopper!
    if (globalregistry->sourcetracker->SpawnChannelChild() < 0) {
        CatchShutdown(-1);
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
    if (globalregistry->sourcetracker->BindSources(0) < 0) {
        ErrorShutdown();
    }

    // Now parse the rest of our options
    // ---------------

    // Grab the rest of our config options
    ProcessBulkConf(conf);
    
    // Delete the conf stuff
    delete conf;
    conf = NULL;

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

#ifdef HAVE_GPS
    if (gps_enable && gps_log == 1) {
        if (gpsdump.OpenDump(gpslogfile.c_str(), xmllogfile.c_str()) < 0) {
            fprintf(stderr, "FATAL: GPS dump error: %s\n", gpsdump.FetchError());
            ErrorShutdown();
        }
    }
#endif


    // Open our files first to make sure we can, we'll unlink the empties later.
    FILE *testfile = NULL;
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

#ifdef HAVE_GPS
    if (gps_enable) {
        // Open the GPS
        if (globalregistry->gpsd->OpenGPSD() < 0) {
            fprintf(stderr, "%s\n", globalregistry->gpsd->FetchError());

            gps_enable = 0;
            gps_log = 0;
        } else {
            fprintf(stderr, "Opened GPS connection to %s port %d\n",
                    gpshost, gpsport);

            gpsmode = globalregistry->gpsd->FetchMode();

            last_gpsd_reconnect = time(0);
        }
    }
#endif

    // Set up the 
    if (kistcpserver->EnableServer() < 0 || globalregistry->fatal_condition) {
        CatchShutdown(-1);
    }

    if (globalregistry->fatal_condition)
        CatchShutdown(-1);
    
    // Schedule our routine events that repeat the entire operational period.  We don't
    // care about their ID's since we're never ever going to cancel them.
    fprintf(stderr, "Registering builtin timer events...\n");

    // Write network info and tick the tracker once per second
    globalregistry->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, &NetWriteEvent, NULL);
#ifdef HAVE_GPS
    // Update GPS coordinates and handle signal loss if defined
    globalregistry->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, &GpsEvent, NULL);
#endif
    // Sync the data files if requested
    if (datainterval > 0 && no_log == 0)
        globalregistry->timetracker->RegisterTimer(datainterval * SERVER_TIMESLICES_SEC, NULL, 1, &ExportSyncEvent, NULL);
    // Write waypoints if requested
    if (waypoint)
        globalregistry->timetracker->RegisterTimer(decay * SERVER_TIMESLICES_SEC, NULL, 1, &WaypointSyncEvent, NULL);

    time_t last_click = 0;
    int num_networks = 0, num_packets = 0, num_noise = 0, num_dropped = 0;

    // We're ready to begin the show... Fill in our file descriptors for when
    // to wake up
    FD_ZERO(&read_set);

    fprintf(stderr, "Gathering packets...\n");

    time_t cur_time;
    while (1) {
        int max_fd = 0;
        fd_set rset, wset;
        cur_time = time(0);

        FD_ZERO(&rset);
        FD_ZERO(&wset);

        // Merge fd's from the server and the packetsources
        max_fd = globalregistry->sourcetracker->MergeSet(rset, wset, max_fd, &rset, &wset);
        max_fd = kistcpserver->MergeSet(rset, wset, max_fd, &rset, &wset);

        struct timeval tm;
        tm.tv_sec = 0;
        tm.tv_usec = 100000;

        if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
            if (errno != EINTR) {
                snprintf(status, STATUS_MAX,
                         "select() error %d (%s)", errno, strerror(errno));
                globalregistry->messagebus->InjectMessage(status, MSGFLAG_FATAL);
                CatchShutdown(-1);
            }
        }

        if (kistcpserver->Poll(rset, wset) < 0 || globalregistry->fatal_condition)
            CatchShutdown(-1);

        // Process sourcetracker-level stuff... This should someday handle packetpath
        // stuff, and should someday be the same argument format as uiserver.poll...
        int ret;
        ret = globalregistry->sourcetracker->Poll(&rset, &wset);
        if (ret < 0 || globalregistry->fatal_condition) {
            CatchShutdown(-1);
        }
      
        // This is ugly, come up with a better way to do it someday
        vector<KisPacketSource *> packet_sources = globalregistry->sourcetracker->FetchSourceVec();
        
        for (unsigned int src = 0; src < packet_sources.size(); src++) {
            if (FD_ISSET(packet_sources[src]->FetchDescriptor(), &rset)) {
                // Capture the packet from whatever device
                // len = psrc->FetchPacket(&packet, data, moddata);

                ret = packet_sources[src]->FetchPacket(&packet, data, moddata);
                
                if (ret > 0) {
                    // Handle a packet
                    packnum++;

                    static packet_info info;

                    GetPacketInfo(&packet, &info, &globalregistry->bssid_wep_map, wep_identity);

                    last_info = info;

                    // Discard it if we're filtering it at the tracker level
                    if (globalregistry->filter_tracker == 1) {
                        int filter_packet = 0;

                        // Look for the attributes of the packet for each filter address
                        // type.  If filtering is inverted, then lack of a match means
                        // allow the packet
                        macmap<int>::iterator fitr = globalregistry->filter_tracker_bssid.find(info.bssid_mac);
                        // In the list and we've got inverted filtering - kill it
                        if (fitr != globalregistry->filter_tracker_bssid.end() &&
                            globalregistry->filter_tracker_bssid_invert == 1)
                            filter_packet = 1;
                        // Not in the list and we've got normal filtering - kill it
                        if (fitr == globalregistry->filter_tracker_bssid.end() &&
                            globalregistry->filter_tracker_bssid_invert == 0)
                            filter_packet = 1;

                        // And continue for the others
                        fitr = globalregistry->filter_tracker_source.find(info.source_mac);
                        if (fitr != globalregistry->filter_tracker_source.end() &&
                            globalregistry->filter_tracker_source_invert == 1)
                            filter_packet = 1;
                        if (fitr == globalregistry->filter_tracker_source.end() &&
                            globalregistry->filter_tracker_source_invert == 0)
                            filter_packet = 1;

                        fitr = globalregistry->filter_tracker_dest.find(info.dest_mac);
                        if (fitr != globalregistry->filter_tracker_dest.end() &&
                            globalregistry->filter_tracker_dest_invert == 1)
                            filter_packet = 1;
                        if (fitr == globalregistry->filter_tracker_dest.end() &&
                            globalregistry->filter_tracker_dest_invert == 0)
                            filter_packet = 1;

                        if (filter_packet == 1) {
                            localdropnum++;

                            continue;
                        }

                    }

#ifdef HAVE_GPS
                    if (gps_log == 1 && info.type != packet_noise && 
                        info.type != packet_unknown && info.type != packet_phy && 
                        info.corrupt == 0) {
                        if (gpsdump.DumpPacket(&info) < 0) {
                            snprintf(status, STATUS_MAX, "%s", gpsdump.FetchError());
                            globalregistry->messagebus->InjectMessage(status, MSGFLAG_ERROR);
                        }
                    }
#endif

                    globalregistry->packetracker->ProcessPacket(info);

                    if (globalregistry->packetracker->FetchNumNetworks() > num_networks) {
                        if (sound == 1)
                            if (info.wep && wav_map.find("new_wep") != wav_map.end())
                                sound = PlaySound("new_wep");
                            else
                                sound = PlaySound("new");
                        if (speech == 1) {
                            string text;

                            if (info.wep)
                                text = ExpandSpeechString(speech_sentence_encrypted, &info, 
                                                          speech_encoding);
                            else
                                text = ExpandSpeechString(speech_sentence_unencrypted, 
                                                          &info, speech_encoding);

                            speech = SayText(MungeToShell(text).c_str());
                        }
                    }
                    num_networks = globalregistry->packetracker->FetchNumNetworks();

                    if (globalregistry->packetracker->FetchNumPackets() != num_packets) {
                        if (cur_time - last_click >= decay && sound == 1) {
                            if (globalregistry->packetracker->FetchNumPackets() - num_packets >
                                globalregistry->packetracker->FetchNumDropped() + localdropnum - num_dropped) {
                                sound = PlaySound("traffic");
                            } else {
                                sound = PlaySound("junktraffic");
                            }

                            last_click = cur_time;
                        }

                        num_packets = globalregistry->packetracker->FetchNumPackets();
                        num_noise = globalregistry->packetracker->FetchNumNoise();
                        num_dropped = globalregistry->packetracker->FetchNumDropped() + localdropnum;
                    }

                    // Send the packet info to clients if any of them are requesting it
                    if (globalregistry->kisnetserver->FetchNumClientRefs(globalregistry->pkt_prot_ref) > 0) {
                        PACKET_data pdata;
                        Protocol_Packet2Data(&info, &pdata);
                        globalregistry->kisnetserver->SendToAll(globalregistry->pkt_prot_ref, (void *) &pdata);
                    }

                    // Extract and send string info to clients if any are requesting it
                    if (info.type == packet_data && (info.encrypted == 0 || 
                                                     info.decoded == 1) &&
                        globalregistry->kisnetserver->FetchNumClientRefs(globalregistry->str_prot_ref) > 0) {
                        vector<string> strlist;
                        STRING_data sdata;

                        strlist = GetPacketStrings(&info, &packet);
                        sdata.bssid = info.bssid_mac.Mac2String();
                        sdata.sourcemac = info.source_mac.Mac2String();

                        for (unsigned int y = 0; y < strlist.size(); y++) {
                            sdata.text = strlist[y];
                            globalregistry->kisnetserver->SendToAll(globalregistry->str_prot_ref, (void *) &sdata);
                        }

                    }

                    if (fifo)
                        fifodump.DumpPacket(&info, &packet);

                    if (data_log && !(info.type == packet_noise && noise_log == 1) &&
                        !(info.corrupt != 0 && corrupt_log == 1)) {
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

                            globalregistry->messagebus->InjectMessage(status, MSGFLAG_INFO);
                        }

                        int log_packet = 1;

                        if (globalregistry->filter_dump == 1) {
                            macmap<int>::iterator fitr = globalregistry->filter_dump_bssid.find(info.bssid_mac);
                            // In the list and we've got inverted filtering - kill it
                            if (fitr != globalregistry->filter_dump_bssid.end() &&
                                globalregistry->filter_dump_bssid_invert == 1)
                                log_packet = 0;
                            // Not in the list and we've got normal filtering - kill it
                            if (fitr == globalregistry->filter_dump_bssid.end() &&
                                globalregistry->filter_dump_bssid_invert == 0)
                                log_packet = 0;

                            // And continue for the others
                            fitr = globalregistry->filter_dump_source.find(info.source_mac);
                            if (fitr != globalregistry->filter_dump_source.end() &&
                                globalregistry->filter_dump_source_invert == 1)
                                log_packet = 0;
                            if (fitr == globalregistry->filter_dump_source.end() &&
                                globalregistry->filter_dump_source_invert == 0)
                                log_packet = 0;

                            fitr = globalregistry->filter_dump_dest.find(info.dest_mac);
                            if (fitr != globalregistry->filter_dump_dest.end() &&
                                globalregistry->filter_dump_dest_invert == 1)
                                log_packet = 0;
                            if (fitr == globalregistry->filter_dump_dest.end() &&
                                globalregistry->filter_dump_dest_invert == 0)
                                log_packet = 0;
                        }

                        if (log_packet == 1) {
                            int ret = dumpfile->DumpPacket(&info, &packet);
                            if (ret < 0) {
                                snprintf(status, STATUS_MAX, "%s", dumpfile->FetchError());
                                globalregistry->messagebus->InjectMessage(status, MSGFLAG_FATAL);
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

                } else if (ret < 0 || globalregistry->fatal_condition) {
                    CatchShutdown(-1);
                }
            } // End processing new packets

        }

        globalregistry->timetracker->Tick();

        // Sleep if we have a custom additional sleep time
        if (sleepu > 0)
            usleep(sleepu);
    }

    CatchShutdown(-1);
}
