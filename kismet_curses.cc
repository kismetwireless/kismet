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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "getopt.h"
#include "tcpclient.h"
#include "frontend.h"
#include "cursesfront.h"
#include "panelfront.h"
#include "configfile.h"
#include "speech.h"

#ifndef exec_name
char *exec_name;
#endif

enum gui_type {
    gui_ncurses, gui_panel
    };

const char *config_base = "kismet.conf";
const char *uiconfig_base = "kismet_ui.conf";

TcpClient kismet_serv;
Frontend *gui;
gui_type guitype;
char *configfile;
char *uiconfigfile;
char *server = NULL;
int sound = -1;
int speech = -1;
int speech_encoding = 0;
string speech_sentence_encrypted, speech_sentence_unencrypted;
unsigned int metric = 0;
unsigned int reconnect = 0;

int group_track = 0;
string configdir, groupfile;
FILE *group_file = NULL;

// Pipe file descriptor pairs and fd's
int soundpair[2];
int speechpair[2];
pid_t soundpid = -1, speechpid = -1;

// Catch our interrupt
void CatchShutdown(int sig) {

    // Kill our sound players
    if (soundpid > 0)
        kill(soundpid, 9);
    if (speechpid > 0)
        kill(speechpid, 9);

    if (group_track) {
        if ((group_file = fopen(groupfile.c_str(), "w")) == NULL) {
            fprintf(stderr, "WARNING: Unable to open '%s' for writing, groups will not be saved.\n",
                    groupfile.c_str());
        } else {
            gui->WriteGroupMap(group_file);
        }
    }

    int ret = 0;
    if (gui != NULL && sig != SIGHUP)
        gui->EndDisplay();

    if (kismet_serv.Valid() == 0)
        ret = 5;

    exit(ret);
}

int Usage(char *argv) {
    printf("Usage: %s [OPTION]\n", argv);
    printf("Most (or all) of these options can (and should) be configured via the\n"
           "kismet_ui.conf global config file, but can be overridden here.\n");
    printf(
           "  -f, --config-file <file>     Use alternate config file\n"
           "  -u, --ui-config-file <file>  Use alternate UI config file\n"
           "  -q, --quiet                  Don't play sounds\n"
           "  -s, --server <host:port>     Connect to Kismet host and port\n"
           "  -g, --gui <type>             GUI type to create (curses, panel)\n"
           "  -c, --columns <list>         Columns to display initially (comma seperated)\n"
           "  -r, --reconnect              Try to reconnect after the client/server connection\n"
           "                               fails.\n"
           "  -C, --client-columns <list>  Columns to display for client info\n"
           "  -v, --version                Kismet version\n"
           "  -h, --help                   What do you think you're reading?\n");
    exit(1);
}

// sigpipe handler
void PipeHandler(int sig) {
    exit(0);
}

// Subprocess sound handler
void SoundHandler(int *fds, const char *player, map<string, string> soundmap) {
    int read_sock = fds[0];

    close(fds[1]);

    signal(SIGPIPE, PipeHandler);

    fd_set rset;

    char data[1024];

    pid_t sndpid = -1;
    int harvested = 1;

    while (1) {
        FD_ZERO(&rset);
        FD_SET(read_sock, &rset);
        char *end;

        memset(data, 0, 1024);

        if (harvested == 0) {
            // We consider a wait error to be a sign that the child pid died
            // so we flag it as harvested and keep on going
            pid_t harvestpid = waitpid(sndpid, NULL, WNOHANG);
            if (harvestpid == -1 || harvestpid == sndpid)
                harvested = 1;
        }

        struct timeval tim;
        tim.tv_sec = 1;
        tim.tv_usec = 0;

        if (select(read_sock + 1, &rset, NULL, NULL, &tim) < 0) {
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
                fclose(stdout);
                fclose(stderr);

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

        struct timeval tim;
        tim.tv_sec = 1;
        tim.tv_usec = 0;

        if (select(read_sock + 1, &rset, NULL, NULL, &tim) < 0) {
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


int PlaySound(string in_sound) {

    char snd[1024];

    snprintf(snd, 1024, "%s\n", in_sound.c_str());

    if (write(soundpair[1], snd, strlen(snd)) < 0) {
        char status[STATUS_MAX];
        snprintf(status, STATUS_MAX,
                 "ERROR: Could not write to sound pipe.  Stopping sound.");
        gui->WriteStatus(status);

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
        snprintf(status, STATUS_MAX,
                 "ERROR: Could not write to speech pipe.  Stopping speech.");
        gui->WriteStatus(status);

        return 0;
    }

    return 1;
}

int main(int argc, char *argv[]) {
    exec_name = argv[0];

    time_t last_draw = time(0);
    char status[STATUS_MAX];

    const char *reqgui = NULL;

    string sndplay;
    const char *festival = NULL;

    const char *columns = NULL;
    const char *clientcolumns = NULL;

    map<string, string> wav_map;

    char guihost[1024];
    int guiport = -1;

    int gpsmode = -1;

    configfile = NULL;
    uiconfigfile = NULL;

    char *ap_manuf_name = NULL, *client_manuf_name = NULL;
    FILE *manuf_data;

    static struct option long_options[] = {   /* options table */
        { "config-file", required_argument, 0, 'f' },
        { "ui-config-file", required_argument, 0, 'u' },
        { "quiet", no_argument, 0, 'q' },
        { "server", required_argument, 0, 's' },
        { "help", no_argument, 0, 'h' },
        { "version", no_argument, 0, 'v' },
        { "columns", required_argument, 0, 'c' },
        { "client-columns", required_argument, 0, 'C'},
        { "reconnct", no_argument, 0, 'r' },
        { 0, 0, 0, 0 }
    };
    int option_index;
    int decay = 5;

    // Catch the interrupt handler to shut down
    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGPIPE, SIG_IGN);

    while(1) {
        int r = getopt_long(argc, argv, "f:c:qs:hvg:u:r",
                            long_options, &option_index);
        if (r < 0) break;
        switch(r) {
        case 'f':
            // Config path
            configfile = optarg;
            fprintf(stderr, "Using alternate config file: %s\n", configfile);
            break;
        case 'u':
            // UI config path
            uiconfigfile = optarg;
            fprintf(stderr, "Using alternate UI config file: %s\n", uiconfigfile);
            break;
        case 'q':
            sound = 0;
            break;
        case 'g':
            reqgui = optarg;
            break;
        case 'v':
            fprintf(stderr, "Kismet curses %d.%d.%d\n", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY);
            break;
        case 's':
            server = optarg;
            fprintf(stderr, "Using server: %s\n", server);
            break;
        case 'c':
            columns = optarg;
            break;
        case 'C':
            clientcolumns = optarg;
            break;
        case 'r':
            reconnect = 1;
            break;
        default:
            Usage(argv[0]);
            break;
        }
    }

    ConfigFile *server_conf = new ConfigFile;
    ConfigFile *gui_conf = new ConfigFile;

    // If we haven't gotten a command line config option...
    if (configfile == NULL) {
        configfile = (char *) malloc(1024*sizeof(char));
        snprintf(configfile, 1024, "%s/%s", SYSCONF_LOC, config_base);
    }

    if (uiconfigfile == NULL) {
        uiconfigfile = (char *) malloc(1024*sizeof(char));
        snprintf(uiconfigfile, 1024, "%s/%s", SYSCONF_LOC, uiconfig_base);
    }

    // Parse the config and load all the values from it and/or our command
    // line options.  This is a little soupy but it does the trick.
    if (server_conf->ParseConfig(configfile) < 0) {
        fprintf(stderr, "Unable to parse config file.");
        exit(1);
    }

    if (gui_conf->ParseConfig(uiconfigfile) < 0) {
        fprintf(stderr, "Unable to parse ui config file.");
        exit(1);
    }

    if (server_conf->FetchOpt("configdir") != "") {
        configdir = server_conf->ExpandLogPath(server_conf->FetchOpt("configdir"), "", "", 0, 1);
    } else {
        fprintf(stderr, "FATAL:  No 'configdir' option in the config file.\n");
        exit(1);
    }

    if (server_conf->FetchOpt("groupmap") != "") {
        // Explode the group map path
        groupfile = server_conf->ExpandLogPath(configdir + server_conf->FetchOpt("groupmap"),
                                              "", "", 0, 1);
        group_track = 1;
    }

    if (server_conf->FetchOpt("metric") == "true") {
        metric = 1;
    }

    if (reqgui == NULL) {
        if (gui_conf->FetchOpt("gui") == "") {
            fprintf(stderr, "ERROR:  No gui given in config file and none given on the command line.\n");
            exit(1);
        }

        reqgui = gui_conf->FetchOpt("gui").c_str();
    }

    if (!strcasecmp(reqgui, "curses")) {
#if defined(HAVE_LIBNCURSES) && defined(BUILD_CURSES)
        gui = new NCurseFront;
        guitype = gui_ncurses;
#else
        fprintf(stderr, "ERROR:  Curses support not compiled in.\n");
        exit(1);
#endif
    } else if (!strcasecmp(reqgui, "panel")) {
#if defined(HAVE_LIBPANEL) && defined(BUILD_PANEL) && defined(HAVE_LIBNCURSES)
        gui = new PanelFront;
        guitype = gui_panel;
#else
        fprintf(stderr, "ERROR:  Panels support not compiled in.\n");
        exit(1);
#endif
    } else {
        fprintf(stderr, "ERROR:  Unknown GUI type requested ('%s')\n", reqgui);
        exit(1);
    }

    if (columns == NULL) {
        if (gui_conf->FetchOpt("columns") == "") {
            fprintf(stderr, "FATAL:  No columns in the config file and none given on the command line.\n");
            exit(1);
        }

        columns = gui_conf->FetchOpt("columns").c_str();
    }

    if (clientcolumns == NULL) {
        if (gui_conf->FetchOpt("clientcolumns") == "") {
            fprintf(stderr, "FATAL: No client columns in the config file and none given on the command line.\n");
            exit(1);
        }

        clientcolumns = gui_conf->FetchOpt("clientcolumns").c_str();
    }

    if (server == NULL) {
        server = (char *) gui_conf->FetchOpt("host").c_str();
    }

    if (gui_conf->FetchOpt("sound") == "true" && sound == -1) {
        if (gui_conf->FetchOpt("soundplay") != "") {
            sndplay = gui_conf->FetchOpt("soundplay");
            sound = 1;

            if (gui_conf->FetchOpt("soundopts") != "")
                sndplay += " " + gui_conf->FetchOpt("soundopts");

            if (gui_conf->FetchOpt("sound_new") != "")
                wav_map["new"] = gui_conf->FetchOpt("sound_new");
            if (gui_conf->FetchOpt("sound_traffic") != "")
                wav_map["traffic"] = gui_conf->FetchOpt("sound_traffic");
            if (gui_conf->FetchOpt("sound_junktraffic") != "")
                wav_map["junktraffic"] = gui_conf->FetchOpt("sound_junktraffic");
            if (gui_conf->FetchOpt("sound_gpslock") != "")
                wav_map["gpslock"] = gui_conf->FetchOpt("sound_gpslock");
            if (gui_conf->FetchOpt("sound_gpslost") != "")
                wav_map["gpslost"] = gui_conf->FetchOpt("sound_gpslost");
            if (gui_conf->FetchOpt("sound_alert") != "")
                wav_map["alert"] = gui_conf->FetchOpt("sound_alert");

        } else {
            fprintf(stderr, "ERROR:  Sound alerts enabled but no sound playing binary specified.\n");
            sound = 0;
        }
    } else if (sound == -1)
        sound = 0;

    /* Added by Shaw Innes 17/2/02 */
    if (gui_conf->FetchOpt("speech") == "true" && speech == -1) {
        if (gui_conf->FetchOpt("festival") != "") {
            festival = gui_conf->FetchOpt("festival").c_str();
            speech = 1;

            string speechtype = gui_conf->FetchOpt("speech_type");

            if (!strcasecmp(speechtype.c_str(), "nato"))
                speech_encoding = SPEECH_ENCODING_NATO;
            else if (!strcasecmp(speechtype.c_str(), "spell"))
                speech_encoding = SPEECH_ENCODING_SPELL;
            else
                speech_encoding = SPEECH_ENCODING_NORMAL;

            // Make sure we have encrypted text lines
            if (gui_conf->FetchOpt("speech_encrypted") == "" || gui_conf->FetchOpt("speech_unencrypted") == "") {
                fprintf(stderr, "ERROR:  Speech request but speech_encrypted or speech_unencrypted line missing.\n");
                speech = 0;
            }

            speech_sentence_encrypted = gui_conf->FetchOpt("speech_encrypted");
            speech_sentence_unencrypted = gui_conf->FetchOpt("speech_unencrypted");

        } else {
            fprintf(stderr, "ERROR: Speech alerts enabled but no path to festival has been specified.\n");
            speech = 0;
        }
    } else if (speech == -1)
        speech = 0;

    if (gui_conf->FetchOpt("decay") != "") {
        if (sscanf(gui_conf->FetchOpt("decay").c_str(), "%d", &decay) != 1) {
            fprintf(stderr, "FATAL:  Illegal config file value for decay.\n");
            exit(1);
        }
    }

    if (server_conf->FetchOpt("ap_manuf") != "") {
        ap_manuf_name = strdup(server_conf->FetchOpt("ap_manuf").c_str());
    } else {
        fprintf(stderr, "WARNING:  No ap_manuf file specified, AP manufacturers and defaults will not be detected.\n");
    }

    if (server_conf->FetchOpt("client_manuf") != "") {
        client_manuf_name = strdup(server_conf->FetchOpt("client_manuf").c_str());
    } else {
        fprintf(stderr, "WARNING:  No client_manuf file specified.  Client manufacturers will not be detected.\n");
    }

    if (sscanf(server, "%1024[^:]:%d", guihost, &guiport) != 2) {
        fprintf(stderr, "FATAL:  Invalid server (%s) specified (host:port required)\n",
               server);
        exit(1);
    }

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

    if (group_track) {
        if (stat(groupfile.c_str(), &fstat) == -1) {
            fprintf(stderr, "NOTICE:  Group file did not exist, it will be created.\n");
        } else {
            if ((group_file = fopen(groupfile.c_str(), "r")) == NULL) {
                fprintf(stderr, "FATAL:  Could not open group file '%s': %s\n",
                        groupfile.c_str(), strerror(errno));
                exit(1);
            }

            gui->ReadGroupMap(group_file);

            fclose(group_file);
        }
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

    if (kismet_serv.Connect(guiport, guihost) < 0) {
        fprintf(stderr, "FATAL:  Could not connect to %s:%d.\n", guihost, guiport);
        CatchShutdown(-1);
    }

    time_t serv_start = 0;
    // Spin for 15 seconds until we get a header from the server, or die
    fprintf(stderr, "Looking for startup info from %s:%d...", guihost, guiport);
    int header_count = 0;

    while (serv_start == 0) {

        fprintf(stderr, ".");

        if (kismet_serv.Valid())
            kismet_serv.Poll();

        if (header_count++ >= 20) {
            fprintf(stderr, " failed.\nFATAL:  Did not get startup info from %s:%d within 20 seconds.\n",
                    guihost, guiport);
            CatchShutdown(-1);
        }

        serv_start = kismet_serv.FetchStart();

        sleep(1);
    }

    fprintf(stderr, " found.\nConnected to Kismet server %d.%d.%d on %s:%d\n",
            kismet_serv.FetchMajor(), kismet_serv.FetchMinor(), kismet_serv.FetchTiny(),
            guihost, guiport);

    map<string, string> prefs;

    prefs["columns"] = columns;
    prefs["clientcolumns"] = clientcolumns;

    if (gui_conf->FetchOpt("apm") == "true")
        prefs["apm"] = "true";

    prefs["simpleborders"] = gui_conf->FetchOpt("simpleborders");

    prefs["color"] = gui_conf->FetchOpt("color");
    prefs["backgroundcolor"] = gui_conf->FetchOpt("backgroundcolor");
    prefs["textcolor"] = gui_conf->FetchOpt("textcolor");
    prefs["bordercolor"] = gui_conf->FetchOpt("bordercolor");
    prefs["titlecolor"] = gui_conf->FetchOpt("titlecolor");
    prefs["wepcolor"] = gui_conf->FetchOpt("wepcolor");
    prefs["factorycolor"] = gui_conf->FetchOpt("factorycolor");
    prefs["opencolor"] = gui_conf->FetchOpt("opencolor");
    prefs["monitorcolor"] = gui_conf->FetchOpt("monitorcolor");

    // We're done with the config files, delete their memory allocations
    delete server_conf;
    delete gui_conf;
    server_conf = gui_conf = NULL;

    gui->AddPrefs(prefs);

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
            gui->ReadAPManufMap(manuf_data);
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
            gui->ReadClientManufMap(manuf_data);
            fclose(manuf_data);
        }

        free(client_manuf_name);
    }

    gui->AddClient(&kismet_serv);

    gui->InitDisplay(decay, serv_start);

    snprintf(status, STATUS_MAX, "Connected to Kismet server version %d.%d.%d on %s:%d",
             kismet_serv.FetchMajor(), kismet_serv.FetchMinor(), kismet_serv.FetchTiny(),
             guihost, guiport);
    gui->WriteStatus(status);

    int num_networks = 0, num_packets = 0, num_noise = 0, num_dropped = 0;

    time_t last_click = time(0);

    fd_set read_set;
    FD_ZERO(&read_set);

    unsigned int max_fd = 0;
    FD_SET(fileno(stdin), &read_set);

    vector<TcpClient *> client_list;
    TcpClient *primary_client;

    while (1) {
        fd_set rset;
        FD_ZERO(&rset);
        rset = read_set;

        // Grab the list of clients and set them all in the readset
        gui->FetchClients(&client_list);
        primary_client = gui->FetchPrimaryClient();

        for (unsigned int cli = 0; cli < client_list.size(); cli++) {
            if (client_list[cli]->Valid()) {
                unsigned int client_descrip = client_list[cli]->FetchDescriptor();
                FD_SET(client_descrip, &rset);
                if (client_descrip > max_fd)
                    max_fd = client_descrip;
            }
        }

        struct timeval tim;
        tim.tv_sec = 0;
        tim.tv_usec = 500000;

        if (select(max_fd + 1, &rset, NULL, NULL, &tim) < 0) {
            if (errno != EINTR) {
                snprintf(status, STATUS_MAX,
                         "ERROR: select() error %d (%s)", errno, strerror(errno));
                gui->WriteStatus(status);
            }
        }

        // Handle user data
        if (FD_ISSET(fileno(stdin), &rset)) {
            int poll_ret;
            poll_ret = gui->Poll();

            if (poll_ret == FE_QUIT)
                CatchShutdown(-1);
        }

        // Reset our counters so we can add the different servers
        num_networks = 0;
        num_packets = 0;
        num_noise = 0;
        num_dropped = 0;

        for (unsigned int cli = 0; cli < client_list.size(); cli++) {
            // If we have incoming data...
            TcpClient *tcpcli = client_list[cli];
            unsigned int client_descrip = tcpcli->FetchDescriptor();
            if (tcpcli->Valid()) {
                if (FD_ISSET(client_descrip, &rset)) {
                    int pollret;
                    if ((pollret = tcpcli->Poll()) < 0) {
                        snprintf(status, STATUS_MAX, "%s:%d TCP error: %s",
                                 tcpcli->FetchHost(), tcpcli->FetchPort(), tcpcli->FetchError());
                        gui->WriteStatus(status);

                        // not any longer - clients are dynamically set in rset each time from
                        // the list of clients now
                        // Remove the client descriptor if we're not valid anymore
                        // FD_CLR(client_descrip, &read_set);

                        if (reconnect) {
                            snprintf(status, STATUS_MAX, "Will attempt to reconnect to %s:%d",
                                     tcpcli->FetchHost(), tcpcli->FetchPort());
                            gui->WriteStatus(status);
                        }

                    }

                    if (pollret != 0) {
                        if (pollret == CLIENT_ALERT)
                            if (sound == 1)
                                sound = PlaySound("alert");

                        if (strlen(tcpcli->FetchStatus()) != 0) {
                            gui->WriteStatus(tcpcli->FetchStatus());
                            // gui->DrawDisplay();
                        }

                        // The GPS only gets updated for the primary client
                        if (tcpcli == primary_client) {
                            if (tcpcli->FetchMode() == 0 && gpsmode != 0) {
                                if (sound == 1 && gpsmode != -1)
                                    sound = PlaySound("gpslost");
                                gpsmode = 0;
                            } else if (tcpcli->FetchMode() != 0 && gpsmode == 0) {
                                if (sound == 1 && gpsmode != -1)
                                    sound = PlaySound("gpslock");
                                gpsmode = 1;
                            }
                        }

                        if (tcpcli->FetchDeltaNumNetworks() != 0) {
                            if (sound == 1) {
                                sound = PlaySound("new");
                            }

                            if (speech == 1) {
                                string text;

                                wireless_network *newnet = tcpcli->FetchLastNewNetwork();

                                if (newnet != NULL) {
                                    if (newnet->wep)
                                        text = ExpandSpeechString(speech_sentence_encrypted, newnet, speech_encoding);
                                    else
                                        text = ExpandSpeechString(speech_sentence_unencrypted, newnet, speech_encoding);

                                    speech = SayText(text.c_str());
                                }
                            }
                        }

                        num_networks += tcpcli->FetchNumNetworks();
                        num_packets += tcpcli->FetchNumPackets();
                        num_noise += tcpcli->FetchNumNoise();
                        num_dropped += tcpcli->FetchNumDropped();

                        if (tcpcli->FetchDeltaNumPackets() != 0) {
                            if (time(0) - last_click >= decay && sound == 1) {
                                if (tcpcli->FetchDeltaNumPackets() > tcpcli->FetchDeltaNumDropped()) {
                                    sound = PlaySound("traffic");
                                } else {
                                    sound = PlaySound("junktraffic");
                                }

                                last_click = time(0);
                            }
                        }
                    }
                }
            } else {
                // If we're supposed to try to reconnect and we're invalid, do so
                if (reconnect) {
                    if (tcpcli->Connect(guiport, guihost) >= 0) {
                        client_descrip = tcpcli->FetchDescriptor();
                        // FD_SET(client_descrip, &read_set);
                        if (client_descrip > max_fd)
                            max_fd = client_descrip;

                        snprintf(status, STATUS_MAX, "Reconnected to %s:%d.",
                                 tcpcli->FetchHost(), tcpcli->FetchPort());
                        gui->WriteStatus(status);
                    }
                }
            }
        }

        // Draw if it's time
        if (time(0) != last_draw) {
            // Let the UI do housekeeping
            gui->Tick();

            // Force a display event
            gui->DrawDisplay();
            last_draw = time(0);
        } else {
            // If we're tainted, update even if it isn't time.  We don't tick since
            // that only happens once a second.
            gui->DrawDisplay();
        }
    }
}

