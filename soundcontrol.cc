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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "soundcontrol.h"
#include "messagebus.h"
#include "configfile.h"

SoundControl::SoundControl() {
    fprintf(stderr, "*** SoundControl() called with no global registry\n");
    globalreg = NULL;
}

SoundControl::SoundControl(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

	sound_enable = -1;

    if (globalreg->kismet_config->FetchOpt("sound") == "true") {
        if (globalreg->kismet_config->FetchOpt("soundplay") != "") {
            player = globalreg->kismet_config->FetchOpt("soundplay");

            if (globalreg->kismet_config->FetchOpt("soundopts") != "")
                player += " " + globalreg->kismet_config->FetchOpt("soundopts");

            sound_enable = 1;

            if (globalreg->kismet_config->FetchOpt("sound_new") != "")
                wav_map["new"] = globalreg->kismet_config->FetchOpt("sound_new");
            if (globalreg->kismet_config->FetchOpt("sound_new_wep") != "")
                wav_map["new_wep"] = globalreg->kismet_config->FetchOpt("sound_new_wep");
            if (globalreg->kismet_config->FetchOpt("sound_traffic") != "")
                wav_map["traffic"] = globalreg->kismet_config->FetchOpt("sound_traffic");
            if (globalreg->kismet_config->FetchOpt("sound_junktraffic") != "")
                wav_map["junktraffic"] = globalreg->kismet_config->FetchOpt("sound_traffic");
            if (globalreg->kismet_config->FetchOpt("sound_gpslock") != "")
                wav_map["gpslock"] = globalreg->kismet_config->FetchOpt("sound_gpslock");
            if (globalreg->kismet_config->FetchOpt("sound_gpslost") != "")
                wav_map["gpslost"] = globalreg->kismet_config->FetchOpt("sound_gpslost");
            if (globalreg->kismet_config->FetchOpt("sound_alert") != "")
                wav_map["alert"] = globalreg->kismet_config->FetchOpt("sound_alert");

        } else {
            globalreg->messagebus->InjectMessage("Sound alerts enabled but no sound player specified, "
                                                 "sound will be disabled", MSGFLAG_ERROR);
            sound_enable = 0;
        }
    } else if (sound_enable == -1) {
        sound_enable = 0;
    }
    
}

SoundControl::~SoundControl() {
    Shutdown();
}

int SoundControl::PlaySound(string in_text) {
    char snd[1024];

    if (sound_enable <= 0)
        return 0;
    
    snprintf(snd, 1024, "%s\n", in_text.c_str());

    if (write(fds[1], snd, strlen(snd)) < 0) {
        globalreg->messagebus->InjectMessage("Write error on sending data to sound "
                                             "child process.  Attempting to restart sound "
                                             "process", MSGFLAG_ERROR);

        if (SpawnChildProcess() < 0)
            return -1;

        if (write(fds[1], snd, strlen(snd)) < 0) {
            globalreg->messagebus->InjectMessage("Continued write error after restarting sound "
                                                 "process.  Sound will be disabled.",
                                                 MSGFLAG_ERROR);
            sound_enable = 0;
        }
    }

    return 1;
}

void SoundControl::Shutdown() {
    if (childpid > 0) {
        close(fds[1]);
        kill(childpid, 9);
    }
}

int SoundControl::SpawnChildProcess() {
    if (pipe(fds) == -1) {
        globalreg->messagebus->InjectMessage("Unable to create pipe for sound.  Disabling sound.",
                                             MSGFLAG_ERROR);
        sound_enable = 0;
    } else {
        childpid = fork();

        if (childpid < 0) {
            globalreg->messagebus->InjectMessage("Unable to fork speech control process.  Disabling speech.",
                                                 MSGFLAG_ERROR);
            sound_enable = 0;
        } else if (childpid == 0) {
            SoundChild();
            exit(0);
        }

        close(fds[0]);
    }

    return 1;
}

void SoundControl::SoundChild() {
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

            if (wav_map.size() == 0)
                snprintf(snd, 1024, "%s", data);
            if (wav_map.find(data) != wav_map.end())
                snprintf(snd, 1024, "%s", wav_map[data].c_str());
            else
                continue;

            char plr[1024];
            snprintf(plr, 1024, "%s", player.c_str());

            harvested = 0;
            if ((sndpid = fork()) == 0) {
                // Suppress errors
                int nulfd = open("/dev/null", O_RDWR);
                dup2(nulfd, 1);
                dup2(nulfd, 2);

                char * const echoarg[] = { plr, snd, NULL };
                execve(echoarg[0], echoarg, NULL);
            }
        }
        data[0] = '\0';
    }

}

