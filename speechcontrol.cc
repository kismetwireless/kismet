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
#include "speechcontrol.h"
#include "messagebus.h"
#include "configfile.h"

char speech_alphabet[2][36][12]={
    {"owl pha", "Bravo", "Charlie", "Deltah", "Echo", "Foxtrot", "Golf",
    "Hotel", "India", "Juliet", "Keylo", "line-ah", "Mike", "November",
    "Oscar", "Pawpa", "qwa-bec", "Romeo", "Sierra", "Tango", "you-niform",
    "vickk-tour", "Whiskey", "ecks-ray", "Yankee", "Zulu",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "niner"},
    {"ae", "BEE", "SEE", "DEE", "EAE", "EF", "GEE", "H", "EYE", "JAY", "KAY",
    "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
};

SpeechControl::SpeechControl() {
    fprintf(stderr, "*** SpeechControl() called with no global registry\n");
    globalreg = NULL;
}

SpeechControl::SpeechControl(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    speech_encoding = 0;

    // Process config file
    if (globalreg->kismet_config->FetchOpt("speech") == "true") {
        if (globalreg->kismet_config->FetchOpt("festival") != "") {
            festival = strdup(globalreg->kismet_config->FetchOpt("festival").c_str());
            globalreg->speech_enable = 1;

            string speechtype = globalreg->kismet_config->FetchOpt("speech_type");

            if (!strcasecmp(speechtype.c_str(), "nato"))
                speech_encoding = SPEECH_ENCODING_NATO;
            else if (!strcasecmp(speechtype.c_str(), "spell"))
                speech_encoding = SPEECH_ENCODING_SPELL;
            else
                speech_encoding = SPEECH_ENCODING_NORMAL;

            // Make sure we have encrypted text lines
            if (globalreg->kismet_config->FetchOpt("speech_encrypted") == "" || 
                globalreg->kismet_config->FetchOpt("speech_unencrypted") == "") {
                globalreg->messagebus->InjectMessage("Speech requested but no speech templates given "
                                                     "in the config file.  Speech will be disabled.", 
                                                     MSGFLAG_ERROR);
                globalreg->speech_enable = 0;
            }

            speech_sentence_encrypted = globalreg->kismet_config->FetchOpt("speech_encrypted");
            speech_sentence_unencrypted = globalreg->kismet_config->FetchOpt("speech_unencrypted");
        } else {
            globalreg->messagebus->InjectMessage("Speech requested but no path to festival has been "
                                                 "specified.  Speech will be disabled",
                                                 MSGFLAG_ERROR);
            globalreg->speech_enable = 0;
        }
    } else if (globalreg->speech_enable == -1) {
        globalreg->speech_enable = 0;
    }
    
}

SpeechControl::~SpeechControl() {
    Shutdown();
}

int SpeechControl::SayText(string in_text) {
    char snd[1024];

    if (globalreg->speech_enable <= 0)
        return -1;

    snprintf(snd, 1024, "%s\n", in_text.c_str());
    MungeToShell(snd, 1024);

    if (write(fds[1], snd, strlen(snd)) < 0) {
        globalreg->messagebus->InjectMessage("Write error on sending data to speech "
                                             "child process.  Attempting to restart speech "
                                             "process", MSGFLAG_ERROR);

        if (SpawnChildProcess() < 0)
            return -1;

        if (write(fds[1], snd, strlen(snd)) < 0) {
            globalreg->messagebus->InjectMessage("Continued write error after restarting speech "
                                                 "process.  Speech will be disabled.",
                                                 MSGFLAG_ERROR);
            globalreg->speech_enable = 0;
        }
    }

    return 1;
}

void SpeechControl::Shutdown() {
    if (childpid > 0) {
        close(fds[1]);
        kill(childpid, 9);
    }
}

int SpeechControl::SpawnChildProcess() {
    if (pipe(fds) == -1) {
        globalreg->messagebus->InjectMessage("Unable to create pipe for speech.  Disabling speech.",
                                             MSGFLAG_ERROR);
        globalreg->speech_enable = 0;
    } else {
        childpid = fork();

        if (childpid < 0) {
            globalreg->messagebus->InjectMessage("Unable to fork speech control process.  Disabling speech.",
                                                 MSGFLAG_ERROR);
            globalreg->speech_enable = 0;
        } else if (childpid == 0) {
            SpeechChild();
            exit(0);
        }

        close(fds[0]);
    }

    return 1;
}

void SpeechControl::SpeechChild() {
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

string SpeechControl::EncodeSpeechString(string in_str) {
    if (speech_encoding != SPEECH_ENCODING_NATO && 
        speech_encoding != SPEECH_ENCODING_SPELL)
        return in_str;

    string encodestr;
    for (unsigned int x = 0; x < in_str.length(); x++) {
        char chr = toupper(in_str[x]);
        int pos;

        // Find our encoding in the array
        if (chr >= '0' && chr <= '9')
            pos = 26 + (chr - '0');
        else if (chr >= 'A' && chr <= 'Z')
            pos = chr - 'A';
        else
            continue;

        if (speech_encoding == SPEECH_ENCODING_NATO) {
            encodestr += speech_alphabet[0][pos];
        } else if (speech_encoding == SPEECH_ENCODING_SPELL) {
            encodestr += speech_alphabet[1][pos];
        }

        encodestr += "., ";
    }

    return encodestr;
}

