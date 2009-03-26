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

#include <sstream>

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

int speech_ipc_callback(IPC_CMD_PARMS) {
	if (parent)
		return 0;

	if (len < 5) {
		_MSG("IPC speech handler got a short text message", MSGFLAG_ERROR);
		return 0;
	}

	// Make sure it's shell-clean, we shouldn't be sent something that isn't,
	// but why risk it?
	MungeToShell((char *) data, len);
	char spk_call[2048];
	snprintf(spk_call, 2048, "echo \"(SayText \\\"%s\\\")\" | %s "
			 ">/dev/null 2>/dev/null", (char *) data, 
			 ((SpeechControl *) auxptr)->FetchPlayer());

	// Blocking system call, this will block the ack until its done.  This
	// is fine.
	system(spk_call);

	return 0;
}

SpeechControl::SpeechControl() {
    fprintf(stderr, "*** SpeechControl() called with no global registry\n");
    globalreg = NULL;
}

SpeechControl::SpeechControl(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

	speech_enable = -1;

    speech_encoding = 0;

    // Process config file
    if (globalreg->kismet_config->FetchOpt("speech") == "true") {
        if (globalreg->kismet_config->FetchOpt("festival") != "") {
            festival = strdup(globalreg->kismet_config->FetchOpt("festival").c_str());
            speech_enable = 1;

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
                _MSG("Speech requested but no speech templates given "
					 "in the config file.  Speech will be disabled.", MSGFLAG_ERROR);
                speech_enable = 0;
            }

            speech_sentence_encrypted = 
				globalreg->kismet_config->FetchOpt("speech_encrypted");
            speech_sentence_unencrypted = 
				globalreg->kismet_config->FetchOpt("speech_unencrypted");
        } else {
            _MSG("Speech requested but no path to festival has been "
				 "specified.  Speech will be disabled", MSGFLAG_ERROR);
            speech_enable = 0;
        }
    } else if (speech_enable == -1) {
        speech_enable = 0;
    }
    

	speech_remote = new IPCRemote(globalreg, "speech daemon");
	speech_ipc_id = 
		speech_remote->RegisterIPCCmd(&speech_ipc_callback, NULL, this, "SPEECH");
}

SpeechControl::~SpeechControl() {
    Shutdown();
}

int SpeechControl::SayText(string in_text) {
	int ret = 0;

	if (speech_enable <= 0)
		return 0;

	// Spawn the child proc if we need to
	if (speech_remote->FetchSpawnPid() == 0) {
		ret = SpawnChildProcess();
	}
	
	// Don't send it until we're not blocked
	if (globalreg->fatal_condition || speech_remote->FetchReadyState() == 0)
		return ret;

    char snd[1024];

    snprintf(snd, 1024, "%s\n", in_text.c_str());
    MungeToShell(snd, 1024);

	ipc_packet *pack = 
		(ipc_packet *) malloc(sizeof(ipc_packet) + strlen(snd) + 1);
	char *msg = (char *) pack->data;

	snprintf(msg, strlen(snd), "%s", snd);

	pack->data_len = strlen(snd) + 1;

	pack->ipc_cmdnum = speech_ipc_id;
	pack->ipc_ack = 0;

	// Push it via the IPC
	speech_remote->SendIPC(pack);

    return 1;
}

void SpeechControl::Shutdown() {
	speech_remote->ShutdownIPC(NULL);
	globalreg->RemovePollableSubsys(speech_remote);
	delete speech_remote;
}

int SpeechControl::SpawnChildProcess() {
	ostringstream osstr;
	
	int ret = speech_remote->SpawnIPC();

	if (ret < 0 || globalreg->fatal_condition) {
		_MSG("SpeechControl failed to create an IPC child process", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	osstr << "SpeechControl spawned IPC child process pid " <<
		speech_remote->FetchSpawnPid();
	_MSG(osstr.str(), MSGFLAG_INFO);

	return 1;
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

