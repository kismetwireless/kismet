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

#include "soundcontrol.h"
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

int sound_ipc_callback(IPC_CMD_PARMS) {
	soundcontrol_ipc_frame *f;

	if (parent)
		return 0;

	if (len < (int) sizeof(soundcontrol_ipc_frame)) {
		_MSG("IPC sound handler got a short sound message", MSGFLAG_ERROR);
		return 0;
	}

	f = (soundcontrol_ipc_frame *) data;

	// Don't play events that are too old
	if (time(0) - f->timestamp > 2)
		return 0;

	int ret = ((SoundControl *) auxptr)->LocalPlay(f->player, f->msg);

	if (ret < 0)
		return -1;

	return 0;
}

int speech_ipc_callback(IPC_CMD_PARMS) {
	soundcontrol_ipc_frame *f;

	if (parent)
		return 0;

	if (len < (int) sizeof(soundcontrol_ipc_frame)) {
		_MSG("IPC sound handler got a short sound message", MSGFLAG_ERROR);
		return 0;
	}

	f = (soundcontrol_ipc_frame *) data;

	// Don't play events that are too old
	if (time(0) - f->timestamp > 2)
		return 0;

	int ret = ((SoundControl *) auxptr)->LocalSpeech(f->player, f->opt, f->msg);

	if (ret < 0)
		return -1;

	return 0;
}

SoundControl::SoundControl() {
    fprintf(stderr, "*** SoundControl() called with no global registry\n");
    globalreg = NULL;
}

SoundControl::SoundControl(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

	sound_enable = 0;
	speech_enable = 0;
	speech_festival = 0;

	if ((nulfd = open("/dev/null", O_RDWR)) < 0) {
		_MSG("SoundControl() opening /dev/null failed (" + string(strerror(errno)) +
			 ") something is weird with your system.)", MSGFLAG_ERROR);
	}

	// Always spawn the sound control daemon
	sound_remote = new IPCRemote(globalreg, "sound daemon");
	sound_ipc_id = 
		sound_remote->RegisterIPCCmd(&sound_ipc_callback, NULL, this, "SOUND");
	speech_ipc_id = 
		sound_remote->RegisterIPCCmd(&speech_ipc_callback, NULL, this, "SPEECH");

	shutdown = 0;
}

SoundControl::~SoundControl() {
    Shutdown();
}

void SoundControl::SetSpeechEncode(string in_encode) {
	string lenc = StrLower(in_encode);
	
	if (lenc == "nato")
		speech_encoding = SPEECH_ENCODING_NATO;
	else if (lenc == "spell")
		speech_encoding = SPEECH_ENCODING_SPELL;
	else
		speech_encoding = SPEECH_ENCODING_NORMAL;
}

int SoundControl::PlaySound(string in_text) {
	// fprintf(stderr, "debug - playsound %s enable %d\n", in_text.c_str(), sound_enable);
	if (sound_enable <= 0)
		return 0;

	return SendPacket(in_text, player, 0, sound_ipc_id);
}

int SoundControl::SayText(string in_text) {
	if (speech_enable <= 0)
		return 0;

	return SendPacket(in_text, speaker, speech_festival, speech_ipc_id);
}

int SoundControl::SendPacket(string text, string in_player, int opt, int id) {
	if (shutdown)
		return 0;

	// fprintf(stderr, "debug - fetchpid %d\n", sound_remote->FetchSpawnPid());
	if (sound_remote->FetchSpawnPid() <= 0) {
		if (SpawnChildProcess() < 0 || globalreg->fatal_condition)
			return -1;
	}

	ipc_packet *pack =
		(ipc_packet *) malloc(sizeof(ipc_packet) + 
							  sizeof(soundcontrol_ipc_frame) +
							  text.length() + 1);

	soundcontrol_ipc_frame *frame = (soundcontrol_ipc_frame *) pack->data;

	snprintf(frame->player, 256, "%s", in_player.c_str());
	snprintf(frame->msg, text.length() + 1, "%s", text.c_str());
	frame->opt = opt;
	frame->timestamp = time(0);
	
	pack->data_len = sizeof(soundcontrol_ipc_frame) + text.length() + 1;
	pack->ipc_cmdnum = id;
	pack->ipc_ack = 0;

	sound_remote->SendIPC(pack);

    return 1;
}

void SoundControl::Shutdown() {
	if (sound_remote) {
		sound_remote->ShutdownIPC(NULL);
		globalreg->RemovePollableSubsys(sound_remote);
		delete sound_remote;
	}

	sound_remote = NULL;
	shutdown = 1;
}

int SoundControl::SpawnChildProcess() {
	ostringstream osstr;

	// fprintf(stderr, "debug - soundremote spawnipc\n");
	int ret = sound_remote->SpawnIPC();

	if (ret < 0 || globalreg->fatal_condition) {
		_MSG("SoundControl failed to create an IPC child process", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	osstr << "SoundControl spawned IPC child process pid " <<
		sound_remote->FetchSpawnPid();
	_MSG(osstr.str(), MSGFLAG_INFO);

	// fprintf(stderr, "debug - soundremote syncipc\n");
	sound_remote->SyncIPC();

    return 1;
}

string SoundControl::EncodeSpeechString(string in_str) {
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

// Spawn a sound process and block until it ends, max 5 seconds for a sound
// to finish playing
int SoundControl::LocalPlay(string in_player, string key) {
	vector<string> args;
	char **eargv;

	pid_t sndpid;
	int status;

	args = QuoteStrTokenize(in_player, " ");

	eargv = (char **) malloc(sizeof(char *) * (args.size() + 2));

	for (unsigned int x = 0; x < args.size(); x++) {
		eargv[x] = strdup(args[x].c_str());
	}
	eargv[args.size()] = strdup(key.c_str());
	eargv[args.size() + 1] = NULL;

	if ((sndpid = fork()) == 0) {
		dup2(nulfd, 1);
		dup2(nulfd, 2);
		execvp(eargv[0], eargv);
		exit(1);
	}

	for (unsigned int x = 0; x < args.size() + 2; x++)
		free(eargv[x]);
	free(eargv);

	time_t play_start = time(0);

	// Spin waiting for the sound to end for 5 seconds, then make it end
	while (1) {
		if (waitpid(sndpid, &status, WNOHANG) == 0) {
			if ((time(0) - play_start) > 5) {
				kill(sndpid, SIGKILL);
				continue;
			}

			usleep(10000);
		} else {
			break;
		}
	}

	return 1;
}

// Spawn a speech process and wait for it to end, it gets more slack time than a 
// sound process before we kill it (20 seconds)
int SoundControl::LocalSpeech(string in_speaker, int in_festival, string text) {
	vector<string> args;
	char **eargv;
	string speech;

	pid_t sndpid;
	int status;
	int pfd[2];

	if (pipe(pfd) != 0) {
		return -1;
	}

	args = QuoteStrTokenize(in_speaker, " ");

	eargv = (char **) malloc(sizeof(char *) * (args.size() + 1));

	for (unsigned int x = 0; x < args.size(); x++) {
		eargv[x] = strdup(args[x].c_str());
	}
	eargv[args.size()] = NULL;

	if ((sndpid = fork()) == 0) {
		dup2(pfd[0], STDIN_FILENO);
		close(pfd[1]);
		dup2(nulfd, STDOUT_FILENO);
		dup2(nulfd, STDERR_FILENO);
		execvp(eargv[0], eargv);
		exit(1);
	}

	close(pfd[0]);

	// Format it for festival
	if (in_festival) {
		speech = "(SayText \"" + text + "\")\n";
	} else {
		speech = text + "\n";
	}

	if (write(pfd[1], text.c_str(), speech.length() + 1) < 0) 
		_MSG(string(__FUNCTION__) + ": Failed to write speech to player: " +
			 string(strerror(errno)), MSGFLAG_ERROR);
	close(pfd[1]);

	for (unsigned int x = 0; x < args.size() + 1; x++)
		free(eargv[x]);
	free(eargv);

	time_t play_start = time(0);

	while (1) {
		if (waitpid(sndpid, &status, WNOHANG) == 0) {
			if ((time(0) - play_start) > 30) {
				kill(sndpid, SIGKILL);
				continue;
			}

			usleep(10000);
		} else {
			break;
		}
	}

	return 1;
}


