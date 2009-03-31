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

	int ret = ((SoundControl *) auxptr)->LocalPlay(f->msg);

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

	int ret = ((SoundControl *) auxptr)->LocalSpeech(f->msg);

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

	sound_enable = -1;

    if (globalreg->kismet_config->FetchOpt("sound") == "true") {
        if (globalreg->kismet_config->FetchOpt("soundplay") != "") {
            player = globalreg->kismet_config->FetchOpt("soundplay");

            if (globalreg->kismet_config->FetchOpt("soundopts") != "")
                player += " " + globalreg->kismet_config->FetchOpt("soundopts");

			player = MungeToShell(player);

            sound_enable = 1;

            if (globalreg->kismet_config->FetchOpt("sound_new") != "")
                wav_map["new"] = globalreg->kismet_config->FetchOpt("sound_new");
            if (globalreg->kismet_config->FetchOpt("sound_new_wep") != "")
                wav_map["new_wep"] = 
					globalreg->kismet_config->FetchOpt("sound_new_wep");
            if (globalreg->kismet_config->FetchOpt("sound_traffic") != "")
                wav_map["traffic"] = 
					globalreg->kismet_config->FetchOpt("sound_traffic");
            if (globalreg->kismet_config->FetchOpt("sound_junktraffic") != "")
                wav_map["junktraffic"] = 
					globalreg->kismet_config->FetchOpt("sound_traffic");
            if (globalreg->kismet_config->FetchOpt("sound_gpslock") != "")
                wav_map["gpslock"] = 
					globalreg->kismet_config->FetchOpt("sound_gpslock");
            if (globalreg->kismet_config->FetchOpt("sound_gpslost") != "")
                wav_map["gpslost"] = 
					globalreg->kismet_config->FetchOpt("sound_gpslost");
            if (globalreg->kismet_config->FetchOpt("sound_alert") != "")
                wav_map["alert"] = 
					globalreg->kismet_config->FetchOpt("sound_alert");

        } else {
            _MSG("Sound alerts enabled but no sound player specified, "
				 "sound will be disabled", MSGFLAG_ERROR);
            sound_enable = 0;
        }
    } else if (sound_enable == -1) {
        sound_enable = 0;
    }

    if (globalreg->kismet_config->FetchOpt("speech") == "true") {
        if (globalreg->kismet_config->FetchOpt("festival") != "") {
            speaker = globalreg->kismet_config->FetchOpt("festival").c_str();
            speech_enable = 1;

			speaker = MungeToShell(speaker);

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
        } else {
            _MSG("Speech requested but no path to festival has been "
				 "specified.  Speech will be disabled", MSGFLAG_ERROR);
            speech_enable = 0;
        }
    } else if (speech_enable == -1) {
        speech_enable = 0;
    }

	sound_remote = new IPCRemote(globalreg, "sound daemon");
	sound_ipc_id = 
		sound_remote->RegisterIPCCmd(&sound_ipc_callback, NULL, this, "SOUND");
	speech_ipc_id = 
		sound_remote->RegisterIPCCmd(&speech_ipc_callback, NULL, this, "SPEECH");
    
}

SoundControl::~SoundControl() {
    Shutdown();
}

int SoundControl::PlaySound(string in_text) {
	if (sound_enable <= 0)
		return 0;

	return SendPacket(in_text, sound_ipc_id);
}

int SoundControl::SayText(string in_text) {
	if (speech_enable <= 0)
		return 0;

	return SendPacket(in_text, speech_ipc_id);
}

int SoundControl::SendPacket(string text, int id) {
	if (sound_remote->FetchSpawnPid() == 0) {
		if (SpawnChildProcess() < 0 || globalreg->fatal_condition)
			return -1;
	}

	ipc_packet *pack =
		(ipc_packet *) malloc(sizeof(ipc_packet) + 
							  sizeof(soundcontrol_ipc_frame) +
							  text.length() + 1);

	soundcontrol_ipc_frame *frame = (soundcontrol_ipc_frame *) pack->data;

	snprintf(frame->msg, text.length(), "%s", text.c_str());
	
	pack->data_len = sizeof(soundcontrol_ipc_frame) + text.length() + 1;
	pack->ipc_cmdnum = id;
	pack->ipc_ack = 0;

	sound_remote->SendIPC(pack);

    return 1;
}

void SoundControl::Shutdown() {
	sound_remote->ShutdownIPC(NULL);
	globalreg->RemovePollableSubsys(sound_remote);
	delete sound_remote;
}

int SoundControl::SpawnChildProcess() {
	ostringstream osstr;

	int ret = sound_remote->SpawnIPC();

	if (ret < 0 || globalreg->fatal_condition) {
		_MSG("SoundControl failed to create an IPC child process", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	osstr << "SoundControl spawned IPC child process pid " <<
		sound_remote->FetchSpawnPid();
	_MSG(osstr.str(), MSGFLAG_INFO);

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

int SoundControl::LocalPlay(string key) {
	string snd;

	if (wav_map.size() == 0)
		snd = MungeToShell(key);
	if (wav_map.find(key) != wav_map.end())
		snd = MungeToShell(wav_map[key]);
	else
		return 0;

	char plr[1024];
	snprintf(plr, 1024, "%s %s", player.c_str(), snd.c_str());

	return system(plr);
}

int SoundControl::LocalSpeech(string text) {
	// Make sure it's shell-clean, we shouldn't be sent something that isn't,
	// but why risk it?
	text = MungeToShell(text);
	char spk_call[2048];
	snprintf(spk_call, 2048, "echo \"(SayText \\\"%s\\\")\" | %s "
			 ">/dev/null 2>/dev/null", text.c_str(), speaker.c_str());

	// Blocking system call, this will block the ack until its done.  This
	// is fine.
	return system(spk_call);
}

