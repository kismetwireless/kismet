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

int sound_ipc_callback(IPC_CMD_PARMS) {
	if (parent)
		return 0;

	if (len < 2) {
		_MSG("IPC sound handler got a short sound message", MSGFLAG_ERROR);
		return 0;
	}

	int ret = ((SoundControl *) auxptr)->LocalPlay((char *) data);

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

	sound_remote = new IPCRemote(globalreg, "sound daemon");
	sound_ipc_id = sound_remote->RegisterIPCCmd(&sound_ipc_callback, NULL, this);
	globalreg->RegisterPollableSubsys(sound_remote);
    
}

SoundControl::~SoundControl() {
    Shutdown();
}

int SoundControl::PlaySound(string in_text) {
	char snd[1024];
	int ret = 0;

	if (sound_enable <= 0)
		return 0;

	if (sound_remote->FetchSpawnPid() == 0) {
		ret = SpawnChildProcess();
	}

	if (globalreg->fatal_condition || sound_remote->FetchReadyState() == 0)
		return ret;

	snprintf(snd, 1024, "%s", in_text.c_str());

	ipc_packet *pack =
		(ipc_packet *) malloc(sizeof(ipc_packet) + strlen(snd) + 1);
	char *msg = (char *) pack->data;

	snprintf(msg, strlen(snd) + 1, snd);
	
	pack->data_len = strlen(snd) + 1;
	pack->ipc_cmdnum = sound_ipc_id;
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

int SoundControl::LocalPlay(string key) {
	char snd[1024];
	pid_t sndpid;

	if (wav_map.size() == 0)
		snprintf(snd, 1024, "%s", key.c_str());
	if (wav_map.find(key) != wav_map.end())
		snprintf(snd, 1024, "%s", wav_map[key].c_str());
	else
		return 0;

	char plr[1024];
	snprintf(plr, 1024, "%s", FetchPlayer().c_str());

	if ((sndpid = fork()) == 0) {
		// Suppress errors
		int nulfd = open("/dev/null", O_RDWR);
		dup2(nulfd, 1);
		dup2(nulfd, 2);

		char * const echoarg[] = { plr, snd, NULL };
		execve(echoarg[0], echoarg, NULL);
	}

	// Blocking wait for the sound to finish
	waitpid(sndpid, NULL, 0);

	return 1;
}

