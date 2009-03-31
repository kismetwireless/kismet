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

#ifndef __SOUNDCONTROL_H__
#define __SOUNDCONTROL_H__

#include "globalregistry.h"
#include "pollable.h"
#include "ipc_remote.h"

#define SPEECH_ENCODING_NORMAL   0
#define SPEECH_ENCODING_NATO     1
#define SPEECH_ENCODING_SPELL    2

struct soundcontrol_ipc_frame {
	time_t timestamp;
	char msg[0];
};

extern char speech_alphabet[2][36][12];

class SoundControl {
public:
    SoundControl();
    SoundControl(GlobalRegistry *in_globalreg);
    virtual ~SoundControl();

    // Kill
    void Shutdown();
   
    int PlaySound(string in_text);
	int SayText(string in_text);

	string EncodeSpeechString(string in_str);

	int LocalPlay(string key);
	int LocalSpeech(string text);

protected:
    int SpawnChildProcess();
	int SendPacket(string text, int id);

    GlobalRegistry *globalreg;

	IPCRemote *sound_remote;

	uint32_t sound_ipc_id, speech_ipc_id;

	int sound_enable, speech_enable;
    
    char errstr[STATUS_MAX];

    string player;

    map<string, string> wav_map;

	friend int sound_ipc_callback(IPC_CMD_PARMS);

	int speech_encoding;
	string speaker;
};

#endif

