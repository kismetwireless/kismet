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

class SoundControl {
public:
    SoundControl();
    SoundControl(GlobalRegistry *in_globalreg);
    virtual ~SoundControl();

    // Kill
    void Shutdown();
   
    // Send something to the speech pipe
    int PlaySound(string in_text);

	string FetchPlayer() { return player; }

protected:
    int SpawnChildProcess();
	int LocalPlay(string key);

    GlobalRegistry *globalreg;

	IPCRemote *sound_remote;

	uint32_t sound_ipc_id;

	int sound_enable;
    
    char errstr[STATUS_MAX];

    string player;

    map<string, string> wav_map;

	friend int sound_ipc_callback(IPC_CMD_PARMS);
};

#endif

