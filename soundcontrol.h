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

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "getopt.h"
#include <stdlib.h>
#include <signal.h>
#include <pwd.h>
#include "globalregistry.h"

class SoundControl {
public:
    SoundControl();
    SoundControl(GlobalRegistry *in_globalreg);
    virtual ~SoundControl();

    // Kill
    void Shutdown();
   
    // Send something to the speech pipe
    int PlaySound(string in_text);

protected:
    int SpawnChildProcess();
    void SoundChild();

    GlobalRegistry *globalreg;
    
    char errstr[STATUS_MAX];

    pid_t childpid;
    int fds[2];
    string player;

    map<string, string> wav_map;
};

#endif

