/*
    This file was written by Loris Degioanni, and is part of Kismet

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

#ifndef __CYGWIN_UTILS_H__
#define __CYGWIN_UTILS_H__

#ifdef SYS_CYGWIN

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

class Handle2Fd {
public:
    Handle2Fd();
	~Handle2Fd();
    int AddHandle(HANDLE h);
	void Signalread();
    int Activate();
    void Reset();
    int GetFd();
    int MergeSet(fd_set *set, int max);
    int IsEventSet(unsigned int HandleNumber);

private:
#ifdef HANDLE2FD_INTERNAL
	// The Unix side of cygwin doesn't like this
	static DWORD WINAPI WaitThread(LPVOID lpParameter);
	CRITICAL_SECTION PipeCs;
    HANDLE WinHandles[MAXIMUM_WAIT_OBJECTS + 1];
#endif
    void SetPipe();
    void ResetPipe();

    int PipeFds[2];

    unsigned int NHandles;

    HANDLE WaitThreadHandle;
	HANDLE ReadEvent;
    int ThreadAlive;

    int PipeSignalled;

    char ResetBuf[300];

	int FirstFdSet;
};

#endif /* sys_cygwin */

#endif

