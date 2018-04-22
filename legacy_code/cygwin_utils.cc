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

#ifdef SYS_CYGWIN

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define HANDLE2FD_INTERNAL
#include "cygwin_utils.h"

//
// There are two main parameters that can be used to tune the WinPcap performance:
// mintocopy and the read event timeout.
//
// Mintocopy is the minimum amount of data in the kernel buffer that causes the read event to
// be set by the driver. A small mintocopy means good responisiveness but high CPU load. A big
// mintocopy forces bigger kernel buffering, at the cost of low responsiveness
//
// The read event timeout can be used to check the availability of data once in a while. When the
// timeout expires, the application will unblock and perform a read, even if the driver doesn't 
// have mintocopy bytes in the buffer.
//
// Using the timeout prevents kismet from sitting forver before processing the packets when traffic 
// is low, but can cause empty reads. Therefore, we set it to a large enough interval that the 
// performace hit is neglibile.
//
#define THREAD_WAIT_INTERVAL 500

Handle2Fd::Handle2Fd() {
    NHandles = 1;
    ThreadAlive = 1;
    PipeSignalled = 0;
    WaitThreadHandle = NULL;
    FirstFdSet = 1;
    InitializeCriticalSection(&PipeCs);
}

Handle2Fd::~Handle2Fd() {
    // Kill the thread and wait until he's returned
    ThreadAlive = 0;
    SetEvent(WinHandles[0]);
    WaitForSingleObject(WaitThreadHandle, INFINITE);
}

// Set the pipe fd so that it unblocks select
void Handle2Fd::SetPipe() {
    int val;

    EnterCriticalSection(&PipeCs);

    if (!PipeSignalled) {
        write(PipeFds[1], &val, sizeof(val));
        fdatasync(PipeFds[1]);
        PipeSignalled = 1;
    }

   LeaveCriticalSection(&PipeCs);
}

// Reset the pipe fd so that it blocks select
void Handle2Fd::ResetPipe()
{
    int val;

    EnterCriticalSection(&PipeCs);

    // First, write something to be sure the read will not block
    write(PipeFds[1], &val, sizeof(val));
    fdatasync(PipeFds[1]);

    // Second, we drain the pipe
    while(read(PipeFds[0], ResetBuf, sizeof(ResetBuf)) == sizeof(ResetBuf));

    // Third, we clear the signalled flag
    PipeSignalled = 0;

    LeaveCriticalSection(&PipeCs);
}

// This thread handles asynchronously waiting on the Windows events.
// It signals the pipe if one or more events are set.
DWORD WINAPI Handle2Fd::WaitThread(LPVOID lpParameter) { 
	DWORD WaitRes; 
	Handle2Fd* This = (Handle2Fd*)lpParameter; 

	while (This->ThreadAlive) { 
		WaitRes = WaitForMultipleObjects(This->NHandles,
										 This->WinHandles,
										 FALSE,
										 THREAD_WAIT_INTERVAL);

		// Event number 0 is the service event used to kill the thread 
		if (WaitRes != WAIT_OBJECT_0) { 
			ResetEvent(This->ReadEvent);
			This->SetPipe();
			WaitForSingleObject(This->ReadEvent, INFINITE);
		} 
	} 

	return 1; 
}

// Mark a signal as read
void Handle2Fd::Signalread() {
	SetEvent(ReadEvent);
}

// Activate this instance of the Handle2Fd class.
// This involves creating the pipe, the service event and the support thread
int Handle2Fd::Activate() {

    // Create the pipe
    if (pipe(PipeFds) != 0) {
        return -1;
    }

    // The fd stars in non-signaled state
    ResetPipe();

    // Create the event for pipe control, and put it in our list
	WinHandles[0] = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!WinHandles[0]) {
        close(PipeFds[0]);
        close(PipeFds[1]);
        return -1;
    }

	// Create the event that will syncronize us with the read loop
	ReadEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!ReadEvent) {
		close(PipeFds[0]);
		close(PipeFds[1]);
		CloseHandle(WinHandles[0]);
		return -1;
	}

    // Start the thread that does the handle checking
    if ((WaitThreadHandle = CreateThread(
        NULL,
        0,
        Handle2Fd::WaitThread,
        this,
        0,
        NULL)) == NULL) {
            close(PipeFds[0]);
            close(PipeFds[1]);
			CloseHandle(WinHandles[0]);
			CloseHandle(ReadEvent);
            return -1;
		}

    return 1;
}

// The pipe exported by the Handle2Fd class requires manual reset.
void Handle2Fd::Reset() {
        ResetPipe();
}

// Add a new handle to the class
int Handle2Fd::AddHandle(HANDLE h) {
    // If the thread is running, we don't accept new handles. This reduces the syncronization requirements
    if (!WaitThreadHandle) {
        if (NHandles < sizeof(WinHandles) / sizeof(WinHandles[0]) - 1) {
            WinHandles[NHandles++] = h;
            return 1;
        }
    }

    return -1;
}

// Get the pipe file descriptor.
int Handle2Fd::GetFd() {
    return PipeFds[0];
}

// Kismet-like MergeSet function
int Handle2Fd::MergeSet(fd_set *set, int max) {
    Reset();	// Manual reset

    if (!FD_ISSET(GetFd(), set)) {
        FD_SET(PipeFds[0], set);
        if (FirstFdSet) {
            max++;
            FirstFdSet = 0;
        }
    }

    return max;
}

// Nonzero if the HandleNumber event is set
int Handle2Fd::IsEventSet(unsigned int HandleNumber) {
    if (WaitForSingleObject(WinHandles[HandleNumber + 1], 0) == WAIT_OBJECT_0) {
        return 1;
    }
    else {
        return 0;
    }
}

#endif

