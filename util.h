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

#ifndef __UTIL_H__
#define __UTIL_H__

#include "config.h"

#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <pwd.h>
#include <ctype.h>
#include <math.h>

#ifdef HAVE_LINUX_WIRELESS

// Because some kernels include ethtool which breaks horribly...
// The stock ones don't but others seem to
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#endif

#include <string>
#include <map>
#include <vector>

// Munge a string to characters safe for calling in a shell
void MungeToShell(char *in_data, int max);
string MungeToShell(string in_data);

string StrLower(string in_str);
string StrStrip(string in_str);

int XtoI(char x);
int Hex2UChar(unsigned char *in_hex, unsigned char *in_chr);

vector<string> StrTokenize(string in_str, string in_split);
vector<string> LineWrap(string in_txt, unsigned int in_hdr_len, unsigned int in_maxlen);
vector<int> Str2IntVec(string in_text);

void Float2Pair(float in_float, int16_t *primary, int64_t *mantissa);
float Pair2Float(int16_t primary, int64_t mantissa);

#ifdef HAVE_LINUX_WIRELESS
// From iwconfig source
float IWFreq2Float(iwreq *inreq);
void IWFloat2Freq(double in_val, struct iw_freq *out_freq);
#endif

// Convert a float frequency to a channel number
int FloatChan2Int(float in_chan);

// Run a system command and return the error code.  Caller is responsible for security.
int ExecSysCmd(char *in_cmd, char *in_err);

class KisRingBuffer {
public:
    KisRingBuffer(int in_size);
    ~KisRingBuffer();

    // See if an insert would succeed (for multi-stage inserts that must
    // all succeed
    int InsertDummy(int in_len);
    // Add data to the ring buffer
    int InsertData(uint8_t *in_data, int in_len);
    // Fetch the length of the longest continual piece of data
    int FetchLen();
    // Fetch the longest continual piece of data
    void FetchPtr(uint8_t **in_dptr, int *in_len);
    // Flag bytes as read.  Will only flag as many bytes are available
    void MarkRead(int in_len);
protected:
    int ring_len;
    uint8_t *ring_data;
    uint8_t *ring_rptr, *ring_wptr;
};

#endif
