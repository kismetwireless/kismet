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


// Dump a file in a format airsnort likes

#ifndef __SPEECH_H__
#define __SPEECH_H__

#include "config.h"

#include <stdio.h>
#include <string>
#include <map>
#include "tracktypes.h"

#define SPEECH_ENCODING_NORMAL   0
#define SPEECH_ENCODING_NATO     1
#define SPEECH_ENCODING_SPELL    2

// Speech manipulation options based on a patch from Andrew Etter 15/9/02

extern char speech_alphabet[2][36][12];

string EncodeSpeechString(string in_str, int in_encoding);

// Internal speech expansion
string IntExpandSpeech(string in_str, int in_encoding, string in_ssid, mac_addr in_mac,
                       int in_channel, float in_maxrate);

// Server expansion
string ExpandSpeechString(string in_str, const packet_info *in_info, int in_encoding);
// Client expansion
string ExpandSpeechString(string in_str, const wireless_network *in_info, int in_encoding);

#endif
