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

#include <ctype.h>

#include "speech.h"

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

string EncodeSpeechString(string in_str, int in_encoding) {
    if (in_encoding != SPEECH_ENCODING_NATO && in_encoding != SPEECH_ENCODING_SPELL)
        return in_str;

    string encodestr;
    for (unsigned int x = 0; x < in_str.length(); x++) {
        char chr = toupper(in_str[x]);
        int pos;

        // Find our encoding in the array
        // Find our encoding in the array
        if (chr >= '0' && chr <= '9')
            pos = 25 + (chr - '0');
        else if (chr >= 'A' && chr <= 'Z')
            pos = chr - 'A';
        else
            continue;

        if (in_encoding == SPEECH_ENCODING_NATO) {
            encodestr += speech_alphabet[0][pos];
            encodestr += " ";
        } else if (in_encoding == SPEECH_ENCODING_SPELL) {
            encodestr += speech_alphabet[1][pos];
            encodestr += " ";
        }
    }

    return encodestr;
}

string IntExpandSpeech(string in_str, int in_encoding, string in_ssid, mac_addr in_mac,
                       int in_channel, float in_maxrate) {
    string strtemplate = in_str;

    for (unsigned int nl = strtemplate.find("%"); nl < strtemplate.length();
         nl = strtemplate.find("%", nl+1))
    {
        char op = strtemplate[nl+1];
        strtemplate.erase(nl, 2);

        if (op == 'b') {
            strtemplate.insert(nl, EncodeSpeechString(in_mac.Mac2String(), in_encoding));
        } else if (op == 's') {
            if (in_ssid == NOSSID)
                strtemplate.insert(nl, EncodeSpeechString("unknown name", in_encoding));
            else
                strtemplate.insert(nl, EncodeSpeechString(in_ssid, in_encoding));
        } else if (op == 'c') {
            char chan[3];
            snprintf(chan, 3, "%d", in_channel);
            strtemplate.insert(nl, chan);
        } else if (op == 'r') {
            char maxrate[5];
            snprintf(maxrate, 5, "%2.1f", in_maxrate);
            strtemplate.insert(nl, maxrate);
        }
    }

    return strtemplate;
}

string ExpandSpeechString(string in_str, const packet_info *in_info, int in_encoding) {
    string strtemplate;

    strtemplate = IntExpandSpeech(in_str, in_encoding, in_info->ssid, in_info->bssid_mac,
                                  in_info->channel, in_info->maxrate);

    return strtemplate;
}

string ExpandSpeechString(string in_str, const wireless_network *in_info, int in_encoding) {
    string strtemplate;

    strtemplate = IntExpandSpeech(in_str, in_encoding, in_info->ssid, in_info->bssid,
                                  in_info->channel, in_info->maxrate);

    return strtemplate;
}

