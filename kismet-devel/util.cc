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

#include "util.h"

// We need this to make uclibc happy since they don't even have rintf...
#ifndef rintf
#define rintf(x) (float) rint((double) (x))
#endif

// Munge input to shell-safe
void MungeToShell(char *in_data, int max) {
    int i, j;

    for (i = 0, j = 0; i < max && j < max; i++) {
        if (in_data[i] == '\0')
            break;

        if (isalnum(in_data[i]) || isspace(in_data[i]) ||
            in_data[i] == '=' || in_data[i] == '-' || in_data[i] == '_' ||
            in_data[i] == '.' || in_data[i] == ',') {

            if (j == i) {
                j++;
            } else {
                in_data[j++] = in_data[i];
            }
        }
    }

    in_data[j] = '\0';

}

// Quick wrapper to save us time in other code
string MungeToShell(string in_data) {
    char *data = new char[in_data.length() + 1];
    string ret;

    snprintf(data, in_data.length() + 1, "%s", in_data.c_str());

    MungeToShell(data, in_data.length() + 1);

    ret = data;
    delete[] data;
    return ret;
}

string StrLower(string in_str) {
    string thestr = in_str;
    for (unsigned int i = 0; i < thestr.length(); i++)
        thestr[i] = tolower(thestr[i]);

    return thestr;

}

string StrStrip(string in_str) {
    string temp;
    unsigned int start, end;

    start = 0;
    end = in_str.length();

    if (in_str[0] == '\n')
        return "";

    for (unsigned int x = 0; x < in_str.length(); x++) {
        if (in_str[x] != ' ' && in_str[x] != '\t') {
            start = x;
            break;
        }
    }
    for (unsigned int x = in_str.length() - 1; x > 0; x--) {
        if (in_str[x] != ' ' && in_str[x] != '\t' && in_str[x] != '\n') {
            end = x;
            break;
        }
    }

    return in_str.substr(start, end-start+1);

}

int XtoI(char x) {
    if (isxdigit(x)) {
        if (x <= '9')
            return x - '0';
        return toupper(x) - 'A' + 10;
    }

    return -1;
}

int Hex2UChar(unsigned char *in_hex, unsigned char *in_chr) {
    memset(in_chr, 0, sizeof(unsigned char) * WEPKEY_MAX);
    int chrpos = 0;

    for (unsigned int strpos = 0; strpos < WEPKEYSTR_MAX && chrpos < WEPKEY_MAX; strpos++) {
        if (in_hex[strpos] == 0)
            break;

        if (in_hex[strpos] == ':')
            strpos++;

        // Assume we're going to eat the pair here
        if (isxdigit(in_hex[strpos])) {
            if (strpos > (WEPKEYSTR_MAX - 2))
                return 0;

            int d1, d2;
            if ((d1 = XtoI(in_hex[strpos++])) == -1)
                return 0;
            if ((d2 = XtoI(in_hex[strpos])) == -1)
                return 0;

            in_chr[chrpos++] = (d1 * 16) + d2;
        }

    }

    return(chrpos);
}

vector<string> StrTokenize(string in_str, string in_split) {
    unsigned int begin = 0;
    unsigned int end = in_str.find(in_split);
    vector<string> ret;

    if (in_str.length() == 0)
        return ret;
    
    while (end != string::npos) {
        string sub = in_str.substr(begin, end-begin);
        begin = end+1;
        end = in_str.find(in_split, begin);
        ret.push_back(sub);
    }
    ret.push_back(in_str.substr(begin, in_str.size() - begin));

    return ret;
}

vector<string> LineWrap(string in_txt, unsigned int in_hdr_len, unsigned int in_maxlen) {
	vector<string> ret;

	unsigned int pos, prev_pos, start, hdroffset;
	start = hdroffset = 0;

	for (pos = prev_pos = in_txt.find(' ', in_hdr_len); pos != string::npos; pos = in_txt.find(' ', pos + 1)) {
		if ((hdroffset + pos) - start > in_maxlen) {
			if (pos - prev_pos > 8) {
				prev_pos = start + (in_maxlen - hdroffset);
			}

			string str(hdroffset, ' ');
			hdroffset = in_hdr_len;
			str += in_txt.substr(start, prev_pos - start);
			ret.push_back(str);
			
			start = prev_pos;
		}

		prev_pos = pos + 1;
	}
	string str(hdroffset, ' ');
	str += in_txt.substr(start, in_txt.length() - start);
	ret.push_back(str);

	return ret;
}

void Float2Pair(float in_float, int16_t *primary, int64_t *mantissa) {
    *primary = (int) in_float;
    *mantissa = (long) (1000000 * ((in_float) - *primary));
}

float Pair2Float(int16_t primary, int64_t mantissa) {
    return (double) primary + ((double) mantissa / 1000000);
}

#ifdef HAVE_LINUX_WIRELESS
// Also cribbed from wireless tools

float IWFreq2Float(iwreq *inreq) {
    return ((float) inreq->u.freq.m) * pow(10,inreq->u.freq.e);
}

void IWFloat2Freq(double in_val, struct iw_freq *out_freq) {
    out_freq->e = (short) (floor(log10(in_val)));
    if(out_freq->e > 8)              
    {  
        out_freq->m = ((long) (floor(in_val / pow(10,out_freq->e - 6)))) * 100; 
        out_freq->e -= 8;
    }  
    else 
    {  
        out_freq->m = (uint32_t) in_val;            
        out_freq->e = 0;
    }  
}
#endif

// 80211b frequencies to channels
int IEEE80211Freq[] = {
    2412, 2417, 2422, 2427, 2432,
    2437, 2442, 2447, 2452, 2457,
    2462, 2467, 2472, 2484,
    5180, 5200, 5210, 5220, 5240,
    5250, 5260, 5280, 5290, 5300, 
    5320, 5745, 5760, 5765, 5785, 
    5800, 5805, 5825,
    -1
};

int IEEE80211Ch[] = {
    1, 2, 3, 4, 5,
    6, 7, 8, 9, 10,
    11, 12, 13, 14,
    36, 40, 42, 44, 48,
    50, 52, 56, 58, 60,
    64, 149, 152, 153, 157,
    160, 161, 165
};

int FloatChan2Int(float in_chan) {
    int mod_chan = (int) rintf(in_chan / 1000000);
    int x = 0;

    while (IEEE80211Freq[x] != -1) {
        if (IEEE80211Freq[x] == mod_chan) {
            return IEEE80211Ch[x];
        }
        x++;
    }

    return 0;
}

KisRingBuffer::KisRingBuffer(int in_size) {
    ring_len = in_size;
    ring_data = new uint8_t[in_size];
    ring_rptr = ring_data;
    ring_wptr = ring_data;
}

KisRingBuffer::~KisRingBuffer() {
    delete[] ring_data;
}

int KisRingBuffer::InsertDummy(int in_len) {
    if (ring_wptr + in_len > ring_data + ring_len) {
        int tail = (ring_data + ring_len) - ring_wptr;
        if (ring_data + (in_len - tail) >= ring_rptr)
            return 0;
    } else {
        if ((ring_rptr > ring_wptr) && (ring_wptr + in_len >= ring_rptr))
            return 0;
    }

    return 1;
}

int KisRingBuffer::InsertData(uint8_t *in_data, int in_len) {
    // Will this hit the end of the ring and go back to the beginning?
    if ((ring_wptr + in_len) >= (ring_data + ring_len)) {
        // How much data gets written to the tail of the ring before we
        // wrap?
        int tail = (ring_data + ring_len) - ring_wptr;

        // If we're going to wrap, will we overrun the read position?
        if (ring_data + (in_len - tail) >= ring_rptr)
            return 0;

        // Copy the data to the end of the loop, move to the beginning
        memcpy(ring_wptr, in_data, tail);
        memcpy(ring_data, in_data + tail, in_len - tail);
        ring_wptr = ring_data + (in_len - tail);
    } else {
        // Will we surpass the read pointer?
        if ((ring_rptr > ring_wptr) && (ring_wptr + in_len >= ring_rptr))
            return 0;

        // Copy the data to the write pointer
        memcpy(ring_wptr, in_data, in_len);
        ring_wptr = ring_wptr + in_len;
    }

    // printf("debug - inserted %d into ring buffer.\n", in_len);

    return 1;
}

int KisRingBuffer::FetchLen() {
    int ret = 0;

    if (ring_wptr < ring_rptr) {
        ret = (ring_data + ring_len) - ring_rptr;
    } else {
        ret = (ring_wptr - ring_rptr);
    }

    //printf("ring begin %p wptr %p rptr %p lt %d len %d\n",
           //ring_data, ring_wptr, ring_rptr, ring_wptr < ring_rptr, ret);

    return ret;
}

void KisRingBuffer::FetchPtr(uint8_t **in_dataptr, int *in_len) {
    // Has the write pointer looped back?
    if (ring_wptr < ring_rptr) {
        // return the read to the end
        *in_len = (ring_data + ring_len) - ring_rptr;
    } else {
        // Return the read to the write
        *in_len = (ring_wptr - ring_rptr);
    }

    *in_dataptr = ring_rptr;
}

void KisRingBuffer::MarkRead(int in_len) {
    // Will we loop the array?
    if ((ring_rptr + in_len) >= (ring_data + ring_len)) {
        // How much comes off the length before we wrap?
        int tail = (ring_data + ring_len) - ring_rptr;

        // Catch surpassing the write pointer after the loop
        if (ring_data + (in_len - tail) > ring_wptr)
            ring_rptr = ring_wptr;
        else
            ring_rptr = ring_data + (in_len - tail);
    } else {
        ring_rptr += in_len;
    }

    //printf("debug - marked %d read in ring\n", in_len);
    
    return;
}

vector<int> Str2IntVec(string in_text) {
    vector<string> optlist = StrTokenize(in_text, ",");
    vector<int> ret;
    int ch;

    for (unsigned int x = 0; x < optlist.size(); x++) {
        if (sscanf(optlist[x].c_str(), "%d", &ch) != 1) {
            ret.clear();
            break;
        }

        ret.push_back(ch);
    }

    return ret;
}

int ExecSysCmd(char *in_cmd, char *in_err) {
    int ret;

    if ((ret = system(in_cmd)) == -1) {
        snprintf(in_err, STATUS_MAX, "fork() for system() failed.");
        return -1;
    }

    if (WEXITSTATUS(ret) != 0) {
        snprintf(in_err, STATUS_MAX, "command '%s' failed.", in_cmd);
        return -1;
    }

    return 0;
}

