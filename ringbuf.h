#ifndef __RINGBUF_H__
#define __RINGBUF_H__

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

#include <string>
#include <map>
#include <vector>

class RingBuffer {
public:
    RingBuffer(int in_size);
    ~RingBuffer();

    // See if an insert would succeed (for multi-stage inserts that must
    // all succeed
    int InsertDummy(int in_len);
    // Add data to the ring buffer
    int InsertData(uint8_t *in_data, int in_len);
    // Fetch the length of the longest continual piece of data
    int FetchLen();
	// Fetch the size of the buffer
	int FetchSize();
    // Fetch the longest continual piece of data
    void FetchPtr(uint8_t *in_dptr, int max_len, int *in_len);
    // Flag bytes as read.  Will only flag as many bytes are available
    void MarkRead(int in_len);
	// Change the size of the ring buffer
	int Resize(int in_newlen);
protected:
    int ring_len;
    uint8_t *ring_data;
    uint8_t *ring_rptr, *ring_wptr;
};

#endif
