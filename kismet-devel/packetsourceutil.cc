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

#include "configfile.h"
#include "packetsourceutil.h"
#include "util.h"

char *card_type_str[] = {
    "unspecified",
    "cisco",
    "cisco_cvs",
    "cisco_bsd",
    "prism2",
    "prism2_legacy",
    "prism2_bsd",
    "prism2_hostap",
    "orinoco",
    "orinoco_bsd",
    "generic",
    "wsp100",
    "wtapfile",
    "viha",
    "ar5k",
    "drone",
    "prism2_avs"
};


map<string, int> ParseEnableLine(string in_named) {
    map<string, int> retmap;

    vector<string> tokens = StrTokenize(in_named, ",");

    for (unsigned int x = 0; x < tokens.size(); x++)
        retmap[StrLower(tokens[x])] = 0;

    return retmap;
}

int ParseCardLines(vector<string> *in_lines, vector<capturesource *> *in_sources) {
    // Now tokenize the sources
    for (unsigned int x = 0; x < in_lines->size(); x++) {
        vector<string> optlist = StrTokenize((*in_lines)[x], ",");

        if (optlist.size() < 3) {
            return (-1) * (x + 1);
        }

        capturesource *newsource = new capturesource;
        newsource->source = NULL;
        newsource->scardtype = optlist[0];
        newsource->interface = optlist[1];
        newsource->name = optlist[2];
        memset(&newsource->packparm, 0, sizeof(packet_parm));
        newsource->childpid = 0;
        newsource->ch_pos = 0;
        newsource->ch_hop = 0;

        in_sources->push_back(newsource);
    }

    return 1;
}

int BindRootSources(vector<capturesource *> *in_capsources, map<string, int> *in_enable,
                   int filter_enable, Timetracker *in_tracker, GPSD *in_gpsd) {
    // Now loop through each of the sources - parse the engines, interfaces, types.
    // Open any that need to be opened as root.
    for (unsigned int src = 0; src < in_capsources->size(); src++) {
        capturesource *csrc = (*in_capsources)[src];

        // If we didn't get sources on the command line or if we have a forced enable
        // on the command line, check to see if we should enable this source.  If we just
        // skip it it keeps a NULL capturesource pointer and gets ignored in the code.
        if (filter_enable) {
            if (in_enable->find(StrLower(csrc->name)) == in_enable->end() &&
                in_enable->size() != 0)
            continue;
        }

        (*in_enable)[StrLower(csrc->name)] = 1;

        // Figure out the card type
        const char *sctype = csrc->scardtype.c_str();

        if (!strcasecmp(sctype, "cisco"))
            csrc->cardtype = card_cisco;
        else if (!strcasecmp(sctype, "cisco_cvs"))
            csrc->cardtype = card_cisco_cvs;
        else if (!strcasecmp(sctype, "cisco_bsd"))
            csrc->cardtype = card_cisco_bsd;
        else if (!strcasecmp(sctype, "prism2"))
            csrc->cardtype = card_prism2;
        else if (!strcasecmp(sctype, "prism2_legacy"))
            csrc->cardtype = card_prism2_legacy;
        else if (!strcasecmp(sctype, "prism2_bsd"))
            csrc->cardtype = card_prism2_bsd;
        else if (!strcasecmp(sctype, "prism2_hostap"))
            csrc->cardtype = card_prism2_hostap;
        else if (!strcasecmp(sctype, "orinoco"))
            csrc->cardtype = card_orinoco;
        else if (!strcasecmp(sctype, "generic"))
            csrc->cardtype = card_generic;
        else if (!strcasecmp(sctype, "wsp100"))
            csrc->cardtype = card_wsp100;
        else if (!strcasecmp(sctype, "wtapfile"))
            csrc->cardtype = card_wtapfile;
        else if (!strcasecmp(sctype, "viha"))
            csrc->cardtype = card_viha;
        else if (!strcasecmp(sctype, "ar5k"))
            csrc->cardtype = card_ar5k;
        else if (!strcasecmp(sctype, "drone"))
            csrc->cardtype = card_drone;
        else if (!strcasecmp(sctype, "prism2_avs"))
            csrc->cardtype = card_prism2_avs;
        else {
            fprintf(stderr, "FATAL:  Source %d (%s):  Unknown card type '%s'\n", src, csrc->name.c_str(), sctype);
            exit(1);
        }

        // Open it if it needs to be opened as root
        card_type ctype = csrc->cardtype;

        if (ctype == card_prism2_legacy) {
#ifdef HAVE_LINUX_NETLINK
            fprintf(stderr, "Source %d (%s): Using prism2 to capture packets.\n", src, csrc->name.c_str());

            csrc->source = new Prism2Source;
#else
            fprintf(stderr, "FATAL:  Source %d (%s): Linux netlink support was not compiled in.\n", src, csrc->name.c_str());
            exit(1);
#endif
        } else if (ctype == card_cisco || ctype == card_cisco_cvs || ctype == card_cisco_bsd ||
                   ctype == card_prism2 || ctype == card_prism2_bsd || ctype == card_prism2_hostap ||
                   ctype == card_orinoco || ctype == card_generic || ctype == card_ar5k ||
                   ctype == card_prism2_avs) {
#ifdef HAVE_LIBPCAP
            if (csrc->interface == "") {
                fprintf(stderr, "FATAL:  Source %d (%s): No capture device specified.\n", src, csrc->name.c_str());
                exit(1);
            }

            fprintf(stderr, "Source %d (%s): Using pcap to capture packets from %s\n",
                    src, csrc->name.c_str(), csrc->interface.c_str());

            csrc->source = new PcapSource;
#else
            fprintf(stderr, "FATAL:  Source %d (%s): Pcap support was not compiled in.\n", src, csrc->name.c_str());
            exit(1);
#endif
        } else if (ctype == card_wtapfile) {
#ifdef HAVE_LIBWIRETAP
            if (csrc->interface == "") {
                fprintf(stderr, "FATAL:  Source %d (%s): No capture device specified.\n", src, csrc->name.c_str());
                exit(1);
            }

            fprintf(stderr, "Source %d (%s): Defering wtapfile open until priv drop.\n", src, csrc->name.c_str());
#else
            fprintf(stderr, "FATAL:  Source %d (%s): libwiretap support was not compiled in.\n", src, csrc->name.c_str());
            exit(1);
#endif
        } else if (ctype == card_drone) {
            if (csrc->interface == "") {
                fprintf(stderr, "FATAL:  Source %d (%s): No capture device specified.\n", src, csrc->name.c_str());
                exit(1);
            }

            fprintf(stderr, "Source %d (%s): Defering drone open until priv drop.\n", src, csrc->name.c_str());

        } else if (ctype == card_wsp100) {
#ifdef HAVE_WSP100
            if (csrc->interface == "") {
                fprintf(stderr, "FATAL:  Source %d (%s): No capture device specified.\n", src, csrc->name.c_str());
                exit(1);
            }

            fprintf(stderr, "Source %d (%s): Using WSP100 to capture packets from %s.\n",
                   src, csrc->name.c_str(), csrc->interface.c_str());

            csrc->source = new Wsp100Source;
#else
            fprintf(stderr, "FATAL:  Source %d (%s): WSP100 support was not compiled in.\n", src, csrc->name.c_str());
            exit(1);
#endif
        } else if (ctype == card_viha) {
#ifdef HAVE_VIHAHEADERS
            fprintf(stderr, "Source %d (%s): Using Viha to capture packets.\n",
                    src, csrc->name.c_str());

            csrc->source = new VihaSource;
#else
            fprintf(stderr, "FATAL:  Source %d (%s): Viha support was not compiled in.\n", src, csrc->name.c_str());
            exit(1);
#endif
        } else {
            fprintf(stderr, "FATAL:  Source %d (%s): Unhandled card type %s\n", src, csrc->name.c_str(), csrc->scardtype.c_str());
            exit(1);
        }

        // Open the packet source and assign the timetracker
        if (csrc->source != NULL) {
            // Run the monitor helper
            fprintf(stderr, "Source %d (%s):  Attempting to enter monitor mode.\n", src, csrc->name.c_str());
            char shellcmd[1024];
            snprintf(shellcmd, 1024, "%s/kismet_monitor %s %s",
                     BIN_LOC, csrc->interface.c_str(), card_type_str[csrc->cardtype]);
            if (system(shellcmd) != 0) {
                fprintf(stderr, "FATAL:  Source %d (%s): Error executing monitor mode helper %s\n",
                        src, csrc->name.c_str(), shellcmd);
                exit(1);
            }

            csrc->source->AddTimetracker(in_tracker);
            csrc->source->AddGpstracker(in_gpsd);

            if (SpawnCapSourceChild(csrc) < 0)
                exit(1);
        }
    }

    return 1;
}

int BindUserSources(vector<capturesource *> *in_capsources, map<string, int> *in_enable,
                    int filter_enable, Timetracker *in_tracker, GPSD *in_gpsd) {
    for (unsigned int src = 0; src < in_capsources->size(); src++) {
        capturesource *csrc = (*in_capsources)[src];

        card_type ctype = csrc->cardtype;

        // For any unopened sources...
        if (csrc->source == NULL) {

            if (filter_enable) {
                if (in_enable->find(StrLower(csrc->name)) == in_enable->end() &&
                    in_enable->size() != 0)
                    continue;
            }

            // We already ran the monitor helper as root...

            (*in_enable)[StrLower(csrc->name)] = 1;

            if (ctype == card_wtapfile) {
#ifdef HAVE_LIBWIRETAP
                fprintf(stderr, "Source %d (%s): Loading packets from dump file %s\n",
                       src, csrc->name.c_str(), csrc->interface.c_str());

                csrc->source = new WtapFileSource;
#else
                fprintf(stderr, "FATAL: Source %d (%s): Wtapfile support was not compiled in.\n", src, csrc->name.c_str());
                exit(1);
#endif
            } else if (ctype == card_drone) {
                fprintf(stderr, "Source %d (%s): Capturing packets from Drone %s.\n",
                        src, csrc->name.c_str(), csrc->interface.c_str());

                csrc->source = new DroneSource;
            }

            // Open the packet source and add the timer tracker
            if (csrc->source != NULL) {
                // Run the monitor helper
                fprintf(stderr, "Source %d (%s):  Attempting to enter monitor mode.\n", src, csrc->name.c_str());
                char shellcmd[1024];
                snprintf(shellcmd, 1024, "%s/kismet_monitor %s %s",
                         BIN_LOC, csrc->interface.c_str(), card_type_str[csrc->cardtype]);
                if (system(shellcmd) != 0) {
                    fprintf(stderr, "FATAL:  Source %d (%s): Error executing monitor mode helper %s\n",
                            src, csrc->name.c_str(), shellcmd);
                    exit(1);
                }

                csrc->source->AddTimetracker(in_tracker);
                csrc->source->AddGpstracker(in_gpsd);

                if (SpawnCapSourceChild(csrc) < 0)
                    exit(1);

            }
        }
    }


    return 1;
}

vector<int> ParseChannelLine(string in_channels) {
    vector<string> optlist = StrTokenize(in_channels, ",");
    vector<int> ret;
    int ch;

    for (unsigned int x = 0; x < optlist.size(); x++) {
        if (sscanf(optlist[x].c_str(), "%d", &ch) != 1) {
            fprintf(stderr, "FATAL: Illegal channel '%s' in channel list '%s'\n", optlist[x].c_str(), in_channels.c_str());
            exit(1);
        }
        ret.push_back(ch);
    }

    return ret;
}

// This is a really big, really scary function that handles figuring out who gets custom channels,
// who gets default channels, and how those channels get split over multiple capture sources.
int ParseSetChannels(vector<string> *in_sourcechanlines, vector<capturesource *> *in_capsources,
                     int in_chsplit, vector<int> *in_80211adefaults, vector<int> *in_80211bdefaults) {
    // Capname to sequence ID map - this links multisources on a single sequence, and defaults
    map<string, int> cap_seqid_map;
    // Sequence ID to channel sequences
    map<int, vector<int> > seqid_seq_map;
    // Sequence counts, if we're splitting.  -1 is 11a def, -2 is 11b def.
    map<int, int> seqid_count_map;
    // OK this is just kind of silly to have so many maps but they're cheap and they're
    // only here during startup
    map<int, int> seqid_assign_map;
    int seqid = 0;

    // Fill in the defaults
    seqid_count_map[-1] = 0;
    seqid_count_map[-2] = 0;
    seqid_seq_map[-1] = (*in_80211adefaults);
    seqid_seq_map[-2] = (*in_80211bdefaults);

    // Temporary vectors of capnames and such
    vector<string> sourcecaps;
    vector<int> sourceseq;

    // Now parse the source lines and assign them
    for (unsigned int sline = 0; sline < in_sourcechanlines->size(); sline++) {
        // Get the sources
        vector<string> sourcebits = StrTokenize((*in_sourcechanlines)[sline], ":");

        if (sourcebits.size() != 2) {
            fprintf(stderr, "FATAL:  Invalid sourcechannel line '%s'\n", (*in_sourcechanlines)[sline].c_str());
            exit(1);
        }

        // Split the sources
        sourcecaps = StrTokenize(sourcebits[0], ",");
        // And the channels
        sourceseq = ParseChannelLine(sourcebits[1]);

        // Now put our sequence in the custom sequence map
        seqid_seq_map[seqid] = sourceseq;
        // And assign it to each of our sources
        for (unsigned int cap = 0; cap < sourcecaps.size(); cap++) {
            if (cap_seqid_map.find(sourcecaps[cap]) != cap_seqid_map.end()) {
                fprintf(stderr, "FATAL:  Capture source '%s' assigned multiple channel sequences.\n",
                        sourcecaps[cap].c_str());
                exit(1);
            }
            // Assign it
            cap_seqid_map[sourcecaps[cap]] = seqid;
        }
        // And increment the sequence id
        seqid++;
    }

    // Now go through the capture sources
    for (unsigned int capnum = 0; capnum < in_capsources->size(); capnum++) {
        capturesource *csrc = (*in_capsources)[capnum];

        if (csrc->source == NULL)
            continue;

        // If they don't have a custom channel sequence, they get the default...
        // Lets figure out what card type they are and assign the right thing
        if (cap_seqid_map.find(csrc->name) == cap_seqid_map.end()) {
            if (csrc->cardtype == card_drone || csrc->cardtype == card_unspecified ||
                csrc->cardtype == card_generic) {
                // non-hopping cap types
                continue;
            } else if (csrc->cardtype == card_ar5k) {
                // 802.11a
                seqid_count_map[-1]++;
                cap_seqid_map[csrc->name] = -1;
            } else {
                // Everything else is 802.11b
                seqid_count_map[-2]++;
                cap_seqid_map[csrc->name] = -2;
            }
        } else {
            // Blow up on card types that don't hop.  We'll be nasty and hard-fault on this.
            if (csrc->cardtype == card_drone || csrc->cardtype == card_unspecified ||
                csrc->cardtype == card_generic) {

                fprintf(stderr, "FATAL:  Source %d (%s) has type %s, which cannot channel hop.\n",
                        capnum, csrc->name.c_str(), card_type_str[csrc->cardtype]);
                exit(1);
            }

            // otherwise increment the seqid
            int id = cap_seqid_map[csrc->name];
            if (seqid_count_map.find(id) == seqid_count_map.end())
                seqid_count_map[id] = 1;
            else
                seqid_count_map[id]++;
        }
    }

    // Now we know how many copies of each source there are, and who gets copies
    // of the default hops.  Lets do some assignments and some math.  It's annoying
    // to have to iterate the capturesources twice, but this only happens at boot
    // so I'm not too concerned
    for (unsigned int capnum = 0; capnum < in_capsources->size(); capnum++) {
        capturesource *csrc = (*in_capsources)[capnum];

        if (csrc->source == NULL)
            continue;

        // If they're a default...
        if (cap_seqid_map.find(csrc->name) == cap_seqid_map.end())
            continue;

        int id = cap_seqid_map[csrc->name];

        csrc->channels = seqid_seq_map[id];
        csrc->ch_hop = 1;

        // handle the splits if we're splitting them
        if (in_chsplit) {
            if (seqid_assign_map.find(id) == seqid_assign_map.end())
                seqid_assign_map[id] = 0;

            csrc->ch_pos = (csrc->channels.size() / seqid_count_map[id]) * seqid_assign_map[id];

            seqid_assign_map[id]++;
        }
    }

    return 1;
}

// Nasty middle-of-file global - these are just to let the signal catcher know who we are
pid_t capchild_global_pid;
capturesource *capchild_global_capturesource;

// Push a string of text out into the ring buffer for OOB-reporting to the server
void CapSourceText(string in_text, KisRingBuffer *in_buf) {
    uint32_t sentinel = CAPSENTINEL;

    // Can we fit it into the buffer?  We don't care about trailing null, but we
    // do add 2 bytes for length and 4 bytes for the sentinel
    if (in_buf->InsertDummy(6 + in_text.length()) == 0) {
        if (!silent)
            fprintf(stderr, "WARNING: capture child text buffer full.\n");
        return;
    }

    uint16_t len = in_text.length();

    in_buf->InsertData((uint8_t *) &sentinel, 4);
    in_buf->InsertData((uint8_t *) &len, 2);
    in_buf->InsertData((uint8_t *) in_text.c_str(), len);

    if (!silent && len > 0)
        fprintf(stderr, "%s\n", in_text.c_str());

}


// Signal catchers
void CapSourceSignal(int sig) {
    fprintf(stderr, "FATAL: Capture child got signal %d, dying.\n", sig);
    exit(0);
}

void CapSourceInterruptSignal(int sig) {
    // Just return to interrupt something else happening
    return;
}

// Spin through our commands and see if we were asked to die...
// return 1 if we were asked to end
int CapSourceFlushCmdDeath(int cmd_fd) {
    int ret;
    int8_t cmd;

    while ((ret = read(cmd_fd, &cmd, 1)) > 0) {
        if (cmd == CAPCMD_DIE)
            return 1;
    }

    if (ret < 0) {
        fprintf(stderr, "FATAL:  Capture child %d command pipe read() error while flushing for exit.",
                capchild_global_pid);
        return -1;
    }

    return 0;
}

// Handle doing things as a child
void CapSourceChild(capturesource *csrc) {
    char txtbuf[1024];
    fd_set rset;
    int diseased = 0;
    int active = 0;
    pid_t mypid = getpid();
    uint32_t sentinel = CAPSENTINEL;

    // Assign globals for signal handler
    capchild_global_pid = mypid;
    capchild_global_capturesource = csrc;

    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, CapSourceInterruptSignal);

    // Make a large ring buffer of packet bits
    KisRingBuffer *ringbuf = new KisRingBuffer(MAX_PACKET_LEN * 50);

    // Make a less large ring buffer for text
    KisRingBuffer *txtringbuf = new KisRingBuffer(1024 * 10);

    // We don't write to the server pair
    close(csrc->servpair[1]);
    // We don't read from the child pair
    close(csrc->childpair[0]);
    // and we don't read from the text stream
    close(csrc->textpair[0]);

    // Try to open the child...
    if (csrc->source->OpenSource(csrc->interface.c_str(), csrc->cardtype) < 0) {
        fprintf(stderr, "FATAL: Capture child %d (%s): %s\n", mypid, csrc->name.c_str(), csrc->source->FetchError());
        exit(1);
    }

    fprintf(stderr, "Capture child %d (%s): Capturing packets from %s\n",
            mypid, csrc->name.c_str(), csrc->source->FetchType());

    while (1) {
        int max_fd = 0;

        FD_ZERO(&rset);

        // A diseased child (ew?) is one who is just waiting to send out the text msg buffer
        // and die... so don't look at commands, don't look at capture sources, and don't
        // try to write any packets.
        if (!diseased) {
            // Read FD for server sending us commands...
            FD_SET(csrc->servpair[0], &rset);
            if (csrc->servpair[0] > max_fd)
                max_fd = csrc->servpair[0];

            // only look at capsource if we're active, and try to slow us down if we're filling
            // the ring buffer.
            if (active && csrc->source->FetchDescriptor() != 0 && ringbuf->InsertDummy(MAX_PACKET_LEN / 2)) {
                FD_SET(csrc->source->FetchDescriptor(), &rset);

                if (csrc->source->FetchDescriptor() > max_fd)
                    max_fd = csrc->source->FetchDescriptor();

            }
        }

        uint8_t *dptr;
        int dlen, ret;

        // Write a text ping if we don't have anything else in the buffer that would be testing the
        // command pipe
        if (txtringbuf->FetchLen() == 0 && active == 1) {
            // Send a text ping.  This might be a little much overhead, but I don't want to do another
            // fd just to see if the server is alive
            CapSourceText("", txtringbuf);
        }

        // Write out a text ring buffer if we can
        if (txtringbuf->FetchLen() != 0) {
            dptr = NULL;

            txtringbuf->FetchPtr(&dptr, &dlen);

            if ((ret = write(csrc->textpair[1], dptr, dlen)) <= 0) {
                csrc->source->CloseSource();

                if (CapSourceFlushCmdDeath(csrc->servpair[0]) == 1) {
                    fprintf(stderr, "Capture child %d asked to die, terminating...\n", mypid);
                    exit(0);
                } else {
                    fprintf(stderr, "FATAL:  capture child %d text write error %d (%s)\n", mypid, errno, strerror(errno));
                    exit(1);
                }
            }

            txtringbuf->MarkRead(ret);
        }

        // if we're diseased and we delivered all our messages, go to the great bitbucked in the sky
        if (diseased && txtringbuf->FetchLen() == 0) {
            if (!silent)
                fprintf(stderr, "Child %d terminating.\n", mypid);

            close(csrc->servpair[0]);
            close(csrc->childpair[1]);
            close(csrc->textpair[1]);

            exit(1);
        }

        // If we're not diseased, keep doing things.

        // Write out data from the packet ring buffer if we can

        if (ringbuf->FetchLen() != 0) {
            dptr = NULL;

            ringbuf->FetchPtr(&dptr, &dlen);

            if ((ret = write(csrc->childpair[1], dptr, dlen)) <= 0) {
                csrc->source->CloseSource();

                if (CapSourceFlushCmdDeath(csrc->servpair[0]) == 1) {
                    fprintf(stderr, "Capture child %d asked to die, terminating...\n", mypid);
                    exit(0);
                } else {
                    fprintf(stderr, "FATAL:  capture child %d packet write error %d (%s)\n", mypid, errno, strerror(errno));
                    exit(1);
                }
            }

            ringbuf->MarkRead(ret);
        }


        // Capture drones don't do things regularly, only when told, so we can sit in a
        // select() forever until something happens
        if (select(max_fd + 1, &rset, NULL, NULL, NULL) < 0) {
            csrc->source->CloseSource();

            if (CapSourceFlushCmdDeath(csrc->servpair[0]) == 1) {
                fprintf(stderr, "Capture child %d asked to die, terminating...\n", mypid);
                exit(0);
            } else {
                fprintf(stderr, "FATAL:  capture child %d select() error %d (%s)\n", mypid, errno, strerror(errno));
                exit(1);
            }
        }

        // Obey commands coming in
        if (FD_ISSET(csrc->servpair[0], &rset)) {
            int8_t cmd = 0;

            if (read(csrc->servpair[0], &cmd, 1) < 0) {
                fprintf(stderr, "FATAL:  capture child %d command read() error %d (%s)", mypid, errno, strerror(errno));
                csrc->source->CloseSource();
                exit(1);
            }

            if (cmd == CAPCMD_ACTIVATE) {
                active = 1;
            } else if (cmd == CAPCMD_NULL) {
                // nothing
            } else if (cmd == CAPCMD_FLUSH) {
                delete ringbuf;
                ringbuf = new KisRingBuffer(MAX_PACKET_LEN * 50);
                snprintf(txtbuf, 1024, "WARNING:  capture child %d packet buffer flushed by server.", mypid);
                CapSourceText(txtbuf, txtringbuf);
            } else if (cmd == CAPCMD_TXTFLUSH) {
                delete txtringbuf;
                txtringbuf = new KisRingBuffer(1024 * 10);
                snprintf(txtbuf, 1024, "WARNING:  capture child %d text buffer flushed by server.", mypid);
                CapSourceText(txtbuf, txtringbuf);
            } else if (cmd == CAPCMD_SILENT) {
                silent = 1;
            } else if (cmd == CAPCMD_DIE) {
                fprintf(stderr, "Capture child %d asked to die, shutting down.\n", mypid);
                csrc->source->CloseSource();
                exit(1);
            } else if (cmd == CAPCMD_PAUSE) {
                csrc->source->Pause();
            } else if (cmd == CAPCMD_RESUME) {
                csrc->source->Resume();
            } else if (cmd > 0) {
                // do a channel set
                if (csrc->source->SetChannel(cmd) < 0) {
                    snprintf(txtbuf, 1024, "FATAL: %s", csrc->source->FetchError());
                    CapSourceText(txtbuf, txtringbuf);
                    diseased = 1;
                }
            } else {
                snprintf(txtbuf, 1024, "WARNING:  capture child unknown command %d", cmd);
                CapSourceText(txtbuf, txtringbuf);
            }

        }
        
        // grab a packet and write it down the pipe
        if (FD_ISSET(csrc->source->FetchDescriptor(), &rset)) {
            kis_packet packet;
            uint8_t data[MAX_PACKET_LEN];
            uint8_t moddata[MAX_PACKET_LEN];

            int len;

            len = csrc->source->FetchPacket(&packet, data, moddata);

            if (len < 0) {
                snprintf(txtbuf, 1024, "FATAL: capture child %d source %s: %s", mypid, csrc->name.c_str(),
                         csrc->source->FetchError());
                CapSourceText(txtbuf, txtringbuf);
                diseased = 1;
            }

            // Don't send len0 stuff
            if (len == 0)
                continue;

            // Can we fit the sentinel + header + packet?
            if (ringbuf->InsertDummy(sizeof(kis_packet) + packet.len + 4) == 0) {
                snprintf(txtbuf, 1024, "WARNING:  capture child %d write packet buffer full, dropped packet", mypid);
                CapSourceText(txtbuf, txtringbuf);
                continue;
            }

            ringbuf->InsertData((uint8_t *) &sentinel, 4);
            ringbuf->InsertData((uint8_t *) &packet, sizeof(kis_packet));
            ringbuf->InsertData((uint8_t *) data, packet.len);
        }

    }
}

// Make a pipe and split off a child process
int SpawnCapSourceChild(capturesource *csrc) {
    pid_t cpid;

    /*
    if (csrc->source->FetchDescriptor() < 0) {
        fprintf(stderr, "FATAL:  Capture source didn't return a valid fd, we don't handle this right now.\n");
        return -1;
    }
    */

    if (csrc->childpid != 0)
        return 0;

    if (pipe(csrc->childpair) == -1) {
        fprintf(stderr, "FATAL:  Unable to create child pipe for capture source.\n");
        return -1;
    }

    if (pipe(csrc->servpair) == -1) {
        fprintf(stderr, "FATAL:  Unable to create server pipe for capture source.\n");
        return -1;
    }

    if (pipe(csrc->textpair) == -1) {
        fprintf(stderr, "FATAL:  Unable to create text pipe for capture source.\n");
        return -1;
    }

    if ((cpid = fork()) < 0) {
        fprintf(stderr, "FATAL:  Unable to create child process for capture source.\n");
        return -1;
    } else if (cpid == 0) {
        // Go off handle being a drone child
        CapSourceChild(csrc);
    }

    csrc->childpid = cpid;

    fprintf(stderr, "Source %s: Created child capture process %d\n", csrc->name.c_str(), cpid);

    // We don't write to the child pair
    close(csrc->childpair[1]);
    // We don't read from the server pair
    close(csrc->servpair[0]);
    // and we don't write to the text stream
    close(csrc->textpair[1]);

    // Go back to doing things
    return 1;
}

int FetchChildPacket(int in_fd, kis_packet *packet, uint8_t *data, uint8_t *moddata, string *in_text) {
    char status[STATUS_MAX];
    unsigned int bcount;
    uint32_t sentinel;
    uint8_t *inbound;

    bcount = 0;
    inbound = (uint8_t *) &sentinel;
    while (bcount < 4) {
        int ret = 0;

        if ((ret = read(in_fd, &inbound[bcount], 4 - bcount)) < 0) {
            snprintf(status, STATUS_MAX, "WARNING: read() error getting packet sentinel: %d %s",
                     errno, strerror(errno));

            (*in_text) = status;

            return -1;
        }

        bcount += ret;
    }

    // If we didn't get a packet sentinel we have a problem, so return a signifier and try to resync
    // the packet ring
    if (sentinel != CAPSENTINEL) {
        return -2;
    }

    bcount = 0;
    inbound = (uint8_t *) packet;
    while (bcount < sizeof(kis_packet)) {
        int ret = 0;

        if ((ret = read(in_fd, &inbound[bcount], sizeof(kis_packet) - bcount)) < 0) {
            snprintf(status, STATUS_MAX, "WARNING: read() error getting packet header: %d %s",
                     errno, strerror(errno));

            (*in_text) = status;

            return -1;
        }

        bcount += ret;
    }

    // Fill in the packet pointers
    packet->data = data;
    packet->moddata = moddata;

    bcount = 0;
    inbound = data;
    while (bcount < packet->len) {
        int ret = 0;

        if ((ret = read(in_fd, &inbound[bcount], packet->len - bcount)) < 0) {
            snprintf(status, STATUS_MAX, "WARNING: read() error getting packet content: %d %s",
                     errno, strerror(errno));

            (*in_text) = status;

            return -1;
        }

        bcount += ret;
    }

    return packet->len;
}

int FetchChildText(int in_fd, string *in_text) {
    char status[STATUS_MAX];
    unsigned int bcount;
    uint32_t sentinel;
    uint16_t size;
    uint8_t *inbound;

    bcount = 0;
    inbound = (uint8_t *) &sentinel;
    while (bcount < 4) {
        int ret = 0;

        if ((ret = read(in_fd, &inbound[bcount], 4 - bcount)) < 0) {
            snprintf(status, STATUS_MAX, "WARNING: read() error getting text sentinel: %d %s",
                     errno, strerror(errno));

            (*in_text) = status;

            return -1;
        }

        bcount += ret;
    }

    // If we didn't get a packet sentinel we have a problem, so return a signifier and try to resync
    // the packet ring
    if (sentinel != CAPSENTINEL) {
        return -2;
    }

    bcount = 0;
    inbound = (uint8_t *) &size;
    while (bcount < 2) {
        int ret = 0;

        if ((ret = read(in_fd, &inbound[bcount], 2 - bcount)) < 0) {
            snprintf(status, STATUS_MAX, "WARNING: read() error getting text size: %d %s",
                     errno, strerror(errno));

            (*in_text) = status;

            return -1;
        }

        bcount += ret;
    }

    if (size == 0)
        return 0;

    bcount = 0;
    inbound = new uint8_t[size + 1];
    while (bcount < size) {
        int ret = 0;

        if ((ret = read(in_fd, &inbound[bcount], size - bcount)) < 0) {
            snprintf(status, STATUS_MAX, "WARNING: read() error getting text content: %d %s",
                     errno, strerror(errno));

            (*in_text) = status;

            delete[] inbound;
            return -1;
        }

        bcount += ret;
    }

    inbound[bcount] = '\0';

    (*in_text) = (char *) inbound;

    delete[] inbound;

    return 1;
}


