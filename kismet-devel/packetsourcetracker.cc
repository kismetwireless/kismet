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

#include "util.h"
#include "packetsourcetracker.h"

Packetsourcetracker::Packetsourcetracker() {
    next_packsource_id = 0;
    next_meta_id = 0;
    gpsd = NULL;
    timetracker = NULL;
}

Packetsourcetracker::~Packetsourcetracker() {
    for (map<string, packsource_protorec *>::iterator x = cardtype_map.begin();
         x != cardtype_map.end(); ++x)
        delete x->second;
}

unsigned int Packetsourcetracker::MergeSet(fd_set *in_rset, fd_set *in_wset,
                                           unsigned int in_max) {
    unsigned int max = in_max;

    if (in_max < (unsigned int) sockpair[1])
        max = sockpair[1];

    // Set the read sock all the time
    FD_SET(sockpair[1], in_rset);

    // Set it for writing if we have some queued
    if (ipc_buffer.size() > 0)
        FD_SET(sockpair[1], in_wset);

    for (unsigned int metc = 0; metc < meta_packsources.size(); metc++) {
        meta_packsource *meta = meta_packsources[metc];

        FD_SET(meta->capsource->FetchDescriptor(), in_rset);
        if (meta->capsource->FetchDescriptor() > (int) max)
            max = meta->capsource->FetchDescriptor();
    }

    return max;
}

// Read from the socket and return text if we have any
int Packetsourcetracker::Poll(fd_set *in_rset, fd_set *in_wset) {
    // This should only ever get called when the fd is set so we don't need to do our 
    // own select...
    chanchild_packhdr in_pak;
    uint8_t *data;

    // Write packets out if we have them queued, and write as many as we can
    if (FD_ISSET(sockpair[1], in_wset)) {
        while (ipc_buffer.size() > 0) {
            chanchild_packhdr *pak = ipc_buffer.front();

            // Send the header if we didn't already
            if (dataframe_only == 0) {
                if (send(sockpair[1], pak, sizeof(chanchild_packhdr) - sizeof(void *), 0) < 0) {
                    if (errno == ENOBUFS) {
                        goto pollendpackpipewrite;
                    } else {
                        snprintf(errstr, 1024, "ipc header send() failed: %d:%s", errno, strerror(errno));
                        return -1;
                    }
                } 
            }

            // send the payload if there is one
            if (pak->datalen > 0) {
                if (send(sockpair[1], pak->data, pak->datalen, 0) < 0) {
                    if (errno == ENOBUFS) {
                        dataframe_only = 1;
                        goto pollendpackpipewrite;
                    } else {
                        snprintf(errstr, 1024, "ipc content send() failed: %d:%s", errno, strerror(errno));
                        return -1;
                    }
                }
            }

            dataframe_only = 0;

            ipc_buffer.pop_front();
            free(pak->data);
            delete pak;
        }

    // Labels are bad, but really, what else to do?
pollendpackpipewrite: 
        ;

    }
    
    // Read responses from the capture child
    if (FD_ISSET(sockpair[1], in_rset)) {
        if (recv(sockpair[1], &in_pak, sizeof(chanchild_packhdr) - sizeof(void *), 0) < 0) {
            snprintf(errstr, 1024, "header recv() error: %d:%s", errno, strerror(errno));
            return -1;
        }

        // Keep trying to go on...
        if (in_pak.sentinel != CHANSENTINEL) {
            snprintf(errstr, 1024, "Got packet from channel control with invalid "
                     "sentinel.");
            return 1;
        }

        // These don't mean anything to us.
        if (in_pak.packtype == CHANPACK_DIE || in_pak.packtype == CHANPACK_CHANNEL)
            return 0;

        if (in_pak.datalen == 0) {
            return 0;
        }

        // Other packets have a data component so we need to allocate it plus a null
        data = (uint8_t *) malloc(sizeof(uint8_t) * (in_pak.datalen + 1));

        if (recv(sockpair[1], data, in_pak.datalen, 0) < 0) {
            snprintf(errstr, 1024, "data recv() error: %d:%s", errno, strerror(errno));
            return -1;
        }

        // Packet acks just set the flag
        if (in_pak.packtype == CHANPACK_CMDACK) {
            // Data should be an 8bit uint with the meta number.
            if (data[0] >= meta_packsources.size()) {
                snprintf(errstr, 1024, "illegal command ack for meta number %d", data[0]);
                return -1;
            }

            // Set the command ack
            meta_packsources[data[0]]->cmd_ack = 1;

            free(data);

            return 0;
        } else if (in_pak.packtype == CHANPACK_TEXT) {
            // Just to be safe
            data[in_pak.datalen] = '\0';
            snprintf(errstr, 1024, "%s", (char *) data);

            free(data);

            // Fatal packets return a fatal condition
            if (in_pak.flags & CHANFLAG_FATAL)
                return -1;

            return 1;
        }
    }

    return 0;
}

// Hop the packet sources up a channel
int Packetsourcetracker::AdvanceChannel() {
    for (unsigned int metac = 0; metac < meta_packsources.size(); metac++) {
        meta_packsource *meta = meta_packsources[metac];

        // Don't do anything for sources with no channel controls
        if (meta->prototype->channelcon == NULL)
            continue;
        
#ifndef HAVE_SUID
        // Control stuff in one process if we don't suiddrop
        //
        int ret;
        ret = (*meta->prototype->channelcon)(meta->device.c_str(),
                                             meta->channels[meta->ch_pos++],
                                             errstr, (void *) meta->capsource);

        if (meta->ch_pos >= (int) meta->channels.size())
            meta->ch_pos = 0;

        if (ret < 0)
            return ret;
#else
        // Stuff that doesn't have a child control gets done now
        if (meta->prototype->child_control == 0) {
            int ret;
            ret = (*meta->prototype->channelcon)(meta->device.c_str(),
                                                 meta->channels[meta->ch_pos++],
                                                 errstr, (void *) meta->capsource);

            if (meta->ch_pos >= (int) meta->channels.size())
                meta->ch_pos = 0;

            if (ret < 0)
                return ret;

            continue;
        }

        // Don't try to change channels if they've not ackd the previous
        if (meta->cmd_ack == 0)
            continue;

        chanchild_packhdr *chancmd = new chanchild_packhdr;
        chanchild_changepacket *data = (chanchild_changepacket *) 
            malloc(sizeof(chanchild_changepacket));

        memset(chancmd, 0, sizeof(chanchild_packhdr));
        memset(data, 0, sizeof(chanchild_changepacket));
        if (data == NULL) {
            snprintf(errstr, STATUS_MAX, "Could not allocate data struct for "
                     "changing channels: %s", strerror(errno));
            return -1;
        }

        chancmd->sentinel = CHANSENTINEL;
        chancmd->packtype = CHANPACK_CHANNEL;
        chancmd->flags = CHANFLAG_NONE;
        chancmd->datalen = sizeof(chanchild_changepacket);
        chancmd->data = (uint8_t *) data;

        data->meta_num = (uint8_t) metac;
        data->channel = (uint16_t) meta->channels[meta->ch_pos++];

        if (meta->ch_pos >= (int) meta->channels.size())
            meta->ch_pos = 0;

        ipc_buffer.push_back(chancmd);
    }
#endif

    return 1;
}

// Map a cardtype string to the registrant function.  Should be called from main() or 
// wherever packet sources get loaded from.  (Plugin hook)
int Packetsourcetracker::RegisterPacketsource(const char *in_cardtype, int in_root, 
                                              const char *in_defaultchanset, 
                                              int in_initch, 
                                              packsource_registrant in_registrant, 
                                              packsource_monitor in_monitor,
                                              packsource_monitor in_unmonitor,
                                              packsource_chcontrol in_channelcon,
                                              int in_childcontrol) {
    // Do we have it?  Can't register a type that's already registered.
    if (cardtype_map.find(in_cardtype) != cardtype_map.end())
        return -1;

    // Register it.
    packsource_protorec *rec = new packsource_protorec;

    rec->id = next_packsource_id++;
    rec->root_required = in_root;
    rec->default_channelset = in_defaultchanset;
    rec->initial_channel = in_initch;

    rec->registrant = in_registrant;
    rec->monitor_enable = in_monitor;
    rec->monitor_disable = in_unmonitor;
    rec->channelcon = in_channelcon;

    rec->child_control = in_childcontrol;

    rec->cardtype = in_cardtype;

    cardtype_map[StrLower(in_cardtype)] = rec;

    return rec->id;
}

int Packetsourcetracker::RegisterDefaultChannels(vector<string> *in_defchannels) {
    vector<string> tokens;

    for (unsigned int sc = 0; sc < in_defchannels->size(); sc++) {
        tokens.clear();
        tokens = StrTokenize((*in_defchannels)[sc], ":");

        if (tokens.size() < 2) {
            snprintf(errstr, 1024, "Illegal default channel line '%s'", 
                     (*in_defchannels)[sc].c_str());
            return -1;
        }

        vector<int> channel_bits = Str2IntVec(tokens[1]);

        if (channel_bits.size() == 0) {
            snprintf(errstr, 1024, "Illegal channel list '%s' in default channel "
                     "line '%s'", tokens[1].c_str(), (*in_defchannels)[sc].c_str());
            return -1;
        }

        if (defaultch_map.find(StrLower(tokens[0])) != defaultch_map.end()) {
            snprintf(errstr, 1024, "Already have defaults for type '%s'",
                     tokens[0].c_str());
            return-1;
        }

        defaultch_map[StrLower(tokens[0])] = channel_bits;

    }
    
    return 1;
}

vector<KisPacketSource *> Packetsourcetracker::FetchSourceVec() {
    return live_packsources;
}

// Big scary function to build the meta-packsource records from the requested configs 
// provided. These configs can come from either the config file or the command line 
// options, caller is responsible for figuring out which ones override and get sent 
// to us.
//
// enableline: vector of source names to be enabled
// cardlines: vector of config lines defining actual capture sources,
// sourcechannels: vector of config lines defining explicit channel sequences for a 
// source
// initchannels: vector of initial channel settings
// chhop: Is hopping enabled?
// chsplit: Are channel allocations split across multiple interfaces?
int Packetsourcetracker::ProcessCardList(string in_enableline, 
                                         vector<string> *in_cardlines, 
                                         vector<string> *in_sourcechannels, 
                                         vector<string> *in_initchannels,
                                         int in_chhop, int in_chsplit) {
    // reuseable token vector
    vector<string> tokens;
    // capsource names to be enabled
    map<string, int> enable_map;
    // We enable all packet sources if none were explicitly listed
    int all_enable = 0;
    // Capsource names mapped to initial channel
    map<string, int> initch_map;
    // Lots of maps to track the channel divisions
    // capname to sequence id
    map<string, int> chan_cap_seqid_map;
    // sequence id to channel sequence
    map<int, vector<int> > chan_seqid_seq_map;
    // Sequence counts, if we're splitting we need to know how many instances use 
    // each seqid
    map<int, int> chan_seqid_count_map;
    // Sequence id counter
    int chan_seqid = 0;

    // Split the enable lines into a map saying if a source should be turned on
    tokens.clear();
    tokens = StrTokenize(in_enableline, ",");
    for (unsigned int x = 0; x < tokens.size(); x++) {
        enable_map[StrLower(tokens[x])] = 1;
    }

    if (enable_map.size() == 0) {
        all_enable = 1;
    }

    // Split the initial channel allocations, with a little help for people with only one
    // capture source enabled - if only a number is given, assume it's a for the only 
    // enabled source.
    if (enable_map.size() == 1 && in_initchannels->size() == 1) {
        int tmpchan;
        if (sscanf((*in_initchannels)[0].c_str(), "%d", &tmpchan) != 1) {
            snprintf(errstr, 1024, "Illegal initial channel '%s'", 
                     (*in_initchannels)[0].c_str());
            return -1;
        }

        initch_map[enable_map.begin()->first] = tmpchan;
    } else {
        for (unsigned int nic = 0; nic < in_initchannels->size(); nic++) {
            tokens.clear();
            tokens = StrTokenize((*in_initchannels)[nic], ":");

            if (tokens.size() < 2) {
                snprintf(errstr, 1024, "Illegal initial channel '%s'", 
                         (*in_initchannels)[nic].c_str());
                return -1;
            }

            int tmpchan;
            if (sscanf(tokens[1].c_str(), "%d", &tmpchan) != 1) {
                snprintf(errstr, 1024, "Illegal initial channel '%s'", 
                         (*in_initchannels)[nic].c_str());
                return -1;
            }

            initch_map[StrLower(tokens[0])] = tmpchan;
        }
    }

    // Register the default channels by making them look like capsource name maps, 
    // giving them their own sequence ids we can count during assignment to see how we 
    // need to split things
    for (map<string, vector<int> >::iterator dchi = defaultch_map.begin(); 
         dchi != defaultch_map.end(); ++dchi) {
        chan_cap_seqid_map[dchi->first] = chan_seqid;
        chan_seqid_seq_map[chan_seqid] = dchi->second;
        chan_seqid++;
    }
    
    // Parse the channel lines into our channel assignment tracking maps
    for (unsigned int sc = 0; sc < in_sourcechannels->size(); sc++) {
        tokens.clear();
        tokens = StrTokenize((*in_sourcechannels)[sc], ":");

        if (tokens.size() < 2) {
            snprintf(errstr, 1024, "Illegal sourcechannel line '%s'", (*in_sourcechannels)[sc].c_str());
            return -1;
        }

        vector<string> chan_capsource_bits = StrTokenize(tokens[0], ",");
        vector<int> chan_channel_bits = Str2IntVec(tokens[1]);

        if (chan_channel_bits.size() == 0) {
            snprintf(errstr, 1024, "Illegal channel list '%s' in sourcechannel line '%s'", 
                     tokens[1].c_str(), (*in_sourcechannels)[sc].c_str());
            return -1;
        }

        // Assign the intvec a sequence id
        chan_seqid_seq_map[chan_seqid] = chan_channel_bits;

        // Assign it to each name slot
        for (unsigned int cap = 0; cap < chan_capsource_bits.size(); cap++) {
            if (chan_cap_seqid_map.find(StrLower(chan_capsource_bits[cap])) != 
                chan_cap_seqid_map.end()) {
                snprintf(errstr, 1024, "Capture source '%s' assigned multiple channel sequences.",
                         chan_capsource_bits[cap].c_str());
                return -1;
            }

            chan_cap_seqid_map[StrLower(chan_capsource_bits[cap])] = chan_seqid;
        }

        // Set this up now to make math easy later
        chan_seqid_count_map[chan_seqid] = 0;
        
        chan_seqid++;
    }
    
    // Parse the card lines into meta records for the sources that will be enabled
    for (unsigned int cl = 0; cl < in_cardlines->size(); cl++) {
        tokens.clear();
        tokens = StrTokenize((*in_cardlines)[cl], ",");

        if (tokens.size() < 3) {
            snprintf(errstr, 1024, "Illegal card source line '%s'", (*in_cardlines)[cl].c_str());
            return -1;
        }

        // Look for the card type, we won't even create a metasource if we dont' have one.
        if (cardtype_map.find(StrLower(tokens[0])) == cardtype_map.end()) {
            snprintf(errstr, 1024, "Unknown capture source type '%s' in source '%s'", 
                     tokens[0].c_str(), (*in_cardlines)[cl].c_str());
            return -1;
        }

        // Look for stuff the code knows about but which was disabled
        if (cardtype_map[StrLower(tokens[0])]->registrant == NULL) {
            snprintf(errstr, 1024, "Support for capture source type '%s' was not compiled in.  "
                     "Check your build-time configure options.", tokens[0].c_str());
            return -1;
        }

        if (enable_map.find(StrLower(tokens[2])) != enable_map.end() ||
            all_enable == 1) {

            meta_packsource *meta = new meta_packsource;
            meta->id = next_meta_id++;
            meta->cmd_ack = 1;
            meta->prototype = cardtype_map[StrLower(tokens[0])];
            meta->name = tokens[2];
            meta->device = tokens[1];
            meta->capsource = NULL;
            meta->ch_pos = 0;
            meta->cur_ch = 0;

            // Assign the initial channel - if one hasn't been requested specifically, 
            // use the prototype default.  cur_ch is treated as the initial channel 
            // when setting up the card.
            if (initch_map.find(StrLower(meta->name)) != initch_map.end()) {
                meta->cur_ch = initch_map[StrLower(meta->name)];
            } else {
                meta->cur_ch = meta->prototype->initial_channel;
            }

            // Assign the channels - if it doesn't have a specific name, we look for 
            // the default channel set.  Assignment counts are used in the next run 
            // through to assign initial channel offsets.  These map references are 
            // pretty ridiculous, but they only happen once during startup so it 
            // doesn't make much sense to go nuts trying to optimize them
            if (chan_cap_seqid_map.find(StrLower(meta->name)) != 
                chan_cap_seqid_map.end()) {
                // Hard-fault on sources that have an explicit channel hop but can't 
                // hop...
                if (meta->prototype->default_channelset == "none") {
                    snprintf(errstr, 1024, "Channel set assigned to capsource %s, which cannot channel hop.",
                             meta->name.c_str());
                    return -1;
                }

                meta->channel_seqid = chan_cap_seqid_map[StrLower(meta->name)];
                chan_seqid_count_map[meta->channel_seqid]++;
            } else if (chan_cap_seqid_map.find(StrLower(meta->prototype->default_channelset)) 
                       != chan_cap_seqid_map.end()) {

                meta->channel_seqid = chan_cap_seqid_map[StrLower(meta->prototype->default_channelset)];
                chan_seqid_count_map[meta->channel_seqid]++;
            }
                        
            meta_packsources.push_back(meta);
        }
    }

    // Now we assign split channels by going through all the meta sources, if we're 
    // hopping and splitting channels, that is.
    //
    // If we're not hopping, this doesn't happen, meta->channels.size() == 0, and 
    // we know not to hop on this device
    if (in_chhop) {
        map<int, int> tmp_seqid_assign_map;

        for (unsigned int metc = 0; metc < meta_packsources.size(); metc++) {
            meta_packsource *meta = meta_packsources[metc];

            meta->channels = chan_seqid_seq_map[meta->channel_seqid];
    
            // Bail if we don't split hop positions
            if (in_chsplit == 0)
                continue;

            // Track how many actual assignments we've made so far and use it to offset the channel position.
            if (tmp_seqid_assign_map.find(meta->channel_seqid) == tmp_seqid_assign_map.end())
                tmp_seqid_assign_map[meta->channel_seqid] = 0;

            meta->ch_pos = (meta->channels.size() / chan_seqid_count_map[meta->channel_seqid]) * 
                tmp_seqid_assign_map[meta->channel_seqid];

            tmp_seqid_assign_map[meta->channel_seqid]++;
        }
    }

    if (meta_packsources.size() == 0) {
        snprintf(errstr, STATUS_MAX, "No packsources were enabled.  Make sure that if you use an enablesource line that you specify the correct sources.");
        return -1;
    }

    return 1;
}

int Packetsourcetracker::BindSources(int in_root) {
    // Walk through all our packet sources and create an instance and opensource all the
    // ones that require root
    for (unsigned int x = 0; x < meta_packsources.size(); x++) {
        meta_packsource *meta = meta_packsources[x];

        // Skip sources that don't apply to this user mode
        if (!meta->prototype->root_required && in_root) {
            continue;
        } else if (meta->prototype->root_required && !in_root) {
            continue;
        }
        
        // Call the registrant to allocate a packet source ... nasty little error
        // handler but it works.
        errstr[0] = '\0';
        meta->capsource = (*meta->prototype->registrant)(meta->name, meta->device, errstr);

        if (meta->capsource == NULL) {
            if (strlen(errstr) == 0)
                snprintf(errstr, 1024, "Unable to create source instance for source '%s'",
                         meta->name.c_str());
            return -1;
        }

        // Enable monitor mode
        int ret = 0;
        if (meta->prototype->monitor_enable != NULL) {
            fprintf(stderr, "Source %d (%s): Enabling monitor mode for %s source "
                    "interface %s channel %d...\n",
                    x, meta->name.c_str(), meta->prototype->cardtype.c_str(), 
                    meta->device.c_str(), meta->cur_ch);

            ret = (*meta->prototype->monitor_enable)(meta->device.c_str(), 
                                                     meta->cur_ch, errstr);
        }

        if (ret < 0) {
            // Errstr gets filled out by the monitor command via reference argument
            return -1;
        }

        // Add it to the live sources vector
        live_packsources.push_back(meta->capsource);
        
        // Register the trackers with it
        meta->capsource->AddTimetracker(timetracker);
        meta->capsource->AddGpstracker(gpsd);
       
        // Open it
        fprintf(stderr, "Source %d (%s): Opening %s source interface %s...\n",
                x, meta->name.c_str(), meta->prototype->cardtype.c_str(), meta->device.c_str());
        if (meta->capsource->OpenSource() < 0) {
            snprintf(errstr, 1024, "%s", meta->capsource->FetchError());
            return -1;
        }

    }

    return 0;
    
}

int Packetsourcetracker::PauseSources() {
    for (unsigned int metc = 0; metc < meta_packsources.size(); metc++) {
        meta_packsource *meta = meta_packsources[metc];

        meta->capsource->Pause();
    }

    return 1;
}

int Packetsourcetracker::ResumeSources() {
    for (unsigned int metc = 0; metc < meta_packsources.size(); metc++) {
        meta_packsource *meta = meta_packsources[metc];

        meta->capsource->Resume();
    }

    return 1;
}

int Packetsourcetracker::SetTypeParms(string in_types, packet_parm in_parm) {
    vector<string> tokens = StrTokenize(in_types, ",");

    for (unsigned int metc = 0; metc < meta_packsources.size(); metc++) {
        meta_packsource *meta = meta_packsources[metc];
        
        for (unsigned int ctype = 0; ctype < tokens.size(); ctype++) {
            if (StrLower(meta->prototype->cardtype) == StrLower(tokens[ctype]) &&
                meta->capsource != NULL) {
                meta->capsource->SetPackparm(in_parm);
                break;
            }
        }

    }

    return 1;
}

int Packetsourcetracker::CloseSources() {
    for (unsigned int metc = 0; metc < meta_packsources.size(); metc++) {
        meta_packsource *meta = meta_packsources[metc];
      
        // close
        meta->capsource->CloseSource();
        
        // delete
        delete meta->capsource;

        // unmonitor - we don't care about errors.
        if (meta->prototype->monitor_disable != NULL)
            (*meta->prototype->monitor_disable)(meta->device.c_str(), 0, errstr);
    }

    return 1;
}

int Packetsourcetracker::SpawnChannelChild() {
    // If we don't do priv dropping don't bother opening a channel control child
#ifndef HAVE_SUID
    return 1;
#else

    int child_control = 0;
    for (unsigned int metac = 0; metac < meta_packsources.size(); metac++) {
        if (meta_packsources[metac]->prototype->child_control == 1) {
            child_control = 1;
            break;
        }
    }

    // Don't spawn a process if we don't ahve anyting to do with it
    if (child_control == 0) {
        chanchild_pid = 0;
        return 1;
    }
    
    // Generate socket pair before we split
    if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sockpair) < 0) {
        fprintf(stderr, "FATAL:  Unable to create child socket pair for channel control: %d, %s\n",
                errno, strerror(errno));
        return -1;
    }

    // Fork
    if ((chanchild_pid = fork()) < 0) {
        fprintf(stderr, "FATAL:  Unable to create child process for channel control.\n");
        return -1;
    } else if (chanchild_pid == 0) {
        // Spawn the child loop code
        ChannelChildLoop();
        exit(0);
    }

    fprintf(stderr, "Spawned channelc control process %d\n", chanchild_pid);
    
    return 1;
#endif
}

// Die cleanly
int Packetsourcetracker::ShutdownChannelChild() {
#ifndef HAVE_SUID
    return 1;
#else
    chanchild_packhdr death_packet;

    if (chanchild_pid == 0)
        return 1;
   
    memset(&death_packet, 0, sizeof(chanchild_packhdr));
    
    death_packet.sentinel = CHANSENTINEL;
    death_packet.packtype = CHANPACK_DIE;
    death_packet.flags = CHANFLAG_FATAL;
    death_packet.datalen = 0;
    death_packet.data = NULL;

    // THIS NEEDS TO BE TIMERED against blocking
    fprintf(stderr, "Sending termination request to channel control child %d...\n",
            chanchild_pid);
    send(sockpair[1], &death_packet, sizeof(chanchild_packhdr) - sizeof(void *), 0);

    // THIS NEEDS TO BE TIMERED TOO
    // At least it should die in 5 seconds from lack of commands if nothing
    // else....
    fprintf(stderr, "Waiting for channel control child %d to exit...\n",
            chanchild_pid);
    wait4(chanchild_pid, NULL, 0, NULL);

    return 1;
#endif
}

// Interrupt handler - we just die.
void ChanChildSignal(int sig) {
    exit(0);
}

// Handle reading channel change requests and driving them
void Packetsourcetracker::ChannelChildLoop() {
    list<chanchild_packhdr *> child_ipc_buffer;
    fd_set rset, wset;
    int child_dataframe_only = 0;
    char txtbuf[1024];
    // Track when we drop dead
    //time_t last_command = time(0);
   
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, ChanChildSignal);
    
    while (1) {
        int max_fd = 0;

        FD_ZERO(&rset);
        FD_ZERO(&wset);

        FD_SET(sockpair[0], &rset);
        max_fd = sockpair[0];

        // Do we need to send packets?
        if (child_ipc_buffer.size() > 0)
            FD_SET(sockpair[0], &wset);

        struct timeval tm;
        tm.tv_sec = 1;
        tm.tv_usec = 0;

        // Timeout after 1 second to see if we stopped getting commands
        if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
            // Die violently if select blows itself up
            fprintf(stderr, "FATAL:  Channel control child %d got select() error "
                    "%d:%s\n", getpid(), errno, strerror(errno));
            exit(1);
        }

        // Kluge in a timeout to exit if we don't see commands.  This shouldn't
        // be needed, but it's better to have it than to leave a root process running
        // that the server can't kill.
        //
        // We won't do this for now until it really becomes a problem
#if 0
        if (time(0) - last_command > 5) {
            fprintf(stderr, "FATAL:  Channel control child %d didn't see a command "
                    "from the server in over 5 seconds.  Something is wrong, "
                    "channel control exiting.\n", getpid());
            close(sockpair[0]);
            close(sockpair[1]);
            exit(1);
        }
#endif

        // Write a packet - wset should never be set if child_ipc_buffer is empty
        if (FD_ISSET(sockpair[0], &wset)) {
            chanchild_packhdr *pak = child_ipc_buffer.front();

            // Send the header if we didn't already
            if (child_dataframe_only == 0) {
                if (send(sockpair[0], pak, sizeof(chanchild_packhdr) - sizeof(void *), 0) < 0) {
                    if (errno == ENOBUFS)
                        goto childendpackpipewrite;
                    else
                        exit(1);
                } 
            }

            // send the payload if there is one
            if (pak->datalen > 0) {
                if (send(sockpair[0], pak->data, pak->datalen, 0) < 0) {
                    if (errno == ENOBUFS) {
                        child_dataframe_only = 1;
                        goto childendpackpipewrite;
                    } else {
                        exit(1);
                    }
                }
            }

            child_dataframe_only = 0;

            // Blow ourselves away if we just wrote a fatal failure
            if (pak->flags & CHANFLAG_FATAL)
                exit(1);

            child_ipc_buffer.pop_front();
            free(pak->data);
            delete pak;
        }

        // Labels are bad, but really, what else to do?
childendpackpipewrite: 
        ;

        // Obey incoming data
        if (FD_ISSET(sockpair[0], &rset)) {
            chanchild_packhdr pak;

            if (recv(sockpair[0], &pak, sizeof(chanchild_packhdr) - sizeof(void *), 0) < 0) {
                exit(1);
            }

            if (pak.sentinel != CHANSENTINEL) {
                snprintf(txtbuf, 1024, "capture child %d got IPC frame without valid sentinel", getpid());
                child_ipc_buffer.push_front(CreateTextPacket(txtbuf, CHANFLAG_NONE));
                continue;
            }

            // Drop dead
            if (pak.packtype == CHANPACK_DIE || pak.flags & CHANFLAG_FATAL) 
                exit(1);
          
            if (pak.packtype == CHANPACK_CMDACK)
                continue;

            // Handle changing channels
            if (pak.packtype == CHANPACK_CHANNEL) {
                chanchild_changepacket chanpak;

                // Just die if we can't receive data
                if (recv(sockpair[0], &chanpak, sizeof(chanchild_changepacket), 0) < 0)
                    exit(1);

                // Sanity check
                if (chanpak.meta_num >= meta_packsources.size()) {
                    snprintf(txtbuf, 1024, "Channel control got illegal metasource number %d", chanpak.meta_num);
                    child_ipc_buffer.push_front(CreateTextPacket(txtbuf, CHANFLAG_NONE));
                    continue;
                }

                // Can this source change the channel?
                if (meta_packsources[chanpak.meta_num]->prototype->channelcon == NULL)
                    continue;

                // Actually change it and blow up if we failed.
                // We pass a void * cast of the instance, which may or may not
                // be valid - channel change stuff has to be smart enough to test
                // for null and report an error accordingly if it uses this
                // data.
                if ((*meta_packsources[chanpak.meta_num]->prototype->channelcon)
                    (meta_packsources[chanpak.meta_num]->device.c_str(), 
                     chanpak.channel, errstr, 
                     (void *) (meta_packsources[chanpak.meta_num]->capsource)) < 0) {
                    snprintf(txtbuf, 1024, "%s", errstr);
                    child_ipc_buffer.push_front(CreateTextPacket(txtbuf, CHANFLAG_FATAL));
                    continue;
                }

                // Acknowledge
                chanchild_packhdr *ackpak = new chanchild_packhdr;

                ackpak->sentinel = CHANSENTINEL;
                ackpak->packtype = CHANPACK_CMDACK;
                ackpak->flags = CHANFLAG_NONE;
                ackpak->datalen = 1;
                ackpak->data = (uint8_t *) malloc(1);
                ackpak->data[0] = (uint8_t) chanpak.meta_num;
                child_ipc_buffer.push_back(ackpak);

            }
        } 
    }

    exit(1);
}

Packetsourcetracker::chanchild_packhdr *Packetsourcetracker::CreateTextPacket(string in_text, int8_t in_flags) {
    chanchild_packhdr *ret = new chanchild_packhdr;

    ret->sentinel = CHANSENTINEL;
    ret->packtype = CHANPACK_TEXT;
    ret->flags = in_flags;
    ret->datalen = in_text.length();
    ret->data = (uint8_t *) strdup(in_text.c_str());

    return ret;
}


