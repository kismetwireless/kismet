---
title: "Datasource capframework library"
permalink: /docs/devel/datasources_capframework/
toc: true
---

# Under Development

These docs represent an API that is still heavily under development - until the first internal implementations are done, it would be unwise to start an independent implementation as I may need to change the protocol.

# Extending Kismet: Datasource Capture Framework Pure-C API

Kismet supports capturing from any binary capable of talking a simple IPC/network protocol.

To minimize the requirements and simplify embedding capture code in small embedded systems without a C++ runtime, `capture_framework.h` and `capture_framework.c` implement the protocol and main communications loops in a pure-c helper library.

## Pure-C

Capture-Framework is written in pure-c which should be compatible with C99 and does not require any C++ runtimes.  The Kismet plugins and decoders still require C++.

## Communication

Kismet capture binaries communicate over IPC on a shared pipe, or via a TCP network connection to the Kismet server.  When using piped IPC, the pipe pairs are passed to the exec()'d capture binary in the --in-fd and --out-fd command line options.

Data is buffered in generic, simplistic ring buffer structures and dispatched via a standard select() loop.

## Threads

Capture-Framework uses pthreads to spawn two threads, in addition to the primary main thread:

### Capture Thread

The capture callback (more on these soon) is run in an independent, cancelable thread.  This allows the capture calls on a binary to block without interfering with the standard select() loop and communication with the Kismet server.

### Channel Hopping Thread

If channel hopping is enabled in the capture binary, an independent thread performs the timing and channel set commands.

## Callbacks

All expandable functions in Capture-Framework are handled by passing callback functions; listing devices, probing, opening, setting channels, etc, are handled by callback functions and can be trivially customized.

# Order of Operations

Kismet will launch a capture binary and perform one of several actions:

## List devices

This is called on all capture drivers to create a list of devices the user could pick.  The capture binary is responsible for enumerating any devices it can support via any mechanism; for instance the Linux Wi-Fi capture binary enumerates devices by processing the /sys/class/net/ pseudofilesystem.

After listing devices, a capture binary should go into a spindown/pending state and wait to be closed, no other action will be taken this execution.

## Probe definition

This is called to determine the driver which can handle a definition, when no type is explicitly specified.  The capture binary is responsible for determining if this looks like a source that can be opened.  For example, the pcapfile capture will attempt to open the definition as a pcap; the Linux Wi-Fi capture will attempt to retrieve the interface channel via SIOCGIWCHAN to determine if it looks to be a Wi-Fi device.

After returning a probe response, a capture binary should go into a spindown/pending state and wait to be closed, no other action will be taken this execution.

## Open definition

This is called to actually open and begin capturing from an interface.

