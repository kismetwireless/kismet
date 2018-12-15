---
title: "Installing Kismet: SUID vs Non-SUID"
permalink: /docs/readme/suid/
excerpt: "SUID and non-SUID installation"
---

## Installing Kismet - Suid vs Normal

It is **strongly** recommended that Kismet never be run as root; instead use the Kismet suid-root installation method; when compiling from source it can be installed via:
```
$ ./configure
$ make
$ sudo make suidinstall
```

Nearly all packages of Kismet *should* support the suid-root install method as well.

This will create a new group, `kismet`, and install capture tools which need root access as suid-root but only runnable by users in the `kismet` group.

This will allow anyone in the Kismet group to change the configuration of wireless interfaces on the system, but will prevent Kismet from running as root.

#### Why does Kismet need root?

Controlling network interfaces on most systems requires root, or super-user access.

While written with security strongly in mind, Kismet is a large and complex program, which handles possibly hostile data from the world.  This makes it a very bad choice to run as root.

To mitigate this, Kismet uses separate processes to control the network interfaces and capture packets.  These capture programs are much smaller than Kismet itself, and do minimal (or no) processing on the contents of the packets they receive.

