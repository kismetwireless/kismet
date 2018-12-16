---
title: "Debugging"
permalink: /docs/readme/debugging/
excerpt: "Kismet README and Quick Start Guide"
---

## Debugging Kismet

Kismet (especially in beta) is in a state of rapid development - this means that bad things can creep into the code.  Sorry about that!

If you're interested in helping debug problems with Kismet, here's the most useful way to do so:

1. Compile Kismet from source (per the quick start guide above)

2. Install Kismet (typically via `sudo make suidinstall`)

3. Run Kismet, *FROM THE SOURCE DIRECTORY*, in `gdb`:

  ```bash
  $ gdb ./kismet
  ```

  This loads a copy of Kismet with all the debugging info intact; the copy of Kismet which is installed system-wide usually has this info removed; the installed version is 1/10th the size, but also lacks a lot of useful information which we need for proper debugging.

4. Tell GDB to ignore the PIPE signal 

   ```
   (gdb) handle SIGPIPE nostop noprint pass
   ```

   This tells GDB not to intercept the SIGPIPE signal (which can be generated, among other times, when a data source has a problem)

5. Configure GDB to log to a file

  ```
  (gdb) set logging on
  ```

  This saves all the output to `gdb.txt`

5. Run Kismet - *in debug mode*

  ```
  (gdb) run --debug [any other options]
  ```

  This turns off the internal error handlers in Kismet; they'd block gdb from seeing what happened.  You can specify any other command line options after --debug; for instance:

  ````
  (gdb) run --debug -n -c wlan1
  ````

6.  Wait for Kismet to crash

7.  Collect a backtrace
   ```
   (gdb) bt
   ```

   This shows where Kismet crashed.

8.  Collect thread info
   ```
   (gdb) info threads
   ```

   This shows what other threads were doing, which is often critical for debugging.

9.  Collect per-thread backtraces
   ```
   (gdb) thread apply all bt full
   ```

   This generates a dump of all the thread states

10. Send us the gdb log and any info you have about when the crash occurred; dragorn@kismetwireless.net or swing by IRC or the Discord channel (info available about these on the website, https://www.kismetwireless.net)

#### Advanced debugging

If you're familiar with C++ development and want to help debug even further, Kismet can be compiled using the ASAN memory analyzer; to rebuild it with the analyser options:

```
    $ make clean
    $ CC=clang CXX=clang++ ./configure --enable-asan
```

ASAN has a performance impact and uses significantly more RAM, but if you are able to recreate a memory error inside an ASAN instrumented Kismet, that will be very helpful.

## Upgrading & Using Kismet Git-Master (or beta)

The safest route is to remove any old Kismet version you have installed - by uninstalling the package if you installed it via your distribution, or by removing it manually if you installed it from source (specifically, be sure to remove the binaries `kismet_server`, `kismet_client`,  and `kismet_capture`, by default found in `/usr/local/bin/` and the config file `kismet.conf`, by default in `/usr/local/etc/`.

You can then configure, and install, the new Kismet per the quickstart guide above.

While heavy development is underway, the config file may change; generally breaking changes will be mentioned on Twitter and in the git commit logs.

Sometimes the changes cause problems with Git - such as when temporary files are replaced with permanent files, or when the Makefile removes files that are now needed.  If there are problems compiling, the easiest first step is to remove the checkout of directory and clone a new copy (simply do a `rm -rf` of the copy you checked out, and `git clone` a new copy)

