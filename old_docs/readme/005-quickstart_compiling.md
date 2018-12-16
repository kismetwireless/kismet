---
title: "Quickstart"
permalink: /docs/readme/quickstart/
excerpt: "Quick Start Guide"
#toc: true
---

## Compiling: Quick Setup

Kismet has many configuration knobs and options; but for the quickest way to get the basics working:

1. Uninstall any existing Kismet installs.  If you installed Kismet using a package from your distribution, uninstall it the same way; if you compiled it yourself, be sure to remove it

2. Install dependencies.  Kismet needs a number of libraries and  development headers to compile; these should be available in nearly all distributions.

   *Ubuntu/Debian/Kali/Mint*

   ```bash
   $ sudo apt-get install build-essential git libmicrohttpd-dev pkg-config zlib1g-dev libnl-3-dev libnl-genl-3-dev libcap-dev libpcap-dev libncurses5-dev libnm-dev libdw-dev libsqlite3-dev libprotobuf-dev libprotobuf-c-dev protobuf-compiler protobuf-c-compiler libsensors4-dev
   ```

   On some older versions, `libprotobuf-c-dev` may be called `libprotobuf-c0-dev`.
   
   For the Python add-ons, you will also need the following Python2 libraries.  The `protobuf` tool currently does not appear to agree with the changes in python3, so python2 is required:

   ```bash
   $ sudo apt-get install python2 python-setuptools python-protobuf python-requests
   ```

   You can also use the `pip` equivalents of the python libraries, so long as they're installed in a location your normal Python interpreter can find them.

   For rtlsdr rtl_433 support, you will also need:

   ```bash
   $ sudo apt-get install librtlsdr0 python-usb python-paho-mqtt
   ```
   as well as the rtl_433 tool from https://github.com/merbanan/rtl_433 if it is not otherwise provided by your distribution.

   For Mousejack/nRF support and other USB based tools, you will need `libusb`:

   ```bash
   $ sudo apt-get install libusb-1.0-0-dev
   ```

   *Fedora (and related)*

   ```bash
   $ sudo dnf install make automake gcc gcc-c++ kernel-devel git libmicrohttpd-devel pkg-config zlib-devel libnl3-devel libcap-devel libpcap-devel ncurses-devel NetworkManager-libnm-devel libdwarf libdwarf-devel elfutils-devel libsqlite3x-devel protobuf-devel protobuf-c-devel protobuf-compiler protobuf-c-compiler lm_sensors-devel libusb-devel fftw-devel
   ```

   You will also need the related python2 packages.

3. Clone Kismet from git.  If you haven't cloned Kismet before:
   ```bash
   $ git clone https://www.kismetwireless.net/git/kismet.git
   ```

    If you have a Kismet repo already:

    ```bash
   $ cd kismet
   $ git pull
    ```

4. Run configure.  This will find all the specifics about your system and prepare Kismet for compiling.  If you have any missing dependencies or incompatible library versions, they will show up here.
   ```bash
   $ cd kismet
   $ ./configure
   ```

   Pay attention to the summary at the end and look out for any warnings! The summary will show key features and raise warnings for missing dependencies which will drastically affect the compiled Kismet.

5. Compile Kismet.
   ```bash
   $ make
   ```

   You can accelerate the process by adding `-j #`, depending on how many CPUs you have.  To automatically compile on all the available cores:
   ```bash
   $ make -j$(nproc)
   ```

   C++ uses quite a bit of RAM to compile, so depending on the RAM available on your system you may need to limit the number of processes you run simultaneously.

6.  Install Kismet.  Generally, you should install Kismet as suid-root; Kismet will automatically add a group and install the capture binaries accordingly.

   When installed suid-root, Kismet will launch the binaries which control the channels and interfaces with the needed privileges, but will keep the packet decoding and web interface running without root privileges.
   ```bash
   $ sudo make suidinstall
   ```

7.  Add your user to the `kismet` group.
   ```bash
   $ sudo usermod -aG kismet $USER
   ```
   This will add your current logged in user to the `kismet` group.

8.  Log out and back in.  Linux does not update groups until you log in; if you have just added yourself to the Kismet group you will have to re-log in.

9.  Check that you are in the Kismet group with:
   ```bash
   $ groups
   ```
   If you are not in the `kismet` group, you should log out entirely, or reboot.

10.  You're now ready to run Kismet!  Point it at your network interface... Different distributions (and kernel versions, and distribution versions) name interfaces differently; your interface may be `wlan0` or `wlan1`, or it may be named something like `wlp0s1`, or it may be named using the MAC address of the card and look like `wlx00c0ca8d7f2e`.

   You can now start Kismet with something like:
   ```bash
   $ kismet -c wlan0
   ```

   *or*, you can just launch Kismet and then use the new web UI to select the card you want to use, by launching it with just:
   ```bash
   $ kismet
   ```

   Remember, until you add a data source, Kismet will not be capturing any packets!

   *THE FIRST TIME YOU RUN KISMET*, it will generate a new, random password for your web interface.

   This password can be found in the config file: `~/.kismet/kismet_httpd.conf` which is in the *home directory of the user* starting Kismet.

   If you start Kismet as or via sudo (or via a system startup script where it runs as root), this will be in *roots* home directory: `/root/.kismet/kismet_httpd.conf`

  You will need this password to control Kismet from the web page - without it you can still view information about devices, view channel allocations, and most other actions, but you CAN NOT control Kismet data sources, view pcaps, or perform other actions.

11.  Point your browser at http://localhost:2501

   You will be prompted to do basic configuration - Kismet has many options in the web UI which can be tweaked.

   To use all the features of the Kismet web UI, put in the password found in the `kismet_httpd.conf` config file above.

