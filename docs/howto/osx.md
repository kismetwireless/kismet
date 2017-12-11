# Compiling Kismet on OSX

Kismet is capable of running on OSX systems, however, currently, it is _not_ capable of capturing data on OSX natively; to capture packets you will need to capture data on a supported remote system (Linux) as a remote capture.

## Building Kismet

Kismet should build on OSX directly, but requires some libraries be installed.  The easiest way to get the libraries is via MacPorts using the `port` tool.

1. Install MacPorts from the Macports website - https://www.macports.org

2. Make a source dir for Kismet (optional, but recommended)
   `$ mkdir src`

3. Get the Kismet code

   `$ git clone https://www.kismetwireless.net/git/kismet.git`

4. Install the needed libraries via ports; When prompted to install other necessary libraries, of course say `yes`:
   `$ sudo port install libmicrohttpd`
   `$ sudo port install pcre`

5. Configure Kismet.  You'll need to pass some options to tell the OSX compilers where to find the libraries and headers installed by Ports:
   `$ CFLAGS="-I/opt/local/include" LDFLAGS="-L/opt/local/lib" CPPFLAGS="-I/opt/local/include" ./configure`

6. Compile Kismet
   `$ make`

7. Install Kismet
   `$ make suidinstall`


`make suidinstall` will install the Kismet helpers as suid-root, executeable by users in the `staff` group in OSX.

## Configuring and Running Kismet

Kismet supports both local capture (from CoreWLAN / Apple wireless devices) and remote capture (from embedded Linux devices, etc, over the network).

Kismet will (currently) work *only* with Wi-Fi devices supported by the built-in Apple drivers; it will *not* work with USB devices; They use vendor drivers which do not support monitor mode or provide control APIs.

Kismet will list the available Wi-Fi sources in the `Datasources` panel of the UI, or can be run from the command line:

`$ kismet -c en1`

## Connect to kismet

The Kismet web UI should be accessible on the OSX system by going to `http://localhost:2501` with your browser.

Remote sources should be shown and be controllable per normal.
