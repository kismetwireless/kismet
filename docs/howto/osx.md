# Compiling Kismet on OSX

Kismet is capable of running on OSX and capturing data on OSX natively.

## Building Kismet

Kismet should build on OSX directly, but requires some libraries be installed.

1. Install XCode from the Apple App Store.  You may be prompted, during the course of installing MacPorts, to install other components of XCode and the XCode command line utilities. 

2. Install a ports library; for example:

   * MacPorts from https://www.macports.org
   * HomeBrew from https://brew.sh/

3. Install the needed external libraries; If prompted to install other necessary libraries or tools, of course say `yes`:

   * For `macports`:

     `$ sudo port install libmicrohttpd pcre protobuf-c protobuf-cpp`

   * For `brew`:

     `$ brew install libmicrohttpd pcre protobuf protobuf-c`

4. Make a source dir for Kismet (optional, but recommended)
   `$ mkdir src`

5. Get the Kismet code

   `$ git clone https://www.kismetwireless.net/git/kismet.git`

6. Configure Kismet.  You'll likely need to pass some options to tell the OSX compilers where to find the libraries and headers:
   `$ CFLAGS="-I/opt/local/include" LDFLAGS="-L/opt/local/lib" CPPFLAGS="-I/opt/local/include" ./configure`

7. Compile Kismet
   `$ make`

   There will be some warnings - generally they can be ignored.  As the OSX port evolves, the warnings will be cleaned up.

8. Install Kismet
   `$ sudo make suidinstall`

   `make suidinstall` will install the Kismet helpers as suid-root, executeable by users in the `staff` group in OSX.  There is more information on the suidinstall method in the Kismet README; in generally it increases the overall Kismet security by allowing you to launch Kismet as a normal user; only the packet capture tools will run as root.

## Configuring and Running Kismet

Kismet supports both local capture (from CoreWLAN / Apple wireless devices) and remote capture (from embedded Linux devices, etc, over the network).

Kismet will (currently) work *only* with Wi-Fi devices supported by the built-in Apple drivers; it will *not* work with USB devices; They use vendor drivers which do not support monitor mode or provide control APIs.

`$ kismet`

Kismet will list the available Wi-Fi sources in the `Datasources` panel of the UI, or sources can be configured from the command line or the Kismet config files.

`$ kismet -c en1`

For more information on configuring Kismet in general, as well as logging formats and other Kismet features, be sure to check out the normal Kismet README file.

## Connect to Kismet

The Kismet web UI should be accessible on the OSX system by going to `http://localhost:2501` with your browser.

The Kismet web password is stored in `~/.kismet/kismet_httpd.conf` in the home directory of the user who is running Kismet.
