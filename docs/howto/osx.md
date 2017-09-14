# Compiling Kismet on OSX

Kismet is capable of running on OSX systems, however, currently, it is _not_ capable of capturing data on OSX natively; to capture packets you will need to capture data on a supported remote system (Linux) as a remote capture.

## Building Kismet

Kismet should build on OSX directly, but requires some libraries be installed.  The easiest way to get the libraries is via MacPorts using the `port` tool:

```
# Make a source dir (optional)
$ mkdir src

# Install libraries via macports
$ sudo port install libmicrohttpd

# Get the Kismet code
$ cd src
$ git clone https://www.kismetwireless.net/git/kismet.git

# Configure kismet
$ ./configure

# Build
$ make

# Install - generally it's best to do 'make suidinstall', but currently there are no binaries for capture using root on OSX
$ sudo make suidinstall

```

## Configuring Kismet

To work with OSX, Kismet needs to have remote capture enabled.  Remote capture can either be enabled on all listening interfaces, or enabled locally and a tunneling tool, such as `stunnel` or `ssh` with port forwarding, can be used to expose the remote capture interface.

### Enabling remote capture

Remote capture should ONLY be enabled on systems on a private network; any system able to connect to the server will be able to send data.

To enable remote capture beyond localhost:

1.  Edit `/usr/local/etc/kismet.conf`
2.  Change the `remote_capture_listen` variable from `127.0.0.1` to `0.0.0.0`:

```
remote_capture_listen=0.0.0.0
remote_capture_port=3501
```

Then, start Kismet.

On the system that will capture data, launch the remote capture process:

For instance,

```
$ sudo /usr/local/bin/kismet_capture_tools/kismet_cap_linux_wifi --connect osx-system-address:3501 --source wlan0:name=some-remote-wlan0
```

or

```
$ sudo /usr/local/bin/kismet_capture_tools/kismet_cap_linux_bluetooth --connect osx-system-address:3501 --source hci0:name=some-remote-hci0
```

### Using SSH tunnels

From the system that will capture packets, SSH into your OSX system using port forwarding:

```
$ ssh someuser@192.168.1.2 -L 3501:localhost:3501
```

Then launch the capture tool pointing at the port forward:

```
$ sudo /usr/local/bin/kismet_capture_tools/kismet_cap_linux_wifi --connect localhost:3501 --source wlan0:name=some-remote-wlan0
```

or

```
$ sudo /usr/local/bin/kismet_capture_tools/kismet_cap_linux_bluetooth --connect localhost:3501 --source hci0:name=some-remote-hci0
```

## Connect to kismet

The Kismet web UI should be accessible on the OSX system by going to `http://localhost:2501` with your browser.

Remote sources should be shown and be controllable per normal.
