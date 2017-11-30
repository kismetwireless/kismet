# Compiling and Running Kismet on Windows 10

With the introduction of the Windows Subsystem for Linux (WSL), it's now possible to run the Kismet server on a Win10 system.

There is one major caveat:  Kismet will not be able to capture packets from your local Wi-Fi interface.  You *must* use a remote kismet capture source - this could be a Linux system, or an embedded capture device like a Wi-Fi Pineapple Tetra or another simple OpenWRT or LEDE device.

## Why would I want to do this?

The main advantage of running Kismet in the WSL is to leverage the full capabilities of your Win10 device, while capturing from a super-lightweight capture device like a Tetra, other OpenWRT, or even Raspberry Pi class device.

## Pre-Req 1:  Windows 10

The WSL only exists for Windows 10; this is not possible under Windows 8 or 9.

## Pre-Req 2:  Activate and install the WSL

You will need to activate the WSL system, and then install a Linux distribution, as per the instructions at:

[https://msdn.microsoft.com/en-us/commandline/wsl/install-win10]https://msdn.microsoft.com/en-us/commandline/wsl/install-win10

The choice of distribution to install is up to you; Ubuntu is the most logical choice as it is known to have compatibility with Kismet.

## Install dependencies

You'll need many of the dependencies Kismet needs to compile; you could install them all, but at a minimum you need to update the Ubuntu systems package lists and install:

```
$ sudo apt-get update
$ sudo apt-get install build-essential libmicrohttpd-dev git \
        libpcap-dev libncurses5-dev libsqlite3-dev
```

## Check out Kismet

As you would on Linux:

```
$ git clone https://www.kismetwireless.net/git/kismet.git
```

## Configure and compile

```
$ cd kismet
$ ./configure
$ make
```

## Install

Install - there's no reason to install as suidroot here since we will not be locally managing interfaces.

```
$ sudo make install
```

## Configure for remote capture

Check the Kismet main README file for more information on configuring remote capture; you can configure it to allow connections from remote sources, OR you can use a tool like `ssh` to tunnel a remote capture secure.

## Launch Kismet 

Run Kismet like you would on Linux:

```
$ kismet
```

or, without logging,

```
$ kismet -n
```

## Visit the Kismet server via the browser

Open your browser and go to `http://localhost:2501` to reach the Kismet server.

The password to the server will be automatically generated the first time Kismet starts.  You can find the password in the WSL filesystem under `~/.kismet/kismet_httpd.conf`.

## Fire up some remote captures

Fire up some remote captures (consult the main Kismet README for more info) and point them at your new server, and watch the packets come in!



