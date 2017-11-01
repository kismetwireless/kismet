# Building Kismet-Git for the Wi-Fi Pineapple Tetra

A number of people have asked how to get Kismet running on the Tetra - until the final release of the new Kismet is done, or if you'd like to play with the git version going forward, here's a quick tutorial.

*Please remember* git versions of Kismet are unstable and under development - not everything may work, or things may change rapidly.  Generally the git versions are usable but every so often you'll get a bad version.

These instructions should work for other openwrt based systems, as well, with some modifications.  In general they're meant to be a quick guide to getting the Kismet specifics compiled, so I recommend checking out some OpenWRT build guides if you're completely new to the whole process.

## Yes, there will be a module!

If these instructions are too much or you don't have a system set up for doing openwrt builds, just hang tight!  There *will* be an official Kismet module, but not until things are a little more stable in the Kismet tree (logging, for instance, is a problem right now for an embedded system like the Tetra).  If you can't wait or love living on the bleeding edge, keep reading.

## Warning: Ubuntu 16.10

It seems like the openwrt trunk (or at least, the one snapshotted to match the shipping Tetra) doesn't like to build under Ubuntu 16.10 due to the new compilers throwing warnings that end up being fatal to the build process.

You can either hack around these, or build under a 16.04 system, for now.

## Step one: Install build-essentials or your distros equivalent

If you don't have them already, you'll need build-essentials and git.

## Get the Kismet code

You'll want the Kismet source code to get the openwrt package definition.

```
$ git clone https://www.kismetwireless.net/kismet.git
```

This will take a little while to download, and due to how Git handles https servers, may look like it's hung - just give it time.

## Get the tetra openwrt code

Firstly, you'll need the Tetra snapshot of OpenWRT.  It's on github at https://github.com/WiFiPineapple/openwrt-pineapple-tetra so you'd do:

```
$ git clone https://github.com/WiFiPineapple/openwrt-pineapple-tetra.git
```

## Fix the OpenWRT download script

Openwrt hasn't been updated in some time; the kernel.org FTP server is now gone.

Edit `scripts/download.pl` in your OpenWRT source and change:

`push @mirrors, "http://ftp.all.kernel.org/pub/$dir";`

to

`push @mirrors, "https://kernel.org/pub/$dir";`

## Enable the feeds in OpenWRT

Kismet needs a bunch of libraries which are found in the OpenWRT Git Feeds.  You can enable them in the OpenWRT build by:

1. Go into the OpenWRT directory you just cloned: `$ cd src/openwrt-pineapple-tetra/`
2. Run menuconfig: `$ make menuconfig`
3. Navigate to 'Image Configuration'
4. Navigate to 'Separate Feed Repositories'
5. Select 'Enable feed packages'

Then tab over to Exit, back out, and when prompted to save, do so.

## Install the feeds

We need to tell OpenWRT to pull the feeds into the build system.  Still in the openwrt directory you checked out, run:

```
$ ./scripts/feeds update -a
$ ./scripts/feeds install -a
```

This will download all the third-party package definitions.

## Copy the Kismet package

We want to copy the Kismet package over, because we'll potentially be making some modifications.

```
$ cp -R ~/src/kismet/packaging/openwrt/kismet-tetra ~/src/openwrt-pineapple-tetra/package/network
```

Where, of course, you want to copy from your checked out Kismet code to the checked out OpenWRT Tetra code; your directories might be different.

## Edit the Kismet package

If you want to get on the absolutely latest bleeding edge Kismet git, there are two changes you can make.  Open up package/network/kismet-tetra/Makefile in an editor, then:

1. Update the git version to the latest.  Run `git log` in the Kismet code directory, and get the latest commit ID.  It should look like a big string of numbers and letters, such as `commit 1e54a5c9d2e45180493c36d528a6e02841dacaa6`.  In the Makefile you're editing, replace the version in the line `PKG_SOURCE_VERSION:=` with this new commit.
2. If you want to make building a lot faster, you can change the line `PKG_SOURCE_URL:=https://www.kismetwireless.net/kismet.git` to point to your local copy you've already checked out, for instance, `PKG_SOURCE_URL:/home/dragorn/src/kismet/`, replacing the path with the path to where you checked out Kismet git in the first step.

## Enable Kismet

Now we need to enable the Kismet package.  Still in your OpenWRT directory:

1. Enter OpenWRT configuration again:  `make menuconfig`
2. Navigate to 'Network'
3. Scroll all the way down to 'kismet-tetra', it will be several screens down.
4. Enable kismet-tetra as a *module*.  Hit 'm' to do so.
5. Exit, saving when prompted to.

## Compile OpenWRT

Now we need to start the build process:  It will take a while.

```
$ make
```

## Copy the packages!

If everything went well, you now have a bunch of packages to copy to your Tetra:

```
$ cd bin/ar71xx/packages
$ scp  packages/libmicrohttpd_0.9.38-1.2_ar71xx.ipk base/libpcap_1.5.3-1_ar71xx.ipk base/libnl_3.2.21-1_ar71xx.ipk base/libnettle_3.1.1-1_ar71xx.ipk packages/libgcrypt_1.6.1-1_ar71xx.ipk packages/libgpg-error_1.12-1_ar71xx.ipk base/libstdcpp_4.8-linaro-1_ar71xx.ipk packages/libcap_2.24-1_ar71xx.ipk base/kismet-tetra_2017git-1_ar71xx.ipk packages/libpcre_8.39-1_ar71xx.ipk packages/libgnutls_3.4.15-1_ar71xx.ipk packages/libsqlite3_3081101-1_ar71xx.ipk root@172.16.42.1:/tmp
```

## If you're rebuilding the latest Git

If you have already compiled Kismet and are just trying to update it, you simply need to:

1. Edit the Kismet package Makefile as above, to set the latest git version
-or-
2. If the git version is set to `'HEAD'`, you will need to delete the staging and downloaded code.  From your openwrt build dir,
    ```
    $ rm -rf build_dir/target-mips_34kc_uClibc-0.9.33.2/kismet-tetra-2017git/
    $ rm dl/kismet*
    ```
3. Run `make menuconfig` to update any dependencies which have changed
4. Compile normally

## Install Kismet on the tetra

SSH into the Tetra and install the packages:

```
$ ssh root@172.16.42.1
...
# cd /tmp
# opkg install *.ipk
```

## Turn off the pineapple management SSID

If you want to run Kismet on both interfaces, turn off the pineapple management SSID via the pineapple webui in Networking, Access Points, Disable Management AP

## Run kismet!

Fire up kismet and see how it goes.  While SSHd into the tetra as root:

```
# kismet_server -n -c wlan0 -c wlan1
```

If you want to leave the management SSID running, only run Kismet on wlan1:

```
# kismet_server -n -c wlan1
```

then point your browser at http://172.16.42.1:2501 and you should see it running!

