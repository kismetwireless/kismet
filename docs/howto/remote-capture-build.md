# Building Kismet-Git remote capture for OpenWrt
Adapted instructions from [here](https://github.com/kismetwireless/kismet/blob/master/docs/howto/pineapple-tetra.md)

A number of people have asked how to get Kismet remote capture running on OpenWrt - until the final release of the new Kismet is done, or if you'd like to play with the git version going forward, here's a quick tutorial.

*Please remember* git versions of Kismet are unstable and under development - not everything may work, or things may change rapidly.  Generally the git versions are usable but every so often you'll get a bad version.

This instruction are meant to be a quick guide to getting the Kismet specifics compiled, so I recommend checking out some OpenWrt build guides if you're completely new to the whole process.

## Step one: Install build-essentials or your distros equivalent

If you don't have them already, you'll need build-essentials and git.

## Get the Kismet code

You'll want the Kismet source code to get the openwrt package definition.

```
$ git clone https://www.kismetwireless.net/kismet.git
```

This will take a little while to download, and due to how Git handles https servers, may look like it's hung - just give it time.

## Get the OpenWrt code

```
$ git clone https://git.openwrt.org/openwrt/openwrt.git
```

## Do the basic OpenWrt Config

You will need to select the basic options for OpenWrt and enable the external feed for additional libraries Kismet needs.  When running `make menuconfig` you may see warnings about needing additional packages - install any that OpenWrt says you are missing.

```
# Go into the directory you just cloned
$ cd openwrt

# Start the configuration tool
$ make menuconfig
```

Inside the OpenWRT configuration you will want to:

1. Confirm that the correct platform is selected. For example: 
   `Target System (Atheros AR7xxx/AR9xxx) `
   and
   `  Subtarget (Generic)`
   Because we are only trying to build packages and not a complete system, we don't need to configure the image formats; default is fine.
2. Navigate to `Image Configuration`
3. Navigate to `Separate Feed Repositories`
4. Select `Enable feed packages`
5. Exit the config tool.  When prompted to save, do so.

## Install the feeds

We need to tell OpenWrt to pull the feeds into the build system.  Still in the openwrt directory you checked out, run:

```
$ ./scripts/feeds update -a
$ ./scripts/feeds install -a
```

This will download all the third-party package definitions.

## Copy the Kismet package definition

We want to copy the Kismet package over, because we'll potentially be making some modifications.

```
$ cp -R kismet/packaging/openwrt/kismet-remote-2018 openwrt/package/network
```

Where, of course, you want to copy from your checked out Kismet code to the checked out OpenWrt code; your directories might be different.

## Install libprotoc-c

In a perfect world the libprotoc-c package in OpenWRT would install the proper host binary for protoc-c, but it does not.  Fortunately, there is only one version of libproto-c (the C-only version), so the package for your host distribution should be sufficient.

```
$ sudo apt-install protobuf-c-compiler
```

will suffice on Ubuntu-style distributions; your distribution may vary.  Note:  This is for the *protobuf-c* version, *not* the normal protobuf (which is C++, and which has a working openwrt package with proper host tools.)

## Enable Kismet

Now we need to enable the Kismet package.  Still in your OpenWrt directory:

1. Enter OpenWrt configuration again:  `make menuconfig`
2. Navigate to 'Network'
3. Scroll all the way down to 'kismet-remote', it will be several screens down.
4. Enable kismet-remote as a *module*.  Hit 'm' to do so.
5. Exit, saving when prompted to.

## Compile OpenWrt

Now we need to start the build process:  It will take a while.

```
$ make
```

Depending on how many processors your system has, you can speed this up with

```
$ make -j4
```

or similar.

If you still get an error regarding protoc-c not found, you may have to link you local version where the OpenWrt version is supposed to be, like:

```
ln -s /usr/bin/protoc-c staging_dir/target-<arch foo>_musl-1.1.16/host/bin/protoc-c
```

## Copy the packages!

If everything went well, you now have two packages to copy to your OpenWrt:
```
$ cd bin/packages/<architecture>/
$ scp packages/libprotobuf-c<arch foo>.ipk base/kismet-remote<arch foo>.ipk root@openwrt-machine:/tmp 
```
## Install Kismet on OpenWrt

SSH into the OpenWrt and install the packages:

```
$ ssh root@openwrt-machine
...
# cd /tmp
# opkg install *.ipk
```

## Run kismet!

Fire up kismet remote capture and see how it goes.  While SSHd into the OpenWrt as root:
```
# kismet_cap_linux_wifi --connect [host]:[port] --source=wlan0
```
or alike. Use `--help` for more information.

