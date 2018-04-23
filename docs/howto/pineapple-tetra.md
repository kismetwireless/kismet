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

## Get the OpenWRT code

With the move to the 2.x firmware, the Tetra is now based on OpenWRT 15.05.  Until the official Tetra branch is posted, for compiling individual packages you should be able to base off the OpenWRT master branch:

```
$ git clone https://git.openwrt.org/15.05/openwrt.git openwrt-cc-tetra
```

## Patch the OpenWRT Code

The 15.05 branch of OpenWRT has issues building on modern systems; so you have 2 options:

1. Install an older Ubuntu in a virtual machine or container (14.04 would likely work)
2. Modify some files.

Assuming you'll be building on a modern system, first you will have to patch the prerequisite build system to detect modern git; without this, `make menuconfig` (or any other build commands) will fail.

```
diff --git a/include/prereq-build.mk b/include/prereq-build.mk
index 32c4adabb7..93aae75756 100644
--- a/include/prereq-build.mk
+++ b/include/prereq-build.mk
@@ -144,8 +144,9 @@ $(eval $(call SetupHostCommand,python,Please install Python 2.x, \
 $(eval $(call SetupHostCommand,svn,Please install the Subversion client, \
        svn --version | grep Subversion))
 
-$(eval $(call SetupHostCommand,git,Please install Git (git-core) >= 1.6.5, \
-       git clone 2>&1 | grep -- --recursive))
+$(eval $(call SetupHostCommand,git,Please install Git (git-core) >= 1.7.12.2, \
+       git --exec-path | xargs -I % -- grep -q -- --recursive %/git-submodule))
+
 
 $(eval $(call SetupHostCommand,file,Please install the 'file' package, \
        file --version 2>&1 | grep file))
```

You'll also need to patch against a bug in the old OpenWRT code triggered by a modern perl version:

```
$ curl 'https://git.openwrt.org/?p=openwrt/openwrt.git;a=blob_plain;f=tools/automake/patches/010-automake-port-to-Perl-5.22-and-later.patch;h=31b9273d547145e5ecbeaef20a1e82cc9292fdc2;hb=92c80f38cff3c20388f9ac13d5196f2745aeaf77' > tools/automake/patches/010-automake-perl.patch
```

## Tweak packet.mk

Some versions of OpenWRT have an issue when using MIPS16 Interlink mode; as the Tetra and Nano use the MIPS processor, this can raise it's head as a bug where Kismet will fail with 'invalid opcode sync' errors.

The simplest way to fix this is to edit `include/package.mk`.  Change the line:

`PKG_USE_MIPS16 ?= 1`
to
`PKG_USE_MIPS16 ?= 0`

If you have already built OpenWRT, you may need to do `make clean` after making this change.

## Do the basic OpenWRT Config

You will need to select the basic options for OpenWRT and enable the external feed for additional libraries Kismet needs.  When running `make menuconfig` you may see warnings about needing additional packages - install any that OpenWRT says you are missing.

```
# Go into the directory you just cloned
$ cd openwrt-cc-tetra

# Start the configuration tool
$ make menuconfig
```

Inside the OpenWRT configuration you will want to:

1. Confirm that the correct platform is selected.  It should say:
   `Target System (Atheros AR7xxx/AR9xxx) `
   and
   `  Subtarget (Generic)`
   These are the defaults so you should be all set.
   Because we are only trying to build packages and not a complete system, we don't need to configure the image formats; default is fine.
2. Navigate to `Image Configuration`
3. Navigate to `Separate Feed Repositories`
4. Select `Enable feed packages`
5. Exit the config tool.  When prompted to save, do so.

## Install the feeds

We need to tell OpenWRT to pull the feeds into the build system.  Still in the openwrt directory you checked out, run:

```
$ ./scripts/feeds update -a
$ ./scripts/feeds install -a
```

This will download all the third-party package definitions.

## Copy the Kismet package definition

We want to copy the Kismet package over, because we'll potentially be making some modifications.

```
$ cp -R ~/src/kismet/packaging/openwrt/kismet-2018-tetra ~/src/openwrt-master-tetra/package/network
```

Where, of course, you want to copy from your checked out Kismet code to the checked out OpenWRT Tetra code; your directories might be different.

## Install libprotoc-c

In a perfect world the libprotoc-c package in OpenWRT would install the proper host binary for protoc-c, but it does not.  Fortunately, there is only one version of libproto-c (the C-only version), so the package for your host distribution should be sufficient.

```
$ sudo apt-install protobuf-c-compiler
```

will suffice on Ubuntu-style distributions; your distribution may vary.  Note:  This is for the *protobuf-c* version, *not* the normal protobuf (which is C++, and which has a working openwrt package with proper host tools.)

## Enable Kismet

Now we need to enable the Kismet package.  Still in your OpenWRT directory:

1. Enter OpenWRT configuration again:  `make menuconfig`
2. Navigate to 'Network'
3. Scroll all the way down to 'kismet', it will be several screens down.
4. Enable kismet-2018-tetra as a *module*.  Hit 'm' to do so.  If you have multiple kismet packages, make sure to select the right one - viewing the help on the entry will show you the version.
5. Exit, saving when prompted to.

## Compile OpenWRT

Now we need to start the build process:  It will take a while.

```
$ make
```

Depending on how many processors your system has, you can speed this up with

```
$ make -j10
```

or similar.

## Copy the packages!

If everything went well, you now have a bunch of packages to copy to your Tetra:

```
$ cd bin/ar71xx/packages
$ scp packages/libmicrohttpd_0.9.38-1.2_ar71xx.ipk base/libpcap_1.8.1-1_ar71xx.ipk base/libnl_3.2.21-1_ar71xx.ipk base/libnettle_3.1.1-1_ar71xx.ipk packages/libgcrypt_1.6.1-1_ar71xx.ipk packages/libgpg-error_1.12-1_ar71xx.ipk base/libstdcpp_4.8-linaro-1_ar71xx.ipk packages/libcap_2.24-1_ar71xx.ipk packages/libpcre_8.39-1_ar71xx.ipk packages/libgnutls_3.4.15-1_ar71xx.ipk packages/libsqlite3_3081101-1_ar71xx.ipk packages/protobuf_2.6.1-1_ar71xx.ipk packages/libprotobuf-c_v1.0.1_ar71xx.ipk base/kismet-2018-tetra_git-0_ar71xx.ipk root@172.16.42.1:/tmp
```

## If you're rebuilding the latest Git

If you have already compiled Kismet and are just trying to update it, you simply need to:

1. Delete the staging and downloaded code.  From your openwrt build dir,

  ```
  $ rm -rf build_dir/target-mips_34kc_uClibc-0.9.33.2/kismet-2018git/
  $ rm dl/kismet*
  ```
2. Run `make menuconfig` to update any dependencies which have changed
3. Compile normally as before or compile just the Kismet package and its dependencies with:
    ` $ make package/network/kismet/compile`

*NOTE* - If you recently updated Kismet to the new Protobuf code, see the above section on modifying `include/package.mk` or you will have problems!

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

