---
title: "Upgrading"
permalink: /docs/readme/upgrading/
excerpt: "Upgrading to the new Kismet"
---

## Upgrading & Using Kismet Git-Master (or beta)

The safest route is to remove any old Kismet version you have installed - by uninstalling the package if you installed it via your distribution, or by removing it manually if you installed it from source (specifically, be sure to remove the binaries `kismet_server`, `kismet_client`,  and `kismet_capture`, by default found in `/usr/local/bin/` and the config file `kismet.conf`, by default in `/usr/local/etc/`.

You can then configure, and install, the new Kismet per the quickstart guide above.

While heavy development is underway, the config file may change; generally breaking changes will be mentioned on Twitter and in the git commit logs.

Sometimes the changes cause problems with Git - such as when temporary files are replaced with permanent files, or when the Makefile removes files that are now needed.  If there are problems compiling, the easiest first step is to remove the checkout of directory and clone a new copy (simply do a `rm -rf` of the copy you checked out, and `git clone` a new copy)
