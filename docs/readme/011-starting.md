---
title: "Starting Kismet"
permalink: /docs/readme/starting_kismet/
excerpt: "Starting Kismet"
---

## Starting Kismet

Kismet can be started normally from the command line, and will run in a small ncurses-based wrapper which will show the most recent server output, and a redirect to the web-based interface.

Kismet can also be started as a service; typically in this usage you should also pass `--no-ncurses` to prevent the ncurses wrapper from loading.

An example systemd script is in the `packaging/systemd/` directory of the Kismet source; if you are installing from source this can be copied to `/etc/systemd/system/kismet.service`, and packages should automatically include this file.

When starting Kismet via systemd, you should install kismet as suidroot, and use `systemctl edit kismet.service` to set the following:

```
[Service]
user=your-unprivileged-user
group=kismet
```
