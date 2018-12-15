---
title: "Webserver"
permalink: /docs/readme/webserver/
excerpt: "Kismet webserver configuration"
toc: true
---

## Kismet Webserver
Kismet now integrates a webserver which serves the web-based UI and data to external clients.

**THE FIRST TIME YOU RUN KISMET**, it will generate a **RANDOM** password.  This password is stored in `~/.kismet/kismet_httpd.conf` which is in the home directory of **the user which started Kismet**.

You will need this password to log into Kismet for the first time.

The webserver is configured via the `kismet_httpd.conf` file.  These options may be included in the base kismet.conf file, but are broken out for clarity.  These options may be overridden in `kismet_site.conf` for pre-configured installs.

By default, Kismet does not run in SSL mode.  If you provide a certificate and key file in PEM format, Kismet supports standard SSL / HTTPS.  For more information on creating a SSL certificate, look at `README.SSL`

HTTP configuration options:

* `httpd_username=username`
   Set the username.  This is required for any actions which can change configuration (adding / removing data sources, changing server-side configuration data, downloading packet captures, etc).
   The default user is `kismet`, and by default, the `httpd_username=` and `httpd_password=` configuration options are stored in the users home directory, in `~/.kismet/kismet_httpd.conf`.

* `httpd_password=password`
   Set the password.  The first time you run Kismet, it will auto-generate a random password and store it in `~/.kismet/kismet_httpd.conf`.
   It is generally preferred to keep the username and password in the per-user configuration file, however they may also be set in the global config.
   If `httpd_username` or `httpd_password` is found in the global config, it is used instead of the per-user config value.

* `httpd_port=port`
   Sets the port for the webserver to listen to.  By default, this is port 2501, the port traditionally used by the Kismet client/server protocol.
   Kismet typically should not be started as root, so will not be able to bind to ports below 1024.  If you want to run Kismet on, for instance, port 80, this can be done with a proxy or a redirector, or via DNAT rewriting on the host.

* `httpd_ssl=true|false`
   Turn on SSL.  If this is turned on, you must provide a SSL certificate and key in PEM format with the `httpd_ssl_cert=` and `httpd_ssl_key=` configuration options.

   See README.SSL for more information about SSL certificates.

* `httpd_ssl_cert=/path/to/cert.pem`
   Path to a PEM-format SSL certificate.

   This option is ignored if Kismet is not running in SSL mode.

   Logformat escapes can be used in this.  Specifically, "%S" will automatically expand to the system install data directory, and "%h" will expand to the home directory of the user running Kismet:
   ```
   httpd_ssl_cert=%h/.kismet/kismet.pem
   ```

* `httpd_ssl_key=/path/to/key.pem`
   Path to a PEM-format SSL key file.  This file should not have a password set as currently Kismet does not have a password prompt system.

   This option is ignored if Kismet is not running in SSL mode.

   Logformat escapes can be used in this.  Specifically, "%S" will automatically expand to the system install data directory, and "%h" will expand to the home directory of the user running Kismet:
   ```
   httpd_ssl_key=%h/.kismet/kismet.key
   ```

* `httpd_home=/path/to/httpd/data`
   Path to static content web data to be served by Kismet.  This is typically set automatically to the directory installed by Kismet in the installation prefix.
   Typically the only reason to change this directory is to replace the Kismet web UI with alternate code.

* `httpd_user_home=/path/to/user/httpd/data`
   Path to static content stored in the home directory of the user running Kismet.  This is typically set to the httpd directory inside the users .kismet directory.

   This allows plugins installed to the user directory to install web UI components.

   Typically there is no reason to change this directory.

   If you wish to disable serving content from the user directory entirely, comment this configuration option out.

* `httpd_session_db=/path/to/session/db`
   Path to save HTTP sessions to.  This allows Kismet to remember valid browser login sessions over restarts of kismet_server. 

   If you want to refresh the logins (and require browsers to log in again after each restart), comment this option.

   Typically there is no reason to change this option.
   
* `httpd_mime=extension:mimetype`
   Kismet supports MIME types for most standard file formats, however if you are serving custom content with a MIME type not correctly set, additional MIME types can be defined here.
   Multiple httpd_mime lines may be used to add multiple mime types:
   ```
   httpd_mime=html:text/html
   httpd_mime=svg:image/svg+xml
   ```
   Typically, MIME types do not need to be added.
