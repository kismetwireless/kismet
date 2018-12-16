---
title: "Creating Kismet plugins"
permalink: /docs/devel/plugins/
toc: true
---

# Extending Kismet - Creating Plugins

Kismet can load additional code dynamically at runtime in the form of a plugin.

Plugins are a double-edged sword: in their current implementation, plugins are full first-class citizens in the Kismet ecosystem:  A plugin can perform any action Kismet native code can perform, and are given a direct reference to the internal Kismet module system.

## Plugin Code

Plugins are shared objects (.so files) with pre-defined functions.


## Plugin Locations

Plugins can be installed into one of two locations:

* System-wide plugins are installed into `[datadir]/kismet/plugins/` where `[datadir]` is the parameter passed to `./configure --datadir=...`.  It defaults to `/usr/local/`.

* Per-user plugins are installed into the users home directory under `~/.kismet/plugins/`


## Plugin Static Web Content

Plugins are mapped into the Kismet webserver under `/plugin/[plugin-directory-name]/` path.  Plugins can add arbitrary content in this directory, but it is strongly recommended that they follow the following convention:

* `[prefix]/plugins/[name]/httpd/js/` - Javascript files
* `[prefix]/plugins/[name]/httpd/css/` - CSS files

To register a JS module for automatic loading (for instance, to interact with the normal Kismet web UI and add new tabs, details, etc), a plugin must either:

* Register the module with with the `kis_httpd_registry::register_js(...)` system
* Define a plugin manifest stored in `[prefix]/plugins/[name]/manifest.conf`

## Plugin Manifests

The manifest file allows Kismet to automatically derive information about a plugin with no native code - this allows for simple HTTP-only plugins which enhance the web UI without requiring them to include compiled code to register the plugin.

The manifest file should be placed in `[prefix]/plugins/[name]/manifest.conf`, and takes the form of a Kismet config file (name=value pairs):

| Key | Content |
| ---- | ------- |
| name | Plugin name |
| description | Plugin description |
| author | Plugin author |
| version | Plugin version |
| object | plugin shared object file name |
| js | JS module and path as `module_name,/web/path/to/js`.|

Example manifest:
```
name=Webplugin
description=Trivial web-only plugin
author=Joe Random <joerandom@random.foo>
version=1.0.0

js=new_web_module,/plugin/webplugin/js/new_web_module.js
```

Example manifest for plugin with C++ code
```
name=Codeplugin
description=Standard code-based plugin
author=Joe Random <joerandom@random.foo>
version=1.0.0

object=kismet-codeplugin.so

js=code_web_module,/plugin/codeplugin/js/code_web_module.js
```

