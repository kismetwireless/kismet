---
title: "Plugins"
permalink: /docs/devel/webui_rest/plugins/
toc: true
---
Kismet plugins may be active C++ code (loaded as a plugin.so shared object file) or they may be web content only which is loaded into the UI without requiring additional back-end code.

## Plugin list

* URL \\
        /plugins/all_plugins.json

* Methods \\
        `GET`

* Results \\
        Returns array of activated plugins

