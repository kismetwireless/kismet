---
title: "REST webserver endpoints"
permalink: /docs/devel/webui_rest/endpoints/
---

Kismet uses a REST-like interface for the embedded webserver, which provides data and accepts commands.  

When fetching data, whenever possible, parameters are passed as part of the GET URI, but for more complex features, command arguments may be sent via POST variables.

Kismet supports multiple output formats; whenever possible, an endpoint will support all output formats.  The default output format used in examples is JSON, but additional output types may be added in the future or added by run-time plugins.  Some unique endpoints are available only under specific output methods because they take advantage of features of that output type.
