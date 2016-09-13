# Extending Kismet

Kismet is designed to be extendable via modular coding.  Extensions to Kismet can add new IDS functionality, new hardware interaction, new radio types, and new ways to interact with the UI.

## Kismet Server Extensions

* [Tracked Components](tracked_component.html) are the central data record Kismet uses for storing information about devices and networks, and are used to serialize data to the REST endpoints in the embedded webserver.  A tracked component is an introspectable, serializeable, nestable C++ object which can function similarly to a JSON data structure or a dictionary in other languages.  By storing data in tracked components, a plugin instantly gains access to all of the flexibility and automatic interface code.

* [Data Sources](datasource.html) replace the original `PacketSource` code in Kismet and allow capture of both packets and fully-tracked device entities, depending on the capabilities of the physical backend.  The new system uses a simple API to pass more complex objects encoded in msgpack between the capture process and Kismet, allowing the capture process to be easily written in other languages besides C++, with minimal glue connecting it to the Kismet server.

* The [Data Tracker](datatracker.html) system aggregates packet and device data and creates the common device records all other data is attached to.

## Kismet Web UI

The Kismet web UI is fed with data from REST-style endpoints supplied by the Kismet server, and self-hosts the HTML, Javascript, and CSS elements.

Extending the Kismet web UI can be done with any toolkit which does not require active server pages (sorry, no CGI or PHP).  Any active server-side code can be included in the Kismet plugin however, as additional endpoints in the webserver.

Kismet predominately uses the jQuery framework for the Web UI, but other frameworks could be included.  Kismet also provides various utility functions and jQuery plugins for defining columns, device detail windows, and other components of the UI.

* [Creating web UI plugins](webui.html) can be done relatively simply by using functions built into `kismet_ui.js` which allow for complex, richly formatted add-ons to be defined by a plugin, integrating directly with the main device view using custom columns, or the device details windows with custom tables or graphs to display radio-specific information.

* [Device detail tables](webui.jquery.kismet.devicedata.html) are handled by a custom jQuery plugin, `jquery.kismet.devicedata` which allows for automatic creation of device information tables with the ability to show or hide rows depending on data availability.
