# Extending Kismet: Data Tracking

Once data has been captured (see the [datasource docs](/docs/dev/datasource.html) for more details about creating a data source) and handled by the DLT handler, additional processing can be done to create device records and data.

Kismet stores information about a device in a `tracker_component` record held by the `DeviceTracker` class.  For more information about the internals and how to make your own `tracker_component` check out the [tracked component docs](/docs/dev/tracked_component.html). 
