# Extending Kismet: Creating Capture Sources

Kismet supports additional capture types via the `KisDatasource` interface.  Data sources run in an independent process and can be written in any language, however they require a C++ component which functions as a Kismet driver to allow it to communicate with the datasource binary.

Datasources can report packets or complex records - if your datasource needs to pass parsed information about a device event, that's possible!

## Capture via IPC

Kismet datasources communicate from the capture binary to the Kismet server via an IPC channel.  This channel passes commands, data, and msgpack binary objects via a simple wrapper protocol.

The datasource IPC channel is via inherited file descriptors:  Prior to launching the capture binary, the Kismet server makes a pipe(2) pair and will pass the read (incoming data to the capture binary) and write (outgoing data from the capture binary) file descriptor numbers on the command line of the capture binary.

Operating as a completely separate binary allows the capture code to use increased permissions via suid, operate independently of the Kismet main loop, allowing the use of alternate main loop methods or other processor-intensive operations which could stall the main Kismet packet loop, or even using other languages to define the capture binary, such as a python capture system which utilizes python radio libraries.

## Defining the driver:  Deriving from KisDatasource

The datasource driver is the C++ component which brokers interactions between the capture binary and Kismet.

All datasources are derived from `KisDatasource`.  A KisDatasource is based on a `tracker_component` to provide easy export of capture status.

The amount of customization required when writing a KisDatasource driver depends on the amount of custom data being passed over the IPC channel.  For packet-based data sources, there should be little additional customization required, however sources which pass complex pre-parsed objects will need to customize the protocol handling methods.

KisDatasource instances are used in two ways:
1. *Maintenance* instances are used as factories to create new instances.  A maintenance instance is used to enumerate supported capture types, initiate probes to find a type automatically, and to build a capture instance.
2. *Capture* instances are bound to an IPC process for the duration of capture and are used to process the full capture protocol.

At a minimum, new datasources must implement the following from KisDatasource:

*probe_type(...)* is called to find out if this datasource supports a known type.  A datasource should return `true` for each type name supported.
```C++
virtual bool probe_type(string in_type) {
    if (StrLower(in_type) == "customfoo")
        return true;

    return false;
}
```

*build_data_source()* is the factory method used for returning an instance of the KisDatasource.  A datasource should simply return a new instance of its custom type.
```C++
virtual KisDataSource *build_data_source() {
    return new CustomKisDataSource(globalreg);
}
```

