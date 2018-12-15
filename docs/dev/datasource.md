---
title: "Creating Kismet datasources"
permalink: /docs/devel/datasources/
toc: true
---

# Under Development

These docs represent a protocol that is still heavily under development - until the first internal implementations are done, it would be unwise to start an independent implementation as I may change the protocol at any point until it's feature complete.

# Extending Kismet: Creating Capture Sources

Kismet supports additional capture types via the `KisDatasource` interface.  Data sources run in an independent process and can be written in any language, however they require a C++ component which functions as a Kismet driver to allow it to communicate with the datasource binary.

Datasources can report packets or complex records - if your datasource needs to pass parsed information about a device event, that's possible!

[TOC]

## Capture via IPC and Network

Kismet datasources communicate from the capture binary to the Kismet server via an IPC channel or TCP connection.  This channel passes commands, data, and other objects via an extension of the Kismet External API protocol; written using the Google Protobuf library this protocol is extendable and parsers can be generated for nearly any language.

The datasource IPC channel is via inherited file descriptors:  Prior to launching the capture binary, the Kismet server makes a pipe(2) pair and will pass the read (incoming data to the capture binary) and write (outgoing data from the capture binary) file descriptor numbers on the command line of the capture binary.

Operating as a completely separate binary allows the capture code to use increased permissions via suid, operate independently of the Kismet main loop, allowing the use of alternate main loop methods or other processor-intensive operations which could stall the main Kismet packet loop, or even using other languages to define the capture binary, such as a python capture system which utilizes python radio libraries.

The network protocol is an encapsulation of the same protocol over a TCP channel, with some additional setup frames.  The network protocol will be more fully defined in future revisions of this document.

## The External Datasource Protocol

The datasource capture protocol acts as additional commands within the Kismet External API; it is defined in `protobuf_definitions/datasource.proto`.

Datasource commands are in the `KismetDatasource` namespace, and their string equivalents in the helper API are prefixed with `KDS`.  Reply-only frames are suffixed with `RESPONSE`.

### KDS Commands

#### `KDSCLOSEDATASOURCE` (KismetDatasource.CloseDatasource) *Kismet -> Datasource*

Closes the active datasource; this is called during the shutdown process when a source is closed or Kismet exits.

##### Content

*None*

##### Reply

*None*

#### `KDSCONFIGURE` (KismetDatasource.Configure) *Kismet -> Datasource*

Configure the behavior of a running source.

##### Content

| Field    | Type                         | Content                                     |
| -------- | ---------------------------- | ------------------------------------------- |
| channel  | KismetDatasource.SubChanset  | *Optional* Fixed-channel control            |
| hopping  | KismetDatasource.SubChanhop  | *Optional* Hopping and channel list control |
| spectrum | KismetDatasource.SubSpectrum | *Optional* Spectrum monitoring control      |

##### Response

`KDSCONFIGUREREPORT` KismetDatasource.ConfigureReport

#### `KDSCONFIGUREREPORT` (KismetDatasource.ConfigureReport) *Datasource -> Kismet*

Report configuration status and success to Kismet; This report must contain the sequence number of the `KDSCONFIGURE` request in the `success` field.

##### Content

| Field   | Type                         | Content                                                      |
| ------- | ---------------------------- | ------------------------------------------------------------ |
| success | KismetDatasource.SubSuccess  | Success report for `KDSCONFIGURE` command                    |
| channel | KismetDatasource.SubChannel  | *Optional* Channel configuration of datasource               |
| hopping | KismetDatasource.SubChanhop  | *Optional* Hopping configuration of datasource               |
| message | KismetExternal.MsgbusMessage | *Optional* Message to be sent to the user via the Kismet Messagebus system |
| warning | string                       | *Optional* Warning message about the current configuration, to be placed in the datasource details. |

##### Response

*None*

#### `KDSDATAREPORT` (KismetDatasource.DataReport) *Datasource -> Kismet*

Datasources uses `KDSDATAREPORT` to send packets, signal data, and GPS data to Kismet.  The packet payload is mapped to the Kismet datasource, and sent to the packet processing subsystem.

##### Content

| Field          | Type                         | Content                                                      |
| -------------- | ---------------------------- | ------------------------------------------------------------ |
| gps            | KismetDatasource.SubGps      | *Optional* GPS coordinates                                   |
| message        | KismetExternal.MsgbusMessage | *Optional* Message to be sent to the user via the Kismet Messagebus system |
| packet         | KismetDatasource.SubPacket   | *Optional* Packet content to be injected into the Kismet packetchain |
| signal         | KismetDatasource.SubSignal   | *Optional* Signal or RSSI information which is not part of the packet data or packet headers. |
| spectrum       | KismetDatasource.SubSpectrum | *Optional* Spectral data                                     |
| warning        | string                       | *Optional* Warning message about the datasource, which will be placed into the datasource details |
| json           | KismetDatasource.SubJson     | *Optional* Arbitrary JSON record for non-packet device data  |
| buffer         | KismetDatasource.SubBuffer   | *Optional* Arbitrary protobuf record for non-packet device data |
| high_prec_time | double                       | *Optional* high-precision Posix timestamp with nanosecond precision, if available. |

##### Response

*None*

#### `KDSERRORREPORT` (KismetDatasource.ErrorReport) *Datasource -> Kismet*

Fatal error condition which should initiate a datasource shutdown.

##### Content

| Field   | Type                         | Content                                                      |
| ------- | ---------------------------- | ------------------------------------------------------------ |
| success | KismetDatasource.SubSuccess  | Error condition with failed sequence number (if any) or 0 (if runtime error) |
| message | KismetExternal.MsgbusMessage | *Optional* Additional message explaining the failure condition. |

##### Response

*None*

#### `KDSLISTINTERFACES` (KismetDatasource.ListInterfaces) *Kismet -> Datasource*

Request a list of supported interfaces; Kismet uses this to populate the Data Sources display where a user can activate available sources.

##### Content

*None*

##### Response

`KDSINTERFACESREPORT` KismetDatasource.InterfacesReport

#### `KDSINTERFACESREPORT` (KismetDatasource.InterfacesReport) *Datasource -> Kismet*

Returns a list of supported interfaces, if the datasource is capable of listing potential sources.

##### Content

| Field      | Type                            | Content                                                      |
| ---------- | ------------------------------- | ------------------------------------------------------------ |
| success    | KismetDatasource.SubSuccess     | Success report for `KDSLISTINTERFACES` command               |
| message    | KismetExternal.MsgbusMessage    | *Optional* Message to be displayed regarding interface list or failure |
| interfaces | KismetDatasource.SubInterface[] | *Optional* List of interfaces                                |

##### Response

*None*

#### `KDSNEWSOURCE` (KismetDatasource.NewSource) *Datasource -> Kismet*

Remote captures are multiplexed over a single TCP port; to associate a remote capture with the proper driver code in Kismet, the datasource must send a `KDSNEWSOURCE`.

##### Content

| Field      | Type   | Content                                                      |
| ---------- | ------ | ------------------------------------------------------------ |
| definition | string | Kismet source definition (from the datasource `--source=` command line option) |
| sourcetype | string | Kismet datasource type (must match a datasource type)        |
| uuid       | string | UUID of the datasource to be created                         |

##### Response

After receiving and successfully mapping a `KDSNEWSOURCE` to a datasource driver, Kismet will send a `KDSOPENSOURCE` command to being configuration.

#### `KDSOPENSOURCE` (KismetDatasource.OpenSource) *Kismet -> Datasource*

Kismet will start a datasource by sending a `KDSOPENSOURCE`; this will be sent for an IPC source or a remote capture source which has completed the initial handshake.

##### Content

| Field      | Type   | Content                  |
| ---------- | ------ | ------------------------ |
| definition | string | Kismet source definition |

##### Response

`KDSOPENSOURCEREPORT` KismetDatasource.OpenSourceReport

#### `KDSOPENSOURCEREPORT` (KismetDatasource.OpenSourceReport) *Datasource -> Kismet*

A `KDSOPENSOURCEREPORT` carries all the information about a new datasource.

##### Content

| Field             | Type                         | Content                                                      |
| ----------------- | ---------------------------- | ------------------------------------------------------------ |
| success           | KismetDatasource.SubSuccess  | Success report for `KDSOPENSOURCE`                           |
| dlt               | int32                        | *Optional* DLT (data link type) for packets from this source |
| capture_interface | string                       | *Optional* Capture interface, if different than the specified interface.  This is common for Wi-Fi devices which use virtual interfaces for capturing. |
| channels          | KismetDatasource.SubChannels | *Optional* Supported channels                                |
| channel           | KismetDatasource.SubChanset  | *Optional* Fixed channel if not hopping                      |
| hop_config        | KismetDatasource.SubChanhop  | *Optional* Channel hopping information                       |
| hardware          | string                       | *Optional* Hardware / chipset                                |
| message           | KismetExternal.MsgbusMessage | *Optional* User message                                      |
| spectrum          | KismetExternal.SubSpecset    | *Optional* Spectrum options                                  |
| uuid              | string                       | *Optional* Source UUID                                       |
| warning           | string                       | *Optional* Warning message about datasource, which will be displayed in the datasource details |

##### Response

*None*

#### `KDSPROBESOURCE` (KismetDatasource.ProbeSource) *Kismet -> Datasource*

Kismet will attempt to match a source to a datasource driver by asking each datasource to probe the source definition.

##### Content

| Field      | Type   | Content                  |
| ---------- | ------ | ------------------------ |
| definition | string | Kismet source definition |

##### Response

`KDSPROBESOURCEREPORT` KismetDatasource.ProbeSourceReport

#### `KDSPROBESOURCEREPORT` (KismetDatasource.ProbeSourceReport) *Datasource -> Kismet*

##### Content

| Field    | Type                         | Content                              |
| -------- | ---------------------------- | ------------------------------------ |
| success  | KismetDatasource.SubSuccess  | Success report for `KDSPROBESOURCE`  |
| message  | KismetExternal.MsgbusMessage | *Optional* User message              |
| channels | KismetDatasource.SubChannels | *Optional* Supported channels        |
| channel  | KismetDatasource.SubChanset  | *Optional* Fixed non-hopping channel |
| spectrum | KismetDatasource.SubSpecset  | *Optional* Spectral scanning support |
| hardware | string                       | *Optional* Hardware / chipset        |

##### Response

*None*

#### `KDSWARNINGREPORT` (KismetDatasource.WarningReport) *Datasource -> Kismet*

`KDSWARNINGREPORT` can be used by the datasource to set a non-fatal warning condition; this will be shown in the datasource details.

##### Content

| Field   | Type   | Content                                                |
| ------- | ------ | ------------------------------------------------------ |
| warning | string | Warning message to be shown in the datasource details. |

##### Response

*None*

### KDS Subcomponents

When the same data is used in multiple packets, it is typically placed in a `KismetDatasource.Sub...` message which is included in the top-level command.

Many `Sub...` blocks contain only a single field; these may be expanded in the future to contain multiple fields, depending on the requirements of the protocol.

#### `KismetDatasource.SubBuffer`

Some datasources may need to send a complete protobuf record for data; this can be accomplished with the SubBuffer structure, which contains simply:

| Field     | Type   | Content                                     |
| --------- | ------ | ------------------------------------------- |
| time_sec  | uint64 | Timestamp of record, Posix second precision |
| time_usec | uint64 | Timestamp of record, microseconds           |
| type      | string | Arbitrary buffer type to help decoder       |
| buffer    | bytes  | Packed protobuf buffer                      |

#### `KismetDatasource.SubChannels`

Basic list of channels.  Channels are reported as strings, as they can represent complex tuning options (Such as `6HT40+` for Wi-Fi).

| Field    | Type     | Content           |
| -------- | -------- | ----------------- |
| channels | string[] | Array of channels |

#### `KismetDatasource.SubChannel`

Basic channel.  Channels are reported as strings, as they can represent complex tuning options.

| Field   | Type   | Content |
| ------- | ------ | ------- |
| channel | string | Channel |

#### `KismetDatasource.SubChanhop`

| Field        | Type     | Content                                                      |
| ------------ | -------- | ------------------------------------------------------------ |
| channels     | string[] | Array of channels to configure as the hopping pattern        |
| rate         | double   | *Optional* Rate at which to hop, in hops per second.  Hop rates less than 1 result in dwelling on a channel for longer than a second. |
| shuffle      | bool     | *Optional* Automatically shuffle the hop list to minimize frequency overlap (maximizing channel coverage) |
| shuffle_skip | uint32   | *Optional* Skip interval when shuffling; this is typically calculated by Kismet to be a prime factor of the number of channels in the hop list, ensuring coverage. |
| offset       | uint32   | *Optional* Offset into the hopping channel list; this is typically calculated by Kismet when multiple radios are present on the same frequency band, and maximizes coverage. |

#### `KismetDatasource.SubGps`

| Field          | Type   | Content                                          |
| -------------- | ------ | ------------------------------------------------ |
| lat            | double | Latitude                                         |
| lon            | double | Longitude                                        |
| alt            | double | Altitude (meters)                                |
| speed          | double | Speed (kph)                                      |
| heading        | double | Heading (degrees)                                |
| precision      | double | Location precision (meters)                      |
| fix            | uint32 | GPS fix quality (2 = 2d, 3 = 3d)                 |
| time_sec       | uint64 | GPS position timestamp as Posix second precision |
| time_usec      | uint64 | GPS position timestamp as microsecond precision  |
| type           | string | GPS type (As defined by GPS driver)              |
| name           | string | GPS name (As defined by user)                    |
| high_prec_time | double | *Optional* High-precision second+nanosecond time |

#### `KisDatasource.SubJson`

| Field     | Type   | Content                                     |
| --------- | ------ | ------------------------------------------- |
| time_sec  | uint64 | Message timestamp as Posix second precision |
| time_usec | uint64 | Message timestamp as microsecond precision  |
| type      | string | Message type to assist in parsing           |
| json      | string | Message, in JSON                            |

#### `KisDatasource.SubInterface`

| Field     | Type   | Content                                                      |
| --------- | ------ | ------------------------------------------------------------ |
| interface | string | Supported interface (which can be passed via `-c [interface]` in Kismet for example) |
| flags     | string | Required option flags (which will be passed via `-c [interface]:flags` in Kismet for example); Flags can refine the interface parameters, etc. |
| hardware  | string | *Optional* Hardware / chipset of device                      |

#### `KisDatasource.SubPacket`

Raw packet data is injected into the Kismet Packetchain system.  Datasources which send data with a DLT handled by Kismet will be automatically processed; datasources sending a new DLT will have to provide a parser for that link type.

| Field     | Type    | Content                                                      |
| --------- | ------- | ------------------------------------------------------------ |
| time_sec  | uint64  | Packet timestamp as Posix second                             |
| time_usec | uint64  | Packet timestamp microseconds                                |
| dlt       | uint32  | DLT (Data Link Type) of packet content, as returned by libpcap |
| size      | uint64  | Packet payload size                                          |
| data      | bytes[] | Raw packet data                                              |

#### `KisDatasource.SubSignal`

Some packet formats include signal level data as part of the packet headers (for example, Radiotap); for other packets, this data may be available as an external set of data.

| Field       | Type   | Content                                                      |
| ----------- | ------ | ------------------------------------------------------------ |
| signal_dbm  | double | *Optional* Signal level in dBm                               |
| noise_dbm   | double | *Optional* Noise level in dBm                                |
| signal_rssi | double | *Optional* Signal level in RSSI.  Kismet cannot convert RSSI to a meaningful number, so whenever possible, a datasource should prefer dBm) |
| noise_rssi  | double | *Optional* Noise level in RSSI.  Kismet cannot convert RSSI to a meaningful number, so whenever possible, a datasource should prefer dBm) |
| freq_khz    | double | *Optional* Frequency of packet, in KHz                       |
| channel     | string | *Optional* Channel of packet, as a string meaningful to the datasource type |
| datarate    | double | *Optional* Data rate of packet                               |

#### `KisDatasource.SubSpecSet`

For data sources which support raw spectrum capture, the `SubSpecSet` configuration block will be sent to configure the ranges.

| Field              | Type   | Content                                                      |
| ------------------ | ------ | ------------------------------------------------------------ |
| start_mhz          | double | *Optional* Starting frequency of sample sweep, in MHz        |
| end_mhz            | double | *Optional* Ending frequency of sample sweep, in MHz          |
| samples_per_bucket | double | *Optional* Number of samples taken per frequency bucket      |
| bucket_width_hz    | double | *Optional* Width of sample bucket, in Hz                     |
| enable_amp         | bool   | *Optional* If available, enable amplifier in radio           |
| if_amp             | uint64 | *Optional* If available, amplification at the IF stage       |
| baseband_amp       | uint64 | *Optional* If available, amplification at the baseband stage |

#### `KisDatasource.SubSpectrum`

Data sources which support raw spectrum capture return the spectrum record in a `SubSpectrum`.

| Field           | Type     | Content                                         |
| --------------- | -------- | ----------------------------------------------- |
| time_sec        | uint64   | *Optional* Timestamp of sweep, in Posix seconds |
| time_usec       | uint64   | *Optional* Timestamp of sweep, microseconds     |
| start_mhz       | double   | *Optional* Starting frequency of sweep, in MHz  |
| end_mhz         | double   | *Optional* Ending frequency of sweep, in MHz    |
| bucket_width_hz | double   | *Optional* Width of sample buckets              |
| data            | uint32[] | *Optional* Sweep samples                        |

#### `KisDatasource.SubSuccess`

Response messages include a `SubSuccess`; this is used to indicate command completion.

| Field   | Type   | Content                                                      |
| ------- | ------ | ------------------------------------------------------------ |
| success | bool   | Transaction was successful (or not)                          |
| seqno   | uint32 | Sequence number of command we are responding to.  If this is a runtime-error not associated with a specific command, this may be 0. |

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

A datasource which operates by passing packets should be able to function with no further customization:  Packet data passed via the `PACKET` record will be
decapsulated and inserted into the packetchain with the proper DLT.

## Handling the PHY

Kismet defines `PhyHandler` objects to handle different physical layer types - for example there are phyhandlers for IEEE802.11, Bluetooth, and so on.

A phy handler is responsible for defining any custom data structures specific to that phy, converting phy-specific data to the common interface so that Kismet can make generic devices for it, providing any additional javascript and web resources, and similar tasks.

## Defining the PHY

Phy handlers are derived from the base `Kis_Phy_Handler` class.

At a minumum a new phy must provide (and override):

* The basic C++ contructor and destructor implementations
* The create function to build an actual instance of the phy handler
* A common classifier stage to create common info from the custom packet info
* A storage loader function to attach any custom data when a device is loaded from storage

## Loading from storage and custom data types

A new phy will almost certainly define a custom tracked data type - `dot11_tracked_device` and `bluetooth_tracked_device` for instance.  As part of defining this custom type, the phy must provide a storage loader function to import stored data into a proper object.

In addition, there are some specific pitfalls when loading custom objects - be sure to check the  "Restoring vector and map objects" section of of the `tracked_component` docs!

## Handling the DLT

A datasource which is packet-based but does not conform to an existing DLT defined in Kismet will often need to provide its own DLT handler.

### Do I need a custom DLT handler?

If data records are entirely parsed by the classifier (see below for more information), then a separate DLT handler may not be necessary, however if your DLT embeds signal, location, or other information which needs to be made available to other Kismet data handlers, it should be decoded by your DLT handler.

Capture sources implementing alternate capture methods for known DLTs (for instance, support for 802.11 on other operating systems, etc) do not need to implement a new DLT handler.

### Deriving the DLT

Kismet DLT handlers are derived from `Kis_DLT_Handler` from `kis_dlt.h`.  A DLT handler needs to override the constructor and the `HandlePacket(...)` functions:

```C++
class DLT_Example : public Kis_DLT_Handler {
public:
    DLT_Example(GlobalRegistry *in_globalreg);

    virtual int HandlePacket(kis_packet *in_pack);
};

DLT_Example::DLT_Example(GlobalRegistry *in_globalreg) :
    Kis_DLT_Handler(in_globalreg) {

    /* Packet components and insertion into the packetchain is handled
       automatically by the Kis_DLT_Handler constructor.  All that needs
       to happen here is setting the name and DLT type */
    dlt_name = "Example DLT";

    /* DLT type is set in tcpdump.h */
    dlt = DLT_SOME_EXAMPLE;

    /* Optionally, announce that we're loaded */
    _MSG("Registering support for DLT_SOME_EXAMPLE", MSGFLAG_INFO);
}

/* HandlePacket(...) is called by the packet chain with the packet data
   as reported by the datasource.  This may already include GPS and signal
   information, as well as the actual link data frame.

   HandlePacket is responsible for decapsulating the DLT, creating any
   additional kis_packet records, and prepping the data for the classifier
   stage.
*/

int DLT_Example::HandlePacket(kis_packet *in_pack) {
    /* Example sanity check - do we already have packet data
       decapsulated?  For a type like radiotap or PPI that encodes another
       DLT, this encapsulated chunk might be handled differently */
    kis_datachunk *decapchunk =
        (kis_datachunk *) in_pack->fetch(pack_comp_decap);
    if (decapchunk != NULL) {
        return 1;
    }

    /* Get the linklayer data record */
    kis_datachunk *linkdata =
        (kis_datachunk *) in_pack->fetch(pack_comp_linkframe);

    /* Sanity check - do we even have a link chunk? */
    if (linkdata == NULL) {
        return 1;
    }

    /* Sanity check - does the DLT match? */
    if (linkdata->dlt != dlt) {
        return 1;
    }

    /* Other code goes here */
}

```

## Handling Non-Packet Data

Non-packet data can be decapsulated by extending the `KisDataSource::handle_packet` method.  By default this method handles defined packet types, an extended version should first call the parent instance.

```C++
void SomeDataSource::handle_packet(string in_type, KVmap in_kvmap) {
    KisDataSource::handle_packet(in_type, in_kvmap);

    string ltype = StrLower(in_type);

    if (ltype == "customtype") {
        handle_packet_custom(in_kvmap);
    }
}
```

Extended information can be added to a packet as a custom record and transmitted via the Kismet packetchain, or can be injected directly into the tracker for the new phy type (See the [datatracker](/docs/dev/datatracker.html) docs for more information).  Injecting into the packet chain allows existing Kismet code to track signal levels, location, etc, automatically.

If the incoming data is directly injected into the data tracking system for the new phy type, then special care must be taken to create pseudo-packet records for the core device tracking system.  Ultimately, a pseudo-packet event must be created, either when processing the custom IPC packet or in the device classifier.  Generally, it is recommended that a datasource attach the custom record to a packet object and process it via the packetchain as documented in [datatracker](/docs/dev/datatracker.html).

When processing a custom frame, existing KV pair handlers can be used.  For example:

```C++
void SomeDataSource::handle_packet_custom(KVmap in_kvpairs) {
    KVmap::iterator i;

    // We inject into the packetchain so we need to make a packet
    kis_packet *packet = NULL;

    // We accept signal and gps info in our custom IPC packet
    kis_layer1_packinfo *siginfo = NULL;
    kis_gps_packinfo *gpsinfo = NULL;

    // We accept messages, so process them using the existin message KV
    // handler
    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        handle_kv_message(i->second);
    }

    // Generate a packet using the packetchain
    packet = packetchain->GeneratePacket();

    // Gather signal data if we have any
    if ((i = in_kvpairs.find("signal")) != in_kvpairs.end()) {
        siginfo = handle_kv_signal(i->second);
    }

    // Gather GPS data if we have any
    if ((i = in_kvpairs.find("gps")) != in_kvpairs.end()) {
        gpsinfo = handle_kv_gps(i->second);
    }

    // Add them to the packet
    if (siginfo != NULL) {
        packet->insert(pack_comp_l1info, siginfo);
    }

    if (gpsinfo != NULL) {
        packet->insert(pack_comp_gps, gpsinfo);
    }

    // Gather whatever custom data we have and add it to the packet
    if ((i = in_kvpairs.find("customfoo")) != in_kvpairs.end()) {
        handle_kv_customfoo(i->second, packet);
    }

    // Update the last valid report time
    inc_num_reports(1);
    set_last_report_time(globalreg->timestamp.tv_sec);

    // Inject the packet into the packet chain, this will clean up
    // the packet when it's done with it automatically.
    packetchain->ProcessPacket(packet);
}

```
