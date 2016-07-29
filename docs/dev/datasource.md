# Extending Kismet: Creating Capture Sources

Kismet supports additional capture types via the `KisDatasource` interface.  Data sources run in an independent process and can be written in any language, however they require a C++ component which functions as a Kismet driver to allow it to communicate with the datasource binary.

Datasources can report packets or complex records - if your datasource needs to pass parsed information about a device event, that's possible!

## Capture via IPC

Kismet datasources communicate from the capture binary to the Kismet server via an IPC channel.  This channel passes commands, data, and msgpack binary objects via a simple wrapper protocol.

The datasource IPC channel is via inherited file descriptors:  Prior to launching the capture binary, the Kismet server makes a pipe(2) pair and will pass the read (incoming data to the capture binary) and write (outgoing data from the capture binary) file descriptor numbers on the command line of the capture binary.

Operating as a completely separate binary allows the capture code to use increased permissions via suid, operate independently of the Kismet main loop, allowing the use of alternate main loop methods or other processor-intensive operations which could stall the main Kismet packet loop, or even using other languages to define the capture binary, such as a python capture system which utilizes python radio libraries.

## The IPC Protocol

The data source capture protocol is defined in `simple_datasource_proto.h`.  It is designed to be a simple protocol to communicate with from a variety of languages.

Each communication to or from the capture driver consists of a high-level frame type (a string), which then contains an arbitrary collection of key:value dictionary pairs.

K:V pairs may be simple (a single value or type), or complex (a binary msgpack object, for instance).

In general, complex objects are always passed as dictionaries holding string:value KV pairs.  This allows multiple languages easy access, eliminates magic number values, and should greatly simplify future compatibility issues if additional fields are required.

Datasource binaries and drivers may use any other message passing mechanism they prefer, but are encouraged to stay with the standard mechanisms.

## Top-level IPC Frame Types

Several top-level packet types and key:value pairs are pre-defined and will be automatically handled by classes derived from the `KisDataSource` driver.

#### CLOSEDEVICE (Kismet->Datasource)
Close any open device and initiate a shutdown.  Sent to capture binary during source close or server shutdown.

KV Pairs:
* NONE

Responses:
* NONE

#### CONFIGURE (Kismet->Datasource)
Pass configuration data

KV Pairs:
* CHANSET
* CHANHOP

Responses:
* NONE

#### DATA (Datasource->Kismet)
Pass capture data.  May be a packet, a decoded trackable entity, or othe r information.

KV Pairs:
* MESSAGE
* SIGNAL
* PACKET
* GPS

Responses:
* NONE

#### ERROR (Any)
An error occurred.  The capture is assumed closed, and the IPC will be shut down.

KV Pairs:
* ERROR

Responses:
* NONE

#### STATUS (Datasource->Kismet)
Generic status report.  May carry other information.

KV Pairs:
* MESSAGE
* SUCCESS

Responses:
* NONE

#### MESSAGE (Datasource->Kismet)
Message for the user - informational, warning, or other non-critical errors.

KV Pairs:
* MESSAGE

Responses:
* NONE

#### OPENDEVICE (Kismet->Datasource)
Open a device.  This should only be sent to a datasource which is capable of handling this device type, but may still return errors.

KV Pairs:
* DEFINITION

Responses:
* OPENRESP

#### OPENRESP (Datasource->Kismet)
Device open response.  Sent to declare the source is open and functioning, or that there was an error.

KV Pairs:
* SUCCESS
* CHANNELS
* MESSAGE

Responses:
* NONE

#### PROBEDEVICE (Kismet->Datasource)
Probe if this datasource can handle a device of unknown type.  This is used during the probing for auto-type sources.

KV Pairs:
* DEFINITION

Responses:
* PROBERESP

#### PROBERESP (Datasource->Kismet)
Response for attempting to probe if a device is supported via PROBEDEVICE.  This should always be sent, even if the answer is that the device is unsupported.

KV Pairs:
* SUCCESS
* CHANNELS
* MESSAGE

Responses:
* NONE

## Standard KV Pairs

Kismet will automatically handle standard KV pairs in a message.  A datasource may define arbitrary additional KV pairs and handle them independently.

#### CHANNELS
Conveys a list of channels supported by this device, if there is a user presentable list for this phy type.  Channels are considered free-form strings which are unique to a phy type, but should be human readable.  Channel definitions may also represent frequencies in a form relevant to the phy, such as "2412MHz", but the representation is phy specific.

Content:

A msgpack packed dictionary of parameters containing the following:
* "channels": Vector of strings defining channels.

Example:

`"channels": ["1", "6", "11", "6HT20", "11HT40-"]` (802.11n complex channel definitions)

#### CHANSET
Used as a set command to configure a single, non-hopping channel.  Channels are free-form strings which are human readable and phy-specific.

Content:

Simple string `(char *)` of the channel, length dictated by the KV length record.

Example:

`"11HT20"`

`"2412MHz"`

#### CHANHOP
Used as a set command to configure hopping over a list of channels or frequencies.  The hop rate is sent as a double containing the number of hops per second, hop rates less than one are interpreted as multiple seconds per hop.

Content:

Msgpack packed dictionary of parameters containing at least the following:
* "channels": Vector of strings defining channels, as show in the `CHANNELS` KV pair.
* "rate": double-precision float indicating channels per second.

Examples:

`{"channels": ["1", "6", "11"], "rate": 10}` (10 channels per second on primary 802.11 channels)

`{"channels": ["3", "6", "9"], "rate": 0.1}` (10 *seconds per channel* on alternate 802.11 channels, caused by a rate of 0.1 channels per second.)

#### DEFINITION
A raw source definition, as a string.  This is identical to the source as defined in `kismet.conf` or on the Kismet command line.

Content:

Simple string `(char *)` of the definition, length dictated by the KV length record.

Example:

`wlan0:hop=true,name=foobar`

#### GPS
If a driver contains its own location information (or is running on a remote system which has its own GPS), captured data may be tagged with GPS information.  This is not necessary when reporting data or device information with inherent location information (such as PPI+GPS packets, or some other phy type which embeds positional information in packets).

The GPS values are inserted into the packet on the Kismet level as a standard location record.

A GPS record is inserted into the Kismet packet as a "GPS" record.

Content:

Msgpack packed dictionary containing at the following values:
* "lat": double-precision float containing latitude
* "lon": double-precision float containing logitude
* "alt": double-precision float containing altitude, in meters
* "speed": double-precision float containing speed, in kilometers per hour
* "heading": double-precision float containing the heading in degrees (optional)
* "precision": double-precision float containing the coordinate precision in meters (optional)
* "fix": int32 integer containing the "fix" quality (0 = none, 2 = 2d, 3 = 3d)
* "time": uint64 containing the time in seconds since the epoch (time_t record)
* "type": string containing the GPS type
* "name": string containing the GPS user-defined name

#### MESSAGE
MESSAGE KV pairs bridge directly to the messagebus of the Kismet server and are presented to users, logged, etc.

Content:

Msgpack packed dictionary containing the following values:
* "flags": uint32 message type flags (defined in `messagebus.h`)
* "msg": string, containing message content

#### PACKET
The PACKET KV pair contains a captured packet.  Datasources which operate on a packet level should use this to inject packets directly into the Kismet packetchain for decoding by a DLT handler.

A PACKET record is inserted into the Kismet packetchain packet as a "LINKFRAME" record.

Content:

Msgpack packed dictionary containing the following:
* "tv_sec": uint64 timestamp in seconds since the epoch (time_t)
* "tv_usec": uint64 timestamp in microseconds after the second
* "dlt": uint64 integer data link type (per tcpdump)
* "size": uint64 integer size of packet bytes
* "packet": binary/raw (interpreted as uint8[]) content of packet.  Size must match the size field.

#### SIGNAL
SIGNAL KV pairs can be added to data frames when the signal values are not included in the existing data.  For example, a driver reporting radiotap or PPI packets would not need to include a SIGNAL pair, however a driver decoding a SDR signal or other raw radio information could include it.

Whenever possible, signal levels should be reported in dBm, as RSSI values cannot be automatically scaled by the Kismet UI.

If a human-readable channel representation is not available due to the characteristics of the phy type, it should be presented as a frequency in a sensible format (such as "433.9MHz")

A SIGNAL record is inserted into the Kismet packetchain packet as a "RADIODATA" record.

Content:

Msgpack packed dictionary containing the following:
* "signal_dbm": int32 signal value in dBm (optional)
* "noise_dbm": int32 noise value in dBm (optional)
* "signal_rssi": int32 signal value in RSSI, dependent on device scaling factors (optional)
* "noise_rssi": int32 noise value in RSSI, dependent on device scaling factors (optional)
* "freq_khz": double-precision float of the center frequency of the signal record, in kHz
* "channel": arbitrary string representing a human-readable channel
* "datarate": double-precision float representing a phy-specific data rate (optional)

#### SUCCESS
A simple boolean indicating success or failure of the relevant command.

Content:
A single byte (`uint8_t`) indicating success (non-zero) or failure (zero).

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

A datasource which operates by passing packets should be able to function with no
further customization:  Packet data passed via the `PACKET` record will be
decapsulated and inserted into the packetchain with the proper DLT.

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
