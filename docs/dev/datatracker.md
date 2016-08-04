# Extending Kismet: Device and Data Tracking

Once data has been captured (see the [datasource docs](/docs/dev/datasource.html) for more details about creating a data source) and handled by the DLT handler, additional processing can be done to create device records and data.

Kismet stores information about a device in a `tracker_component` record held by the `DeviceTracker` class.  For more information about the internals and how to make your own `tracker_component` check out the [tracked component docs](/docs/dev/tracked_component.html).

Information stored in the common base element is used to show summaries about the devices seen, create statistics, and to show information about a device when no custom presentation is defined for the extra data.

Kismet will automatically track signal and location information for the device, assuming they are provided, as well as peak signal locations, device names, packet counts, time ranges seen, channels and frequencies used, and similar information, so long as the phy handler makes the data available.

## The Common Classifier

Each data source which defines a new phy layer (ie, something not already handled in Kismet elsewhere) is responsible for reducing information from that phy to something the common layer of Kismet can understand.

Device records are automatically created by Kismet using the `kis_common_info` packet record.

Datasources need to provide some mechanism for turning their packets and data into a common record, and either attach that record to the packet chain, or explicitly notify the `DeviceTracker` system via a pseudo-packet.

### Common Info From Packets

Typically, for a packet-based protocol, the information needed to form the common info for categorization is part of the packet.  For example, in Wi-Fi, the device MAC, common encryption signifiers, data sizes, etc are all encoded in the dot11 frame, they just need to be converted to the common type.

`kis_common_info` is a basic packet component defined in `packet.h`, and contains a very simple representation of data Kismet needs to assemble a basic device:

#### Mac Addresses (and Mac-Address-Like Addresses)

Four main mac addresses are recorded:

```C++
    mac_addr source, dest;
    mac_addr transmitter, device;
```

* **source** - The original source of the packet.  This may not be the address of the device that transmitted it, for example in Wi-Fi this could be the source mac of a wired device bridged to wireless.
* **dest** - The destination of the packet.  This may or may not be a wireless device, for instance a packet transmitted from a wireless network via a bridge to a wired device.
* **transmitter** - The address of the radio which transmitted the packet, if available.  This may be the same as the source mac.  Again using Wi-Fi as an example, the transmitter mac address would be the access point.
* **device** - The actual address of the device.  This is likely the same as the source mac, and is the address used to identify the device.

If the phy type you are implementing doesn't use traditional MAC addresses, a similar unique addressing scheme must be created for devices in that phy, which can be packed into a mac-address style record.  The addressing should be unique and repeatable (that is, the same device must generate the same mac-like address to be tracked properly).

#### Basic Type

The basic type is aggregated per-packet and used to indicate the type of packet:

```C++
    kis_packet_basictype type;
```

Which draws from the set of:

```C++
enum kis_packet_basictype {
	packet_basic_unknown = 0,
	packet_basic_mgmt = 1,
	packet_basic_data = 2,
	packet_basic_phy = 3
};
```

* **unknown** - An unclassifiable generic packet
* **mgmt** - Management / network maintenance packets.  In Wi-Fi networks, management frames include beacons, probe requests, etc
* **data** - Packet carries data of some sort
* **phy** - Physical-layer control packets.  In Wi-Fi, CTS/RTS packets are classified as phy type frames

#### Basic Encryption Set

The basic encryption allows Kismet to show encrypted, unencrypted, decrypted, and vulnerable devices.  A phy should provide detailed information about the types of encryption used inside its own data, but this allows Kismet to display more common information.

```C++
    // Encryption if applicable
    uint32_t basic_crypt_set;
```

Which is a bit-set of the following from `devicetracker.h`:

```C++
#define KIS_DEVICE_BASICCRYPT_NONE		0
#define KIS_DEVICE_BASICCRYPT_ENCRYPTED	(1 << 1)

#define KIS_DEVICE_BASICCRYPT_L2		(1 << 2)
#define KIS_DEVICE_BASICCRYPT_L3		(1 << 3)
#define KIS_DEVICE_BASICCRYPT_WEAKCRYPT	(1 << 4)
#define KIS_DEVICE_BASICCRYPT_DECRYPTED	(1 << 5)
```

* **NONE** and **ENCRYPTED** define basic encryption being present (or not).
* If available, **L2** and **L3** may be used to indicate layer 2 (such as WPA on Wi-Fi) or layer 3 (such as a VPN detected in layer 3 traffic)
* **WEAKCRYPT** is used to indicate that the encryption method is known to be vulnerable, for example WEP on Wi-Fi is flagged as WEAKCRYPT.  This can be used by Kismet to identify devices which are at increased risk.
* **DECRYPTED** indicates that the data is encrypted, but has been decrypted - for example via a known WEP key or other decryption.

#### Additional Data

```C+++
    int phyid;
```

The phy id should be filled in with the ID of the phy type registered with Kismet.

```C++
    int error;
```

A boolean value indicating the packet is in error.  Kismet uses this to track error rates on tracked devices.

```C++
    int datasize;
```

Basic data size in bytes, used by Kismet to calculate the aggregate data of the tracked device.

```C++
    string channel;
```

Phy-specific complex channel.  Channel is represented as a string and can carry special attributes, or can be a frequency representation if the phy has no channel definitions.  For instance, for 802.11N Wi-Fi, a channel may be represented as "6HT40+" while a simpler radio protocol may simply use "433.9MHz" as the channel string.

```C++
    double freq_khz;
```

The center frequency of the communication, in KHz.

### An Example of Common Info

To demonstrate how to use the common into, lets take the 802.11 common classifier as an example.  This is registered by the 802.11 decoder as a packet chain element in the `CLASSIFIER` portion.

The classifier is called after we have already:

1. Decapsulated the 802.11 frame from any L2 data (such as radiotap or PPI)
2. Processed the signalling (and in PPIs case, location) data from the L2 header
3. Processed the 802.11 packet into our own packet component, dot11info, which tells us about the 802.11 addressing, encryption, errors, etc.

Already knowing the 802.11 characteristics makes filling in the `kis_common_info` record very simple.

```C++
int Kis_80211_Phy::CommonClassifierDot11(CHAINCALL_PARMS) {
    /* Grab the instance of the Dot111 Phy from the auxptr, remember we're a
       static function so that we can be called directly */
    Kis_80211_Phy *d11phy = (Kis_80211_Phy *) auxdata;

    /* Get the 802.11 component of the packet, or die trying */
    dot11_packinfo *dot11info =
        (dot11_packinfo *) in_pack->fetch(d11phy->pack_comp_80211);

	if (dot11info == NULL)
		return 0;

    /* Get the common info, and if it doesn't exist, make one and insert it.
       There shouldn't be a situation where we have a CI already, but if we
       just inserted blindly we risk leaking memory. */
	kis_common_info *ci =
		(kis_common_info *) in_pack->fetch(d11phy->pack_comp_common);

	if (ci == NULL) {
		ci = new kis_common_info;
		in_pack->insert(d11phy->pack_comp_common, ci);
	}

    /* Set the phy ID from our phyhandler */
	ci->phyid = d11phy->phyid;

    /* Start decoding the dot11 to get our common info */
	if (dot11info->type == packet_management) {
		ci->type = packet_basic_mgmt;

		if (dot11info->source_mac == globalreg->empty_mac) {
			if (dot11info->bssid_mac == globalreg->empty_mac) {
				ci->error = 1;
			}

			ci->device = dot11info->bssid_mac;
		} else {
			ci->device = dot11info->source_mac;
		}

		ci->source = dot11info->source_mac;

		ci->dest = dot11info->dest_mac;

        ci->transmitter = dot11info->bssid_mac;
	} else if (dot11info->type == packet_phy) {
        // ...

	} else if (dot11info->type == packet_data) {
        // ...
	}

    /* If we're known corrupt from the dot11 handlers... */
	if (dot11info->type == packet_noise || dot11info->corrupt ||
			   in_pack->error || dot11info->type == packet_unknown ||
			   dot11info->subtype == packet_sub_unknown) {
		ci->error = 1;
	}

    /* Set the channel from the dot11 channel */
	ci->channel = dot11info->channel;

    /* Set the data size */
	ci->datasize = dot11info->datasize;

    /* Either we're encrypted or we're not */
	if (dot11info->cryptset == crypt_none) {
		ci->basic_crypt_set = KIS_DEVICE_BASICCRYPT_NONE;
	} else {
		ci->basic_crypt_set = KIS_DEVICE_BASICCRYPT_ENCRYPTED;
	}

    /* Add in the additional L2/L3 crypto knowledge from the 802.11 decoder */
	if (dot11info->cryptset & crypt_l2_mask) {
		ci->basic_crypt_set |= KIS_DEVICE_BASICCRYPT_L2;
	} if (dot11info->cryptset & crypt_l3_mask) {
		ci->basic_crypt_set |= KIS_DEVICE_BASICCRYPT_L3;
	}

	return 1;
}
```

## Custom Device data

All but the most basic of device records will need custom device data.

Because the `kis_tracked_base` record is a `tracker_component` record, it can hold arbitrary additional `tracker_component` data.  These sub-elements will automatically be included in serialization to web clients and other exports.

Data can be included either as multiple unique fields inserted into the `kis_tracked_base` record, or as a complete sub-record containing all the information.  For organization and simplicity (and ease of serialization to formats like XML) it is generally much better to create a complete sub-record and attach it to the `kis_tracked_base`.
