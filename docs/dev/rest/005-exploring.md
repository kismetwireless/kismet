---
title: "Exploring endpoints"
permalink: /docs/devel/webui_rest/exploring/
---

## Exploring the REST system

The easiest way to explore the REST system, aside from the docs, is to query the JSON endpoints directly.  You can use `curl` and `python` to quickly grab output and format the JSON to be human readable:

```
$ curl http://localhost:2501/datasource/all_sources.json | python -mjson.tool
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 36274  100 36274    0     0   761k      0 --:--:-- --:--:-- --:--:--  770k
[
    {
        "kismet.datasource.capture_interface": "wlp3s0mon",
        "kismet.datasource.channel": "",
        "kismet.datasource.channels": [
            "1",
            "1HT40+",
            "2",
            "3",
            "4",
            "5",
            "6",
            "6HT40-",
            "6HT40+",
            "7",
            "8",
            "9",
            "10",
            "11",
            "11HT40-"
        ],
        "kismet.datasource.definition": "wlp3s0",
        "kismet.datasource.dlt": 127,
        "kismet.datasource.error": 0,
        "kismet.datasource.error_reason": "",
        "kismet.datasource.hop_channels": [
....
```

Similarly, POST data can be sent via curl; for example to test creating an alert via the dynamic alerts endpoint:

```bash
$ curl -d 'json={"name": "JSONALERT", "description": "Dynamic alert added at runtime", "throttle": "10/min", "burst": "1/sec"}' http://kismet:kismet@localhost:2501/alerts/definitions/define_alert.cmd
```

which passes the parameters in the `json=` variable, and the login and password in the URI (kismet:kismet in this example).

### What do all the fields mean?

More information about each field can be found in the `/system/tracked_fields.html` URI by visiting `http://localhost:2501/system/tracked_fields.html` in your browser.  This will show the field names, descriptions, and data types, for every known entity.

### Additional pretty-printed output

For even more information, almost every REST endpoint can be requested using the `{foo}.prettyjson` format; this JSON output is styled for ease of readability and includes additional metadata to help understand the format; for example:

```
$ curl http://localhost:2501/system/status.prettyjson
 {
 "description.kismet.device.packets_rrd": "string, RRD of total packets seen",
 "kismet.device.packets_rrd":
  {
  "description.kismet.common.rrd.last_time": "uint64_t, last time udpated",
  "kismet.common.rrd.last_time": 1506473162,
...
 "description.kismet.system.battery.percentage": "int32_t, remaining battery percentage",
 "kismet.system.battery.percentage": 96,

 "description.kismet.system.battery.charging": "string, battery charging state",
 "kismet.system.battery.charging": "discharging",

 "description.kismet.system.battery.ac": "uint8_t, on AC power",
 "kismet.system.battery.ac": 0,

 "description.kismet.system.battery.remaining": "uint32_t, battery remaining in seconds",
 "kismet.system.battery.remaining": 0,

 "description.kismet.system.timestamp.sec": "uint64_t, system timestamp, seconds",
 "kismet.system.timestamp.sec": 1506473162,
 }
}
```

For each defined field, Kismet will include a metadata field, `description.whatever.field.name`, which gives the type (for instance, uint32_t for a 32bit unsigned int), and the description, for instance 'battery remaining in seconds'.

While the `prettyjson` format is well suited for learning about Kismet and developing tools to interface with the REST API, the `json` format should be used for final code; it is significantly faster than `prettyjson` and is optimized for processing time and space.

`prettyjson` should work with nearly all REST endpoints which return JSON records, but will *NOT* work with `ekjson`-only endpoints (which are relatively rare, and documented accordingly below in the REST docs).

