---
title: "Serialization types"
permalink: /docs/devel/webui_rest/serialization/
---
## Serialization Types

Kismet can export data as several different formats; generally these formats are indicated by the type of endpoint being requested (such as foo.json)

### JSON

Kismet will export objects in traditional JSON format suitable for consumption in javascript or any other language with a JSON interpreter.

### EKJSON

"EK" JSON is modeled after the Elastic Search JSON format, where a complete JSON object is found on each line of the output.

Kismet supports ekjson on any REST UI which returns a vector/list/array of results.  The results will be the same as standard JSON, however each item in the list will be a discrete JSON object.

The primary advantage of the ekjson format is the ability to process it *as a stream* instead of as a single giant object - this reduces the client-side memory requirements of searches with a large number of devices drastically.

### PRETTYJSON

"Pretty" JSON is optimized for human readability and includes metadata fields describing what Kismet knows about each field in the JSON response.  For more information, see the previous section, `Exploring the REST system`.

"Pretty" JSON should only be used for learning about Kismet and developing; for actual use of the REST API standard "JSON" or "EKJSON" endpoints should be used as they are significantly faster and optimized.
