# Extending Kismet: The Web UI

Kismet self-serves its web UI via the built-in webserver.  The web UI can interact with any exposed REST endpoint on the server.  Kismet does not currently support (direct) execution of CGI-style code (PHP, etc), active server-side code should be implemented via a Kismet plugin providing a new endpoint.

## Web UI Plugins

A Kismet plugin can add onto the web UI by defining additional files which are loaded during the startup process.  Add-on files can provide new content for existing elements or define enitrely new mechanisms.

## Making a Module

Kismet JS modules should follow some simple conventions to enable proper loading:

* **All functions should be in a custom namespace**.  This prevents overlap between common names in plugins and simplifies loading.
* **A `load_complete` variable must be provided**.  Because of how asynchronous loading of javascript is handled, the only way to know that a module has fully loaded and executed any setup functions is to scan a variable in the namespace of the module.

### A Basic Module

```javascript
// Module boilerplate.  This will define a module kismet-plugin-foo-js which
// will instantiate under the global object kismet_plugin_foo.
(
    typeof define === "function" ? function (m) { define("kismet-plugin-foo-js", m); } :
     typeof exports === "object" ? function (m) { module.exports = m(); } :
     function(m){ this.kismet_plugin_foo = m(); }
)(function () {

"use strict";

// All functions and variables accessible outside this module are defined
// in exports
var exports = {};

// The first thing we MUST do is define load_complete and set it to 0
exports.load_complete = 0;

// Define a function in our module which simply logs "hello" to the console
exports.test_func = function() {
    console.log("Hello!");
}

// We can perform any other on-load type actions here

// Finally, set load_complete to 1, we've done everything we need to do
exports.load_complete = 1;

// Return our exports object
return exports;

});
```

## Device List

The device list is the central component of the UI, showing the found devices, allowing the user to select devices to inspect, etc.

Custom columns can be added to the device list via `kismet_ui.AddDeviceColumn(...)`.

### Defining a Column

Columns are directly linked to the [jQuery DataTables](https://datatables.net/) implementation and share many characteristics.  A column consists of a string ID (a unique value used for identifying this column in preferences), and an options dictionary.

Columns can be defined as basic mappings of the JSON data in the device summary, custom transforms of the data, or complete custom drawing routines.

#### sTitle

Display title of the column.

#### mData

DataTables-compatible field spec for the data.  This follows the normal DataTables naming convention for nested JSON structures (for example `kismet_device_base_signal.kismet_common_signal_last_signal_dbm`)

#### name (optional)

Optional name of the column definition.  This allows searching by the column name.

#### cbmodule (optional)

Optional name of the module / namespace holding callback function code.  For columns which define a custom render or draw function, `cbmodule` is required to tell the column callbacks where to look.

#### renderfunc (optional)

Optional function for rendering the field.  This is called as the `render` option of a DataTable row and takes the standard DataTable arguments: `data, type, row, meta`.

Render functions return an element to be inserted into the cell and are called before the entire row is assembled.

If a `renderfunc` is provided, a `cbmodule` must also be provided.

#### drawfunc (optional)

Optional function for performing custom drawing when the row is visible.  The devicetable is optimized to only call draw functions when the row is visible, so you don't need to worry about performing unncessary work.

The `drawfunc` function takes three arguments:

* `dyncolumn`, the current column definition, which allows access to the name, id, and other fields passed to the `kismet_ui.AddDeviceColumn(...)` call
* `datatable`, an object instance of the device table as a `.DataTable()` object, allowing access to the over-all data table records
* `row`, an object instance of `.DataTable().row()` for the row being drawn.  This is already resolved to the actual row, eliminating the concern for sorting or visible position resolution.

### Example Columns

To define a simple example column, you can call `kismet_ui.AddDeviceColumn(...)` any time before setting `load_complete=1` in your JS module.

A not-very-useful example would be to define 'column_foo_channel' which simply maps the `kismet_device_base_channel` record and calls it 'Channel'.

```javascript
kismet_ui.AddDeviceColumn('column_foo_channel', {
    sTitle: 'Channel',
    mData: 'kismet_device_base_channel'
});
```

A more interesting example is to use the `renderfunc` option to render a custom timestamp, which is how the base UI renders the `time_t` unix timestamp as human-readable text.  Like the previous example, all this code is placed before the `load_complete=1` in the JS module.

First, we define a function which handles the render callback.  This matches the DataTable render function for a column, and takes the same options:  the data for the cell, the type of query, the full data for the row, and the row/column index information.

```javascript
exports.renderLastTime = function(data, type, row, meta) {
    // Take the data, make a date from it, and slice the string
    return (new Date(data * 1000).toString()).substring(4, 25);
}
```

Now that we have the callback function, we define the column to map the data and the render callback inside our module:

```javascript
kismet_ui.AddDeviceColumn('column_foo_time', {
    sTitle: 'Last Seen',
    mData: 'kismet_device_base_last_time',
    cbmodule: 'kismet_plugin_foo',
    renderfunc: 'renderLastTime'
});
```

Notice that we provide the name of our modue in `cbmodule` - this needs to match the module definition at the top of the file.

Finally, we'll show an example of doing custom drawing in a column.  Because the render function happens too early, the easiest way to accomplish custom elements drawn on a row is to combine a render function which inserts a placeholder, and a draw function which gets called when that row is visible.

Let's use the packet graph / sparkline RRD as an example.  First we put placeholder text into the cell because we defer rendering until later:

```javascript
exports.renderPackets = function(data, type, row, meta) {
    return "<i>Preparing graph</i>";
}
```

Then during the draw function we use jQuery selectors and the DataTable API to find the column (by name) and offset to the proper cell in the table, then we wipe its content and replace it with the sparkline:

```javascript
exports.drawPackets = function(dyncolumn, table, row) {
    // Find the column by name using the 'foo:name' selector.  Get the index
    // of the column, which is the cell # in the row.
    var rid = table.column(dyncolumn.name + ':name').index();

    // Define a match using the array selector in jQuery, we want the
    // column id'th <td> element
    var match = "td:eq(" + rid + ")";

    // Fetch the data from the DataTable row record
    var data = row.data();

    // Do a bunch of RRD manipulation to fast-forward our graph since we only
    // get updates when the network changes so we have to manually move forwards
    // in time if the network is visible but idle.  This is also where we
    // average out the number of points in the graph so we get nice thick
    // sparkline bars which look a lot better.

    // Finally, render the sparkline.  We use the jquery match we defined
    // above to search in the nodes of the row and grab the TD we want.
    // Then we call the jquery sparkline plugin and render directly into that
    // row.
    $(match, row.node()).sparkline(simple_rrd,
        { type: "bar",
            barColor: '#000000',
            nullColor: '#000000',
            zeroColor: '#000000'
        });
};
```

Finally, we add the column like we do anywhere else.  We need to provide a `cbmodule` option and both the `drawfunc` and `renderfunc` functions.  We also set the `name` parameter so we can find the column by name later instead of hardcoded index, and we set `mData` to `null` beause we don't populate from just a single simple field.

```javascript
kismet_ui.AddDeviceColumn('column_foo_packet_rrd', {
    sTitle: 'Packets',
    mData: null,
    name: 'packets_foo',
    cbmodule: 'kismet_plugin_foo',
    renderfunc: 'renderPackets',
    drawfunc: 'drawPackets'
});

```
