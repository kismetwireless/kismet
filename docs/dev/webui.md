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

#### sTitle - string

Display title of the column.  Passed as sTitle directly to the DataTables column definition.

#### mData - string

DataTables-compatible field spec for the data.  This follows the normal DataTables naming convention for nested JSON structures (for example `kismet_device_base_signal.kismet_common_signal_last_signal_dbm`)

#### name - string (optional)

Optional name of the column definition.  This allows searching by the column name in render functions to determine the index.

#### orderable - boolean (optional)

Passed to DataTables as bSortable, allows disabling sorting by this column.  Most useful on graphical columns which don't contain sortable data.

#### visible - boolean (optional)

Passed to DataTables as bVisisible, allows creating invisible columns.  The most common use for an invisible column would be to create a searchable field which isn't shown.  Invisible columns cannot be selected by the user in the column selection UI.

#### searchable - boolean (optional)

Passed to DataTables as bSearchable, controls if the content of the column is searchable from the quick search field.

#### renderfunc - function (optional)

Optional function for rendering the field.  This is called as the `render` option of a DataTable row and takes the standard DataTable arguments: `data, type, row, meta`.

Render functions must return an element to be inserted into the cell and are called before the entire row is assembled.

#### drawfunc - function (optional)

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
    renderfunc: function(data, type, row, meta) {
        return renderLastTime(data, type, row, meta);
    },
});
```

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

Finally, we add the column like we do anywhere else.  We set the `name` parameter so we can find the column by name later instead of hardcoded index, and we set `mData` to `null` beause we don't populate from just a single simple field.

```javascript
kismet_ui.AddDeviceColumn('column_foo_packet_rrd', {
    sTitle: 'Packets',
    mData: null,
    name: 'packets_foo',
    renderfunc: function(data, type, row, meta) {
        return renderPackets(data, type, row, meta);
    },
    drawfunc: function(data, type, row) {
        return drawPackets(data, type, row);
    }
});

```

## Device Details

A device details window can be created by calling the `DeviceDetailWindow(key)` function in `kismet_ui`.

For instance, to show a device detail for a known device key,

```javascript
foo.on('click', 'div', function() {
    kismet_ui.DeviceDetailWindow(somekey);
});
```

## Sidebar Menu

Kismet has a (now standard) sidebar menu which is activated with the 'hamburger menu' in the top left of the UI.  This is generally a good place to put features which are not otherwise directly accessible from the UI (for instance, independent windows which are not linked to device details, etc).

The sidebar menu is managed by the `kismet_ui_sidebar` module which is loaded automatically before any dynamic modules.

Sidebar items are automatically styled and wrapped in a div element which supports hovering animation.

New menu items are added via `kismet_ui_sidebar.AddSidebarItem(options)`.  The `options` parameter is a dictionary object with the following values:

#### id - string (required)

This is the ID assigned to the `<div>` element created in the sidebar.

#### listTitle - string (required)

This is the title of the menu item.  This can included embedded HTML, and for consistency, it is recommended that an icon is selected from the included font-awesome icon font.

#### clickCallback - string (required)

The function in which is called which this item is clicked.  This function is responsible for launching whatever activity corresponds to the menu item.  The menu will be closed automatically when the item is clicked.

#### priority - integer (optional)

Where in the list to insert the new item.  Smaller numbers indicate higher priority.  In general, plugins should use a neutral priority (0) but in some cases it makes logical sense to place an option higher or lower in the list.

### An example sidebar

We will, again, use our example module, `kismet_plugin_foo`.  

Our sidebar option will open an extremely simple jsPanel HTML5 window.

```javascript

// Module boilerplate and other functionality

// Define a function to launch our 
exports.PluginWindowDemo = function() {
    var demopanel = $.jsPanel({
        id: 'sidedemo',
        headerTitle: 'Demo sidebar',
        headerControls: {
            controls: 'closeonely'
            },
            content: 'Hello from the sidebar!',
        }).resize({
            width: $(window).width() / 2,
            height: $(window).height() / 2
        }).reposition({
            my: 'center-top',
            at: 'center-top',
            of: 'window',
            offsetY: 20
        });
};

// Add us to the sidebar with no specific priority
kismet_ui_sidebar.AddSidebarItem({
    id: 'sidebar_demo',
    listTitle: '<i class="fa fa-star" /> Demo Item',
    clickCallback: function() {
        return PluginWindowDemo();
    }
});

```

## Channels

Sometimes Kismet needs to display information by frequency - most notably, in the
"Channels" display of devices per frequency.

Each plugin can provide a custom frequency to channel transform.  Displays like the devices-per-frequency graph can present a selection option to the user.

This is done via the `kismet_ui.AddChannelList(name, list)` function.  The `list` argument can be either a dictionary of `{ frequency: channelname }` pairs, or a function taking the frequency as an argument and returning the channel.

For example:

```javascript
kismet_ui.AddChannelList("RTL 433", {
    433.00, "433 ISM",
    433.10, "Channel 1",
});
```

or the more complex transform used for Wi-Fi, where the frequency passed through
a conversion function:

```javascript
kismet_ui.AddChannelList("Wi-Fi (802.11)", function(in_freq) {
    in_freq = parseInt(in_freq / 1000);

    if (in_freq == 2484)
        return 14;
    else if (in_freq < 2484)
        return (in_freq - 2407) / 5;
    else if (in_freq >= 4910 && in_freq <= 4980)
        return (in_freq - 4000) / 5;
    else if (in_freq <= 45000)
        return (in_freq - 5000) / 5;
    else if (in_freq >= 58320 && in_freq <= 64800)
        return (in_freq - 56160) / 2160;
    else
        return in_freq;
});
```

When using conversion functions, always return the unmodified frequency if no conversion can be found - often devices can be mixed from multiple plugins and frequencies which do not correspond to any known channel may be passed to your conversion function.

