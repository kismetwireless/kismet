---
title: "Extending the WebUI"
permalink: /docs/devel/webui_basics/
toc: true
---

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

#### field - string path and optional rename value

To tell Kismet which fields to include in the summary, the path to the field must be provided.  The path follows normal Kismet field naming - for example, to included a nested signal structure, the field definition could be `'kismet.device.base.signal/kismet.common.signal.last_signal_dbm'`.

When requesting common fields that might have overlapping names (such as location and signal fields), or simply to make referencing the field easier, an alternate name can be provided by passing an array, for example:  `['kismet.device.base.signal/kismet.common.signal.last_signal_dbm', 'base.signal']`.

#### description - string

Human-readable *short* description of the column, used for displaying the column information in the settings pane.

#### drawfunc - function (optional)

Optional function for performing custom drawing when the row is visible.  The devicetable is optimized to only call draw functions when the row is visible, so you don't need to worry about performing unnecessary work.

The `drawfunc` function takes three arguments:

* `dyncolumn`, the current column definition, which allows access to the name, id, and other fields passed to the `kismet_ui.AddDeviceColumn(...)` call
* `datatable`, an object instance of the device table as a `.DataTable()` object, allowing access to the over-all data table records
* `row`, an object instance of `.DataTable().row()` for the row being drawn.  This is already resolved to the actual row, eliminating the concern for sorting or visible position resolution.

#### name - string (optional)

Optional name of the column definition.  This allows searching by the column name in render functions to determine the index.

#### orderable - boolean (optional)

Passed to DataTables as bSortable, allows disabling sorting by this column.  Most useful on graphical columns which don't contain sortable data.

#### renderfunc - function (optional)

Optional function for rendering the field.  This is called as the `render` option of a DataTable row and takes the standard DataTable arguments: `data, type, row, meta`.

Render functions must return an element to be inserted into the cell and are called before the entire row is assembled.

#### sanitize - boolean (optional)

By default, all data is passed through a function which escapes HTML characters; if your data is *known to be safe* (such as locally-generated format data) and you want to insert HTML directly into the row, set sanitize to false.

#### searchable - boolean (optional)

Passed to DataTables as bSearchable, controls if the content of the column is searchable from the quick search field.

#### selectabe - boolean (optional)

Column is selectable by the user (default: true).  The most common use for creating an unselectable column is to pair it with the 'visible' option to create an invisible, but searchable, column (or a column which provides data to another column).

#### visible - boolean (optional)

Passed to datatables as bVisible, allows creating a column which is by default invisible.  To create a column which the user cannot enable, team with 'selectable'.

### Example Columns

To define a simple example column, you can call `kismet_ui.AddDeviceColumn(...)` any time before setting `load_complete=1` in your JS module.

A not-very-useful example would be to define 'column_foo_channel' which simply maps the `kismet.device.base.channel` record and calls it 'Channel'.

```javascript
kismet_ui.AddDeviceColumn('column_foo_channel', {
    sTitle: 'Channel',
    field: 'kismet.device.base.channel'
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
    field: 'kismet.device.base.last_time',
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
function renderPackets(dyncolumn, table, row) {
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

Finally, we add the column like we do anywhere else.  We set the `name` parameter so we can find the column by name later instead of hardcoded index.  We set the field to the packets RRD object which we need Kismet to send us.

```javascript
kismet_ui.AddDeviceColumn('column_foo_packet_rrd', {
    sTitle: 'Packets',
    field: 'kismet.device.base.packets.rrd',
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

A device details window can be created by calling the `kismet_ui.DeviceDetailWindow(key)` function.

For instance, to show a device detail for a known device key,

```javascript
foo.on('click', 'div', function() {
    kismet_ui.DeviceDetailWindow(somekey);
});
```

## Custom Device Details

Plugins can add panes to device details windows via the `kismet_ui.AddDeviceDetail` API:

`kismet_ui.AddDeviceDetail(id, name, priority, options);`

### id - string

An ID for referencing the device details panel

### name - string

User-readable name used for the title of the details panel

### priority - integer

Order preference for the device details.  Smaller numbers have a higher priority.  In general, plugins should use a neutral priority, such as 50.

### options - dictionary

An options object, containing the following:

#### filter - function(data) - optional

A function, returning if this details panel should be displayed.  It is passed the data record for the device.  A simple filter mechanism might be to compare the phy type, for example:

```javascript
filter: function(data) {
    return (data['kismet.device.base.phyname'] === 'IEEE802.11');
}
```

#### draw - function(data, target) 

A function, responsible for populating the content of the details panel.  It is passed the data record for the active device, and the element created for the details panel.

A draw function can use any mechanism for populating the details panel.  To replicate the standard system for displaying details, the `jquery.kismet.devicedata` module can be used (and is documented at [DeviceData](webui.jquery.kismet.devicedata.html))

## Sidebar Menu

Kismet has a (now standard) sidebar menu which is activated with the 'hamburger menu' in the top left of the UI.  This is generally a good place to put features which are not otherwise directly accessible from the UI (for instance, independent windows which are not linked to device details, etc).

The sidebar menu is managed by the `kismet_ui_sidebar` module which is loaded automatically before any dynamic modules.

Sidebar items are automatically styled and wrapped in a div element which supports hovering animation.

New menu items are added via `kismet_ui_sidebar.AddSidebarItem(options)`.  The `options` parameter is a dictionary object with the following values:

### id - string (required)

This is the ID assigned to the `<div>` element created in the sidebar.

### listTitle - string (required)

This is the title of the menu item.  This can included embedded HTML, and for consistency, it is recommended that an icon is selected from the included font-awesome icon font.

### clickCallback - string (required)

The function in which is called which this item is clicked.  This function is responsible for launching whatever activity corresponds to the menu item.  The menu will be closed automatically when the item is clicked.

### priority - integer (optional)

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

## Preferences / Settings

Kismet provides a common settings panel, which plugins are strongly encouraged to use.

A plugin can register multiple categories of settings.

### Settings windows
Settings windows are registered via `kismet_ui_settings.AddSettingsPane(options)`, where options is a dictionary containing:

#### id - string (required)

Set the ID of this setting panel so that it can be referenced directly

#### listTitle - string (required)

The title of the settings group in the settings list

#### windowTitle - string (optional)

The title appended to the settings window when this group is selected.  If no windowTitle is provided, the listTitle is used to make the window title.

#### create - function (required)

The create function is passed the content of the settings panel, and is responsible for populating it and creating any input callbacks.

The create function is also called when the user clicks the 'Reset settings' button.

#### save - function (required)

The save function is passed the content element of the settings panel, and is called when the user opts to save the settings.  The function should use HTML5 local storage for any browser-local settings, and can use this callback as an opportunity to call the server with changes.

#### priority - integer (optional)

Where in the settings list to add this item.  Smaller numbers are higher in the list.  In general, plugins should use a neutral priority (0).

### Settings Panels

Settings panels are a vertically-scrolling panel, and generally constructed using the jquery-ui toolkit.  For visual consistency, plugin settings should also use the jquery-ui methods when creating input forms.

Settings should only be saved when the user clicks the 'Save' button in the settings panel - the `save` callback is called in the settings object passed to `AddSettingsPanel`.

Settings plugins are responsible for telling the settings system when values are modified - this allows the settings window to show the 'Save Settings' button and the window-closing assistant.

### Launching directly to settings

A specific settings panel can be shown automatically by launching directly to that settings id when opening the settings panel:

```javascript
kismet_ui_settings.ShowSettings('demo_settings_panel');
```


### Example Settings

An example settings group in a plugin module might look like:


```javascript

// Define a function for creating and populating our settings panel
function CreateSettings(elem) {
    // Create the object tree
    elem.append(
        $('<form>', {
            id: 'form'
        })
        .append(
            $('<fieldset>', {
                id: 'set_radio',
            })
            .append(
                $('<legend>')
                .html("Radio example")
            )
            .append(
                $('<input>', {
                    type: 'radio',
                    id: 'demo_r_one',
                    name: 'radioexample',
                    value: 'one'
                })
            )
            .append(
                $('<label>', {
                    for: 'demo_r_one'
                })
                .html('Option One')
            )
            .append(
                $('<input>', {
                    type: 'radio',
                    id: 'demo_r_two',
                    name: 'radioexample',
                    value: 'two'
                })
            )
            .append(
                $('<label>', {
                    for: 'demo_r_two'
                })
                .html('Option Two')
            )
        )
    );

    // On any change, notify the settings panel
    $('#form', elem).on('change', function() {
        kismet_ui_settings.SettingsModified();
    });

    // Populate from html5 storage with default value of 'one'
    if (kismet.getStorage('plugin.demo.radioexample', 'one') === 'one')
        $('#demo_r_one', elem).attr('checked', 'checked');
    else
        $('#demo_r_two', elem).attr('checked', 'checked');

    // Make a jqueryui controlgroup
    $('#set_radio', elem).controlgroup();
}

// Make a simple function for saving settings
function SaveSettings(elem) {
    // jquery selector to get the checked elements value
    var r1 = $("input[name='radioexample']:checked", elem).val();

    // Put it into local storage
    kismet.putStorage('plugin.demo.radioexample', r1);
}

// Finally, actually register a settings panel
kismet_ui_settings.AddSettingsPanel({
    id: 'demo_settings'
    listTitle: 'Demo Settings',
    create: function(e) { CreateSettings(e); },
    save: function(e) { SaveSettings(e); },
});

```

## Tab pane views

Kismet provides two main views:  The primary display (where the device list lives), and the lower display (approximately 25% of the screen) where multiple other panels live, including messages and channel graphs.

Plugins may create their own tabs by calling `kismet_ui_tabpane.AddTab(...)` and passing an object dictionary containing:

### Tab pane parameters

#### id - string (required)

The ID of the div to be created

#### tabTitle - string (required)

Title HTML of the tab.  May include special formatting, but typically should be plain text.

#### expandable - boolean (optional)

Tab is expandable into its own sub-window (handled by jspanel).  This allows the user to 'pop' a tab out into its own panel floating over the base window, to show other tabs and content simultaneously.

#### createCallback(div) - function (required)

A function, taking the newly created div as an argument.  This function is responsible for populating the div once it is added to the page layout.

#### expandCallback(jspanel) - function (option)

A function, taking a jspanel as an argument.  This function is called when the tab is expanded into its own breakout jspanel window, if the tab is marked as expandable.  This allows tabs to set attributes on the expanded jspanel window.

#### priority - integer (optional)

The priority of the tab - tabs are sorted left to right, lowest numbers first.  Priority should only be set when the tab position is critical.

### Example tab pane

```javascript

// Add a generic pane
kismet_ui_tabpane.AddTab({
    id: 'boring',
    tabTitle: 'Boring tab',
    createCallback: function(div) {
        div.html("I am <i>Boring</i>");
    }
});
```

## Channels and Frequencies

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

## Iconbar docked icons

Kismet displays widgets in the upper right in the 'icon bar'; This is where simple single-icon alert-style elements can be added, and where by default, the login status, alert icon, and battery status are displayed.

Plugins may create their own tabs by calling `kismet_ui_iconbar.AddIconbarItem(...)` and passing an object dictionary containing:

### Icon bar parameters

#### id - string (required)

The ID is used to identify the iconbar item and identify the div created.

#### createCallback(div) - function (required)

The createCallback is called with the div created for the icon.  The createCallback can perform any actions to set up the iconbar item, including setting animations and click handlers.

#### priority - integer (optional)

If provided, sets the default priority in the iconbar list for the icon; plugins are encouraged to use negative numbers to place themselves to the left of the stock iconbar items.

### Example iconbar item

```javascript
// Add the alert handler icon using the jquery.kismet.alert code
kismet_ui_iconbar.AddIconbarItem({
    id: 'alert',
    priority: 125,
    createCallback: function(div) {
        div.alert();
    },
});
```
