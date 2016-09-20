# Extending Kismet - Web UI Device Data

It's often desireable to display simple data in Kismet as a table.  Kismet handles this in the web UI as a jquery plugin, `jquery.kismet.devicedata`.

`devicedata` takes a JSON object and a set of options, which includes a set of flexible field definitions able to map simple data/title pairs as well as filtering, complex render functions, empty field substitutions, and nested groups.

## Applying `$.devicedata()`

`devicedata` can be applied to any entity, but generally only makes sense to apply to a `div` or similar container.

```html
<div id="devicedata">

<script>
$('#devicedata').devicedata(data, options);
</script>
```

## Devicedata options

A `devicedata` instance takes a small number of options and an array of field defintions which perform the heavy lifting of the table display.

### id (optional)

Sets the entity ID of the table created by `devicedata`.  Defaults to 'kismetDeviceData'.

### stripe (optional)

Applies an alternating faded stripe to denote rows in the table if `true`.

### fields

Array of field definitions, discussed in the next section.

### filter (optional)

A function, taking a data argument and returning boolean, which determines if this entire display is rendered or skipped.

```javascript
{
    ...
    filter: function(data) {
        if (data[something])
            return true;
        return false;
    }
}
```

## Devicedata fields

The field definitions are where the magic happens in the `devicedata` plugin.  They function similarly to `DataTable` column definitions - a field definition can provide a simple title/content map, or can provide multiple callback functions.

### field

A DataTables-style field spec.  This allows for addressing nested and index data by chaining the fields, for example, `kismet_device_base_signal.kismet_common_signal_last_signal_dbm`.

### title

Title text presented to the user in the header for the row

### empty (optional)

Text to be substituted if the key is not available in the data set.

### render (optional)

The render option can be a fixed string, or a function.  The render function will called during creation of the table row, and the returned string is placed directly in the cell, prior to completion of the entire table.  The render function is called with:

* **key** - the key field specified in the `field` option.
* **data** - the complete data record for this table.
* **value** - the resolved value from the key/data pair.

For example, a row rendering the timestamp as a human-readable time:
```javascript
{
    field: "kismet_device_base_first_time",
    title: "First Seen",
    render: function(key, data, value) {
        return new Date(value * 1000);
    }
},
```

### draw (optional)

Draw function called AFTER creation of the table.  This function can be used to manipulate the contents of the row (or entire table) after it has been created and rendered.  The draw callback is mostly used for graphs or other non-text content which needs to be updated.  The draw function is called with:

* **key** - the key field specified in the 'field' option.
* **data** - the complete data record for this table.
* **value** - the resolved value from the key/data pair.
* **container** - the `<td>` cell containing the output

For example, to insert a sparkline in a row you could combine the `draw` and `render` functions:
```javascript
{
    field: "some_data_array",
    title: "Sparkline",
    render: function(key, data, value) {
        return '<i>Graph coming soon</i>';
    },
    draw: function(key, data, value, container) {
        container.sparkline({data: value;});
    }
}
```

A more complex example could create themed elements in the `draw` function and later utilzie them in the `render`:
```javascript
{
    field: "some_data",
    title: "Dynamid draw",
    render: function(key, data, value) {
        return '<div class="custom" />';
    },
    draw: function(key, data, value, container) {
        var mydiv = $('div.custom', container);
        mydiv.html('Added dynamically in draw');
    }
}
```

### filter (optional)

Filter function called during creation of the table row.  This function returns a boolean, and determines if the row is created.  The function takes the same arguments as the render function:

* **key** - field specified in the `field` option.
* **data** - complete data record for this table.
* **value** - the resolved value from the key/data pair.

For example, a row which combines filtering and drawing to only display the dBm signal value when signal data is present:

```javascript
{
    field: "kismet_device_base_signal.kismet_common_signal_last_signal_dbm",
    title: "Latest Signal",
    render: function(key, data, value) {
        return value + " dBm";
    },
    filter: function(key, data, value) {
        return (value != 0);
    }
},
```

### groupTitle (optional)

Indicates that this is a sub-group and provides a user-visible title for the group.

Sub-groups are rendered as a nested table, and fields defining a subgroup act as a top-level options directive - that is, they may then contain their own `id` and `fields` options.  The `id` option is applied to the nested table, and the `fields` are placed inside the nested instance.

The `groupTitle` option can be a fixed string, or a function taking a `(key, data, value)` set of arguments.

For example, to define a location group:

```javascript
{
    // Indicate that we're a subgroup, and give it the title 'Avg. Location'
    groupTitle: "Avg. Location",

    // The subgroup doesn't apply to a specific field, so we give it a junk value
    field: "group_avg_location",

    // Assign an ID to our subgroup
    id: "group_avg_location",

    // Subgroups can have filters, too, so we query the data and see if we have
    // a valid location.  If not, this subgroup will be hidden entirely
    filter: function(key, data, value) {
        return (kismet.ObjectByString(data, "kismet_device_base_location.kismet_common_location_avg_loc.kismet_common_location_valid") == 1);
    },

    // Fields in subgroup
    fields: [
        {
            field: "kismet_device_base_location.kismet_common_location_avg_loc.kismet_common_location_lat",
            title: "Latitude"
        },
        {
            field: "kismet_device_base_location.kismet_common_location_avg_loc.kismet_common_location_lon",
            title: "Longitude"
        },
    ],
}
```

### span (option)

Spans the `<td>` table cell containing the output across both columns (eliminating the title).  This allows for rows with custom graphs to center them above the following columns, and other custom behavior.

A spanned column will not show any title.

For example to simply show the value, centered in bold across the entire column:
```javascript
{
    field: "some_placeholder",
    span: true,
    render: function(key, data, value) {
        return '<b>' + value + '</b>';
    }
}
```

## Manipulating Devicedata Tables

Most of the requirements for manipulating the content of a Devicedata table should be met by the internal functions for rendering, drawing, etc.  However, if you need to modify or access data from outside the Devicedata object, the following elements are created:

* **table**, `id` using the supplied `id` field, class `kismet_devicedata`.  This table is created for every group of fields - a devicedata table.  The parent table uses the master `id` option, and subgroup tables are each created using the `id` of the subgroup definition.
* **tr**, `id` using a sanitized field reference prefixed with `tr_`.  To meet the requirements of an ID, complex field references (nested field names, indexed fields, etc) are converted by replacing all special characters with `_`.  A field reference such as `foo_bar_baz.sub_field` will form the table ID `tr_foo_bar_baz_sub_field`.
