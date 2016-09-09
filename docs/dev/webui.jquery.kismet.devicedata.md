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

Render function called during creation of the table row.  The results of this function are placed directly in the cell, prior to completion of the entire table.  The render function is called with:

* **key** - the field specified in the `field` option.
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
