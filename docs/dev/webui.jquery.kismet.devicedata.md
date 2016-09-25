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

### id - string (optional)

Sets the entity ID of the table created by `devicedata`.  Defaults to 'kismetDeviceData'.

### fields - array

Array of field definitions, discussed in the next section.

## Devicedata fields

The field definitions are where the magic happens in the `devicedata` plugin.  They function similarly to `DataTable` column definitions - a field definition can provide a simple title/content map, or can insert fully rendered graphics, other objects, etc.

Many options can be passed as a string or as a function.  Functions all take an options dictionary object, containing at least:

* **key** - String key of current field
* **data** - Complete data set assigned to this `devicedata` object
* **value** - Resolved value for the current field
* **basekey** - Optional string key of base object, used in iterative groups (more on these later)
* **base** - Object of the sub-set of data for the current field, used it iterative groups.

Additional fields may be present in the options object depending on the callback, and will be mentioned below.

### field

A DataTables-style field spec.  This allows for addressing nested and index data by chaining the fields, for example, `kismet_device_base_signal.kismet_common_signal_last_signal_dbm`.

### title - string

Title text presented to the user in the header for the row

### empty - string | function(opts) (optional)

Text to be substituted if the key is not available in the data set.

### filter - function (optional)

A function, taking a opts argument and returning boolean, which determines if this entire display is rendered or skipped.  Filter functions should return `true` to display the field and `false` to hide it.

```javascript
{
    ...
    filter: function(opts) {
        if (data[something])
            return true;
        return false;
    }
}
```

### filterOnEmpty - boolean (optional)

Filter this field if it is undefined, or an empty string.  This is identical to comparing the value in a filter function.

### filterOnZero - boolean (optional)

Filter this field if it is undefined, or a zero number.  This is identical to comparing the value in a filter function.

### render - string | function (optional)

If the render option is a string, it is placed in the HTML of the `<td>` container.

If the render option is a function, it will called during creation of the table row, and the returned string is placed directly in the cell, prior to completion of the entire table.  The render function is called before the DOM of the container is finalized.  Render functions may return complex HTML.

The render function is called with a standard options dictionary.

For example, a row rendering the timestamp as a human-readable time:
```javascript
{
    field: "kismet_device_base_first_time",
    title: "First Seen",
    render: function(options) {
        return new Date(options['value'] * 1000);
    }
},
```

### draw - function(opts) (optional)

Draw function called AFTER creation of the table.  This function can be used to manipulate the contents of the row (or entire table) after it has been created and rendered.  The draw callback is mostly used for graphs or other non-text content. Draw is called after the DOM is finalized so can manipulate the objects directly.

Draw functions receive the normal options object, with an additional value:
* **container** - object container for the `<td>` cell for this field.

For example, to insert a sparkline in a row you could combine the `draw` and `render` functions:
```javascript
{
    field: "some_data_array",
    title: "Sparkline",
    render: '<i>Graph coming soon</i>';
    draw: function(opts) {
        opts['container'].sparkline({data: opts['value'];});
    }
}
```

A more complex example could create themed elements in the `draw` function and later utilize them in the `render` function:
```javascript
{
    field: "some_data",
    title: "Dynamid draw",
    render: '<div class="custom" />',
    draw: function(opts) {
        var mydiv = $('div.custom', opts['container']);
        mydiv.html('Added dynamically in draw');
    }
}
```

### groupTitle string | function (optional)

Indicates that this is a sub-group and provides a user-visible title for the group.

Sub-groups are rendered as a nested table, and fields defining a subgroup act as a top-level options directive - that is, they may then contain their own `id` and `fields` options.  The `id` option is applied to the nested table, and the `fields` are placed inside the nested instance.

In simpler terms, subgroups create a new `devicedata` table, which can, in turn, contain more fields, subgroups, etc.

The `groupTitle` option can be a fixed string, or a function taking an options set.

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
    filter: function(opts) {
        return (kismet.ObjectByString(opts['data'], "kismet_device_base_location.kismet_common_location_avg_loc.kismet_common_location_valid") == 1);
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

### groupIterate - boolean (optional)

Indicated that this field contains an iterative group.

Iterative groups apply to data sets like arrays or dictionaries.  The group is treated like a subgroup, and loops over each value in the array or dictionary.

Iterative groups treat the `fields` option slightly differently:  all options for fields are processed as normal, however the field definition should be the field name only - the complete, indexed field path will be prepended automatically.

It is simpler to provide an example.

Given the data:

```javascript
var data = {
    'somegroup': [
        { 
            'field1': "one",
            'field2': "two"
        },
        {
            'field1': "three",
            'field2': "four"
        }
    ]
};
```

A *standard* field definition might be `somegroup.field1`.  However, for an iterative group, you would want to use:

```javascript
{
    // We're an iterative group
    groupIterate: true,

    // Provide the GROUP FIELD, ie the dictionary or array object field
    field: 'somegroup',

    // Now our fields are referenced within `somegroup` automatically for us
    fields: [
    {
        field: 'field1',
        title: 'Field One'
    },
    {
        field: 'field2',
        title: 'Field Two'
    }
    ]
}
```

Additionally, field functions called as part of an iterative group are given an additional option in the callback options:
* **index** - The index value used for this iteration. 

### iterateTitle - string | function (optional)

Provide a title for an iterative group.  May be a fixed string, or a function taking the standard options group.

Additionally, the options group will contain:
* **index** - The index value used for this iteration. 

### span - boolean (optional)

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
