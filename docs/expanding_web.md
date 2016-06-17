# Extending Kismet Web Services
Kismet serves complex objects over a REST interface by implementing "tracked components".

Tracked components are introspectable via C++ code and can be dynamically exported to other formats, such as msgpack.

## Deriving from tracker_component
Any data you wish to expose as an object must be derived from tracker_component.

A tracker_component is, internally, a tracked element map, which contains multiple objects.

### First, the boilerplate:

For our example, we want to mimic the behavior of the Kismet messagebus so that we can display messages on the web UI.

We need to create a message record which has a timestamp, the message content, and a set of flags.

```C++
class WebTrackedMessage : public tracker_component {
public:
    // tracker_component constructor which takes in the global registry 
    // pointer and the id of this element
    WebTrackedMessage(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        // Register and reserve fields will be covered later
        register_fields();
        reserve_fields(NULL);
    }

    // The second common constructor, which takes in the globalreg
    // pointer and id, but also a pointer to a an existing data
    // object.  This is used to construct a custom object from
    // a base which already contains the same fields
    WebTrackedMessage(GlobalRegistry *in_globalreg, int in_id,
            TrackerElement *e) :
        tracker_component(in_globalreg, in_id) {
        // Again the register and reserve, but this time we pass the
        // pre-existing element to the reserve_fields object
        register_fields();
        reserve_fields(e);
    }

    // Finally, we need to provide a mechanism for cloning the type
    // of this custom object.  When we add this object to the tracking
    // system which keeps track of named fields, this provides a 
    // factory mechanism which builds a copy when requested.
    virtual WebTrackedMessage *clone_type() {
        return new WebTrackedMessage(globalreg, get_id());
    }

}
```

This creates a tracked object, but there is nothing inside of it.  To do that, we need to add some data fields.

### TrackerElement Fields

To track a field, we need to track the ID and we need the field itself, so lets add:

```C++
protected:
    int timestamp_id;
    TrackerElement *timestamp;
    
    int message_id;
    TrackerElement *message;
    
    int flags_id;
    TrackerElement *flags;
```

This gives us three fields, and id values for them.

### Registering Fields

To actually use the fields, they need to be initialized with a type and name.  This is done in the `register_fields()` class method.

```C++
protected:
    virtual void register_fields() {
        // Call the parent register_fields() function
        tracker_component::register_fields();

        // Register the timestamp as a uint64_t
        timestamp_id = RegisterField("kismet.message.timestamp", 
                TrackerUInt64, "message timestamp", (void **) &timestamp);

        // Register the message as a basic string
        message_id = RegisterField("kismet.message.message",
                TrackerString, "message content", (void **) &message);

        // Register the flags as a uint32_t
        flags_id = RegisterField("kismet.message.flags",
                TrackerUInt32, "message flags", (void **) &flags);
    }
```

`RegisterField(...) is part of the base tracker_component class, and handles the connection between a tracked data set and the tracking system which assigns fields.

It requires a name (which should be unique, you can ensure uniqueness by including a reference to your module in the name), a type (used to manage introspection and export, the list is below), a description (which is shown on the tracked_fields page and is helpful for future developers), and finally a void ** handle (pointer-to-a-pointer) to the TrackerElement that will hold the data when your class is assembled.

### Field Primitives

TrackerElements can store most types of data as a primitive:

|Tracker Type|C++ Type|Description|
|---------|--------|-----------|
TrackerString | string | Standard std::string
TrackerInt8 | int8_t | 8bit signed 
TrackerUInt8 | uint8_t | 8bit unsigned
TrackerInt16 | int16_t | 16bit signed
TrackerUInt16 | uint16_t | 16bit unsigned
TrackerInt32 | int32_t | 32bit signed
TrackerUInt32 | uint32_t | 32bit unsigned
TrackerInt64 | int64_t | 64bit signed
TrackerUInt64 | uint64_t | 64bit unsigned
TrackerFloat | float | Floating-point value
TrackerDouble | double | Double-precision floating point value
TrackerMac | mac_addr | Kismet MAC address record
TrackerUuid | uuid | Kismet UUID record

TrackerElements can also contain more complex data:
|Tracker Type|C++ Equivalent|Description|
|------------|----------------------------|-----------|
TrackerMap | map/dictionary | Element contains additional sub-fields.  All tracker_component objects are Maps internally.
TrackerVector | vector<TrackerElement *> | Element is a vector of additional elements
TrackerIntMap | map<int, TrackerElement *> | Element is an integer-indexed map of additional elements.  This is useful for representing a keyed list of data.
TrackerMacMap | map<mac_addr, TrackerElement *> | Element is a MAC-indexed map of additional elements.  This is useful for representing a keyed list of data such as device relationships.
TrackerStringMap | map<string, TrackerElement *> | Element is a string-indexed map of additional elements.  This is useful for representing a keyed list of data such as advertised names.
TrackerDoubleMap | map<double, TrackerElement *> | Element is a double-indexed map of additional elements.

### Accessing the data:  Proxy Functions

Now that we have some data structures, we need to define how to access them.

It's certainly possible to define your own get/set methods, but there are some macros to help you.

The `__Proxy(...)` macro allows easy definition of a handful of methods in one line, at the expense of slightly obtuse syntax.

`__Proxy(...)` takes five arguments: The name to be used in the generated functions, the content type of the TrackerElement, the input type to the get/set functions, the return type from the get function, and finally the variable it will use for the get/set operations.

This allows you to define in a single line cast-conversions between compatible types and define standard get/set mechanisms.  For example, for a simple unsigned int element, `flags`, defined as `TrackerUInt32`, you might use:

```C++
public:
    __Proxy(flags, uint32_t, uint32_t, uint32_t, flags);
```

This would expand to define:

```C++
public:
    virtual uint32_t get_flags() const {
        return (uint32_t) GetTrackerValue<uint32_t>(flags);
    }
    virtual void set_flags(uint32_t in) {
        flags->set((uint32_t) in);
    }
```

This looks fairly standard, but allows for more interesting behavior to be defined simply.  For instance, we want to hold a stanard unix timestamp (`time_t`) in the timestamp field, however there is no TrackerElement primitive for timestamps.  However, if we do the following:

```C++
public:
    __Proxy(timestamp, uint64_t, time_t, time_t, timestamp);
```

Now we have a get and set pair of functions which accept time_t and transparently cast it to a uint64_t when saving or reading from the TrackerElement variable.  The same trick can be used to make automatic get and set functions for any data type which can be cast directly to the internal tracked type.

Additionally, individual get and set functions can be proxied via `__ProxyGet(...)` and `__ProxySet(...)` if you wish to only expose the get or set, or if you provide a custom get or set function which is more complex.  Numerical values can also define `__ProxyIncDec(...)` or `__ProxyAddSub(...)` to generate increment/decrement (++ and --) and addition/subtraction functions automatically.  Fields which represent a bitset can use `__ProxyBitset(...)` to define bitwise set and clear functions.

There are some other tricks for accessing data which is represented by complex data types, we'll cover them later.

