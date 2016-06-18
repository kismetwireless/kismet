# Extending Kismet: Creating Tracked Components

Kismet serves complex objects over a REST interface by implementing "tracked components".

Tracked components are introspectable via C++ code and can be dynamically exported to other formats, such as msgpack (which is used heavily in the web interface).

## Deriving from tracker_component
Any data you wish to expose as an object must be derived from tracker_component.

A tracker_component is, internally, a tracked element map, which contains multiple objects, organized as a named dictionary.  This structure typically matches how data presented to the user or to scripts is organized.

Tracker_component objects are derived directly from the base TrackerElement.  A tracker_component may be generated and destroyed for a communication, or used as a permanent storage mechanism.  Kismet typically uses tracker_components to store an object for its entire life cycle when possible.

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

        // Register the flags as an int32_t
        flags_id = RegisterField("kismet.message.flags",
                TrackerInt32, "message flags", (void **) &flags);
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

### Building from other data structures

Often you will want to automatically populate a tracked component from an existing data structure.

Due to how trackercomponents are generated, it is not possible to extend the constructors and import data that way, however creating a function for importing data is trivial, especially once the `__Proxy(...)` functions are defined.

To continue our Messagebus example, let's define a method for adapting a message to our tracker_component:

```C++
public:
    void set_from_message(string in_msg, int in_flags) {
        // We have the globalreg, so inherit the timestamp from there.
        // Since our proxy function accepts a time_t value we can call it
        // directly
        set_timestamp(globalreg->timestamp.tv_sec);

        set_message(in_msg);
        set_flags(in_flags);
    }
```

### Using Complex Fields

Complex field types - vectors and maps - need special handling.  Typically they do not get manipulated with traditional get/set functions.  

#### Using complex fields locally

It is possible to use a complex TrackerElement directly via the complex access APIs, ie `add_vector()`, `add_doublemap()`, etc.  However, it is much simpler to use the wrapper classes which translate the TrackerElements to behave like the STL library versions of their data.

```C++
public:
    void do_something_on_stringmap(string in_key) {
        // Assuming that example_map is a TrackerStringMap, wrap it with
        // a TrackerElementStringMap class
        TrackerElementStringMap smap(example_map);

        if (smap->find(in_key) != smap.end()) {
            // ...
        }

        for (TrackerElementStringMap::const_iterator i = smap.begin();
                i != smap.end(); ++i) {
            // ...
        }
    }
```

Wrapper classes are provided for all of the complex TrackerElement variants:

* `TrackerElementVector`
* `TrackerElementMap`
* `TrackerElementIntMap`
* `TrackerElementStringMap`
* `TrackerElementDoubleMap`
* `TrackerElementMacMap`

#### Accessing from outside the object

It may be necessary to allow access from outside callers.  There are several methods you can utilize:

##### Method one: Provide functions which interface to the complex type

In some instances you may wish to write methods which provide access to the complex type.  For example, assuming that `TrackerElement *example_vec` is a TrackerVector, it may make sense to implement access thusly:

```C++
public:
    void example_vec_push_back(TrackerElement *e) {
        example_vec->add_vector(e);
    }
```

##### Method two: Proxy the TrackedElement directly

By directly returning a pointer to the TrackedElement you can allow consumers to wrap the complex data themselves.  A proxy macro similar to the others is provided:

```C++
public:
    __ProxyTrackable(example_vec, TrackedElement, example_vec);
```

`__ProxyTrackable(...)` takes a name, and the type of pointer to return.  This can be used to automatically cast custom data objects to the proper type on access, here, we use TrackedElement and don't change anything.  Finally, it takes the variable.

A caller could use this via:

```C++
    ...
    TrackedElementVector ev(foo->get_example_vec);
    for (TrackedElementVector::const_iterator i = foo->begin; 
            i != foo->end(); ++i) {
        ...
    }
    ...
```


