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

`RegisterField(...)` is part of the base tracker_component class, and handles the connection between a tracked data set and the tracking system which assigns fields.

It requires a name (which should be unique, you can ensure uniqueness by including a reference to your module in the name), a type (used to manage introspection and export, the list is below), a description (which is shown on the tracked_fields page and is helpful for future developers), and finally a void ** handle (pointer-to-a-pointer) to the TrackerElement that will hold the data when your class is assembled.

### Field Primitives

TrackerElements can store most types of data as a primitive:

|Tracker Type|C++ Type|Description|
|---------|--------|-----------|
TrackerString | string | Basic std::string
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
|---------|--------|-----------|
TrackerMap | map/dictionary | Element contains additional sub-fields.  All tracker_component objects are Maps internally.
TrackerVector | vector<TrackerElement *> | Element is a vector of additional elements
TrackerIntMap | map<int, TrackerElement *> | Element is an integer-indexed map of additional elements.  This is useful for representing a keyed list of data.
TrackerMacMap | map<mac_addr, TrackerElement *> | Element is a MAC-indexed map of additional elements.  This is useful for representing a keyed list of data such as device relationships.
TrackerStringMap | map<string, TrackerElement *> | Element is a string-indexed map of additional elements.  This is useful for representing a keyed list of data such as advertised names.
TrackerDoubleMap | map<double, TrackerElement *> | Element is a double-indexed map of additional elements.

### Accessing the data:  Proxy Functions

Now that we have some data structures, we need to define how to access them.

It's certainly possible to define your own get/set methods, but there are some macros to help you.

The `__Proxy(...)` macro allows easy definition of a handful of methods in one line, at the expense of slightly obtuse syntax:

`__Proxy(name, tracker type, input type, return type, variable)`

This expands to define get and set functions (get_*name* and set_*name*) which accept *input type* variables and return *return type*, while automatically casting it to the type required by the TrackerElement, indicated by *tracker type*.

What this really allows you to define in a single line cast-conversions between compatible types and define standard get/set mechanisms.  For example, for a simple unsigned int element, `flags`, defined as `TrackerUInt32`, you might use:

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

This looks fairly standard, but allows for more interesting behavior to be defined simply.  For instance, we want to hold a standard unix timestamp (`time_t`) in the timestamp field, however there is no TrackerElement primitive for timestamps.  However, if we do the following:

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
        // Since we used __Proxy to define get and set functions, we'll
        // call them instead of doing custom get/set and risking doing
        // it wrong.
        
        set_timestamp(globalreg->timestamp.tv_sec);
        set_message(in_msg);
        set_flags(in_flags);
    }
```

### Using Vector and Map elements

More complex field types - vectors and maps - need special handling.  Typically they do not get manipulated with traditional get/set functions.  

#### Using vectors and maps locally

It is possible to use a TrackerElement directly via the complex access APIs, ie `add_vector()`, `add_doublemap()`, etc.  However, it is much simpler to use the wrapper classes which translate the TrackerElements to behave like the STL library versions of their data.

```C++
public:
    void do_something_on_stringmap(string in_key) {
        // Assuming that example_map is a TrackerStringMap, wrap it with
        // a TrackerElementStringMap class
        TrackerElementStringMap smap(example_map);

        if (smap->find(in_key) != smap.end()) {
            // ...
        }

        for (TrackerElementStringMap::iterator i = smap.begin();
                i != smap.end(); ++i) {
            // ...
        }
    }
```

Wrapper classes are provided for all of the TrackerElement variants:

* `TrackerElementVector`
* `TrackerElementMap`
* `TrackerElementIntMap`
* `TrackerElementStringMap`
* `TrackerElementDoubleMap`
* `TrackerElementMacMap`

#### Accessing from outside the object

It may be necessary to allow access from outside callers.  This is only required for other code directly accessing your object; for exporting your data via the REST interface and other serialization methods, so long as your data is in `TrackerElement` objects it will be handled automatically.

If you do need to provide access to your data objects, there are several methods you can utilize:

##### Method one: Provide functions which interface to the complex type

In some instances you may wish to write methods which provide access to the complex type.  For example, assuming that `TrackerElement *example_vec` is a TrackerVector, it may make sense to implement access thusly:

```C++
public:
    void example_vec_push_back(TrackerElement *e) {
        example_vec->add_vector(e);
    }
```

Essentially the same is hiding the internal data structure via your object API:  `add_foo(...)` may internally add to the vector, without ever explicitly exposing the actual data types.

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
    for (TrackedElementVector::iterator i = foo->begin; 
            i != foo->end(); ++i) {
        ...
    }
    ...
```

##### Method three: Provide wrapper objects and expose them

It may make sense to expose the wrapper objects (`TrackerElementVector` and friends):

```C+++
public:
    TrackerElementVec *get_foo_vec() {
        return foovec_wrapper;
    }

protected:
    TrackerElement *foovec;
    TrackerElementVec *foovec_wrapper;
```

Then there is the question of how to assign the wrapper during the creation.  To do this, we need to override the `reserve_fields(...)` function.  This function is responsible for allocating fields defined in `register_fields()`, and in complex classes, is used to map complex sub-types.

We can ignore the more complex issues, for now, and just use it to build our wrapper.

```C++
private:
    virtual void reserve_fields(TrackerElement *e) {
        tracker_component::reserve_fields(e);

        foovec_wrapper = new TrackerElementVec(foovec);
    }
```

Of course, now we'll also need to update our destructor to prevent leaking the wrapper memory:

```C++
public:
    virtual ~TrackedFoo() {
        delete(foovec_wrapper);
    }
```

## Including complex sub-components

Being able to nest complex objects inside a `tracker_component` is one of the major advantages it offers, and code and data-type re-use is encouraged whenever possible.

Lets say we want to add a location to our data type.  A location block is already defined in `devicetracker_component.h`.

### First, add the location elements

Just like any other `TrackerElement` / `tracker_component` derived item, we need the ID and the element to track it.  In this case, we'll use the actual C++ class, remembering to include `devicetracker_component.h`: 

```C++
private:
    int location_id;
    kis_tracked_location *location;
```

### Registering complex elements

To register an element derived from a complex class like `kis_tracked_location`, we need to provide an instance of the C++ class.  Later, the entry tracker code will use this class to call `clone_type()` and generate a new instance for us.  

To do this, our `register_fields()` function looks like this now:

```C++
private:
    virtual void register_fields() {
        ... Existing field registration

        // We instantiate a builder, passing in globalreg, and an id of 0.  The
        // entry tracker will fill in the correct ID later.
        kis_tracked_location *loc_builder = new kis_tracked_location(globalreg, 0);

        // Register the field as complex type, providing our builder.  We still
        // give it a name based on our class, and a description
        location_id =
            RegisterComplexField("foo.location", loc_builder, "location");

        // RegisterComplex clones the builder internally, so we no longer need it
        // and should delete it
        delete(loc_builder);
    }
```

### Allocating the complex element

Also, special care needs to be taken for actually allocating the complex element.  As we learned above, allocating fields is done in the `reserve_fields(...)` function.

The `reserve_fields(...)` method is used to both allocate new instances of fields, or to attach fields to an existing TrackerElement (for instance, once received from a generic deserialization of incoming data).  

For our complex element, we simply need to instantiate it using the incoming data:

```C++
private:
    virtual void reserve_fields(TrackerElement *e) {
        // We MUST call the parent instance
        tracker_component::reserve_fields(e);

        // The parent takes care of anything that uses TrackerElement, we only
        // have to worry about the custom fields

        if (e != NULL) {
            // If we're absorbing an existing generic structure, all we
            // need to do is instantiate a new object of the right ID.
            // It's already part of the map for the base object.
          
            // So we pass globalreg, the id we got from registering,
            // and then we search in our object for the sub-tree of data
            // matching our ID, which was built for us during deserializaton
            location = new kis_tracked_location(globalreg, location_id,
                    e->get_map_value(location_id));
        } else {
            // Otherwise, we're making a whole new object.  This is usually the
            // case.

            // So make a new location object
            location = new kis_tracked_location(globalreg, location_id);

            // And then attach it to our map so that it's tracked correctly
            add_map(location);
        }
    }
```

### Providing access

Providing access to the child custom type is much the same as providing access to complex `TrackerElement` types, either by providing custom APIs or providing direct access via `__ProxyTrackable(...)`.

## Serialization

Serialization is handled by the `tracker_component` and `TrackerElement` system automatically.  Since the types of the fields are introspectable, serialization systems should be able to export nested data automatically.  

The only aspect of serialization that a custom `tracker_component` class needs to consider is what happens prior to serialization.  This is handled by the `pre_serialize()` method, and is called by any serialization/export class.

This method allows the class to do any updating, averaging, etc before its contents are delivered to a REST endpoing, XML serialization, or other export.

For example, the RRD object uses this method to ensure that the data is synced to the current time:

```C++
public:
    virtual void pre_serialize() {
        // Always call the parent in case work needs to be done
        tracker_component::pre_serialize();

        // Call an internal funtion for adding a sample; we add '0' to our
        // current sample and set the time, this fast-forwards the RRD to
        // 'now' and computes history for us in case we didn't see an update
        // in a long time
        add_sample(0, globalreg->timestamp.tv_sec);
    }
```

### Using `tracker_component` objects elsewhere

Sometimes you will want to use a `tracker_component` in a class that is not, itself, a component: creating data for serialization is a good example.

`tracker_component` objects can be created and used as normal, with one important exception: Any object created manually must be referenced with `link()` before use and should be destroyed with `unlink()`, not `delete()`:

```C++

int foo::bar() {
    some_component *c = new some_component(globalreg, some_component_id);

    c->link();

    // Do stuff

    c->unlink();
}
```

Objects which remain active for the parents lifecycle should be linked at the time of creation, and unlinked in the parents destructor.

This precaution is required because `tracker_component` objects manage memory and multiple associations by using a reference counting system.  When the reference count hits zero, the object is destroyed.  When using functions which manipulate `tracker_component` objects, they are linked and unlinked during use.  If the owning object does not link the object, the reference is falsely set to zero (because it is unused in any known context) and destroyed prematurely.

