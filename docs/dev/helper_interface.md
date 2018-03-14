# Kismet Helper Tools

Kismet helper tools are external programs which Kismet uses; splitting functionality into an external helper can be for several reasons:

1. Security. By moving operations into external tools, Kismet can avoid requiring root / administrative privileges itself. Almost any capture from a network interface will require root, both to configure the interface and to initiate the packet capture. 
2. Enabling other languages. Kismet is written in C++, but this isn't necessarily the best language for all situations. Kismet uses pure C for capture tools to minimize the runtime library requirements, and other components may best be implemented in a language like Python. 
3. Plugin functionality. Some plugins need to manage long running tools, or the author may wish to avoid C++ for whatever reason. 
4. Process management. Some plugins and capture methods demand their own lifecycle loops.  While it would likely be possible to encapsulate these in a thread, using process separation ensures no crossover problems. 

## External Interface Protocol

Kismet uses a flexible protocol to communicate with external tools. Built around Google Protobuf, at it's heart every message contains: