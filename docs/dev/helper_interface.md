# Kismet Helper Tools

Kismet helper tools are external programs which Kismet uses; splitting functionality into an external helper can be for several reasons:

1. Security. By moving operations into external tools, Kismet can avoid requiring root / administrative privileges itself. Almost any capture from a network interface will require root, both to configure the interface and to initiate the packet capture. 
2. Enabling other languages. Kismet is written in C++, but this isn't necessarily the best language for all situations. Kismet uses pure C for capture tools to minimize the runtime library requirements, and other components may best be implemented in a language like Python. 
3. Plugin functionality. Some plugins need to manage long running tools, or the author may wish to avoid C++ for whatever reason. 
4. Process management. Some plugins and capture methods demand their own lifecycle loops.  While it would likely be possible to encapsulate these in a thread, using process separation ensures no crossover problems. 

## External Interface Protocol

Kismet uses a flexible protocol to communicate with external tools. Built around Google Protobuf, each top-level message is bundled in a network frame for delivery, and contains:

1.  The command type; an arbitrary string which defines the type, such as "MESSAGE" or "CONFIGURE". 
2. A unique sequence number, which is used to respond to commands or return errors.
3. The payload of the command, as a string. The payload should typically be a Protobuf serialized message. While, technically, a custom command could encode any data, implementations are strongly encouraged to use the Protobuf framework. 

## KismetExternal Commands

The top-level protocol defines a few key commands and their payloads:

### `MESSAGE` (KismetExternal.MsgbusMessage) Helper -> Kismet

Prints a message via the MessageBus system; these messages are printed to the Kismet console, displayed in the Messages section of the UI, and logged to the Messages section of the Kismet log. 

### `PING` (KismetExternal.Ping) Bidirectional

A ping message acts as a keepalive signal which expects an answering `PONG` packet.

### `PONG` (KismetExternal.Pong) Bidirectional

Answering packet to a `PING`

## KismetExternal HTTP Proxy

The Kismet external protocol has hooks for extending the web server functionality to external tools, regardless of the language they are written in. 

The web server extortion uses three messages:

### `HTTPREGISTERURI` (KismetExternalHttp.HttpRegisterUri) Helper -> Kismet

A helper can create endpoints in the Kismet server by registering the URI.  The URI can be registered as a GET or PUSH, and can specify if there just be an authenticated login. 

Kismet will handle the incoming web request and authentication validation. 

### `HTTPREQUEST` (KismetExternalHttp.HttpRequest) Kismet -> Helper

When an incoming request is received by the web server which matches a registered URI, Kismet will send a request packet to the helper with a unique connection ID and any form post variables. 

### `HTTPRESPONSE` (KismetExternalHttp.HttpResponse) Helper -> Kismet

Multiple response frames may be sent for any request; request responses may include custom HTTP headers, fixed content or streaming data, and external helpers may keep the connection open in a streaming mode to continually send streaming real time data.  

Internally, the web proxy system uses the Kismet chained buffer system; this sends the buffer to the web client as quickly as possible while it is still being populated; if the client is fast enough, the buffer will never grow beyond the basic size, but if the client is not keeping up with the buffer, it will grow automatically. The external tool can pass data as quickly as it can be generated without concern for the web budgeting system. 

Generally, an external tool should limit the data per frame to a reasonable amount (1kb would be a reasonable size); if a packet is larger than the buffer allocated in Kismet it will not be properly received and Kismet may be running on an extremely memory constrained system. Large amounts of data can be sent by sending multiple response frames. 

