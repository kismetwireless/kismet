---
title: "Helper tools"
permalink: /docs/devel/external_helper_tools/
toc: true
---

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

### `MESSAGE` (KismetExternal.MsgbusMessage) *Helper -> Kismet*

Prints a message via the MessageBus system; these messages are printed to the Kismet console, displayed in the Messages section of the UI, and logged to the Messages section of the Kismet log. 

#### Content:

| Field   | Type        | Content                                   |
| ------- | ----------- | ----------------------------------------- |
| msgtype | MessageType | Type of message (Info, Debug, Alert, Etc) |
| msgtext | string      | Message content                           |

#### MessageType

| Type  | Value |
| ----- | ----- |
| DEBUG | 1     |
| INFO  | 2     |
| ERROR | 4     |
| ALERT | 8     |
| FATAL | 16    |

### `PING` (KismetExternal.Ping) *Bidirectional*

A ping message acts as a keepalive signal which expects an answering `PONG` packet. 

#### Content

*None*

### `PONG` (KismetExternal.Pong) *Bidirectional*

Answering packet to a `PING`, which must include the sequence number of the `PING` command.  `PONG` responses should be sent immediately.

#### Content

| Field      | Type   | Content                                    |
| ---------- | ------ | ------------------------------------------ |
| ping_seqno | uint32 | Seqno of `PING` request this is a reply to |

### `SHUTDOWN` (KismetExternal.Shutdown) *Bidirectional*

Either side of the connection can request the connection be shut down; upon receiving a `SHUTDOWN` message the external helper will be terminated.

#### Content

*None*

### `SYSTEMREGISTER` (KismetExternal.SystemRegister) *Helper -> Kismet*

When using network sockets to connect external helpers, the Kismet listening socket may be multiplexed across many different handlers.  The external helper can identify itself with the `SYSTEMREGISTER` message so that it may be dispatched to the proper handler.

#### Content

| Field     | Type   | Content        |
| --------- | ------ | -------------- |
| subsystem | string | Subsystem name |

## KismetExternal HTTP Proxy

The Kismet external protocol has hooks for extending the web server functionality to external tools, regardless of the language they are written in. 

### `HTTPREQUESTAUTH` (KismetExternalHttp.HttpAuthTokenRequest) *Helper -> Kismet*

External tools may request a HTTP authorization token; instead of transmitting the Kismet admin username and password, a web session cookie is generated and returned in a `HTTPAUTH` response.

#### Content

*None*

### `HTTPAUTH` (KismetExternalHttp.HttpAuthToken) *Kismet -> Helper*

Once Kismet has generated a HTTP authentication token it is sent to the helper in a `HTTPAUTH` response.  The session hash is suitable for use as the `KISMET` cookie in HTTP communication.

#### Content

| Field | Type   | Content         |
| ----- | ------ | --------------- |
| token | string | HTTP auth token |

### `HTTPREGISTERURI` (KismetExternalHttp.HttpRegisterUri) *Helper -> Kismet*

A helper can create endpoints in the Kismet server by registering the URI.  The URI can be registered as a GET or PUSH, and can specify if there just be an authenticated login. 

Kismet will handle the incoming web request and authentication validation. 

#### Content

| Field         | Type    | Content                                            |
| ------------- | ------- | -------------------------------------------------- |
| uri           | string  | Full path and file extension URI to register       |
| method        | string  | HTTP method (currently GET and POST are supported) |
| auth_required | boolean | Indicates if a valid HTTP session is required      |

### `HTTPREQUESTCANCEL` (KismetExternalHttp.HttpRequestCancel) *Kismet->Helper*

If a HTTP request is closed by the client before the external helper has sent a `HTTPRESPONSE` message with `close_connection`, Kismet will send a `HTTPREQUESTCANCEL` to the helper.  The helper should stop processing this request.

#### Content

| Field  | Type   | Message                    |
| ------ | ------ | -------------------------- |
| req_id | uint32 | Session ID to be cancelled |

### `HTTPREQUEST` (KismetExternalHttp.HttpRequest) *Kismet -> Helper*

When an incoming request is received by the web server which matches a registered URI, Kismet will send a request packet to the helper with a unique connection ID and any form post variables. 

If the URI requires a login, Kismet will only send the `HTTPREQUEST` to the helper tool if there is a valid login session.

#### Content

| Field     | Type            | Content                                                      |
| --------- | --------------- | ------------------------------------------------------------ |
| req_id    | uint32          | Unique request ID, `HTTPRESPONSE` commands must reference this ID |
| uri       | string          | Full path and file extension of the URI                      |
| method    | string          | HTTP method                                                  |
| post_data | SubHttpPostData | *Optional* Array of HTTP Post variables                      |

#### `SubHttpPostData` (KismetExternalHttp.SubHttpPostData)

HTTP POST variables are transmitted as an array of HttpPostData.

| Field   | Type   | Content               |
| ------- | ------ | --------------------- |
| field   | string | POST variable field   |
| content | string | POST variable content |

### `HTTPRESPONSE` (KismetExternalHttp.HttpResponse) *Helper -> Kismet*

Multiple response frames may be sent for any request; request responses may include custom HTTP headers, fixed content or streaming data, and external helpers may keep the connection open in a streaming mode to continually send streaming real time data.  

Internally, the web proxy system uses the Kismet chained buffer system; this sends the buffer to the web client as quickly as possible while it is still being populated; if the client is fast enough, the buffer will never grow beyond the basic size, but if the client is not keeping up with the buffer, it will grow automatically. The external tool can pass data as quickly as it can be generated without concern for the web budgeting system. 

Generally, an external tool should limit the data per frame to a reasonable amount (1kb would be a reasonable size); if a packet is larger than the buffer allocated in Kismet it will not be properly received and Kismet may be running on an extremely memory constrained system. Large amounts of data can be sent by sending multiple response frames. 

The helper may include additional data in the `HTTPRESPONSE` such as custom HTTP headers, and the helper may change the HTTP result code.  Headers may only be sent *before* or *with* the first `HTTPRESPONSE` message.

#### Content

| Field          | Type          | Content                                                      |
| -------------- | ------------- | ------------------------------------------------------------ |
| req_id         | uint32        | Unique session ID (from `HTTPREQUEST`)                       |
| header_content | SubHttpHeader | *Optional* Array of custom headers to send.  May *only* be sent with the *first* `HTTPRESPONSE` message. |
| content        | bytes         | *Optional* HTTP content.  Messages should be limited to `1024` bytes of content; larger responses may be split over multiple `HTTPRESPONSE` messages. |
| resultcode     | uint32        | *Optional* HTTP numeric result code.  Connections closed with no `HTTPRESPONSE` messages including a resultcode are closed with `200 OK` |
| close_response | boolean       | *Optional* This is the last `HTTPRESPONSE` message for this connection, close the HTTP request.  If a `resultcode` has been provided, the final result of the request will be set accordingly. |

#### `SubHttpHeader` (KismetExternalHttp.SubHttpHeader)

HTTP header values to be transmitted at the beginning of the connection.

| Field   | Type   | Content        |
| ------- | ------ | -------------- |
| header  | string | HTTP header    |
| content | string | Header content |

