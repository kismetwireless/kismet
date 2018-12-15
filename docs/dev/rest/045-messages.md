---
title: "Messages"
permalink: /docs/devel/webui_rest/messages/
toc: true
---

Kismet uses an internal `messagebus` system for communicating text messages from system components to the user.  The messagebus is used to pass error, state, and debug messages, as well as notifications to the user about detected devices, alerts, etc.

## All messages
* URL \\
        /messagebus/all_messages.json

* Method \\
        `GET`

* Result \\
        Array of the last 50 messages in the messagebus

## Recent messages
* URL \\
        /messagebus/last-time/*[TIMESTAMP]*/messages.json

* Method \\
        `GET`

* URL parameters

| Key | Description |
| --- | ----------- |
| *[TIMESTAMP]* | Relative or absolute [timestamp](/docs/devel/webui_rest/commands/#timestamp) |

* Result \\
        Array of messages since *TIMESTAMP*

