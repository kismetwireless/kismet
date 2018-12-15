---
title: "Prelude SIEM"
permalink: /docs/readme/integration_prelude/
excerpt: "Integration with the Prelude SIEM"
---

## SIEM support

Kismet is natively compatible with the Prelude SIEM event management system (https://www.prelude-siem.org) and can send Kismet alerts to Prelude.

To enable communication with a Prelude SIEM sensor, support must be enabled at compile time by adding --enable-prelude to any other options passed to the configure script:
```bash
$ ./configure --enable-prelude
```
