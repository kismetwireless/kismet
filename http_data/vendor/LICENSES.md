# Third-party code

Libraries used by the UI are kept in this directory, never loaded from a CDN.
Each must be GPL2-compatible (MIT, BSD, ISC, MPL-2.0, LGPL; not Apache-2.0)
and free of commercial-use restrictions.  List each one here:

| Library | Version | License | Files | Used for |
|---|---|---|---|---|
| [Leaflet](https://leafletjs.com) | 1.9.4 | BSD-2-Clause (leaflet/LICENSE) | leaflet/leaflet.js, leaflet/leaflet.css | The map tab (js/widgets/map.js), loaded when the tab is first opened |

The rest of the UI is plain JavaScript; its icons (js/core/icons.js) and
graphs (js/widgets/sparkline.js) are its own.
