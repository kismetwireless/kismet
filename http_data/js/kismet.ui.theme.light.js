
/* jshint browser: true */
/* global define, module */
( // Module boilerplate to support browser globals and browserify and AMD.
  typeof define === "function" ? function (m) { define("kismet_theme", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_theme = m(); }
)(function () {
"use strict";

    var exports = {};

    exports.theme = 'light';

    exports.page_background = '#FFF';

    exports.sparkline_main = '#000';

    exports.graphBasicColor = 'rgba(160, 160, 160, 1)';

    document.documentElement.setAttribute('data-theme', 'light');

return exports;
});
