/* jshint browser: true */
/* global define, module */
( // Module boilerplate to support browser globals and browserify and AMD.
  typeof define === "function" ? function (m) { define("kismet_theme", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_theme = m(); }
)(function () {
    "use strict";

    $('head').append('<link rel="stylesheet" type="text/css" href="css/kismet-dark.css">');
    $('head').append('<link rel="stylesheet" type="text/css" href="css/dark.css">');
    $('head').append('<link rel="stylesheet" type="text/css" href="css/datatables-dark.css">');

    var exports = {};

    exports.theme = 'dark';

    exports.page_background = '#222';

    exports.sparkline_main = '#FFF';

    Chart.defaults.backgroundColor = '#333';
    Chart.defaults.borderColor = '#555';
    Chart.defaults.color = '#FFF';

    exports.graphBasicColor = 'rgba(255, 255, 255, 1)';

    document.documentElement.setAttribute('data-theme', 'dark');

    return exports;
});
