
/* jshint browser: true */
/* global define, module */
( // Module boilerplate to support browser globals and browserify and AMD.
  typeof define === "function" ? function (m) { define("kismet_theme", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_theme = m(); }
)(function () {
    "use strict";

    $('head').append('<link rel="stylesheet" type="text/css" href="css/jquery-ui.min.css">');
    $('head').append('<link rel="stylesheet" type="text/css" href="css/jquery.dataTables.min.css">');
    $('head').append('<link rel="stylesheet" type="text/css" href="css/kismet.css">');

    var exports = {};

    exports.theme = 'light';

    exports.page_background = '#FFF';
    exports.sparkline_multi_a = '#C70039';
    exports.sparkline_multi_b = '#002EFF';

    exports.sparkline_main = '#000';

    exports.graphBasicColor = 'rgba(160, 160, 160, 1)';

    // document.documentElement.setAttribute('data-theme', 'light');

    return exports;
});
