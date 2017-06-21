(
  typeof define === "function" ? function (m) { define("kismet-ui-gadgets-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_gadgets = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

var gadgets = new Array();



// We're done loading
exports.load_complete = 1;

return exports;

});
