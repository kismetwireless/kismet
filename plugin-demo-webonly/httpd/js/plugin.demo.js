(
  typeof define === "function" ? function (m) { define("plugin-web-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.plugin_web = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

console.log("Loaded demo plugin");

// We're done loading
exports.load_complete = 1;

return exports;

});
