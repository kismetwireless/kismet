(
  typeof define === "function" ? function (m) { define("kismet-ui-settings-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_settings = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

// Load our css
$('<link>')
    .appendTo('head')
    .attr({
        type: 'text/css', 
        rel: 'stylesheet',
        href: '/css/kismet.ui.settings.css'
    });

/*
 * Settings are stored as an array of objects which define a title and a 
 * callback executed when the title is selected, or when the save/reset
 * buttons are called.
 *
 * The settings panel is a modular alert window which implements a two-pane
 * settings window with multiple settings categories on the left and the
 * settings pane itself in the center.
 *
 */

var SettingsPanes = new Array();

/* Add a settings pane
 *
 * Options is a dictionary which must include:
 *
 * listTitle: Title shown in list
 * windowTitle: Title appended to window (optional, if omitted, will use listTitle)
 * cbmodule: string name of callback module (ie "kismet_dot11")
 * paneCallback: Function creating the settings panel in a provided element
 * paneModifiedCallback: Function for telling the settings UI the panel has been modified
 * paneSaveCallback: Function for saving the panel
 */
exports.AddSettingPane = function(id, options) {
    if (! 'listTitle' in options ||
        ! 'cbmodule' in options ||
        ! 'paneCallback' in options ||
        ! 'paneModifiedCallback' in options ||
        ! 'paneSaveCallback' in options) {
        return;
    }

    SettingsPanes.push(options);
};

exports.ShowSettings = function() {
    var w = $(window).width() * 0.75;
    var h = $(window).height() * 0.75;

    var settingspanel = $.jsPanel({
        id: 'settings',
        headerTitle: 'Settings',
        paneltype: 'modal',
        headerControls: {
            controls: 'none',
        },
    }).resize({
        width: w,
        height: h
    }).reposition({
        my: 'center',
        at: 'center',
        of: 'window',
    });

};

// We're done loading
exports.load_complete = 1;

return exports;

});
