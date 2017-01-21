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
 * create: Function creating the settings panel in a provided element
 * save: Function for saving the panel
 * reset: User has cancelled editing & values should be set to 
 * original
 * priority: priority in list, lower is higher (optional)
 *
 * Settings panels should notify the sidebar when a setting is changed via
 * kismet_ui_sidbar.SettingsChanged()
 *
 */
exports.AddSettingsPane = function(options) {
    if (! 'listTitle' in options ||
        ! 'cbmodule' in options ||
        ! 'create' in options ||
        ! 'save' in options ||
        ! 'reset' in options) {
        return;
    }

    if (! 'priority' in options)
        options['priority'] = 100;

    SettingsPanes.push(options);
};

var modified = false;
var settingspanel = null;

/* Indicate to the settings UI that an option has been modified so that the
 * save and reset buttons can be activated */
exports.SettingsModified = function() {
    modified = true;

    $('.k-s-button-save', settingspanel.content).button("enable");
    $('.k-s-button-save', settingspanel.content).addclass('k-s-button-hot');
}

var selected_item = null;

function clickSetting(c) {
    var content = $('.k-s-pane-content', settingspanel.content);
    content.empty();

    if ('windowTitle' in c)
        settingspanel.headerTitle('Settings - ' + c.windowTitle);
    else
        settingspanel.headerTitle('Settings - ' + c.listTitle);
            
    window[c.cbmodule][c.create](content);
}

function populateList(list) {
    for (var i in SettingsPanes) {
        var c = SettingsPanes[i];
        list.append(
            $('<div>', {
                class: 'k-s-list-item'
            })
            .html(c.listTitle)
            .on('click', function() { 
                clickSetting(c); 
            })
        );
    }
}

exports.ShowSettings = function() {
    var w = $(window).width() * 0.75;
    var h = $(window).height() * 0.75;

    var content = $('<div>', {
        class: 'k-s-container'
    })
    .append(
        $('<div>', {
            class: 'k-s-list'
        })
    )
    .append(
        $('<div>', {
            class: 'k-s-pane-holder'
        })
        .append(
            $('<div>', {
                class: 'k-s-pane-content'
            })
            .text("Settings content")
        )
        .append(
            $('<div>', {
                class: 'k-s-pane-buttons'
            })
            .append(
                $('<button>', {
                    class: 'k-s-button-reset'
                })
                .text("Reset")
                .button()
                .button("disable")
            )
            .append(
                $('<button>', {
                    class: 'k-s-button-save'
                })
                .text("Save Changes")
                .button()
                .button("disable")
            )
        )
    );

    populateList($('.k-s-list', content));

    settingspanel = $.jsPanel({
        id: 'settings',
        headerTitle: '<i class="fa fa-gear" /> Settings',
        paneltype: 'modal',
        headerControls: {
            controls: 'closeonly',
        },
        onbeforeclose: function() {
            return true;
        },
        content: content,
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
