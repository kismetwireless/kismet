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
 * create: Function creating the settings panel in a provided element
 * save: Function for saving the panel
 * priority: priority in list, lower is higher (optional)
 *
 * Settings panels should notify the sidebar when a setting is changed via
 * kismet_ui_sidbar.SettingsChanged()
 *
 */
exports.AddSettingsPane = function(options) {
    if (! 'listTitle' in options ||
        ! 'create' in options ||
        ! 'save' in options) {
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
exports.SettingsModified = function(mod = true) {
    if (mod) {
        modified = true;

        $('.k-s-button-save', settingspanel.content).button("enable");
        $('.k-s-button-save', settingspanel.content).addClass('k-s-button-hot');

        $('.k-s-button-reset', settingspanel.content).button("enable");
    } else {
        modified = false;

        $('.k-s-button-save', settingspanel.content).button("disable");
        $('.k-s-button-save', settingspanel.content).removeClass('k-s-button-hot');

        $('.k-s-button-reset', settingspanel.content).button("disable");
    }

}

var selected_item = null;

function clickSetting(c) {
    if (c == selected_item)
        return;

    selected_item = c;

    if ('windowTitle' in c)
        settingspanel.headerTitle('Settings - ' + c.windowTitle);
    else
        settingspanel.headerTitle('Settings - ' + c.listTitle);

    exports.SettingsModified(false);

    $('.k-s-list-item', settingspanel.content).removeClass('k-s-list-item-active');
    $('.k-s-list-item#sb_' + c.position, 
        settingspanel.content).addClass('k-s-list-item-active');

    populateSetting(c);
}

function populateSetting(c) {
            
    var content = $('.k-s-pane-content', settingspanel.content);
    content.empty();

    c.create(content);
}

function populateList(list) {
    SettingsPanes.sort(function(a, b) {
        if (a.priority < b.priority)
            return -1;
        if (a.priority > b.priority)
            return 1;

        return 0;
    });

    for (var i in SettingsPanes) {
        var c = SettingsPanes[i];

        c.position = i;

        list.append(
            $('<div>', {
                class: 'k-s-list-item',
                id: 'sb_' + c.position,
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
            .html("<h3>Kismet Settings</h3><p>Kismet UI settings are stored in your browsers local storage and are saved between uses.")
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
                .on('click', function() {
                    if (selected_item != null) {
                        exports.SettingsModified(false);
                        populateSetting(selected_item);
                    }
                })
            )
            .append(
                $('<button>', {
                    class: 'k-s-button-save'
                })
                .text("Save Changes")
                .button()
                .button("disable")
                .on('click', function() {
                    if (selected_item != null) {
                        selected_item.save(content);
                        exports.SettingsModified(false);
                    }
                })
            )
        )
    );

    populateList($('.k-s-list', content));

    selected_item = null;

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
