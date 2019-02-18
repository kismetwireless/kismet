(
  typeof define === "function" ? function (m) { define("kismet-ui-settings-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_settings = m(); }
)(function () {

"use strict";

var exports = {};

var local_uri_prefix = ""; 
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

// Flag we're still loading
exports.load_complete = 0;

// Load our css
$('<link>')
    .appendTo('head')
    .attr({
        type: 'text/css', 
        rel: 'stylesheet',
        href: local_uri_prefix + 'css/kismet.ui.settings.css'
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
 * Settings panels should notify the when a setting is changed via
 * kismet_ui_settings.SettingsChanged()
 *
 */
exports.AddSettingsPane = function(options) {
    if (! 'listTitle' in options ||
        ! 'create' in options ||
        ! 'save' in options) {
        return;
    }

    if (! 'priority' in options)
        options['priority'] = 0;

    SettingsPanes.push(options);
};

var modified = false;
var settingspanel = null;
var alertpanel = null;

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

function createClickCallback(c) {
    return function() { checkClose(c); };
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
            .on('click', createClickCallback(c))
        );
    }
}

function checkClose(transfer = null) {
    if (!modified) {
        if (transfer != null) {
            clickSetting(transfer);
            return;
        }

        return true;
    }

    if (modified) {
        var content = $('<div>', {
            class: 'k-s-alert'
        })
        .append(
            $('<div>', {
                class: 'k-s-alert-content'
            })
            .append(
                $('<div>', { 
                    class: 'k-s-alert-header'
                })
                .html("Settings changed")
            )
            .append(
                $('<div>')
                .html("Would you like to save the changes?")
            )
        )
        .append(
            $('<div>', {
                class: 'k-s-pane-buttons'
            })
            .append(
                $('<button>', {
                    class: 'k-s-button-reset'
                })
                .text("Don't Save")
                .button()
                .on('click', function() {
                    exports.SettingsModified(false);
                    if (transfer != null) {
                        alertpanel.close();
                        clickSetting(transfer);
                    } else {
                        settingspanel.close();
                    }
                })
            )
            .append(
                $('<button>', {
                    class: 'k-s-button-save'
                })
                .text("Save Changes")
                .button()
                .on('click', function() {
                    if (selected_item != null) {
                        selected_item.save(settingspanel.content);
                        exports.SettingsModified(false);
                    }

                    if (transfer != null) {
                        alertpanel.close();
                        clickSetting(transfer);
                    } else {
                        settingspanel.close();
                    }
                })
            )
        );

        alertpanel = $.jsPanel({
            template: jsPanel.tplContentOnly,
            container: settingspanel,
            paneltype: {
                tooltip: true,
                mode: 'sticky',
                iconfont: 'jsglyph',
            },
            position: {
                my: 'center', 
                at: 'center', 
                of: '.k-s-container', 
            },
            contentSize: {
                width: $('.k-s-container', settingspanel.content).width() * 0.4, 
                height: $('.k-s-container', settingspanel.content).height() * 0.25, 
            },
            theme: 'red filledlight',
            border: '2px solid',
            show: 'animated bounceInLeft',
            content: content,
        });

        return false;
    }
}

exports.ShowSettings = function(starter) {
    var w = $(window).width() * 0.75;
    var h = $(window).height() * 0.75;

    if (w < 450 || h < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
    }

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
            .append(
                $('<h3>')
                .html("Kismet Settings")
            )
            .append(
                $('<p>')
                .html('Kismet UI settings are stored in your browsers local storage, and are unique to each browser.')
            )
            .append(
                $('<p>')
                .html('To perform some actions (configuring data sources, downloading pcap files, and changing other server-side options), you need to be logged in.  Kismet generates a random password, which can be found in the file <code>~/.kismet/kismet_httpd.conf</code>.')
            )
            .append(
                $('<p>')
                .html('If you do not want to log in or are a guest on this server, you can still set local preferences and view device information.')
            )
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
            iconfont: 'jsglyph',
        },
        onbeforeclose: function() {
            return checkClose();
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

    if (starter) {
        for (var i in SettingsPanes) {
            var c = SettingsPanes[i];

            if (c.id == starter) {
                clickSetting(c);
                break;
            }
        }
    }

};

/* Add the settings sidebar */
kismet_ui_sidebar.AddSidebarItem({
    id: 'sidebar-settings',
    listTitle: '<i class="fa fa-gear"></i> Settings',
    priority: -100000,
    clickCallback: function() {
        exports.ShowSettings();
    }
});


// We're done loading
exports.load_complete = 1;

return exports;

});
