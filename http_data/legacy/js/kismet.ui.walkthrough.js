(
  typeof define === "function" ? function (m) { define("kismet-ui-walkthrough-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_walkthrough = m(); }
)(function () {

/* A tabbed set of introductory/walkthrough windows, for instance to implement
 * an onboarding process.
 *
 * Each step should contain:
 * title            Main title of step
 * content          String content or function(element)
 */

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

// Generate a walkthrough
exports.MakeWalkthrough = function() {
    wt = {};
    wt['steps'] = [];
}

// Concatenate a step onto the list of actions
exports.AddWalkthroughStep = function(walkthrough, step) {
    walkthrough['steps'].push(step);
    return walkthrough;
}

// Disable the 'next' button in the walkthrough
exports.DisableNext = function(walkthrough) {
    // ...
}

// Enable the 'next' button in the walkthrough
exports.EnableNext = function(walkthrough) {
    // ...
}

exports.ShowWalkthrough = function(walkthrough) {
    var w = $(window).width() * 0.85;
    var h = $(window).height() * 0.75;
    var offy = 20;

    if ($(window).width() < 450 || $(window).height() < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
        offy = 0;
    }

    walkthrough['content'] =
        $('<div>', {
            class: 'wt-content',
        });

    walkthrough['prevbutton'] =
        $('<button>', {
            class: 'wt-button-previous',
        })
        .text("Previous")
        .button()
        .button("disable")
        .on('click', function() {
            exports.PreviousWalkthrough(walkthrough);
        });

    walkthrough['nextbutton'] =
        $('<button>', {
            class: 'wt-button-next',
        })
        .text("Next")
        .button()
        .button("disable")
        .on('click', function() {
            exports.NextWalkthrough(walkthrough);
        });

    var content = 
        $('<div>', {
            class: 'wt-holder'
        })
        .append(walkthrough['content'])
        .append(
            $('<div>', {
                class: 'wt-buttons',
            })
            .append(walkthrough['prevbutton'])
            .append(walkthrough['nextbutton'])
        );


    walkthrough['panel'] = $.jsPanel({
        headerControls: {
            iconfont: 'jsglyph',
        },
        content: content,
    }).resize({
        width: w,
        height: h
    }).reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: offy,
    });


}

exports.CancelWalkthrough = function(walkthrough) {

}

exports.NextWalkthrough = function(walkthrough) {

}

epxorts.PreviousWalkthrough = function(walkthrough) {

}

return exports;

});
