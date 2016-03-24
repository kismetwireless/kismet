/* jshint browser: true */
/* global define, module */
( // Module boilerplate to support browser globals and browserify and AMD.
  typeof define === "function" ? function (m) { define("kismet-ui-channelgraph-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_channelgraph = m(); }
)(function () {
"use strict";

var exports = {};

var channelTid; 

function updateChannelSignalGraph(svg, width, height, dataset, nameset) {
    var w = width;
    var h = height;

    var padding = 20;

    var mod_dataset = []
    for (var x = 0; x < dataset.length; x++)
        mod_dataset[x] = 120 - (dataset[x] * -1);

    var xScale = d3.scale.ordinal()
        .domain(d3.range(dataset.length))
        .rangeRoundBands([0, w], 0.05);

    var yScale = d3.scale.linear()
        //.domain([0, d3.max(mod_dataset) + 10])
        .domain([20, 120])
        .range([padding, h - padding]);

    var cScale = d3.scale.linear()
        .domain([80, 60, 40])
        .range(['green', 'blue', 'red'])

    var bars = svg.selectAll("rect")
        .data(mod_dataset); 

    bars.enter()
        .append("rect")
        .attr("x", w)
        .attr("y", function(d) {
            return h - yScale(d);
        })
        .attr("width", xScale.rangeBand())
        .attr("height", function(d) {
            return yScale(d);
        })
        .attr("fill", function(d) {
            return cScale(d)
        });

    bars.transition()
        .duration(500)
        .attr("x", function(d, i) {
            return xScale(i);
        })
        .attr("y", function(d) {
            return h - yScale(d) - padding;
        })
        .attr("width", xScale.rangeBand())
        .attr("height", function(d) {
            return yScale(d);
        })
        .attr("fill", function(d) {
            return cScale(d)
        });


    var text = svg.selectAll("text")
        .data(mod_dataset);

    text.enter()
        .append("text")
        .text(function(d) {
            return d;
        })
        .attr("text-anchor", "middle")
        .attr("x", function(d, i) {
            return xScale(i) + xScale.rangeBand() / 2;
        })
        .attr("y", function(d) {
            return h - yScale(d) + 14;
        })
        .attr("font-family", "sans-serif")
        .attr("font-size", "11px")
        .attr("fill", "white");

    text.transition()
        .delay(500)
        .text(function(d) {
            return (120 - d) * -1;
        })
        .attr("x", function(d, i) {
            return xScale(i) + xScale.rangeBand() / 2;
        })
        .attr("y", function(d) {
            return h - yScale(d) + 14 - padding;
        });

    var xAxis = d3.svg.axis()
        .scale(xScale)
        .orient("bottom")
        .tickFormat(function(d, i){
            return nameset[d];
        });

    svg.append("g")
        .attr("class", "x axis")
        .attr("transform", "translate(0," + (h - padding) + ")")
        .call(xAxis);
}

function timerChannelSignalGraph(svg, width, height) {
    kismet.GetChannelData(function(channeldata) { // Success
        var dataset = [];
        var nameset = [];


        for (var key in channeldata['kismet.channeltracker.channel_map']) {
            nameset.push(key);
            var chandata = channeldata['kismet.channeltracker.channel_map'][key];
            dataset.push(chandata['kismet.channelrec.signal']['kismet.common.signal.last_signal_dbm']);
        }

        updateChannelSignalGraph(svg, width, height, dataset, nameset);
    }, function(msg) { // failure
        console.log(msg);

    });

    channelTid = setTimeout(timerChannelSignalGraph, 2000, svg, width, height);
}

exports.ChannelSignalGraph = function(container, width, height) {
    //Width and height
    var w = width;
    var h = height;

    var dataset = [];

    var xScale = d3.scale.ordinal()
        .domain(d3.range(dataset.length))
        .rangeRoundBands([0, w], 0.05);

    var yScale = d3.scale.linear()
        .domain([0, d3.max(dataset)])
        .range([0, h]);

    //Create SVG element
    var svg = d3.select(container)
        .append("svg")
        .attr("width", w)
        .attr("height", h);

    // Create bars
    svg.selectAll("rect")
        .data(dataset)
        .enter()
        .append("rect")
        .attr("x", function(d, i) {
            return xScale(i);
        })
    .attr("y", function(d) {
        return h - yScale(d);
    })
    .attr("width", xScale.rangeBand())
    .attr("height", function(d) {
        return yScale(d);
    })
    .attr("fill", function(d) {
        return "rgb(0, 0, " + (d * 10) + ")";
    });



    timerChannelSignalGraph(svg, width, height);
}

return exports;

});
