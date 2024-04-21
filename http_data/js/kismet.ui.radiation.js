
"use strict";

var local_uri_prefix = ""; 
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

$('<link>')
    .attr({
        type: 'text/css', 
        rel: 'stylesheet',
        href: local_uri_prefix + 'css/kismet.ui.radiation.css'
    })
    .appendTo('head');

kismet_ui_iconbar.AddIconbarItem({
    id: 'radiation',
    priority: 1,
    createCallback: (div) => {
        div.append('<div id="radiation-toolbar-sideby" class="rad-side"></div>')

        $('#radiation-toolbar-sideby', div).append('<div id="radiation-toolbar-cps-stack" class="rad-dual-stack"><div id="radiation-toolbar-cps" class="radiation-toolbar-cps">n/a</div><div>CPS</div></div>');

        $('#radiation-toolbar-sideby', div).append('<div id="radiation-toolbar-usv-stack" class="rad-dual-stack"><div id="radiation-toolbar-usv" class="radiation-toolbar-usv">n/a</div><div>uSv</div></div>');

        let show_cps = kismet.getStorage('kismet.ui.radiation.showcps', false);
        let show_usv = kismet.getStorage('kismet.ui.radiation.showusv', false);

        if (!show_cps) {
            $('#radiation-toolbar-cps-stack', div).hide();
        }

        if (!show_usv) {
            $('#radiation-toolbar-usv-stack', div).hide();
        }

        kismet_ui_base.SubscribeEventbus("RADIATION", [], (data) => {
            let show_cps = kismet.getStorage('kismet.ui.radiation.showcps', false);
            let show_usv = kismet.getStorage('kismet.ui.radiation.showusv', false);

            if (!show_cps) {
                $('#radiation-toolbar-cps-stack', div).hide();
            } else {
                $('#radiation-toolbar-cps-stack', div).show();
            }

            if (!show_usv) {
                $('#radiation-toolbar-usv-stack', div).hide();
            } else {
                $('#radiation-toolbar-usv-stack', div).show();
            }

            let max_cps = 0;
            let max_usv = 0;

            for (const di in data) {
                const d = data[di];

                let cps = d['radiation.sensor.cps_rrd']['kismet.common.rrd.last_value'];
                let usv = d['radiation.sensor.usv_rrd']['kismet.common.rrd.last_value'];

                console.log(cps, usv);

                if (max_cps < cps) {
                    max_cps = cps;
                }

                if (max_usv < usv) {
                    max_usv = usv;
                }
            }

            $('#radiation-toolbar-cps').html(max_cps.toFixed(2));
            $('#radiation-toolbar-usv').html(max_usv.toFixed(2));
        })
    }
})

kismet_ui_sidebar.AddSidebarItem({
    id: 'radiation_sidebar',
    listTitle: '<i class="fa fa-circle-radiation"></i> Radiation',
    clickCallback: function() {
        radiationWindow();
    },
});

kismet_ui_settings.AddSettingsPane({
    id: 'radiation',
    listTitle: 'Radiation Sensors',
    create: (elem) => {
        elem.append('<form><fieldset id="fs_rad"><legend>Radiation Sensors</legend><div id="radconfig"></div></fieldset></form>');

        let config = $('#radconfig', elem);

        config.append('<p><b>CAUTION</b>: Radiation exposure counts and dosages are dependent on the radiation detector used.  Most radiation detectors have maximum speeds at which detection can reliably occur.  Each radiation detectors <i>must be properly calibrated</i> and properly oriented for detection.</p>');
        config.append('<p><i>BE SAFE.</i>  <b>NEVER</b> trust the Kismet display of radiation data for personal safety!</p>');

        config.append('<div><input type="checkbox" id="r_showcps"><span>Show counts per second</span></div>');
        config.append('<div><input type="checkbox" id="r_showusv"><span>Show uSv per second</span></div>');

        let show_cps = kismet.getStorage('kismet.ui.radiation.showcps', false);
        let show_usv = kismet.getStorage('kismet.ui.radiation.showusv', false);

        if (show_cps) {
            $('#r_showcps', elem).prop('checked', true);
        }

        if (show_usv) {
            $('#r_showusv', elem).prop('checked', true);
        }

        $('form', elem).on('change', () => {
            kismet_ui_settings.SettingsModified();
        });

    },
    save: (elem) => {
        kismet.putStorage('kismet.ui.radiation.showcps', $('#r_showcps', elem).is(':checked'));
        kismet.putStorage('kismet.ui.radiation.showusv', $('#r_showusv', elem).is(':checked'));
        
    }
})

var rad_update_tid;
var rad_panel = null;
var rad_hps_chart = null;
var rad_usv_chart = null;
var rad_spectrum_chart = null;
var rad_content = 
    $('<div class="k-rad-contentdiv">')
    .append($('<canvas>', {
        id: 'k-rad-spectrum-canvas',
        class: 'k-rad-spectrum-canvas',
    }));


function radiationWindow() {
    let w = $(window).width() * 0.75;
    let h = $(window).height() * 0.5;
    let offty = 20;

    if ($(window).width() < 450 || $(window).height() < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
        offty = 0;
    }

    rad_panel = $.jsPanel({
        id: 'radiation',
        headerTitle: '<i class="fa fa-circle-radiation"></i> Radiation',
        headerControls: {
            controls: 'closeonly',
            iconfont: 'jsglyph',
        },
        content: rad_content,
        onclosed: () => {
            clearTimeout(rad_update_tid);
            rad_spectrum_chart = null;
        },
    }).resize({
        width: w,
        height: h
    }).reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: offty
    })
    .front();

    updateRadiationData();
}

function updateRadiationData() {
    clearTimeout(rad_update_tid);

    $.get(local_uri_prefix + "radiation/sensors/all_sensors.json")
    .done(function(data) {
        data = kismet.sanitizeObject(data);

        for (const sk in data) {
            var datasets = [
                {
                    label: sk,
                    data: data[sk]['radiation.sensor.aggregate_spectrum'],
                }
            ];

            if (rad_spectrum_chart == null) {
                var canvas = $('#k-rad-spectrum-canvas');

                // We need to fill the labels even though we don't use them
                var labels = Array.apply(null, Array(500)).map(function (x, i) { return i; })

                rad_spectrum_chart = new Chart(canvas, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: datasets,
                    },
                    options: {
                        animation: false,
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                title: {
                                    text: 'Count',
                                    display: true,
                                },
                                ticks: {
                                    display: false,   
                                },
                            },
                            x: {
                                title: {
                                    text: 'Energy',
                                    display: true,
                                },
                                ticks: {
                                    display: false,   
                                },
                            }
                        },
                    },
                });
            } else {
                rad_spectrum_chart.data.datasets[0].data = data[sk]['radiation.sensor.aggregate_spectrum'];
                rad_spectrum_chart.update('none');
            }
        }
    })
    .always(() => {
        rad_update_tid = setTimeout(() => {
            updateRadiationData();
        }, 1000)
    });
}
