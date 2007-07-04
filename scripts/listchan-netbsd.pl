#!/usr/bin/perl -w
use strict;
use warnings;

my $device = shift or die "No device specified\n";

my @channels = ();

# Set the device to have no channel and automatically mode itself
# Otherwise, we only get A or B channels, depending on the last mode
# used on the device.

system("ifconfig $device -chan mode auto");

for my $chan (1 .. 255) {
	open (my $conf, "ifconfig 2>&1 $device chan $chan|");
        my $out = do { local $/ ; <$conf>};
	next if $out =~ /SIOCS80211CHANNEL: Invalid argument/;
        push @channels, $chan;
}

print join(q{,}, @channels), "\n";

