#!/usr/bin/perl

$device = shift;

die("No device specified") if ($device eq "");

for ($i = 0; $i < 255; $i++)
{
	undef $bad;
	open (IWCONFIG, "iwconfig 2>&1 $device channel $i|");
	while (<IWCONFIG>)
	{ /Error for wireless request "Set Frequency"/ && ($bad++); }
	next if $bad;
	$list .= "$i,";
}
$list =~ s/,$//;
print "$list\n";

