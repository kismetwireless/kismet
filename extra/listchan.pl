#!/usr/bin/perl

my @devices = `cat /proc/net/wireless`;
my $nodevs = "0";

foreach my $dev (@devices)
{
	if ($dev !~ /(^Inter-)|(^ face)/)
	{
		$nodevs++;	
		$dev =~ s/^(.+)://;
		$dev = $1;
		$dev =~ s/^ //;
		checkchans ($dev);
	}
}


sub checkchans
{
	my $device = $_[0];
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
	print "Channels supported by $device: $list\n";
}



