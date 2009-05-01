#!/usr/bin/perl -w
#############################################################################
# ldms_netstat_mac.pl, v 1.0                                                #
# (c) 2007 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address.                               #
# Thanks to $Bill Luebkert for the command-line handling.                   #
#############################################################################


#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use strict;
use XML::Writer;
use IO::File;

#############################################################################
# Variables                                                                 #
#############################################################################
our %A;		# get commandline switches into %A
for (my $ii = 0; $ii < @ARGV; ) {
	last if $ARGV[$ii] =~ /^--$/;
	if ($ARGV[$ii] !~ /^-{1,2}(.*)$/) { $ii++; next; }
	my $arg = $1; splice @ARGV, $ii, 1;
	if ($arg =~ /^([\w]+)=(.*)$/) { $A{$1} = $2; } else { $A{$1}++; }
}

my $DEBUG = $A{d} || 0;
(my $prog = $0) =~ s/^.*[\\\/]//;
my $ver = "1.0";
my $dir = '/Library/Application Support/LANDesk/CustomData';
my $command = 'netstat -an -finet';
my $file = $dir."/netstat.xml";
my $usage = <<EOD;

Usage: $prog [-d] [-h] [-i]
	-d		debug
	-h(elp)		this display

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This script will parse and output netstat information for use in Custom Data.
The latest version lives at 
http://www.droppedpackets.org/inventory/ldms_netstat

EOD
#############################################################################
# Main Loop                                                                 #
#############################################################################
die $usage if $A{h} or $A{help};

my $output = new IO::File(">$file") or die "Can't open $file: $!\n";

my $doc = new XML::Writer(OUTPUT => $output);
# print the open tag, including the attribute
$doc->startTag("Netstat", class => "simple");

# Run netstat and process the output
my @netstat = `$command`;
foreach my $i (@netstat) {
	&trim($i);
	if ($i =~ /^$/) { next; }
	if ($i =~ /^Active/i) { next; }
	if ($i =~ /\sProto\s/i) { next; }
	my @line = split(' ',$i);
	if ($line[0] =~ /tcp4/i && $line[5] =~ /LISTEN/i) {
		my $tcpport;
		my @port = split('\.',$line[3]);
		if ($port[0] =~ /\*/) {
			$tcpport = $port[1];
		} else {
			$tcpport = $port[4];
		}
		if ($tcpport =~ /\*/) { next; }
		$doc->startTag("OpenPort");
		$doc->startTag("TCP");
		my $tcplabel="TCP-$tcpport";
		$doc->dataElement($tcplabel => "TCP/$tcpport");
		$doc->endTag("TCP");
		$doc->endTag( "OpenPort");
	}
	if ($line[0] =~ /udp4/i) {
		my $udpport;
		my @port = split('\.',$line[3]);
		if ($port[0] =~ /\*/) {
			$udpport = $port[1];
		} else {
			$udpport = $port[4];
		}
		if ($udpport =~ /\*/) { next; }
		$doc->startTag("OpenPort");
		$doc->startTag("UDP");
		my $udplabel="UDP-$udpport";
		$doc->dataElement($udplabel => "UDP/$udpport");
		$doc->endTag("UDP");
		$doc->endTag( "OpenPort");
	}
}

$doc->endTag("Netstat");
$doc->end();$output->close();
exit;

#############################################################################
# Subroutines                                                               #
#############################################################################

sub trim($) {
	my $string = shift;
	$string =~ s/^\s+|\s+$//;
	$string =~ s/\'|\"//g;
	$string =~ s/\n|\r//g;
	$string =~ s/ //g;
	return $string;
}

