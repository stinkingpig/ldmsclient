#############################################################################
# ldms_client_mac.pl                                                        #
# (c) 2008 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.droppedpackets.org/scripts/ldms_client                         #
#############################################################################
#
# TODO -- last start up time

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use strict;
use warnings;
use Config::Tiny;
use XML::Writer;
use IO::File;
use File::Find;
use File::Basename;

#############################################################################
# Variables                                                                 #
#############################################################################
our %A;    # get commandline switches into %A
for ( my $ii = 0 ; $ii < @ARGV ; ) {
    last if $ARGV[$ii] =~ /^--$/;
    if ( $ARGV[$ii] !~ /^-{1,2}(.*)$/ ) { $ii++; next; }
    my $arg = $1;
    splice @ARGV, $ii, 1;
    if ( $arg =~ /^([\w]+)=(.*)$/ ) { $A{$1} = $2; }
    else                            { $A{$1}++; }
}

( my $prog = $0 ) =~ s/^.*[\\\/]//;
my $ver = "1.4";
my $DEBUG = $A{d} || 0;

my $dir         = "/Library/Application\ Support/LANDesk";
my $file        = $dir . "/CustomData/ldms_client.xml";
my $sdclient    = $dir . "/bin/sdclient";

my $ldms_config_file = "/Library/Preferences/com.landesk.ldms";
my $netstatcommand = 'netstat -an -finet';

# Prepare logging system
my $logfile = "/Library/Application\ Support/LANDesk/ldms_client.log";
open(LOGFILE, ">>$logfile") or die "Cannot open $logfile: $!\n";
&Log("$prog $ver starting");

if ($DEBUG) { Log("Output file is $file"); }

my ($output, $doc);

my $usage = <<EOD;

Usage: $prog [-d] [-h]
	-d			debug
	-h(elp)		this display

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This program will extend the LANDesk Inventory using custom data.
The latest version lives at 
http://www.droppedpackets.org/inventory-and-slm/ldms_client/

EOD

#############################################################################
# Main Loop                                                                 #
#############################################################################

die $usage if $A{h} or $A{help};

# Set the process priority so we don't murderize the CPU.

# Read my configuration file from the core.
# Who's the Core Server? 
my $core = `defaults read $ldms_config_file ServerIPAddress` || &LogDie("Can't read ServerIPAddress from $ldms_config_file: $!");
chomp($core);
if ($DEBUG) { &Log("Core Server is at $core"); }

my $configfileresult = `"$sdclient" -noinstall -package "http://$core/ldlogon/ldms_client.ini"`;
if ($DEBUG) { &Log("Fetched config file, result code is $configfileresult"); }

my $configfile = $dir . "/sdcache/ldms_client.ini";

# If I didn't get a config file, I should bail
if (! -e "$configfile") {
	&LogDie("Unable to download config file from $core!");
}

my $Config = Config::Tiny->new();
$Config = Config::Tiny->read($configfile)
  || &LogDie( "Can't read $configfile: ",
    Config::Tiny->errstr() );

my $coreversion = $Config->{version}->{Version};
if ( $coreversion ne $ver ) {
    &LogWarn(
"ldms_client version is different on the core, this could potentially lead to inventory problems."
    );
}

# Reading properties
my $Macintosh       = $Config->{Macintosh};
my $Netstat         = $Config->{Macintosh}->{MacNetstat};
my $Optical         = $Config->{Macintosh}->{MacOptical};

if ($Macintosh) {
    # Setup my file
    $output = new IO::File(">$file") or &LogDie( "Can't open $file: $!");
    $doc = new XML::Writer(OUTPUT => $output, DATA_MODE=>1);
    $doc->xmlDecl("UTF-8");
    $doc->startTag("ldms_client");

    # Get my info -- need to test if configuration file asked for each of these
    if ($Netstat) {
        &CallNetstat;
    }
    if ($Optical) {
        &CallOptical;
    }

    # Clean up... shut down any objects and close my file
    if ($DEBUG) { Log("Closing data file"); }
    $doc->endTag("ldms_client");
    $doc->end();
    $output->close();
}

# Otherwise, there was nothing to do
unlink $configfile;
Log("$prog $ver exiting.\n");
close LOGFILE;
exit 0;

#############################################################################
# Subroutines                                                               #
#############################################################################

###  CallNetstat sub ##########################################################
sub CallNetstat {
    if ($DEBUG) { Log("CallNetstat: Looking for open network ports"); }
    my @netstat = `$netstatcommand`;
    # print the open tag, including the attribute
    $doc->startTag("Netstat");
    foreach my $i (@netstat) {
        &trim($i);
        if ( $i =~ /^$/ )         { next; }
        if ( $i =~ /^Active/i )   { next; }
        if ( $i =~ /\sProto\s/i ) { next; }
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
                $doc->endTag("OpenPort");
        }
    }
    $doc->endTag("Netstat");
    return 0;
}
### End of CallNetstat sub ####################################################

# Read optical drive information ##############################################
sub CallOptical {
    if ($DEBUG) { Log("CallOptical: Looking for optical drives"); }
	open (PROFILE, "system_profiler SPParallelATADataType |") || &LogDie("Can't open system profiler!");
	$doc->startTag("OpticalDrive");
	while (<PROFILE>) {
		if (/Model: (.*)$/) {
			$doc->dataElement("Model" => $1);
		}
		if (/Revision: (.*)$/) {
			$doc->dataElement("Revision" => $1);
		}
		if (/Serial Number: (.*)$/) {
			$doc->dataElement("SerialNumber" => $1);
		}
		if (/Socket Type: (.*)$/) {
			$doc->dataElement("SocketType" => $1);
		}
		if (/Low Power Polling: (.*)$/) {
			$doc->dataElement("LowPowerPolling" => $1);
		}
	}
	$doc->endTag("OpticalDrive");
	close PROFILE;
	return 0;
}

### Logging subroutine ########################################################
sub Log {
    my $msg = shift;
    my $nowstring = localtime;
    print LOGFILE "INFO -- $nowstring -- $msg\n";
    return 0;
}

### Logging with warning subroutine ###########################################
sub LogWarn {
    my $msg = shift;
    my $nowstring = localtime;
    print LOGFILE "WARN -- $nowstring -- $msg\n";
      return 0;
}

### Logging with death subroutine #############################################
sub LogDie {
    my $msg = shift;
    my $nowstring = localtime;
    print LOGFILE "ERR! -- $nowstring -- $msg\n";
    exit 1;
}

### Trim subroutine ###########################################################
sub trim($) {
    my $string = shift;
    unless ( !defined($string) ) {
        $string =~ s/^\s+|\s+$//;
        $string =~ s/\'|\"//g;
        $string =~ s/\n|\r//g;
        $string =~ s/ //g;
    }
    return $string;
}
