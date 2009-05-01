use strict;
use warnings;
use Env;
use DBI;
use IO::Handle;
use Win32;
use Win32::File::VersionInfo;
use Win32::API::Prototype;
use Win32::OLE qw(in);
use Win32::OLE::Variant;
use Win32::Security::SID;
use Win32::OLE::NLS qw(:TIME
  :DATE
  GetLocaleInfo GetUserDefaultLCID
  LOCALE_SMONTHNAME1 LOCALE_SABBREVMONTHNAME1
  LOCALE_SDAYNAME1 LOCALE_SABBREVDAYNAME1
  LOCALE_IFIRSTDAYOFWEEK
  LOCALE_SDATE LOCALE_IDATE
  LOCALE_SGROUPING
);
use Win32::OLE::Variant;
use Win32::TieRegistry ( Delimiter => "/", ArrayValues => 1, qw(KEY_READ) );
use Config::Tiny;
use XML::Simple;
use File::Find;
use File::Basename;
use Readonly;
use Sys::Hostname::FQDN qw( fqdn );

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
my $ver = "1.7";

my $DEBUG = $A{debug} || 0;

my $core;
my $strComputer = '.';
my $dir         = Win32::GetShortPathName($LDMS_LOCAL_DIR);
my $file        = $dir . '\\ldms_client.dat';
my $ldclient    = Win32::GetShortPathName($PROGRAMFILES);
$ldclient .= "\\LANDesk\\LDClient";

# NetworkD's dumbass installation methods try to run ldms_client before the
# environment variables are active.
if ( !defined($dir) ) {
    $dir = $ldclient . "\\data";
}
my $sdcache = $ldclient . "\\sdmcache";

my $netstatcommand = 'netstat -an';

my ( $totalpstsize, $totalnsfsize ) = 0;

# File handles I'll need
my ( $FILE, $PSFILE, $PKDFILE, $RRTEMP );

# Battery-specific variables
my (
    $BatteryLabel,  $BatteryID,           $Chemistry,
    $ChemistryCode, $BatteryName,         $Capacity,
    $BatteryDate,   $BatteryManufacturer, $BatteryLocation,
    $BatteryStatus
);

# Prepare logging system
my $logfile = "ldms_client.log";
my $LOG;
open( $LOG, '>', $logfile ) or die "Cannot open $logfile - $!";
print $LOG localtime() . " $prog $ver starting.\n";
close($LOG);

my $usage = <<EOD;

Usage: $prog [-d] [-h]
	-debug      debug
	-h(elp)     this display

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This program will extend the LANDesk Inventory using custom data.
The latest version lives at 
http://www.droppedpackets.org/inventory-and-slm/ldms_client/

EOD
die $usage if $A{h} or $A{help};

# Read my configuration file from the core.
# Eventually, this will need to be downloaded from the core and cached/aged
# Tie registry to find HKEY_LOCAL_MACHINE\SOFTWARE\Intel\LANDesk\LDWM CoreServer
my $RegKey = $Registry->{"HKEY_LOCAL_MACHINE/Software/Intel/LANDesk/LDWM"};
if ($RegKey) {
    $core = $RegKey->GetValue("CoreServer");
}

# Setup Windows OLE object for reading WMI
Readonly my $HKEY_LOCAL_MACHINE => 0x80000002;
Readonly my $EPOCH              => 25569;
Readonly my $SEC_PER_DAY        => 86400;
my $objWMIService =
  Win32::OLE->GetObject( 'winmgmts:'
      . '{impersonationLevel=impersonate}!\\\\'
      . $strComputer
      . '\\root\\cimv2' );
my $objShell = Win32::OLE->new('WScript.Shell');

our $lcid;

BEGIN {
    $lcid = GetUserDefaultLCID();
    Win32::OLE->Option( LCID => $lcid );
}
# Setup my file
open( $FILE, '>', "$file" ) or die "Can't open $file: $!\n";

# Get my info -- need to test if configuration file asked for each of these

&GetProductInfo;

sub GetProductInfo {
    my ($ProductName, $ProductID);
    # Read Product ID from WMI
    my $ProductList =
      $objWMIService->ExecQuery('SELECT * FROM Win32_Product') || die "can't
      read WMI: $!";
      print "$ProductList->Count\n";
    if ( $ProductList->Count > 0 ) {
        foreach my $Product ( in $ProductList) {
            if ( $Product->Name ) {
                $ProductName = $Product->Name;
                if ( $Product->ProductID ) {
                    $ProductID = $Product->ProductID;
                    print "$ProductName - $ProductID\n";
                }
            }
        }
    }
}




