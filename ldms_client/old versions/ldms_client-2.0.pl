#############################################################################
# ldms_client.pl                                                            #
# (c) 2008 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.droppedpackets.org/scripts/ldms_client                         #
#############################################################################
#
# TODO: Report system crashes from event log

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
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
my $ver = "2.0";

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

#############################################################################
# Main Loop                                                                 #
#############################################################################

# Suppress DOS Windows
BEGIN {
    Win32::SetChildShowWindow(0) if defined &Win32::SetChildShowWindow;
}

die $usage if $A{h} or $A{help};

# Set the process priority so we don't murderize the CPU.
ApiLink( 'kernel32.dll',
    "BOOL SetPriorityClass( HANDLE hThread, DWORD dwPriorityClass )" )
  || &LogDie("Unable to load SetPriorityClass()");
ApiLink( 'kernel32.dll', "HANDLE OpenProcess()" )
  || &LogDie("Unable to load GetCurrentProcess()");
ApiLink( 'kernel32.dll', "HANDLE GetCurrentProcess()" )
  || &LogDie("Unable to load GetCurrentProcess()");
ApiLink( 'kernel32.dll', "BOOL CloseHandle( HANDLE )" )
  || &LogDie("Unable to load CloseHandle()");
my $hProcess = GetCurrentProcess();
if ( 0 == SetPriorityClass( $hProcess, 0x00000040 ) ) {
    &Log("Unable to set master PID scheduling priority to low.");
}
else {
    &Log("master PID scheduling priority set to low.");
}
CloseHandle($hProcess);

# Read my configuration file from the core.
# Eventually, this will need to be downloaded from the core and cached/aged
# Tie registry to find HKEY_LOCAL_MACHINE\SOFTWARE\Intel\LANDesk\LDWM CoreServer
my $RegKey = $Registry->{"HKEY_LOCAL_MACHINE/Software/Intel/LANDesk/LDWM"};
if ($RegKey) {
    $core = $RegKey->GetValue("CoreServer");
}
else {
    &Log(
"can't find core server name in HKLM/Software/Intel/LANDesk/LDWM CoreServer."
    );
}

if ($DEBUG) {
    &Log(   "Core server is $core, client directory is $ldclient, "
          . "Output file is $file" );
}

# download the file with sdclient from http, read it, then delete it after inventory scanning is complete.
my $configfileresult =
  `$ldclient\\sdclient.exe /f /p="http://$core/ldlogon/ldms_client.ini"`;
my $configfile = $ldclient . "\\sdmcache\\ldms_client.ini";
if ( !-e $configfile ) {
    &LogDie("Unable to get configuration from core server. $configfileresult");
}
my $Config = Config::Tiny->new();
$Config = Config::Tiny->read("$configfile")
  || &LogDie( "Can't read $configfile : ", Config::Tiny->errstr() );

my $coreversion = $Config->{version}->{Version};
if ( $coreversion ne $ver ) {
    &LogWarn(
"ldms_client version is different on the core, this could potentially lead to inventory problems."
    );
}

# Reading properties
my $Battery         = $Config->{_}->{Battery};
my $Netstat         = $Config->{_}->{Netstat};
my $PolicyList      = $Config->{_}->{PolicyList};
my $FindPST         = $Config->{_}->{FindPST};
my $FindNSF         = $Config->{_}->{FindNSF};
my $AggroMailSearch = $Config->{_}->{AggroMailSearch};
my $FindProfileSize = $Config->{_}->{FindProfileSize};
my $NicDuplex       = $Config->{_}->{NicDuplex};
my $EnumerateGroups = $Config->{_}->{EnumerateGroups};
my $LANDeskInfo     = $Config->{_}->{LANDeskInfo};
my $RegistryReader  = $Config->{_}->{RegistryReader};
my $RegistryInfo    = $Config->{_}->{RegistryInfo};
my $Produkey        = $Config->{_}->{Produkey};
my $ProdukeyBinary  = $Config->{_}->{ProdukeyBinary};
my $DCCUWol         = $Config->{_}->{DCCUWol};
my $DCCUWolBinary   = $Config->{_}->{DCCUWolBinary};
my $SID             = $Config->{_}->{SID};

# What HKCU keys will we look for?
my @rr;
foreach my $index ( 1 .. 10 ) {
    if ( length( $Config->{RegistryReader}->{$index} ) > 1 ) {
        $rr[$index] = $Config->{RegistryReader}->{$index};
    }
    else {
        $rr[$index] = "";
    }
}

# How about HKLM keys?
my @ri;
foreach my $index ( 1 .. 10 ) {
    if ( length( $Config->{RegistryInfo}->{$index} ) > 1 ) {
        $ri[$index] = $Config->{RegistryInfo}->{$index};
    }
    else {
        $ri[$index] = "";
    }
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
if ($Battery) {
    &CallBattery;
}
if ($Netstat) {
    &CallNetstat;
}
if ($PolicyList) {
    &CallPolicyList;
}
if ($FindPST) {
    &CallFindPST;
}
if ($FindNSF) {
    &CallFindNSF;
}
if ($FindProfileSize) {
    &CallFindProfileSize;
}
if ($NicDuplex) {
    &CallNicDuplex;
}
if ($LANDeskInfo) {
    &CallLANDeskInfo;
}
if ($EnumerateGroups) {
    &CallEnumerateGroups;
}
if ($RegistryReader) {
    &CallRegistryReader;
}
if ($RegistryInfo) {
    &CallRegistryInfo;
}
if ($Produkey) {
    &CallProdukey;
}
if ($DCCUWol) {
    &CallDCCUWol;
}
if ($SID) {
    &CallSID;
}

# Clean up... shut down OLE object, Registry object, and close my file
if ($DEBUG) { &Log("Closing data file"); }
close $FILE;
$objShell = undef;
unlink "$ldclient/ldms_client.ini";
unlink "$sdcache/ldms_client.ini";
&Log("$prog $ver exiting.");

#############################################################################
# Subroutines                                                               #
#############################################################################

### Get Battery Information ###################################################
sub CallBattery {

    my $x = 0;
    if ($DEBUG) { &Log("CallBattery: Looking for battery information"); }

    # First try to get data from the PortableBattery object
    my $BatteryList =
      $objWMIService->ExecQuery('SELECT * FROM Win32_PortableBattery');
    if ( $BatteryList->Count > 0 ) {
        foreach my $Battery ( in $BatteryList) {
            $x++;
            if ( $Battery->Description ) {
                $BatteryLabel = $Battery->Description;
            }
            else {
                $BatteryLabel = "Portable Battery $x";
            }
            if ( $Battery->DeviceID ) {
                $BatteryID = $Battery->DeviceID;
                print $FILE "Battery - $BatteryLabel - DeviceID = $BatteryID\n";
            }
            if ( $Battery->Manufacturer ) {
                $BatteryManufacturer = $Battery->Manufacturer;
                print $FILE
"Battery - $BatteryLabel - Manufacturer = $BatteryManufacturer\n";
            }
            if ( $Battery->ManufactureDate ) {

                $BatteryDate = $Battery->ManufactureDate;
                $BatteryDate = WMIDateStringToDate($BatteryDate);
                print
                  "Battery - $BatteryLabel - ManufactureDate = $BatteryDate\n";
            }
            if ( $Battery->Name ) {
                $BatteryName = $Battery->Name;
                print $FILE "Battery - $BatteryLabel - Name = $BatteryName\n";
            }
            if ( $Battery->Chemistry ) {

                $ChemistryCode = $Battery->Chemistry;

                # Get a useful value for Chemistry
                &DecodeChemistry();
            }
            if ( $Battery->Location ) {
                $BatteryLocation = $Battery->Location;
                print $FILE
                  "Battery - $BatteryLabel - Location = $BatteryLocation\n";
            }
            if ( $Battery->DesignCapacity ) {
                if ( $Battery->FullChargeCapacity ) {
                    $Capacity =
                      &FormatPercent( $Battery->FullChargeCapacity /
                          $Battery->DesignCapacity );
                    print $FILE
                      "Battery - $BatteryLabel - Capacity = $Capacity\n";
                }
            }
            if ( $Battery->Status ) {
                $BatteryStatus = $BatteryStatus;
                print $FILE
                  "Battery - $BatteryLabel - Status = $BatteryStatus\n";
            }
        }
    }
    $x = 0;

# Then see what the Battery object has. This may overwrite values found from PortableBattery.
    $BatteryList = $objWMIService->ExecQuery('SELECT * FROM Win32_Battery');
    if ( $BatteryList->Count > 0 ) {
        foreach my $Battery ( in $BatteryList) {
            if ( $Battery->Description ) {
                $BatteryLabel = $Battery->Description;
            }
            else {
                $BatteryLabel = "Battery $x";
            }
            if ( $Battery->DeviceID ) {
                $BatteryID = $Battery->DeviceID;
                print $FILE "Battery - $BatteryLabel - DeviceID = $BatteryID\n";
            }
            if ( $Battery->Name ) {
                $BatteryName = $Battery->Name;
                print $FILE "Battery - $BatteryLabel - Name = $BatteryName\n";
            }
            if ( $Battery->InstallDate ) {
                $BatteryDate = $Battery->InstallDate;
                $BatteryDate = WMIDateStringToDate($BatteryDate);
                print $FILE
                  "Battery - $BatteryLabel - InstallDate = $BatteryDate\n";
            }
            if ( $Battery->Chemistry ) {
                $ChemistryCode = $Battery->Chemistry;

                # Get a useful value for Chemistry.
                &DecodeChemistry();
            }
            if ( $Battery->Location ) {
                $BatteryLocation = $Battery->Location;
                print $FILE
                  "Battery - $BatteryLabel - Location = $BatteryLocation\n";
            }
            if ( $Battery->DesignCapacity ) {
                if ( $Battery->FullChargeCapacity ) {
                    $Capacity =
                      &FormatPercent( $Battery->FullChargeCapacity /
                          $Battery->DesignCapacity );
                    print $FILE
                      "Battery - $BatteryLabel - Capacity = $Capacity\n";
                }
            }
            if ( $Battery->Status ) {
                $BatteryStatus = $Battery->Status;
                print $FILE
                  "Battery - $BatteryLabel - Status = $BatteryStatus\n";
            }
        }
    }
    return 0;
}
### End of CallBatteryInfo sub ################################################

### DecodeChemistry sub #######################################################
sub DecodeChemistry {
    my $returnvalue;
    if ( $ChemistryCode == 1 ) {
        $Chemistry = 'Other';
    }
    if ( $ChemistryCode == 2 ) {
        $Chemistry = 'Unknown';
    }
    if ( $ChemistryCode == 3 ) {
        $Chemistry = 'Lead Acid';
    }
    if ( $ChemistryCode == 4 ) {
        $Chemistry = 'Nickel Cadmium';
    }
    if ( $ChemistryCode == 5 ) {
        $Chemistry = 'Nickel Metal Hydride';
    }
    if ( $ChemistryCode == 6 ) {
        $Chemistry = 'Lithium Ion';
    }
    if ( $ChemistryCode == 7 ) {
        $Chemistry = 'Zinc Air';
    }
    if ( $ChemistryCode == 8 ) {
        $Chemistry = 'Lithium Polymer';
    }
    if ($DEBUG) {
        &Log("DecodeChemistry: Received $ChemistryCode, Returned $Chemistry");
    }
    print $FILE "Battery - $BatteryLabel - Chemistry = $Chemistry\n";
    return 0;
}
### End of DecodeChemistry sub ################################################

###  CallNetstat sub ##########################################################
sub CallNetstat {
    if ($DEBUG) { &Log("CallNetstat: Looking for open network ports"); }
    my @netstat = `$netstatcommand`;
    foreach my $i (@netstat) {
        &trim($i);
        if ( $i =~ /^$/ )         { next; }
        if ( $i =~ /^Active/i )   { next; }
        if ( $i =~ /\sProto\s/i ) { next; }
        my @port;
        my @line = split( ' ', $i );
        if ( $line[0] =~ /TCP/ && $line[3] =~ /LISTENING/i ) {
            @port = split( ':', $line[1] );
            print $FILE
              "Netstat - Open Port - $line[0] - $port[1] = $line[0]/$port[1]\n";
        }
        if ( $line[0] =~ /UDP/i ) {
            @port = split( ':', $line[1] );
            print $FILE
              "Netstat - Open Port - $line[0] - $port[1] = $line[0]/$port[1]\n";
        }
    }
    return 0;
}
### End of CallNetstat sub ####################################################

###  CallPolicyList sub #######################################################
sub CallPolicyList {

    if ($DEBUG) { &Log("CallPolicyList: Looking for LANDesk policies"); }

# What LANDesk version are we working with?
# Might be better to check for existence of policy.*.exe files in ldclient, but 8.7 service packs 4 and 5 may have had pre-work in them...
    my $ldms_version;
    my $versionfile = Win32::GetShortPathName($PROGRAMFILES);
    $versionfile .= "\\LANDesk\\LDClient\\ldiscn32.exe";
    if ($DEBUG) { &Log("CallPolicyList: versionfile is $versionfile"); }
    my $version = GetFileVersionInfo($versionfile);
    if ($version) {
        $ldms_version = $version->{FileVersion};

        # Remove the dots and convert to an integer so that we can do numerical
        # comparison... e.g., version 8.80.0.249 is rendered as 8800249
        $ldms_version =~ s/\.?(?=[0-9])//g;

        # LANDesk buildmasters keep screwing with the number of ordinals in the
        # version number, so this has grown unreliable with certain patches.
        # If I just use the first two numbers, that should work well enough.
        $ldms_version = substr( $ldms_version, 0, 2 );
        $ldms_version = &atoi($ldms_version);
        if ($DEBUG) { &Log("DEBUG: LANDesk version is $ldms_version"); }
    }
    else {
        &LogWarn("Cannot determine LANDesk version from $versionfile");
        return 1;
    }

    # If it's pre-8.8, we're looking in the registry.
    if ( $ldms_version < 88 ) {

        if ($DEBUG) { &Log("CallPolicyList: Searching in registry"); }

        # Subroutine specific variables
        my ( $PolicyName, $PolicyGUID, $PolicyInfoDesc, $PolicyStatus );

        my $PolicyRegHive =
          $Registry->{
"HKEY_LOCAL_MACHINE/Software/Intel/LANDesk/LDWM/AppHealing/Agent/AMClient/APM/PolicyCache"
          };
        my @policy_names = $PolicyRegHive->SubKeyNames;
        foreach my $policy (@policy_names) {
            my $PolicyRegEntry =
              $Registry->{
"HKEY_LOCAL_MACHINE/Software/Intel/LANDesk/LDWM/AppHealing/Agent/AMClient/APM/PolicyCache"
              }->{$policy};
            $PolicyName = $PolicyRegEntry->GetValue("Name");
            $PolicyGUID = $PolicyRegEntry->GetValue("GUID");
            $PolicyInfoDesc =
              $PolicyRegEntry->GetValue("Informational Description");
            $PolicyStatus = $PolicyRegEntry->GetValue("Status");
            print $FILE
"LANDesk Management - APM - Policies - $PolicyName - GUID = $PolicyGUID\n";
            print $FILE
"LANDesk Management - APM - Policies - $PolicyName - Description = $PolicyInfoDesc\n";
            print $FILE
"LANDesk Management - APM - Policies - $PolicyName - Status = $PolicyStatus\n";
        }
    }
    else {

        # If it's 8.8 or post, we're looking in SQLite
        my $dbfile = Win32::GetShortPathName($ALLUSERSPROFILE);
        $dbfile .=
"\\Application\ Data\\LANDesk\\ManagementSuite\\Database\\LDClientDB.db3";
        $dbfile = Win32::GetShortPathName($dbfile);
        if ( -e $dbfile ) {

            if ($DEBUG) {
                &Log("CallPolicyList: Searching in database $dbfile");
            }
            my @rows;

            my $dbh = DBI->connect( "dbi:SQLite:dbname=$dbfile", "", "" )
              or &LogWarn("Can't open $dbfile: $!");

            if ($dbh) {

                my $sql =
"select name,filename,description,status from PortalTaskInformation";

                my $sth = $dbh->prepare($sql)
                  or &LogWarn("Policy database prepare statement failed!: $!");
                $sth->execute()
                  or &LogWarn("Policy database execute statement failed: $!");
                while ( my @row = $sth->fetchrow_array() ) {
                    print $FILE
"LANDesk Management - APM - Policies - $row[0] - GUID = $row[1]\n";
                    print $FILE
"LANDesk Management - APM - Policies - $row[0] - Description = $row[2]\n";
                    print $FILE
"LANDesk Management - APM - Policies - $row[0] - Status = $row[3]\n";
                }
            }
        }
        else {
            if ($DEBUG) { &Log("Policy database file $dbfile is not present"); }
        }

    }

    # And we're all done here
    return 0;
}
### End of CallPolicyList sub #################################################

###  CallNicDuplex sub ########################################################
sub CallNicDuplex {

    if ($DEBUG) { &Log("CallNicDuplex: Looking for NIC Settings"); }
    my $DuplexRegHive =
      $Registry->{
"HKEY_LOCAL_MACHINE/System/Currentcontrolset/Control/Class/{4D36E972-E325-11CE-BFC1-08002bE10318}"
      };
    my @nic_names = $DuplexRegHive->SubKeyNames;
    foreach my $nic (@nic_names) {
        my $DuplexRegEntry = $DuplexRegHive->{$nic};
        my $DriverName     = $DuplexRegEntry->GetValue("DriverDesc");
        if ( !$DriverName ) {
            next;
        }
        if ( $DriverName eq '1394 Net Adapter' ) {
            next;
        }
        if ( $DriverName eq 'Direct Parallel' ) {
            next;
        }
        if ( $DriverName eq 'RAS Async Adapter' ) {
            next;
        }
        if ( $DriverName =~ m/VPN/ ) {
            next;
        }
        if ( $DriverName =~ m/Miniport/ ) {
            next;
        }
        if ( $DriverName =~ m/Virtual Ethernet Adapter/ ) {
            next;
        }

        # Not one of the bogus drivers, so let's look at DuplexMode
        my ( $ReportedMode, $drivertype );

        # Realtek, 3Com
        my $DuplexMode = $DuplexRegEntry->GetValue("DuplexMode");
        if ($DuplexMode) {
            $drivertype = 1;
        }

        # Intel cards
        $DuplexMode = $DuplexRegEntry->GetValue("SpeedDuplex");
        if ($DuplexMode) {
            $drivertype = 1;
        }

        # Broadcom NetXtreme Gigabit Ethernet
        $DuplexMode = $DuplexRegEntry->GetValue("RequestedMediaType");
        if ($DuplexMode) {
            $drivertype = 2;
        }

        # AMD, VMWare (though VMWare is filtered out anyway)
        $DuplexMode = $DuplexRegEntry->GetValue("EXTPHY");
        if ($DuplexMode) {
            $drivertype = 3;
        }

        # VIA, Davicom
        $DuplexMode = $DuplexRegEntry->GetValue("ConnectionType");
        if ($DuplexMode) {
            $drivertype = 3;
        }

# If nothing was detected at all, the interface is probably defaulting to auto-detect
        if ( !$drivertype ) {
            $ReportedMode = 'Auto Detect';
        }

        # Decode the number to something useful.
        if ( $drivertype == 1 ) {

            # Most cards seem to follow this
            if ( $DuplexMode == '0' ) {
                $ReportedMode = 'Auto Detect';
            }
            if ( $DuplexMode == '1' ) {
                $ReportedMode = '10Mbps \\ Half Duplex';
            }
            if ( $DuplexMode == '2' ) {
                $ReportedMode = '10Mbps \\ Full Duplex';
            }
            if ( $DuplexMode == '3' ) {
                $ReportedMode = '100Mbps \\ Half Duplex';
            }
            if ( $DuplexMode == '4' ) {
                $ReportedMode = '100Mbps \\ Full Duplex';
            }
            if ( $DuplexMode == '5' ) {
                $ReportedMode = '1000Mbps \\ Auto-Negotiate';
            }
        }
        if ( $drivertype == 2 ) {

            # Broadcom has to be special, though
            if ( $DuplexMode == '0' ) {
                $ReportedMode = 'Auto Detect';
            }
            if ( $DuplexMode == '3' ) {
                $ReportedMode = '10Mbps \\ Half Duplex';
            }
            if ( $DuplexMode == '4' ) {
                $ReportedMode = '10Mbps \\ Full Duplex';
            }
            if ( $DuplexMode == '5' ) {
                $ReportedMode = '100Mbps \\ Half Duplex';
            }
            if ( $DuplexMode == '6' ) {
                $ReportedMode = '100Mbps \\ Full Duplex';
            }
        }
        if ( $drivertype == 3 ) {

            # Who knows what they're smoking at VIA, AMD and Davicom
            if ( $DuplexMode == '0' ) {
                $ReportedMode = 'Auto Detect';
            }
            if ( $DuplexMode == '2' ) {
                $ReportedMode = '100Mbps \\ Full Duplex';
            }
            if ( $DuplexMode == '4' ) {
                $ReportedMode = '100Mbps \\ Full Duplex';
            }
            if ( $DuplexMode == '9' ) {
                $ReportedMode = '100Mbps \\ Full Duplex';
            }
        }

        # Okay to report
        if ($ReportedMode) {
            print $FILE "NIC - $DriverName - Duplex Mode = $ReportedMode\n";
        }

        # Just for giggles, let's see about Media Type and Wake on LAN status.
        # Media
        my $NICMedia = $DuplexRegEntry->GetValue("Media");
        if ($NICMedia) {
            print $FILE "NIC - $DriverName - Media = $NICMedia\n";
        }
        my $NICMediaType = $DuplexRegEntry->GetValue("Media_Type");
        if ($NICMediaType) {
            print $FILE "NIC - $DriverName - Media Type = $NICMediaType\n";
        }

        # Wake On LAN
        my $NICWOL = $DuplexRegEntry->GetValue("WakeOn");
        if ($NICWOL) {

# This has to be decoded too... $DIETY grant that it's more standard than duplex mode
            if ( $NICWOL == '0' ) {
                $NICWOL = 'Disabled';
            }
            if ( $NICWOL == '6' ) {
                $NICWOL = 'Wake on Magic Packet';
            }
            if ( $NICWOL == '116' ) {
                $NICWOL = 'Wake on Directed Packet';
            }
            if ( $NICWOL == '118' ) {
                $NICWOL = 'Wake on Magic or Directed Packet';
            }
            if ( $NICWOL == '246' ) {
                $NICWOL = 'OS Directed';
            }
            print $FILE "NIC - $DriverName - Wake On = $NICWOL\n";
        }
        my $NICWOLLink = $DuplexRegEntry->GetValue("WakeOnLink");
        if ($NICWOLLink) {
            if ( $NICWOLLink == '0' ) {
                $NICWOLLink = 'Disabled';
            }
            if ( $NICWOLLink == '1' ) {
                $NICWOLLink = 'OS Controlled';
            }
            if ( $NICWOLLink == '2' ) {
                $NICWOLLink = 'Forced';
            }
            print $FILE "NIC - $DriverName - Wake On Link = $NICWOLLink\n";
        }
    }
    return 0;
}
### End of CallNicDuplex sub ##################################################

###  CallLANDeskInfo sub ######################################################
sub CallLANDeskInfo {

    if ($DEBUG) { &Log("CallLANDeskInfo: Looking for Broker Settings"); }

    # What mode is brokerconfig in?
    my $brokerconfigfile = Win32::GetShortPathName($PROGRAMFILES);
    $brokerconfigfile .=
      "\\LANDesk\\Shared Files\\cbaroot\\broker\\brokerconf.xml";
    if ($DEBUG) {
        &Log("CallLANDeskInfo: brokerconfigfile is $brokerconfigfile.");
    }
    if ( -e $brokerconfigfile ) {
        my $brokerxml  = new XML::Simple;
        my $brokerdata = $brokerxml->XMLin($brokerconfigfile)
          or &LogWarn("Can't open $brokerconfigfile : $!");
        if ($brokerdata) {
            if ( $brokerdata->order == 1 ) {
                print $FILE
"LANDesk Management - Broker Configuration Mode = Connect using the Management Gateway\n";
            }
            if ( $brokerdata->order == 2 ) {
                print $FILE
"LANDesk Management - Broker Configuration Mode = Connect directly to LDMS core\n";
            }
            if ( $brokerdata->order == 0 ) {
                print $FILE
"LANDesk Management - Broker Configuration Mode = Dynamically determine connection route\n";
            }
        }
    }
    if ($DEBUG) { &Log("CallLANDeskInfo: Looking for Preferred Servers"); }
    my $psdir = $dir . "\\sdmcache";
    my ( $psfile, $psentry, $psentries );
    if ( -e "$psdir\\preferredserver.dat" ) {

        # 8.7.1 client
        $psfile = "$psdir\\preferredserver.dat";
        open( $PSFILE, '<', "$psfile" ) or &LogWarn("Can't open $psfile : $!");
        $psentry = <$psfile>;
        close $PSFILE;
        $psentry = &trim($psentry);
        print $FILE "LANDesk Management - Preferred Server = $psentry\n";
    }
    if ( -e "$psdir\\preferredservers.dat" ) {

        # 8.7.2 or greater client
        $psfile = "$psdir\\preferredservers.dat";
        open( $PSFILE, '<', "$psfile" ) or &LogWarn("Can't open $psfile : $!");
        while ( $psentry = <$psfile> ) {
            $psentry =~ m/\?.*$/;
            $psentries .= &trim($psentry);
        }
        close $PSFILE;
        print $FILE "LANDesk Management - Preferred Servers = $psentries\n";
    }
    $psentries = "";
    $RegKey =
      $Registry->{
"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/WinClient/SoftwareDistribution"
      };
    if ($RegKey) {
        $psentries = $RegKey->GetValue("PreferredPackageServer");
    }
    return 0;
}
### End of CallLANDeskInfo sub ################################################

###  CallEnumerateGroups sub ##################################################
sub CallEnumerateGroups {

   # TODO -- gather Last Logon Time:
   # http://msdn.microsoft.com/en-us/library/ms676823(VS.85).aspx
   # http://www.microsoft.com/technet/scriptcenter/topics/win2003/lastlogon.mspx
    if ($DEBUG) {
        &Log("CallEnumerateGroups: Looking for domain user and group names");
    }
    my ( $GroupList, $GroupName, $MemberList, $MemberName, $GroupMembers );
    my $Members = "";
    $GroupList = Win32::OLE->GetObject( 'WinNT://' . $strComputer . '' );
    $GroupList->{Filter} = ['group'];
    foreach my $Group ( in $GroupList) {

        # For each group
        if ( $Group->Name ) {
            $GroupName  = $Group->Name;
            $MemberList = Win32::OLE->GetObject(
                'WinNT://' . $strComputer . '/' . $GroupName );
            $GroupMembers = "";
            foreach my $Member ( in $MemberList->Members ) {

                # Get each user name, returned as a comma-separated list
                if ( $Member->Name ) {
                    if ( $Member->Domain ) {
                        $MemberName = $Member->Domain . "\\" . $Member->Name;
                    }
                    else {
                        $MemberName = $Member->Name;
                    }
                    $GroupMembers .= "$MemberName, ";
                }
            }

            # Chop off that last comma and space
            $GroupMembers = substr( $GroupMembers, 0, -2 );
            print $FILE
"Local Users and Groups - Local Groups - $GroupName - Members = $GroupMembers\n";
        }
    }
    return 0;
}
### End of CallEnumerateGroups sub ############################################

###  CallFindPST sub ##########################################################
sub CallFindPST {

    if ($DEBUG) {
        &Log( "CallFindPST: Looking for PST Files, Aggressiveness="
              . $AggroMailSearch );
    }

    if ( $AggroMailSearch == 3 ) {
        my ( undef, $sysdrive, undef ) = fileparse( $WINDIR, qr{\..*} );
        if ($DEBUG) { &Log("Looking for PST and OST files under $sysdrive"); }
        find( \&ProcessPSTFile, $sysdrive );
    }
    else {

        # Find where user profiles are stored
        my $userdir = Win32::GetShortPathName($USERPROFILE);
        $userdir =~ s|\\[^\\]*$||;
        for my $user ( glob( $userdir . '/*' ) ) {
            if ( $AggroMailSearch == 1 ) {
                $user .= "/Local\ Settings/Application\ Data/Microsoft/Outlook";
            }
            if ( -d $user ) {

                # Search that path recursively for .pst or .ost files
                $user = Win32::GetShortPathName($user);
                if ($DEBUG) {
                    &Log("Looking for PST and OST files under $user");
                }
                find( \&ProcessPSTFile, $user );
            }
        }
    }
    print $FILE "Email - PST Files - Total Disk Size = $totalpstsize\n";
    return 0;
}
### End of CallFindPST sub ####################################################

###  CallFindNSF sub ##########################################################
sub CallFindNSF {

    if ($DEBUG) {
        &Log( "CallFindNSF Looking for NSF Files, Aggressiveness="
              . $AggroMailSearch );
    }

    if ( $AggroMailSearch == 3 ) {
        my ( undef, $sysdrive, undef ) = fileparse( $WINDIR, qr{\..*} );
        if ($DEBUG) { &Log("Looking for NSF files under $sysdrive"); }
        find( \&ProcessNSFFile, $sysdrive );
    }
    else {

        # Find where user profiles are stored
        my $userdir = Win32::GetShortPathName($USERPROFILE);
        $userdir =~ s|\\[^\\]*$||;
        for my $user ( glob( $userdir . '/*' ) ) {
            if ( $AggroMailSearch == 1 ) {
                $user .= "/Local\ Settings/Application\ Data/Lotus/Notes/Data";
            }
            if ( -d $user ) {

                # Search that path recursively for .nsf files
                $user = Win32::GetShortPathName($user);
                if ($DEBUG) {
                    &Log("Looking for NSF files under $user");
                }
                find( \&ProcessNSFFile, $user );
            }
        }
    }
    print $FILE "Email - NSF Files - Total Disk Size = $totalnsfsize\n";
    return 0;
}
### End of CallFindNSF sub ####################################################

###  CallFindProfileSize sub ##################################################
sub CallFindProfileSize {

    if ($DEBUG) { &Log("CallFindProfileSize: Looking for user profile sizes"); }

    # Find where user profiles are stored
    my $userdir = Win32::GetShortPathName($USERPROFILE);
    $userdir =~ s|\\[^\\]*$||;
    for my $user ( glob( $userdir . '/*' ) ) {
        if ( -d $user ) {

            # Search that path recursively for its size
            my $size = 0;
            find( sub { $size += -s if -f $_ }, "$user" );
            print $FILE "Profile Size - $user = $size\n";
        }
    }
    return 0;
}
### End of CallFindProfileSize sub ############################################

### ProcessPSTFile sub (File::Find uses this) #################################
sub ProcessPSTFile {

    # TODO -- find the type (different formats)
    # Each file needs to be looked at
    my ( undef, undef, $extension ) = fileparse( $_, qr{\..*} );
    $extension = lc($extension);
    if ( $extension ne ".pst" && $extension ne ".ost" ) {
        return 0;
    }
    print $FILE "Email - PST Files - $_ - File Location = $File::Find::name\n";

    # stat -- 7 is file size in bytes
    my $pstfilesize = ( stat($File::Find::name) )[7];
    print $FILE "Email - PST Files - $_ - File Size = $pstfilesize\n";
    $totalpstsize += $pstfilesize;
    return 0;
}
### End of ProcessPSTFile sub #################################################

### ProcessNSFFile sub (File::Find uses this) #################################
sub ProcessNSFFile {

    # Each file needs to be looked at
    my ( undef, undef, $extension ) = fileparse( $_, qr{\..*} );
    $extension = lc($extension);
    if ( $extension ne ".nsf" ) {
        return 0;
    }
    print $FILE "Email - NSF Files - $_ - File Location = $File::Find::name\n";

    # stat -- 7 is file size in bytes
    my $nsffilesize = ( stat($File::Find::name) )[7];
    print $FILE "Email - NSF Files - $_ - File Size = $nsffilesize\n";
    $totalnsfsize += $nsffilesize;
    return 0;
}
### End of ProcessNSFFile sub #################################################

### CallRegistryReader sub ####################################################
sub CallRegistryReader {
    if ($DEBUG) { &Log("CallRegistryReader: Looking for HKCU Registry keys"); }

    # Locate startasuser binary
    my $startasuser           = $ldclient . "\\startasuser.exe";
    my $ldms_client_regreader = $ldclient . "\\ldms_client_regreader.exe";
    my $rrtemp                = $ldclient . "\\rrtemp.txt";
    if ( -e $startasuser ) {
        if ( -e $ldms_client_regreader ) {

            # If I'm in debug mode, I should pass that down to regreader
            if ($DEBUG) { $ldms_client_regreader .= " -d"; }

            # Prepare my temp file
            open( $RRTEMP, '>', "$rrtemp" )
              or &LogWarn("Cannot open $rrtemp for writing: $!");

            # Read in the .ini keys I need to look for
            for my $rri ( 1 .. 10 ) {

               # For each key, Call $startasuser ldms_client_regreader.exe -$key
               # then write the value out
                if ( my $hkcukey = $rr[$rri] ) {

                    $hkcukey = &trimkey($hkcukey);

                    # Registry reading differentiates between key and path.
                    # Split it up into components
                    my @parts = split( /\//, $hkcukey );

                    # Pop off the last subkey
                    my $subkey = pop(@parts);

                    # Join everything else back together
                    $hkcukey = join( "/", @parts );
                    print $RRTEMP "$hkcukey,$subkey\n";
                    if ($DEBUG) {
                        &Log(
"Wrote processed input of $hkcukey, $subkey to $rrtemp"
                        );
                    }
                }
            }
            close($RRTEMP);
            if ($DEBUG) {
                &Log(
"CallRegistryReader: $startasuser ///timeout=10 ///silent $ldms_client_regreader -keyfile=\"$rrtemp\"."
                );
            }
            my $hkcuresult =
`$startasuser ///timeout=10 ///silent $ldms_client_regreader -keyfile="$rrtemp"`;

            if ( !$hkcuresult ) {

                open( $RRTEMP, '<', "$rrtemp" )
                  or &LogWarn("Cannot open $rrtemp for reading: $!");
                while (<$RRTEMP>) {

                    my ( $hkcukey, $subkey, $value ) = split(/,/);
                    chomp($value);
                    print $FILE
                      "Custom Data - HKCU - $hkcukey - $subkey = $value\n";
                }
                close($RRTEMP);
                unlink($rrtemp)
                  or &LogWarn("Cannot delete temp file $rrtemp: $!");
            }
        }
        else {
            &LogWarn("$ldms_client_regreader missing, cannot read registry");
        }
    }
    else {
        &LogWarn("$startasuser missing, cannot read registry");
    }

    return 0;
}
### End of CallRegistryReader sub #############################################

### CallRegistryInfo sub ######################################################
sub CallRegistryInfo {
    if ($DEBUG) { &Log("CallRegistryInfo: Looking for HKLM Registry keys"); }
    my ( $type, $key );
    my $HKLMKey = $Registry->{"HKEY_LOCAL_MACHINE/"}
      or &LogWarn("Cannot open the HKLM hive for reading! $^E");

    # Read in the .ini keys I need to look for
    for my $rii ( 1 .. 10 ) {

        # For each key, dig in HKLM and write the value out
        if ( my $hklmkey = $ri[$rii] ) {

            $hklmkey = &trimkey($hklmkey);

            # Registry reading differentiates between key and path.
            # Split it up into components
            my @parts = split( /\//, $hklmkey );

            # Pop off the last subkey
            my $subkey = pop(@parts);

            # Join everything else back together
            $hklmkey = join( "/", @parts );
            if ( defined($hklmkey) && defined($subkey) ) {
                if ($DEBUG) {
                    &Log(
"Read processed input of $hklmkey, $subkey from configuration file"
                    );
                }
                my $value;
                if ( $RegKey->{$hklmkey}->{$subkey} ) {
                    ( $value, $type ) = $RegKey->{$key}->GetValue("$subkey");
                    if ( defined($value) ) {
                        if (   $type == REG_SZ()
                            or $type == REG_EXPAND_SZ()
                            or $type == REG_MULTI_SZ() )
                        {

                            # It's a string, don't need to do anything special
                        }
                        elsif ( $type == REG_DWORD() or $type == REG_BINARY() )
                        {

                            # It's a binary value and must be unpacked
                            # This will only work if it's four bytes or less
                            $value = unpack( "L", $value );
                        }
                        else {
                            &LogWarn(
                                "$key $subkey is an unsupported type: $type");
                        }
                        if ($DEBUG) { &Log("Read output of $value"); }
                    }
                    else {
                        if ($DEBUG) { &Log("$hklmkey $subkey has no value"); }
                    }
                }
                else {
                    if ($DEBUG) { &Log("Found nothing at $hklmkey $subkey"); }
                    $value = "NULL";
                }
                print $FILE
                  "Custom Data - HKLM - $hklmkey - $subkey = $value\n";
            }
        }
    }
    return 0;
}
### End of CallRegistryInfo sub ###############################################

### CallProdukey sub ##########################################################
sub CallProdukey {

    if ($DEBUG) { &Log("CallProdukey: Looking for Microsoft product keys"); }

    # Locate produkey binary
    my $produkey = $ldclient . "/produkey.exe";
    if ($ProdukeyBinary) { $produkey = $ProdukeyBinary; }
    my $produkeydat = $ldclient . "/produkeydat.csv";
    if ( -e $produkey ) {

        my $version = GetFileVersionInfo($produkey);
        my $pk_version;
        if ($version) {
            $pk_version = $version->{FileVersion};

         # Remove the dots and convert to an integer so that we can do numerical
         # comparison... e.g., version 8.80.0.249 is rendered as 8800249
            $pk_version =~ s/\.?(?=[0-9])//g;

          # If I just use the first three numbers, that should work well enough.
            $pk_version = substr( $pk_version, 0, 3 );
            $pk_version = &atoi($pk_version);
            if ($DEBUG) { &Log("DEBUG: Produkey version is $pk_version"); }
        }
        else {
            &LogWarn("Cannot determine Produkey version from $produkey");
            return 1;
        }
        if ( $pk_version < 126 ) {
            &LogWarn(
                "CallProdukey: $produkey is too old, should be 1.2.6 or better"
            );
            return 1;
        }

        # Call it
        my $produkeyResult = `$produkey /scomma $produkeydat`;
        if ( $? != 0 ) { &LogWarn("Produkey run error: $! $?"); }

        # Read results
        if ( -e $produkeydat ) {

            open( $PKDFILE, '<', "$produkeydat" )
              or &LogWarn("Can't open $produkeydat: $!");
            while (<$PKDFILE>) {
                my (
                    $pk_name,    $pk_id, $pk_key,
                    $pk_install, $pk_sp, $pk_machine
                ) = split(/,/);
                if ($pk_sp) {
                    $pk_name = $pk_name . " " . $pk_sp;
                }
                print $FILE "Licenses - $pk_name - product_id = $pk_id\n";
                print $FILE "Licenses - $pk_name - product_key = $pk_key\n";
                print $FILE
                  "Licenses - $pk_name - installation_folder = $pk_install\n";
            }
            close($PKDFILE);
            unlink($produkeydat)
              or &Logwarn("Cannot delete temp file $produkeydat: $!");
        }
    }
    else {
        &LogWarn("$produkey not found");
    }
    return 0;
}
### End of CallProdukey sub ###################################################

### CallDCCUWol sub ##########################################################
sub CallDCCUWol {

    if ($DEBUG) { &Log("CallDCCUWol Looking for Dell Wake-on-LAN status"); }

    # Locate getwol binary
    my $getwol;
    if ($DCCUWolBinary) { $getwol = $DCCUWolBinary; }

    # The pre-3.0 DCCU file
    my $getwoldat = dirname($getwol) . "/DCCUResults_SUCCESS.xml";
    if ( !-e $getwoldat ) {

        # The 3.x DCCU file
        $getwoldat = dirname($getwol) . "/TaskResult.xml";
    }

    # If it was already run, I can just read the dat file
    # Otherwise, I need to run getwol... if it exists
    if ( !-e $getwoldat ) {
        if ( -e $getwol ) {

            # Call it
            my $getwolResult = `$getwol`;
            if ( $? != 0 ) { &LogWarn("$getwol run error: $! $?"); }
        }
    }

    # Read results... by now we ought to have some.
    if ( -e $getwoldat ) {

#this is technically an xml file, but opening it as XML looks like
#a waste of everyone's time. Here's a sample:
# <?xml version="1.0"?>
# <root>
# <command name="get">
# <property name="WakeupOnLAN" ischecked="1" value="6" outcome="OK" errorcode="0x0"/>
# </command>
# </root>
        my ( $GETWOLDAT, $line, $wolresult );
        open( $GETWOLDAT, '<', "$getwoldat" )
          or &LogWarn("Can't open $getwoldat for reading: $!");
        while ( $line = <$GETWOLDAT> ) {
            if ( $line =~ m/property name/ix ) {
                if ( $line =~ /WakeupOnLAN\"/ix ) {
                    my @properties = split( ' ', $line );
                    foreach my $property (@properties) {
                        if ( $property =~ m/value/ix ) {

                            # second to last character
                            $wolresult = substr( $property, -2, 1 );
                        }
                    }
                }
            }
        }
        close $GETWOLDAT;

        # 2: Unsupported
        # 3: Disabled
        # 4: Enabled for add-in NIC
        # 5: Enabled for on-board NIC
        # 6: Enabled for all NICs
        # 7: Enabled with boot to NIC

        if ( $wolresult < 2 or $wolresult > 7 ) {
            print $FILE "BIOS - WakeOnLAN = $wolresult\n";
        }
        if ( $wolresult == 2 ) {
            print $FILE "BIOS - WakeOnLAN = Unsupported\n";
        }
        if ( $wolresult == 3 ) {
            print $FILE "BIOS - WakeOnLAN = Disabled\n";
        }
        if ( $wolresult == 4 ) {
            print $FILE "BIOS - WakeOnLAN = Enabled for add-in NIC\n";
        }
        if ( $wolresult == 5 ) {
            print $FILE "BIOS - WakeOnLAN = Enabled for on-board NIC\n";
        }
        if ( $wolresult == 6 ) {
            print $FILE "BIOS - WakeOnLAN = Enabled for all NICs\n";
        }
        if ( $wolresult == 7 ) {
            print $FILE "BIOS - WakeOnLAN = Enabled with boot to NIC\n";
        }
    }
    else {
        &LogWarn("$getwoldat not available");
    }
    return 0;
}
### End of CallProdukey sub ###################################################

### CallSID sub ###############################################################
#http://www.droppedpackets.org/inventory-and-slm/quick-and-dirty-machine-sid-into-inventory/
sub CallSID {
    if ($DEBUG) { &Log("CallSID: Looking for Machine SID"); }
    my ( $system, $domain ) = Win32::NodeName;
    my $account = Win32::LoginName;
    no warnings 'uninitialized';
    my ( $sid, $sidtype );
    Win32::LookupAccountName( $system, $account, $domain, $sid, $sidtype );
    my $sidstring = &trim( Win32::Security::SID::ConvertSidToStringSid($sid) );
    print $FILE "Machine SID = $sidstring\n";
    if ($DEBUG) { &Log("CallSID: Looking for Machine FQDN"); }
    my $fqdn = &trim( fqdn() );
    print $FILE "Network - TCPIP - FQDN = $fqdn\n";
    return 0;
}
### End of CallSID sub ########################################################

### Logging subroutine ########################################################
sub Log {
    my $msg = shift;
    if ( !defined($msg) ) { $msg = "Log: Can't report nothing"; }
    open( $LOG, '>>', "$logfile" ) or die "Can't open $logfile - $!";
    $LOG->autoflush();
    print $LOG localtime() . ": $msg\n";
    close($LOG);
    return 0;
}

### Logging with warning subroutine ###########################################
sub LogWarn {
    my $msg = shift;
    if ( !defined($msg) ) { $msg = "LogWarn: Can't report nothing"; }
    open( $LOG, '>>', "$logfile" ) or die "Can't open $logfile - $!";
    $LOG->autoflush();
    print $LOG localtime() . ":WARN: $msg\n";
    close($LOG);
    return 0;
}

### Logging with death subroutine #############################################
sub LogDie {
    my $msg = shift;
    if ( !defined($msg) ) { $msg = "LogDie Can't report nothing"; }
    open( $LOG, '>>', "$logfile" ) or die "Can't open $logfile - $!";
    $LOG->autoflush();
    print $LOG localtime() . ":DIE: $msg\n";
    close($LOG);
    exit 1;
}

### Trim subroutine ###########################################################
sub trim {
    my $string = shift;
    unless ( !defined($string) ) {
        $string =~ s/^\s+|\s+$//;
        $string =~ s/\'|\"//g;
        $string =~ s/\n|\r//g;
        $string =~ s/ //g;
    }
    return $string;
}

### Format numbers with commas ################################################
sub commify {
    local ($_) = shift;
    1 while s/^(-?\d+)(\d{3})/$1,$2/;
    return $_;
}

### ASCII to Integer subroutine ###############################################
sub atoi {
    my $t = 0;
    foreach my $d ( split( //, shift() ) ) {
        $t = $t * 10 + $d;
    }
    return $t;
}

### trimkey subroutine ######################################################
sub trimkey {
    my $input = my $string = shift;
    unless ( !defined($string) ) {

        # Replace backslashes with forward slashes
        $string =~ s/\\/\//g;

        # Remove beginning slashes (forward or backward)
        $string =~ s/^\/|^\\//g;

        # Remove beginning references to the registry hive
        $string =~ s/^HKCU\/|^HKEY_CURRENT_USER\///g;
    }
    if ($DEBUG) { &LogWarn("trimkey: trimmed $input to $string"); }
    return $string;
}

# Return the local time in seconds since the epoch ############################
sub _localtime_in_sec {
    require Time::Local;
    return 2.0 * CORE::time() - Time::Local::timelocal(gmtime);
}

# Extract specific information out of a date ##################################
sub _extract_from_date {
    my ( $date, $method, $format ) = @_;
    return unless $date;
    unless ( UNIVERSAL::isa( $date, "Win32::OLE::Variant" ) ) {
        $date = Variant( VT_DATE, $date );
    }
    return $date->$method( $format, $lcid );
}

# Format number per locale ####################################################
sub FormatNumber {
    my (
        $number,         $DecimalPlaces, $IncLeadingZero,
        $UseParenthesis, $groupDigits
    ) = @_;
    my $format = {};
    $format->{NumDigits}     = $DecimalPlaces  if defined $DecimalPlaces;
    $format->{LeadingZero}   = $IncLeadingZero if defined $IncLeadingZero;
    $format->{NegativeOrder} = 0               if $UseParenthesis;
    if ( defined $groupDigits ) {
        if ( !$groupDigits ) {
            $format->{Grouping} = 0;
        }
        else {
            my $sgroup = GetLocaleInfo( $lcid, LOCALE_SGROUPING );
            $sgroup =~ s/\D.*//;
            $format->{Grouping} = $sgroup;
        }
    }
    my $v = Variant( VT_R8, $number );
    $v = $v->Number( $format, $lcid );
    return $v;
}

# Percentify numbers ##########################################################
sub FormatPercent {
    my $number = shift;
    my $v = FormatNumber( $number * 100, $number );
    $v = "$v\%";
    $v =~ s/\)%$/%)/;
    return $v;
}

# Use substr to get specific chunks from WMI data #############################
sub Mid {
    my ( $substr, $start, $len ) = @_;
    $start--;
    return defined $len
      ? substr( $substr, $start, $len )
      : substr( $substr, $start );
}

# Convert WMI Dates to Useful Dates ###########################################
sub WMIDateStringToDate {
    my ($dtmWMIDate) = @_;
    if ( !!($dtmWMIDate) ) {
        return Variant( VT_DATE,
                Mid( $dtmWMIDate, 5, 2 ) . '/'
              . Mid( $dtmWMIDate, 7, 2 ) . '/'
              . substr( $dtmWMIDate, 0, 4 ) . ' '
              . Mid( $dtmWMIDate, 9,  2 ) . ':'
              . Mid( $dtmWMIDate, 11, 2 ) . ':'
              . Mid( $dtmWMIDate, 13, 2 ) );
    }
    return 0;
}

