#############################################################################
# ldms_client.pl                                                            #
# (c) 2008-2009 Jack Coates, jack@monkeynoodle.org                          #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.droppedpackets.org/inventory-and-slm/ldms_client               #
#############################################################################
#
# TODO - Currently attached SSID -- http://community.landesk.com/support/message/18826
# TODO - Further aggression level to search all attached drives
# TODO - Vista compatibility for policy, profile
# TODO - Recursive registry search for mounted PSTs. The walk begins at
# HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging
# Subsystem\Profiles\Default Outlook Profile (or one level up) and we need to look
# for all values of 001f6700 (001e6700 for W2K) and then convert the reg_binary
# values into text.
# TODO - Oh, hey, how about a feature request while I am at it... any way to gather 
# information on mapped network printers?  It is in HKCU under Printers\Connections 
# but each printer is set up with its own key based on the network printer path 
# making it a slightly different problem than pulling values from known keys.
# TODO - wildcard registry keys. Need a subroutine that recurses a registry
# path, could use for PST and printer search too.

package ldms_client;
#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use strict;
use warnings;
use Env;
use Cwd;
use DBI;
use Getopt::Long;
use IO::Handle;
use Win32;
use Win32::EventLog;
use Win32API::Net;
use Win32::File::VersionInfo;
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
use Number::Bytes::Human qw(format_bytes);
use File::Find;
use File::Basename;
use Readonly;
use Sys::Hostname::FQDN qw( fqdn );
use Carp ();
local $SIG{__WARN__} = \&Carp::cluck;

#############################################################################
# Variables                                                                 #
#############################################################################
my ( $DEBUG, $help ) = '';
GetOptions(
    '/',
    'debug' => \$DEBUG,
    'help'  => \$help,
);

( my $prog = $0 ) =~ s/^.*[\\\/]//x;
my $VERSION = "2.4.6";

my $usage = <<"EOD";

Usage: $prog [/d] [/h]
	/d(ebug)    debug
	/h(elp)     this display

$prog v $VERSION
Jack Coates, jack\@monkeynoodle.org, released under GPL
This program will extend the LANDesk Inventory using custom data.
The latest version lives at 
http://www.droppedpackets.org/inventory-and-slm/ldms_client/

EOD

croak($usage) if $help;

my $core = &FindCoreName;
my $strComputer = '.';
my $basedir = "C:\\Progra~1";
if ($PROGRAMFILES) {
    $basedir = Win32::GetShortPathName($PROGRAMFILES);
}
my $ldclient = $basedir . "\\LANDesk\\LDClient";
my $sdcache = $ldclient . "\\sdmcache";
my $file = $ldclient . '\\data\\ldms_client.dat';

my $netstatcommand = 'netstat -an';

my ( $totalpstsize,  $totalostsize,  $totalnsfsize )  = 0;
my ( $totalpstcount, $totalostcount, $totalnsfcount ) = 0;

# File handles I'll need
my ( $FILE, $PSFILE, $PKDFILE, $RRTEMP, $MDTEMP );

# Global variables
my ($RegKey);

# Prepare logging system
my $logfile = $ldclient . "\\ldms_client.log";
my $LOG;
open( $LOG, '>', $logfile ) or croak("Cannot open $logfile - $!");
print $LOG localtime() . " $prog $VERSION starting.\n";
close($LOG);

#############################################################################
# Main Loop                                                                 #
#############################################################################

# Suppress DOS Windows
BEGIN {
    Win32::SetChildShowWindow(0) if defined &Win32::SetChildShowWindow;
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

my $lcid;

BEGIN {
    $lcid = GetUserDefaultLCID();
    Win32::OLE->Option( LCID => $lcid );
}

# Get the config file
my $configfile = &FindConfigFile;

# Read it
my $Config = Config::Tiny->new();
$Config = Config::Tiny->read("$configfile")
  || &LogDie( "Can't read $configfile : ", Config::Tiny->errstr() );

# If I'm running as a user with no administrative rights, I should bail out.
# This is not strictly necessary, but it causes a crash on some locked down
# systems. Scheduled and CBA-driven scans are running as localsystem, this
# only affects scans that are started by an interactive user on the client.
my $NonAdminBail = $Config->{_}->{NonAdminBail};
if ($NonAdminBail) {
    if ( !&IsAdmin ) {
        &LogDie("Running without privileges disabled by administrator.");
    }
}

my $coreversion = $Config->{version}->{Version};
if ( $coreversion ne $VERSION ) {
    &LogWarn( "ldms_client version is different on the core, "
          . "this could potentially lead to inventory problems." );
}

# Reading properties
my $Battery         = $Config->{_}->{Battery};
my $Netstat         = $Config->{_}->{Netstat};
my $PolicyList      = $Config->{_}->{PolicyList};
my $FindPST         = $Config->{_}->{FindPST};
my $FindOST         = $Config->{_}->{FindOST};
my $FindNSF         = $Config->{_}->{FindNSF};
my $AggroMailSearch = $Config->{_}->{AggroMailSearch};
my $FindProfileSize = $Config->{_}->{FindProfileSize};
my $NICDuplex       = $Config->{_}->{NICDuplex};
my $EnumerateGroups = $Config->{_}->{EnumerateGroups};
my $LANDeskInfo     = $Config->{_}->{LANDeskInfo};
my $RegistryReader  = $Config->{_}->{RegistryReader};
my $RegistryInfo    = $Config->{_}->{RegistryInfo};
my $Produkey        = $Config->{_}->{Produkey};
my $ProdukeyBinary  = $Config->{_}->{ProdukeyBinary};
my $DCCUWol         = $Config->{_}->{DCCUWol};
my $DCCUWolBinary   = $Config->{_}->{DCCUWolBinary};
my $SID             = $Config->{_}->{SID};
my $MappedDrives    = $Config->{_}->{MappedDrives};
my $CrashReport     = $Config->{_}->{CrashReport};
my $DefragNeeded    = $Config->{_}->{DefragNeeded};

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

# Prepare the report file
open( $FILE, '>', "$file" ) or croak("Can't open $file - $!");
close $FILE;

# How about if I log my own version?
&ReportToCore("Custom Data - $prog - version = $VERSION");

# Get my info
&RunTests;

# Clean up... shut down OLE object, Registry object, delete configs
$objShell = undef;

# Don't test for failure on these unlinks -- the config file might not be
# there to delete, and that's a good thing
unlink "$ldclient/ldms_client.ini";
unlink "$sdcache/ldms_client.ini";
&Log("$prog $VERSION exiting.");

#############################################################################
# Subroutines                                                               #
#############################################################################

### Do I have rights? #######################################################
sub IsAdmin {
    my $Server = "";
    my %CallerUserInfo;
    my $Caller = getlogin;

    # LocalSystem isn't an admin, but is still able to do the deeds
    if ( $Caller eq "SYSTEM" ) { return 1; }
    Win32API::Net::UserGetInfo( $Server, $Caller, "1", \%CallerUserInfo );
    if ($DEBUG) { &Log("IsAdmin got $CallerUserInfo{priv} for $Caller"); }

    return $CallerUserInfo{priv};
}
### end of IsAdmin ##########################################################

### Find my core server #####################################################
sub FindCoreName {
    my $output = "";
    # Tie registry to find 
    # HKEY_LOCAL_MACHINE\SOFTWARE\Intel\LANDesk\LDWM CoreServer
    $RegKey = $Registry->{"HKEY_LOCAL_MACHINE/Software/Intel/LANDesk/LDWM"};
    if ($RegKey) {
        $output = $RegKey->GetValue("CoreServer");
    }
    else {
        &Log(
"can't find core server name in HKLM/Software/Intel/LANDesk/LDWM CoreServer."
        );
        $output = "";
    }
    return $output;
}
### end of FindCoreName #####################################################

### Find my configuration ###################################################
# Read my configuration file from the core.
# Eventually, this will need to be downloaded from the core and cached/aged
sub FindConfigFile {

    my $output;

    if ($DEBUG) {
        &Log(   "Core server is $core, client directory is $ldclient, "
              . "Output file is $file" );
    }

    # First try to read the cofig file directly from the server
    $output = "\\\\$core\\ldlogon\\ldms_client.ini";
    if ( !-e $output ) {
        if ($DEBUG) { &Log("Didn't see $output, trying with sdclient."); }

        # download the file with sdclient from http, read it,
        # then delete it after inventory scanning is complete.
        my $sdclient =
            $ldclient
          . '\\sdclient.exe /f /p="http://'
          . $core
          . '/ldlogon/ldms_client.ini"';
        system($sdclient);
        $configfile = $sdcache . "\\ldms_client.ini";
        if ( !-e $output ) {
            if ($DEBUG) {
                &Log(   "Ran $sdclient, but didn't see $output, "
                      . "trying in $ldclient now." );
            }
            $output = $ldclient . "\\ldms_client.ini";
            if ( !-e $output ) {
                if ($DEBUG) { &Log("Didn't see $configfile, giving up."); }
                &LogDie("Unable to get configuration from core server. ");
            }
        }
    }
    return $output;
}
### End of FindConfigFile #####################################################

### RunTests subroutine #######################################################
sub RunTests {

    # need to test if configuration file asked for each of these
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
    if ($FindOST) {
        &CallFindOST;
    }
    if ($FindNSF) {
        &CallFindNSF;
    }
    if ($FindProfileSize) {
        &CallFindProfileSize;
    }
    if ($NICDuplex) {
        &CallNICDuplex;
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
    if ($MappedDrives) {
        &CallMappedDrives;
    }
    if ($Produkey) {
        &CallProdukey;
    }
    if ($DCCUWol) {
        if (&IsDell) {
            &CallDCCUWol;
        }
    }
    if ($SID) {
        &CallSID;
    }
    if ($CrashReport) {
        &CallCrashReport;
    }
    if ($DefragNeeded) {
        &CallNeedsDefrag;
    }
    return 0;
}
### End of RunTests ###########################################################

### Ask WMI if this is Dell hardware we're on #################################
sub IsDell {
    my $output = 'unknown';
    my $SystemList = $objWMIService->ExecQuery("SELECT * FROM Win32_ComputerSystem");
    if ( $SystemList->Count > 0 ) {
        foreach my $System ( in $SystemList) {
            $output = $System->Manufacturer;
            if ($DEBUG) { &Log("IsDell found $output"); }
        }
    }
    if ($output =~ m/DELL/i) {
        return 1;
    } else {
        return 0;
    }
}
### End of IsDell sub ########################################################

### Look for System crashes in the Event Viewer ##############################
# Need to limit this to a single day's data ##################################
sub CallCrashReport {

    if ($DEBUG) { &Log("CallCrashReport looking for system crashes"); }
    # I'll need a handle to do this with
    my $EventViewerhandle = Win32::EventLog->new( "System", $COMPUTERNAME )
      or &LogWarn("Initialization: Can't open System EventLog");

    my %Event;
    my $BSODcount = 0;

    # One week ago
    my $TIME_LIMIT = time() - 604800;
    while (
        $EventViewerhandle->Read(
            EVENTLOG_FORWARDS_READ | EVENTLOG_SEQUENTIAL_READ,
            0, \%Event
        )
      )
    {
        if ( $Event{TimeGenerated} >= $TIME_LIMIT ) {
            if ( $Event{Source} eq "EventLog" && $Event{EventType} == 1 ) {
                my $eventid = eval($Event{EventID} & 0xffff);
                if ( $eventid == 6008 ) {
                    $BSODcount++;
                    if ($DEBUG) {
                        my $text = $Event{Strings};
                        if ( defined($text) ) {
                            &Log("Crash detected: $text" );
                        }
                    }
                }
            }
       }
    }
    # Let the eventlog go
    $EventViewerhandle->Close();

    # Log what happened
    if ( $BSODcount > 0 ) {
        &ReportToCore(
        "System - Crashes in last seven days = $BSODcount"
        );
    }
    return 0;
}
###############################################################################


### Wrapper for getting Battery Information from two different WMI points #####
sub CallBattery {

    if ($DEBUG) { &Log("CallBattery: Looking for battery information"); }

    # First try to get data from the PortableBattery object
    my $query = "SELECT * FROM Win32_PortableBattery";
    &ReadBattery($query);

    # Then see what the Battery object has.
    # This may overwrite values found from PortableBattery.
    $query = "SELECT * FROM Win32_Battery";
    &ReadBattery($query);

    return 0;
}
### End of CallBatteryInfo sub ################################################

### Get Battery Information ###################################################
sub ReadBattery {

    my $input = shift;
    if ($DEBUG) { &Log("ReadBattery: Asking WMI for $input"); }

    # Battery-specific variables
    my (
        $BatteryLabel,  $BatteryID,           $Chemistry,
        $ChemistryCode, $BatteryName,         $Capacity,
        $BatteryDate,   $BatteryManufacturer, $BatteryLocation,
        $BatteryStatus
    );
    my $x           = 0;
    my $BatteryList = $objWMIService->ExecQuery("$input");
    if ( $BatteryList->Count > 0 ) {
        foreach my $Battery ( in $BatteryList) {
            $x++;
            if ($DEBUG) { &Log("ReadBattery: Processing battery $x"); }
            if ( $Battery->Description ) {
                $BatteryLabel = $Battery->Description;
            }
            else {
                $BatteryLabel = "Portable Battery $x";
            }
            if ( $Battery->DeviceID ) {
                $BatteryID = $Battery->DeviceID;
                &ReportToCore(
                    "Battery - $BatteryLabel - DeviceID = $BatteryID");
            }
            if ( $Battery->Manufacturer ) {
                $BatteryManufacturer = $Battery->Manufacturer;
                &ReportToCore(
"Battery - $BatteryLabel - Manufacturer = $BatteryManufacturer"
                );
            }
            if ( $Battery->ManufactureDate ) {

                $BatteryDate = $Battery->ManufactureDate;
                $BatteryDate = WMIDateStringToDate($BatteryDate);
                &ReportToCore(
                    "Battery - $BatteryLabel - ManufactureDate = $BatteryDate"
                );
            }
            if ( $Battery->InstallDate ) {
                $BatteryDate = $Battery->InstallDate;
                $BatteryDate = WMIDateStringToDate($BatteryDate);
                &ReportToCore(
                    "Battery - $BatteryLabel - InstallDate = $BatteryDate");
            }
            if ( $Battery->Name ) {
                $BatteryName = $Battery->Name;
                &ReportToCore("Battery - $BatteryLabel - Name = $BatteryName");
            }
            if ( $Battery->Chemistry ) {

                $ChemistryCode = $Battery->Chemistry;

                # Get a useful value for Chemistry
                $Chemistry = &DecodeChemistry;
                &ReportToCore(
                    "Battery - $BatteryLabel - Chemistry = $Chemistry");
            }
            if ( $Battery->Location ) {
                $BatteryLocation = $Battery->Location;
                &ReportToCore(
                    "Battery - $BatteryLabel - Location = $BatteryLocation");
            }
            if ( $Battery->DesignCapacity ) {
                if ( $Battery->FullChargeCapacity ) {
                    $Capacity =
                      &FormatPercent( $Battery->FullChargeCapacity /
                          $Battery->DesignCapacity );
                    &ReportToCore(
                        "Battery - $BatteryLabel - Capacity = $Capacity");
                }
            }
            if ( $Battery->Status ) {
                $BatteryStatus = $Battery->Status;
                &ReportToCore(
                    "Battery - $BatteryLabel - Status = $BatteryStatus");
            }
        }
    }
    else {
        if ($DEBUG) { &Log("No battery found"); }
    }
    return 0;
}
### End of ReadBattery sub ####################################################

### DecodeChemistry sub #######################################################
sub DecodeChemistry {
    my $input = shift;
    if ($input) {
        my $output =
            $input == 1 ? 'Other'
          : $input == 2 ? 'Unknown'
          : $input == 3 ? 'Lead Acid'
          : $input == 4 ? 'Nickel Cadmium'
          : $input == 5 ? 'Nickel Metal Hydride'
          : $input == 6 ? 'Lithium Ion'
          : $input == 7 ? 'Zinc Air'
          : $input == 8 ? 'Lithium Polymer'
          :               'UNDETERMINED';

        if ($DEBUG) {
            &Log("DecodeChemistry: received $input, returned $output");
        }
        return $output;
    }
    else {
        if ($DEBUG) {
            &Log("DecodeChemistry: Called with nothing to do");
        }
        return 0;
    }

}
### End of DecodeChemistry sub ################################################

###  CallNetstat sub ##########################################################
sub CallNetstat {
    if ($DEBUG) { &Log("CallNetstat: Looking for open network ports"); }
    my @netstat = `$netstatcommand`;
    foreach my $i (@netstat) {
        &Trim($i);
        ## no critic
        if ( $i =~ /^$/ )         { next; }
        if ( $i =~ /^Active/i )   { next; }
        if ( $i =~ /\sProto\s/i ) { next; }
        ## use critic
        my @port;
        my @line = split( ' ', $i );
        if ( $line[0] =~ /TCP/ && $line[3] =~ /LISTENING/i ) {
            @port = split( ':', $line[1] );
            &ReportToCore(
                "Netstat - Open Port - $line[0] - $port[1] = $line[0]/$port[1]"
            );
        }
        if ( $line[0] =~ /UDP/i ) {
            @port = split( ':', $line[1] );
            &ReportToCore(
                "Netstat - Open Port - $line[0] - $port[1] = $line[0]/$port[1]"
            );
        }
    }
    if ($DEBUG) { &Log("CallNetstat: Finished"); }
    return 0;
}
### End of CallNetstat sub ####################################################

###  CallPolicyList sub #######################################################
sub CallPolicyList {

    if ($DEBUG) { &Log("CallPolicyList: Looking for LANDesk policies"); }

    # What LANDesk version are we working with?
    # Might be better to check for existence of policy.*.exe files in ldclient,
    # but 8.7 service packs 4 and 5 may have had pre-work in them...
    my $ldms_version;
    my $versionfile = Win32::GetShortPathName($PROGRAMFILES);
    $versionfile .= "\\LANDesk\\LDClient\\ldiscn32.exe";
    if ($DEBUG) { &Log("CallPolicyList: versionfile is $versionfile"); }
    my $version = GetFileVersionInfo($versionfile);
    if ($version) {
        $ldms_version = $version->{FileVersion};

        # Remove the dots and convert to an integer so that we can do numerical
        # comparison... e.g., version 8.80.0.249 is rendered as 8800249
        $ldms_version =~ s/\.?(?=[0-9])//gx;

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
            &ReportToCore(
"LANDesk Management - APM - Policies - $PolicyName - GUID = $PolicyGUID"
            );
            &ReportToCore(
"LANDesk Management - APM - Policies - $PolicyName - Description = $PolicyInfoDesc"
            );
            &ReportToCore(
"LANDesk Management - APM - Policies - $PolicyName - Status = $PolicyStatus"
            );
        }
    }
    else {

        # If it's 8.8 or post, we're looking in SQLite
        my $dbfile = Win32::GetShortPathName($ALLUSERSPROFILE);
        $dbfile .=
"\\Application\ Data\\LANDesk\\ManagementSuite\\Database\\LDClientDB.db3";
        $dbfile = Win32::GetShortPathName($dbfile);

        # Does it exist? Is it bigger than zero?
        if ( -e $dbfile && -s $dbfile ) {

            if ($DEBUG) {
                &Log("CallPolicyList: Searching in database $dbfile");
            }

            my $dbh = DBI->connect( "dbi:SQLite:dbname=$dbfile", "", "" )
              or &LogWarn("Can't open $dbfile - $!");

            if ($dbh) {

                my $sql =
"select name,filename,description,status from PortalTaskInformation";

                my $sth = $dbh->prepare($sql)
                  or &LogWarn("Policy database prepare statement failed!: $!");
                $sth->execute()
                  or &LogWarn("Policy database execute statement failed: $!");
                while ( my @row = $sth->fetchrow_array() ) {
                    &ReportToCore(
"LANDesk Management - APM - Policies - $row[0] - GUID = $row[1]"
                    );
                    &ReportToCore(
"LANDesk Management - APM - Policies - $row[0] - Description = $row[2]"
                    );
                    &ReportToCore(
"LANDesk Management - APM - Policies - $row[0] - Status = $row[3]"
                    );
                }
            }
        }
        else {
            if ($DEBUG) { &Log("Policy database file $dbfile is not present"); }
        }

    }

    # And we're all done here
    if ($DEBUG) { &Log("CallPolicyList: Finished"); }
    return 0;
}
### End of CallPolicyList sub #################################################

###  CallNICDuplex sub ########################################################
sub CallNICDuplex {

    # This stuff is pretty complex, so here's a walk-through
    # get every NIC from the registry, filter out the ones that are known junk
    # Use DecodeDriverType to figure out which class of NICs it is
    # Use DecodeMode to figure out how it's configured
    # Find some standard (and rarely used) values. LookupWoL and LookupWoLLink
    # support this activity.
    if ($DEBUG) { &Log("CallNICDuplex: Looking for NIC Settings"); }
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
        if ( &SkipNIC($DriverName) ) {
            if ($DEBUG) { &Log("CallNICDuplex: Skipping $nic"); }
            next;
        }

        # Not one of the bogus drivers, so let's look at DuplexMode
        my ( $DuplexMode, $drivertype ) =
          &DecodeDriverType( $DuplexRegEntry, $DriverName );
        my $ReportedMode;

# If nothing was detected at all, the interface is probably defaulting to auto-detect
        if ( !$drivertype ) {
            if ($DEBUG) {
                &Log(   "CallNICDuplex: $DriverName doesn't seem to "
                      . "have a known type, assuming AutoDetect" );
            }
            $ReportedMode = 'Auto Detect';
        }
        else {

            # Decode the number to something useful.
            $ReportedMode = &DecodeMode( $drivertype, $DuplexMode );

            # Okay to report
            if ($ReportedMode) {
                &ReportToCore(
                    "NIC - $DriverName - Duplex Mode = $ReportedMode");
            }
        }

        # Just for giggles, let's see about Media Type and Wake on LAN status.
        # Media
        my $NICMedia = $DuplexRegEntry->GetValue("Media");
        if ($NICMedia) {
            &ReportToCore("NIC - $DriverName - Media = $NICMedia");
        }
        my $NICMediaType = $DuplexRegEntry->GetValue("Media_Type");
        if ($NICMediaType) {
            &ReportToCore("NIC - $DriverName - Media Type = $NICMediaType");
        }

        # Wake On LAN
        my $NICWOL = $DuplexRegEntry->GetValue("WakeOn");
        if ($NICWOL) {

# This has to be decoded too... $DIETY grant that it's more standard than duplex mode
            $NICWOL = &LookupWoL($NICWOL);
            &ReportToCore("NIC - $DriverName - Wake On = $NICWOL");
        }
        my $NICWOLLink = $DuplexRegEntry->GetValue("WakeOnLink");
        if ($NICWOLLink) {
            $NICWOLLink = &LookupWoLLink($NICWOLLink);
            &ReportToCore("NIC - $DriverName - Wake On Link = $NICWOLLink");
        }
    }
    return 0;
}
### End of CallNICDuplex sub ##################################################

###  SkipNICsub ##############################################################
sub SkipNIC {
    my $DriverName = shift;
    if ( !$DriverName ) {

        # Return positive value to skip the NIC
        return 1;
    }
    if (   $DriverName eq '1394 Net Adapter'
        || $DriverName eq 'Direct Parallel'
        || $DriverName eq 'RAS Async Adapter'
        || $DriverName =~ m/VPN/
        || $DriverName =~ m/Miniport/
        || $DriverName =~ m/Virtual Ethernet Adapter/ )
    {
        return 1;
    }
    else {

        # return zero to allow NIC processing
        return 0;
    }
}
### End of SkipNIC sub #######################################################

### DecodeDriverType sub ######################################################
sub DecodeDriverType {

    my ( $NICHandle, $NICName ) = @_;
    my ( $DuplexMode, $output, $message );
    if ($NICHandle) {

        $message = "DecodeDriverType: $NICName seems to be ";

        # Realtek, 3Com
        $DuplexMode = $NICHandle->GetValue("DuplexMode");
        if ($DuplexMode) {
            $message .= "a Realtek or 3Com.";
            $output = 1;
        }

        # Intel cards
        $DuplexMode = $NICHandle->GetValue("SpeedDuplex");
        if ($DuplexMode) {
            $message .= "an Intel.";
            $output = 1;
        }

        # Broadcom NetXtreme Gigabit Ethernet
        $DuplexMode = $NICHandle->GetValue("RequestedMediaType");
        if ($DuplexMode) {
            $message .= "a Broadcom.";
            $output = 2;
        }

        # AMD, VMWare (though VMWare is filtered out anyway)
        $DuplexMode = $NICHandle->GetValue("EXTPHY");
        if ($DuplexMode) {
            $message .= "an AMD or VMware.";
            $output = 3;
        }

        # VIA, Davicom
        $DuplexMode = $NICHandle->GetValue("ConnectionType");
        if ($DuplexMode) {
            $message .= "a VIA or Davicom.";
            $output = 3;
        }
    }
    if ( $DEBUG && $output ) { &Log($message); }
    return $DuplexMode, $output;
}
### End of DecodeDriverType sub ##############################################

### LookupWoL sub ############################################################
sub LookupWoL {
    my $input  = shift;
    my $output = 'UNKNOWN';
    my %lookup = (

        # WMI value => means in English
        '0'   => 'Disabled',
        '6'   => 'Wake on Magic Packet',
        '116' => 'Wake on Directed Packet',
        '118' => 'Wake on Magic or Directed Packet',
        '246' => 'OS Directed',
    );

    #translate WMI code to useful phrase
    my $return = $lookup{$input};
    if ( defined($return) ) { $output = $return; }
    if ($DEBUG) {
        &Log("LookupWoL: Translated $input to $output");
    }
    return $output;
}

### LookupWoLLink sub ########################################################
sub LookupWoLLink {
    my $input  = shift;
    my $output = 'UNKNOWN';
    my %lookup = (

        # WMI value => means in English
        '0' => 'Disabled',
        '1' => 'OS Controlled',
        '2' => 'Forced',
    );

    #translate WMI code to useful phrase
    my $return = $lookup{$input};
    if ( defined($return) ) { $output = $return; }
    if ($DEBUG) {
        &Log("LookupWoLLink: Translated $input to $output");
    }
    return $output;
}
### end of LookupWoLLink sub #################################################

### DecodeMode sub ###########################################################
sub DecodeMode {
    my ( $type, $mode ) = @_;
    my $output = 'UNKNOWN';
    if ( $type < 1 || $type > 3 ) {
        if ($DEBUG) { &Log("DecodeMode can't work with $type"); }
        return $output;
    }
    my %lookup;
    if ( $type == 1 ) {
        %lookup = (

            # WMI Mode => English Mode
            '0' => 'Auto Detect',
            '1' => '10Mbps \\ Half Duplex',
            '2' => '10Mbps \\ Full Duplex',
            '3' => '100Mbps \\ Half Duplex',
            '4' => '100Mbps \\ Full Duplex',
            '5' => '1000Mbps \\ Auto-Negotiate',
        );
    }
    if ( $type == 2 ) {
        %lookup = (
            '0' => 'Auto Detect',
            '3' => '10Mbps \\ Half Duplex',
            '4' => '10Mbps \\ Full Duplex',
            '5' => '100Mbps \\ Half Duplex',
            '6' => '100Mbps \\ Full Duplex',
        );
    }
    if ( $type == 3 ) {
        %lookup = (
            '0' => 'Auto Detect',
            '2' => '100Mbps \\ Full Duplex',
            '4' => '100Mbps \\ Full Duplex',
            '9' => '100Mbps \\ Full Duplex',
        );
    }

    #translate WMI code to useful phrase
    my $return = $lookup{$mode};
    if ( defined($return) ) { $output = $return; }
    if ($DEBUG) {
        &Log("DecodeMode: Translated driver type $type mode $mode to $output");
    }
    return $output;
}
### end of DecodeMode sub #####################################################

###  CallLANDeskInfo sub ######################################################
sub CallLANDeskInfo {

    if ($DEBUG) { &Log("CallLANDeskInfo: Looking for Broker Settings"); }
    &ReadBrokerSettings;
    if ($DEBUG) { &Log("CallLANDeskInfo: Looking for Preferred Servers"); }
    &ReadPreferredServers;
    return 0;
}
### End of CallLANDeskInfo sub ################################################

### ReadBrokerSettings sub ####################################################
sub ReadBrokerSettings {

    # What mode is brokerconfig in?
    my $brokerconfigfile = Win32::GetShortPathName($PROGRAMFILES);
    $brokerconfigfile .=
      "\\LANDesk\\Shared Files\\cbaroot\\broker\\brokerconf.xml";
    if ( -e $brokerconfigfile ) {
        if ($DEBUG) {
            &Log("CallLANDeskInfo: brokerconfigfile is $brokerconfigfile.");
        }
        my ( $input, $BH, $line );
        open( $BH, '<', "$brokerconfigfile" )
          or croak("Can't open $brokerconfigfile - $!");
        my $brokerdata = <$BH>;
        close($BH);
        foreach $line ($brokerdata) {
            if ( $line =~ "<order>" ) {
                $line =~ /(\d)/x;
                if ($1) { $input = $1; }
            }
        }
        my $output =
            $input == 1 ? 'Connect using the Management Gateway'
          : $input == 2 ? 'Connect directly to LDMS core'
          : $input == 0 ? 'Dynamically determine connection route'
          :               $input;

        &ReportToCore(
            "LANDesk Management - Broker Configuration Mode = $output");
        return 0;
    }
    else {

        # If there's no brokerconfig file, the agent defaults to dynamic mode
        &ReportToCore( "LANDesk Management - Broker Configuration Mode = "
              . "Dynamically determine connection route" );
        if ($DEBUG) {
            &Log(   "ReadBrokerSettings: $brokerconfigfile not present, "
                  . "defaulting to 'dynamic detection'." );
        }
        return 0;
    }
}
### End of ReadBrokerSettings sub #############################################

### ReadPreferredServers sub ##################################################
sub ReadPreferredServers {
    my ( $psfile, $psentry, $psentries );
    if ( -e "$sdcache\\preferredserver.dat" ) {

        # 8.7.1 client
        $psfile = "$sdcache\\preferredserver.dat";
        if ($DEBUG) {
            &Log("ReadPreferredServers: $psfile is present.");
        }
        open( $PSFILE, '<', "$psfile" ) or &LogWarn("Can't open $psfile : $!");
        $psentry = <$PSFILE>;
        close $PSFILE;
        $psentry = &Trim($psentry);
        &ReportToCore("LANDesk Management - Preferred Server = $psentry");
    }
    my @targets;

    # 8.7.2 and up client
    push( @targets, "$sdcache\\preferredservers.dat" );

    # 8.8 client
    push( @targets, "$sdcache\\preferredservers.$core.dat" );

    foreach my $targetfile (@targets) {
        if ( -e $targetfile ) {

            if ($DEBUG) {
                &Log("ReadPreferredServers: $targetfile is present.");
            }
            open( $PSFILE, '<', "$targetfile" )
              or &LogWarn("Can't open $targetfile : $!");
            my $line;
            while ( $line = <$PSFILE> ) {
                $line =~ /\?(.*)$/x;
                if ($1) { $psentry .= &Trim($1); }
            }
            close $PSFILE;
            &ReportToCore("LANDesk Management - Preferred Servers = $psentry");
        }
    }
    $psentries = "";
    $RegKey =
      $Registry->{
"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/WinClient/SoftwareDistribution"
      };
    if ($RegKey) {
        $psentries = $RegKey->GetValue("PreferredPackageServer");
        if ($psentries) {
            if ($DEBUG) {
                &Log("ReadPreferredServers: $psentries present in Registry.");
            }
            &ReportToCore("LANDesk Management - PreferredServers = $psentries");
        }
    }
    if ($DEBUG) {
        &Log("ReadPreferredServers: finished");
    }
    return 0;
}
### End of ReadPreferredServers sub ###########################################

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
            &ReportToCore(
"Local Users and Groups - Local Groups - $GroupName - Members = $GroupMembers"
            );
        }
    }
    if ($DEBUG) {
        &Log("CallEnumerateGroups: Finished");
    }
    return 0;
}
### End of CallEnumerateGroups sub ############################################

###  CallFindPST sub ##########################################################
sub CallFindPST {

    ## Put the filename into the root of Email; but not the individual size,
    #because that may conflict. filename will not conflict because it's full
    #path
    if ($DEBUG) {
        &Log( "CallFindPST: Looking for PST Files, Aggressiveness="
              . $AggroMailSearch );
    }

    if ( $AggroMailSearch == 3 ) {
        my ( undef, $sysdrive, undef ) = fileparse( $WINDIR, qr{\..*}x );
        if ($DEBUG) { &Log("Looking for PST files under $sysdrive"); }
        find( \&ProcessPSTFile, $sysdrive );
    }
    else {

        # Find where user profiles are stored
        my $userdir = Win32::GetShortPathName($USERPROFILE);
        $userdir =~ s|\\[^\\]*$||x;
        for my $user ( glob( $userdir . '/*' ) ) {
            if ( $AggroMailSearch == 1 ) {
                $user .= "/Local\ Settings/Application\ Data/Microsoft/Outlook";
            }
            if ( -d $user ) {

                # Search that path recursively for .pst files
                $user = Win32::GetShortPathName($user);
                if ($DEBUG) {
                    &Log("Looking for PST files under $user");
                }
                find( \&ProcessPSTFile, $user );
            }
        }
    }
    &ReportToCore( "Email - PST Files - Total Disk Size = "
          . format_bytes($totalpstsize) );
    &ReportToCore("Email - PST Files - Number of Files = $totalpstcount");
    return 0;
}
### End of CallFindPST sub ####################################################

###  CallFindOST sub ##########################################################
sub CallFindOST {

    ## Put the filename into the root of Email; but not the individual size,
    #because that may conflict. filename will not conflict because it's full
    #path
    if ($DEBUG) {
        &Log( "CallFindOST: Looking for OST Files, Aggressiveness="
              . $AggroMailSearch );
    }

    if ( $AggroMailSearch == 3 ) {
        my ( undef, $sysdrive, undef ) = fileparse( $WINDIR, qr{\..*}x );
        if ($DEBUG) { &Log("Looking for OST files under $sysdrive"); }
        find( \&ProcessOSTFile, $sysdrive );
    }
    else {

        # Find where user profiles are stored
        my $userdir = Win32::GetShortPathName($USERPROFILE);
        $userdir =~ s|\\[^\\]*$||x;
        for my $user ( glob( $userdir . '/*' ) ) {
            if ( $AggroMailSearch == 1 ) {
                $user .= "/Local\ Settings/Application\ Data/Microsoft/Outlook";
            }
            if ( -d $user ) {

                # Search that path recursively for .ost files
                $user = Win32::GetShortPathName($user);
                if ($DEBUG) {
                    &Log("Looking for OST files under $user");
                }
                find( \&ProcessOSTFile, $user );
            }
        }
    }
    &ReportToCore( "Email - OST Files - Total Disk Size = "
          . format_bytes($totalostsize) );
    &ReportToCore("Email - OST Files - Number of Files = $totalostcount");
    return 0;
}
### End of CallFindOST sub ####################################################

###  CallFindNSF sub ##########################################################
sub CallFindNSF {

    if ($DEBUG) {
        &Log( "CallFindNSF Looking for NSF Files, Aggressiveness="
              . $AggroMailSearch );
    }

    if ( $AggroMailSearch == 3 ) {
        my ( undef, $sysdrive, undef ) = fileparse( $WINDIR, qr{\..*}x );
        if ($DEBUG) { &Log("Looking for NSF files under $sysdrive"); }
        find( \&ProcessNSFFile, $sysdrive );
    }
    else {

        # Find where user profiles are stored
        my $userdir = Win32::GetShortPathName($USERPROFILE);
        $userdir =~ s|\\[^\\]*$||x;
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
    &ReportToCore( "Email - NSF Files - Total Disk Size = "
          . format_bytes($totalnsfsize) );
    &ReportToCore("Email - NSF Files - Number of Files = $totalnsfcount");
    return 0;
}
### End of CallFindNSF sub ####################################################

###  CallFindProfileSize sub ##################################################
sub CallFindProfileSize {

    if ($DEBUG) { &Log("CallFindProfileSize: Looking for user profile sizes"); }

    # Find where user profiles are stored
    my $userdir = Win32::GetShortPathName($USERPROFILE);
    $userdir =~ s|\\[^\\]*$||x;
    for my $user ( glob( $userdir . '/*' ) ) {
        if ( -d $user ) {

            # Search that path recursively for its size
            my $size = 0;
            find( sub { $size += -s if -f $_ }, "$user" );
            &ReportToCore( "Profile Size - $user = " . format_bytes($size) );
        }
    }
    return 0;
}
### End of CallFindProfileSize sub ############################################

### ProcessPSTFile sub (File::Find uses this) #################################
sub ProcessPSTFile {

    # TODO -- find the type (different formats)
    # Each file needs to be looked at
    my ( undef, undef, $extension ) = fileparse( $_, qr{\..*}x );
    $extension = lc($extension);
    if ( $extension ne ".pst" ) {
        return 0;
    }
    &ReportToCore("Email - PST Files - $_ - File Location = $File::Find::name");

    # stat -- 7 is file size in bytes
    my $pstfilesize = ( stat($File::Find::name) )[7]
      or &LogWarn("stat failed on $File::Find::Name - $!");
    &ReportToCore(
        "Email - PST Files - $_ - File Size = " . format_bytes($pstfilesize) );
    $totalpstsize += $pstfilesize;
    $totalpstcount++;
    return 0;
}
### End of ProcessPSTFile sub #################################################

### ProcessOSTFile sub (File::Find uses this) #################################
sub ProcessOSTFile {

    # TODO -- find the type (different formats)
    # Each file needs to be looked at
    my ( undef, undef, $extension ) = fileparse( $_, qr{\..*}x );
    $extension = lc($extension);
    if ( $extension ne ".ost" ) {
        return 0;
    }
    &ReportToCore("Email - OST Files - $_ - File Location = $File::Find::name");

    # stat -- 7 is file size in bytes
    my $ostfilesize = ( stat($File::Find::name) )[7]
      or &LogWarn("stat failed on $File::Find::Name - $!");
    &ReportToCore(
        "Email - OST Files - $_ - File Size = " . format_bytes($ostfilesize) );
    $totalostsize += $ostfilesize;
    $totalostcount++;
    return 0;
}
### End of ProcessPSTFile sub #################################################

### ProcessNSFFile sub (File::Find uses this) #################################
sub ProcessNSFFile {

    # Each file needs to be looked at
    my ( undef, undef, $extension ) = fileparse( $_, qr{\..*}x );
    $extension = lc($extension);
    if ( $extension ne ".nsf" ) {
        return 0;
    }
    &ReportToCore("Email - NSF Files - $_ - File Location = $File::Find::name");

    # stat -- 7 is file size in bytes
    my $nsffilesize = ( stat($File::Find::name) )[7]
      or &LogWarn("stat failed on $File::Find::Name - $!");
    &ReportToCore(
        "Email - NSF Files - $_ - File Size = " . format_bytes($nsffilesize) );
    $totalnsfsize += $nsffilesize;
    $totalnsfcount++;
    return 0;
}
### End of ProcessNSFFile sub #################################################

### CallMappedDrives sub ######################################################
sub CallMappedDrives {
    if ($DEBUG) { &Log("CallMappedDrives: Looking for network drives"); }

    # Locate startasuser binary
    my $startasuser           = $ldclient . "\\startasuser.exe";
    my $ldms_client_regreader = $ldclient . "\\ldms_client_regreader.exe";
    my $mdtemp                = $ldclient . "\\mdtemp.txt";

    if ( -e $startasuser ) {
        if ( -e $ldms_client_regreader ) {

            # Prepare my temp file
            open( $MDTEMP, '>', "$mdtemp" )
              or &LogWarn("Cannot open $mdtemp for writing: $!");
            foreach my $letter ( 'A' .. 'Z' ) {
                my $networkpath = "Network/$letter,RemotePath";
                print $MDTEMP "$networkpath\n";
                if ($DEBUG) {
                    &Log("Wrote $networkpath to $mdtemp");
                }
            }
            close($MDTEMP);
            my $mappeddriveresult =
                $startasuser
              . ' ///timeout=10 ///silent '
              . $ldms_client_regreader . ' '
              . $mdtemp;
            if ($DEBUG) {
                &Log("CallMappedDrives: $mappeddriveresult");
            }
            system($mappeddriveresult);
            open( $MDTEMP, '<', "$mdtemp" )
              or &LogWarn("Cannot open $mdtemp for reading: $!");

            while (<$MDTEMP>) {

                my ( $hkcukey, $subkey, $value ) = split(/,/x);
                if ($DEBUG) {
                    &Log(   "hkcukey is $hkcukey, "
                          . "subkey is $subkey, "
                          . "value is $value" );
                }
                chomp($subkey);
                chomp($value);
                &ReportToCore(
                    "Custom Data - HKCU - $hkcukey - $subkey = $value");
            }
            close($MDTEMP);
            if ($DEBUG) {
                &Log("Leaving $mdtemp in place for debug purposes");
            }
            else {
                unlink($mdtemp)
                  or &LogWarn("Cannot delete temp file $mdtemp - $!");
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

### End of CallMappedDrives sub ###############################################

### CallRegistryReader sub ####################################################
sub CallRegistryReader {
    if ($DEBUG) { &Log("CallRegistryReader: Looking for HKCU Registry keys"); }

    # Locate startasuser binary
    my $startasuser           = $ldclient . "\\startasuser.exe";
    my $ldms_client_regreader = $ldclient . "\\ldms_client_regreader.exe";
    my $rrtemp                = $ldclient . "\\rrtemp.txt";
    if ( -e $startasuser ) {
        if ( -e $ldms_client_regreader ) {

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
                    my @parts = split( /\//x, $hkcukey );

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
            my $hkcuresult =
                $startasuser
              . ' ///timeout=10 ///silent '
              . $ldms_client_regreader . ' '
              . $rrtemp;
            if ($DEBUG) {
                &Log("CallRegistryReader: $hkcuresult");
            }
            system($hkcuresult);
            open( $RRTEMP, '<', "$rrtemp" )
              or &LogWarn("Cannot open $rrtemp for reading: $!");
            while (<$RRTEMP>) {

                my ( $hkcukey, $subkey, $value ) = split(/,/x);
                if ($DEBUG) {
                    &Log(   "hkcukey is $hkcukey, "
                          . "subkey is $subkey, "
                          . "value is $value" );
                }
                chomp($subkey);
                chomp($value);
                &ReportToCore(
                    "Custom Data - HKCU - $hkcukey - $subkey = $value");
            }
            close($RRTEMP);
            if ($DEBUG) {
                &Log("Leaving $rrtemp in place for debug purposes");
            }
            else {
                unlink($rrtemp)
                  or &LogWarn("Cannot delete temp file $rrtemp - $!");
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
    my ( $value, $type, $HKLMKey );

    # Read in the .ini keys I need to look for
    for my $rii ( 1 .. 10 ) {

        # For each key, dig in HKLM and write the value out
        if ( my $hklmkey = $ri[$rii] ) {

            $hklmkey = &trimkey($hklmkey);

            # Registry reading differentiates between key and path.
            # Split it up into components
            my @parts = split( /\//x, $hklmkey );

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
                if ( $subkey =~ m/\(default\)/ix ) {
                    $subkey = "";
                }
                $hklmkey = "HKEY_LOCAL_MACHINE/" . $hklmkey;
                $HKLMKey = $Registry->{"$hklmkey"};
                if ($HKLMKey) {
                    ( $value, $type ) = $HKLMKey->GetValue($subkey)
                      or &LogWarn("Can't read $hklmkey $subkey key: $^E");
                    if ( defined($value) ) {
                        $value = &ParseRegistryValue( $type, $value );
                    }
                    else {
                        $value = "NULL";
                    }
                    if ( $subkey eq "" ) { $subkey = "(Default)"; }
                    &ReportToCore(
                        "Custom Data - HKLM - $hklmkey - $subkey = $value");
                }
            }
        }
    }
    return 0;
}
### End of CallRegistryInfo sub ###############################################

### ParseRegistryValue ######################################################
sub ParseRegistryValue {
    my ( $type, $value ) = @_;
    if (   $type eq "REG_SZ"
        or $type eq "REG_EXPAND_SZ"
        or $type eq "REG_MULTI_SZ" )
    {

        # It's a string, don't need to do anything special
        return $value;
    }
    elsif ($type eq "REG_DWORD"
        or $type eq "REG_BINARY" )
    {

        # It's a binary value and must be unpacked
        # This will only work if it's four bytes or less
        $value = unpack( "L", $value );
    }
    else {
        $value = "NULL";
    }
    return $value;
}
### ParseRegistryValue ######################################################

### CallProdukey sub ##########################################################
sub CallProdukey {

    if ($DEBUG) {
        &Log("CallProdukey: Looking for Microsoft product keys");
    }

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
            $pk_version =~ s/\.?(?=[0-9])//gx;

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
        my $produkeyResult = $produkey . " /scomma " . $produkeydat;
        system($produkeyResult);

        # Read results
        if ( -e $produkeydat ) {

            open( $PKDFILE, '<', "$produkeydat" )
              or &LogWarn("Can't open $produkeydat - $!");
            while (<$PKDFILE>) {
                my (
                    $pk_name,    $pk_id, $pk_key,
                    $pk_install, $pk_sp, $pk_machine
                ) = split(/,/x);
                if ($pk_sp) {
                    $pk_name = $pk_name . " " . $pk_sp;
                }
                &ReportToCore("Licenses - $pk_name - product_id = $pk_id");
                &ReportToCore("Licenses - $pk_name - product_key = $pk_key");
                &ReportToCore(
                    "Licenses - $pk_name - installation_folder = $pk_install");
            }
            close($PKDFILE);
            if ($DEBUG) {
                &Log("Leaving $produkeydat in place for debug purposes");
            }
            else {
                unlink($produkeydat)
                  or &Logwarn("Cannot delete temp file $produkeydat - $!");
            }
        }
    }
    else {
        &LogWarn("$produkey not found");
    }
    return 0;
}
### End of CallProdukey sub ###################################################

### CallNeedsDefrag sub ######################################################
sub CallNeedsDefrag {

    my $fragged = 'UNKNOWN';
    my $fragreco = 'UNKNOWN';

    # Find the system drive letter
    my $drive = 'c:';
    if ($SYSTEMDRIVE) {
        $drive = $SYSTEMDRIVE;
    }
    # make sure defrag.exe exists
    my $defrag = 'c:\\windows\\system32\\defrag.exe';
    if ($WINDIR) {
        $defrag = $WINDIR . '\\system32\\defrag.exe';
    }
    # call defrag -a $drive and capture output
    if (-e $defrag) {
        my @defragresult = `$defrag -a $drive`;
        # parse:
        #C:\>defrag -a c:
        #
        #Windows Disk Defragmenter
        #Copyright (c) 2003 Microsoft Corp. and Executive Software International, Inc.
        #
        #Analysis Report
        #    142 GB Total,  54.28 GB (38%) Free,  0% Fragmented (1% file fragmentation)
        #
        #You do not need to defragment this volume.
        foreach my $line (@defragresult) {
            if ($line =~ m/(\d+)% Fragmented/) {
                if ($1) {
                    $fragged = $1;
                } else {
                    $fragged = 0;
                }
            }
            if ($line =~ m/^You /) {
                $fragreco = &Trim($line);
            }
        }
    }
    # Remove the colon from the drive letter
    chop ($drive);
    &ReportToCore("Mass Storage - Logical Drive - $drive - Fragmentation"
        . " = $fragged");
    &ReportToCore("Mass Storage - Logical Drive - $drive - Recommendation"
        . " = $fragreco");
    return 0;

}
### End of CallNeedsDefrag sub ###############################################

### CallDCCUWol sub ##########################################################
sub CallDCCUWol {

    if ($DEBUG) {
        &Log("CallDCCUWol: Looking for Dell Wake-on-LAN status");
    }

    # Locate getwol binary
    my $getwol;
    if ($DCCUWolBinary) { $getwol = $DCCUWolBinary; }

    # Find my file
    my $getwoldat = &FindGetwoldat;

    # If it was already run, I can just read the dat file
    # Otherwise, I need to run getwol... if it exists
    if ( !-e $getwoldat ) {
        if ( -e $getwol ) {

            # Call it
            if ($DEBUG) { &Log("CallDCCUWol: Running $getwol"); }
            system($getwol);

            # If it's running as localsystem and the user's rights are
            # limited, inventory.exe doesn't finish successfully when run via
            # system; but it does seem to when using backticks. This is
            # essentially voodoo chicken-waving and ought to be fixed properly
            # someday. Reporting user is Steven Hamel [shamel@mediacomcc.com].
            if ( !-e $getwoldat ) {
                my $getwolresult = `$getwol`;
            }

            # Gotta look for the file again
            $getwoldat = &FindGetwoldat;
        }
        else {

            # Might as well bail out at this point
            if ($DEBUG) { &Log("can't find DCCU binary at $getwol"); }
            return 1;
        }
    }

    # Read results... by now we ought to have some.
    if ( -e $getwoldat ) {

        if ($DEBUG) { &Log("CallDCCUWol: using $getwoldat"); }
        my $wolresult = &ProcessGetwoldat($getwoldat);
        &ReportToCore("BIOS - WakeOnLAN = $wolresult");
    }
    else {
        &LogWarn("$getwoldat not available");
    }
    return 0;
}
### End of CallDCCUWol sub ###################################################

### ProcessGetwoldat sub #####################################################
sub ProcessGetwoldat {

#this is technically an xml file, but opening it as XML looks like
#a waste of everyone's time. Here's a sample:
# <?xml version="1.0"?>
# <root>
# <command name="get">
# <property name="WakeupOnLAN" ischecked="1" value="6" outcome="OK" errorcode="0x0"/>
# </command>
# </root>
    my $input = shift;
    my ( $GETWOLDAT, $line, $wolresult );
    open( $GETWOLDAT, '<', "$input" )
      or &LogWarn("ProcessGetwoldat: Can't open $input for reading: $!");
    while ( $line = <$GETWOLDAT> ) {
        if ( $line =~ /WakeupOnLAN\"/ix ) {
            my @properties = split( ' ', $line );
            foreach my $property (@properties) {
                if ( $property =~ m/value/ix ) {

                    # second to last character
                    $wolresult = substr( $property, -2, 1 );
                    if ($DEBUG) {
                        &Log(   "ProcessGetwoldat: found $wolresult "
                              . "from $line" );
                    }
                }
            }
        }
    }
    close $GETWOLDAT;

    my $output =
        $wolresult == 2 ? 'Unsupported'
      : $wolresult == 3 ? 'Disabled'
      : $wolresult == 4 ? 'Enabled for add-in NIC'
      : $wolresult == 5 ? 'Enabled for on-board NIC'
      : $wolresult == 6 ? 'Enabled for all NICs'
      : $wolresult == 7 ? 'Enabled with boot to NIC'
      :                   $wolresult;

    return $output;
}
### End of ProcessGetwoldat sub ##############################################

### FindGetwoldat sub ########################################################
sub FindGetwoldat {

    # The pre-3.0 DCCU file is DCCUResults_SUCCESS.xml
    # The 3.x DCCU file is TaskResult.xml
    my @searchpaths;
    my $searchfile;
    my @candidates;
    my %ages;

    # This value is the "my age is better than that" marker
    # and should start as a large number - 4msec is about a month
    my $timediff = 4000000;
    my $output;

    if ($DCCUWolBinary) { push( @searchpaths, dirname($DCCUWolBinary) ); }

    # I know current directory exists
    my $searchpath = Win32::GetShortPathName(Cwd::getcwd);
    push( @searchpaths, $searchpath );

    # Let's look in some of $ldclient's hideyholes too, for luck.
    push( @searchpaths, $ldclient );
    push( @searchpaths, "$ldclient\\data" );
    push( @searchpaths, $sdcache );

    # System32 is a popular place for it to live when running as localsystem
    push( @searchpaths, "$WINDIR\\system32" );

    foreach my $path (@searchpaths) {

        # Look for the old file first
        $searchfile = $path . "\\DCCUResults_SUCCESS.xml";
        if ( -e $searchfile ) {
            if ($DEBUG) { &Log("$searchfile exists"); }
            push( @candidates, $searchfile );
        }

        # Look for the new file next
        $searchfile = $path . "\\TaskResult.xml";
        if ( -e $searchfile ) {
            if ($DEBUG) { &Log("$searchfile exists"); }
            push( @candidates, $searchfile );
        }
    }

    # Now let's look for what's actually there, and how old it is
    for ( 0 .. $#candidates ) {
        if ( !-e $candidates[$_] ) {
            if ($DEBUG) { &Log("FindGetwoldat: $candidates[$_] is absent"); }
            splice( @candidates, $_, 1 );
        }
    }
    for ( 0 .. $#candidates ) {

        # stat, 7 is SIZE, 8 is ATIME, 9 is MTIME, 10 is CTIME
        my $ctime = ( stat( $candidates[$_] ) )[10]
          or &LogWarn("FindGetwoldat: stat($candidates[$_]) failed: $!");
        if ( $ctime <= 0 ) {
            if ($DEBUG) {
                &Log(   "replaced bogus creation time for file "
                      . "$candidates[$_] with current time." );
            }
            $ctime = time();
        }
        $ages{ $candidates[$_] } = time() - $ctime;
    }

    # Sort by age
    foreach my $possible (@candidates) {

        # prefer more recently created files
        if ( $ages{$possible} < $timediff ) {
            if ($DEBUG) {
                &Log(
"$possible is more recent at $ages{$possible} than $timediff"
                );
            }
            $timediff = $ages{$possible};
            $output   = $possible;
        }

    }

    if ($output) {
        return $output;
    }
    else {

        # If it couldn't be found, we'll need to run the binary
        if ($DEBUG) {
            &Log("FindGetwoldat: Didn't find a DCCU output file");
        }
        return 0;
    }
}
### End of FindGetwoldat sub #################################################

### CallSID sub ###############################################################
#http://www.droppedpackets.org/inventory-and-slm/quick-and-dirty-machine-sid-into-inventory/
sub CallSID {
    if ($DEBUG) { &Log("CallSID: Looking for Machine SID"); }
    my ( $system, $domain, $account ) = Win32::NodeName;
    my ( $sid, $sidtype );
    Win32::LookupAccountName( $system, $account, $domain, $sid, $sidtype );
    my $sidstring = Win32::Security::SID::ConvertSidToStringSid($sid);
    if ( length($sidstring) < 10 ) {
        if ($DEBUG) {
            &Log("CallSID: got short SID, not reporting: $sidstring");
        }
    }
    else {
        &ReportToCore("Machine SID = $sidstring");
    }
    if ($DEBUG) { &Log("CallSID: Looking for Machine FQDN"); }
    my $fqdn = &Trim( fqdn() );
    &ReportToCore("Network - TCPIP - FQDN = $fqdn");
    return 0;
}
### End of CallSID sub ########################################################

### Logging subroutine ########################################################
sub Log {
    my $msg = shift;
    if ( !defined($msg) ) { $msg = "Log: Can't report nothing"; }
    open( $LOG, '>>', "$logfile" ) or croak("Can't open $logfile - $!");
    $LOG->autoflush();
    print $LOG localtime() . ": $msg\n";
    close($LOG);
    return 0;
}

### Logging with warning subroutine ###########################################
sub LogWarn {
    my $msg = shift;
    if ( !defined($msg) ) { $msg = "LogWarn: Can't report nothing"; }
    open( $LOG, '>>', "$logfile" ) or croak("Can't open $logfile - $!");
    $LOG->autoflush();
    print $LOG localtime() . ": WARN: $msg\n";
    close($LOG);
    return 0;
}

### Logging with death subroutine #############################################
sub LogDie {
    my $msg = shift;
    if ( !defined($msg) ) { $msg = "LogDie Can't report nothing"; }
    open( $LOG, '>>', "$logfile" ) or croak("Can't open $logfile - $!");
    $LOG->autoflush();
    print $LOG localtime() . ": DIE: $msg\n";
    close($LOG);
    exit 1;
}

### Trim subroutine ###########################################################
sub Trim {
    my $string = shift;
    $string =~ s/^\s+      # substitute spaces from the beginning of line
                 |\s+$     # or from the end of the line
                 //x;
    $string =~ s/\'        # substitute single quotes
                 |\"       # or double quotes, globally
                 //gx;
    $string =~ s/\n        # substitute end of line or
                 |\r       # carriage returns, globally
                 //gx;
    $string =~ s/ //gx;
    return $string;
}

### Format numbers with commas ################################################
sub commify {
    local ($_) = shift;
    1 while s/^(-?\d+)(\d{3})/$1,$2/x;
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

### Report something subroutine ##############################################
sub ReportToCore {
    my $msg = shift;
    if ($msg) {
        $msg =~ m/(.*)\s=\s(.*)/x;
        if ( defined($1) && length($2) >= 1 ) {
            open( $FILE, '>>', "$file" ) or croak("Can't open $file - $!");
            $FILE->autoflush();
            print $FILE "$msg\n";
            close $FILE;
            if ($DEBUG) { &Log("ReportToCore: wrote $msg"); }
            return 0;
        }
        else {
            if ($DEBUG) {
                &Log(   "ReportToCore: received a partial message and will not"
                      . " report it to the core. Input was: $msg" );
            }
            return 1;
        }
    }
    else {
        &LogWarn("ReportToCore called with nothing to do!");
        return 1;
    }
}
### trimkey subroutine ######################################################
sub trimkey {
    my $input = my $string = shift;
    if ( defined($string) ) {

        # Replace backslashes with forward slashes
        $string =~ s/\\/\//gx;

        # Remove beginning slashes (forward or backward)
        $string =~ s/^\/|^\\//gx;

        # Remove beginning references to the registry hive
        $string =~ s/^HKCU\/|^HKEY_CURRENT_USER\///gx;
    }
    if ($DEBUG) {
        if ( $input ne $string ) {
            &LogWarn("trimkey: trimmed $input to $string");
        }
    }
    return $string;
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
            $sgroup =~ s/\D.*//x;
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
    $v =~ s/\)%$/%)/x;
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

1;
__END__
