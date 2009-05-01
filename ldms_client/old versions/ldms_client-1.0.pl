#############################################################################
# ldms_client.pl, v 1.0                                                     #
# (c) 2008 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.droppedpackets.org/scripts/ldms_client                         #
#############################################################################
#

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use strict;
use warnings;
use Env;
use DBI;
use Win32;
use Win32::File::VersionInfo;
use Win32::API::Prototype;
use Win32::OLE qw(in);
use Win32::OLE::Variant;
use Win32::EventLog::Carp;
use Win32::EventLog::Message;
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
use Win32::TieRegistry ( Delimiter => "/", ArrayValues => 1 );
use Config::Tiny;
use XML::Simple;
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
my $ver = "1.0";
my $DEBUG = $A{d} || 0;

my $core;
my $strComputer = '.';
my $dir         = Win32::GetShortPathName($LDMS_LOCAL_DIR);
my $file        = $dir . '\\ldms_client.dat';

my $netstatcommand = 'netstat -an';

my $totalpstsize = 0;

# Battery-specific variables
my (
	$BatteryLabel,  $BatteryID, $Chemistry, $ChemistryCode, $BatteryName,
	$Capacity, $BatteryDate, $BatteryManufacturer, $BatteryLocation, $BatteryStatus
);

# Prepare logging system
Win32::EventLog::Message::RegisterSource( 'Application', $prog );
my $event = Win32::EventLog->new($prog) || die "Can't open Event log!\n";
use Win32::EventLog::Carp qw(cluck carp croak click confess),
  { Source => $prog };

if ($DEBUG) { Log("Output file is $file"); }

my $usage = <<EOD;

Usage: $prog [-d] [-h]
	-d			debug
	-h(elp)		this display

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This program will extend the LANDesk Inventory using custom data.
The latest version lives at 
http://www.droppedpackets.org/scripts/ldms_client

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
  || croak "Unable to load SetPriorityClass()";
ApiLink( 'kernel32.dll', "HANDLE OpenProcess()" )
  || croak "Unable to load GetCurrentProcess()";
ApiLink( 'kernel32.dll', "HANDLE GetCurrentProcess()" )
  || croak "Unable to load GetCurrentProcess()";
ApiLink( 'kernel32.dll', "BOOL CloseHandle( HANDLE )" )
  || croak "Unable to load CloseHandle()";
my $hProcess = GetCurrentProcess();
if ( 0 == SetPriorityClass( $hProcess, 0x00000040 ) ) {
    Log("Unable to set master PID scheduling priority to low.\n");
}
else {
    Log("$prog $ver starting, master PID scheduling priority set to low.\n");
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
    Log(
"can't find core server name in HKLM/Software/Intel/LANDesk/LDWM CoreServer."
    );
}
my $Config = Config::Tiny->new();
$Config = Config::Tiny->read("//$core/ldlogon/ldms_client.ini")
  || &LogDie("Can't read //$core/ldlogon/ldms_client.ini: ",
  Config::Tiny->errstr());

my $coreversion = $Config->{version}->{Version};
if ($coreversion ne $ver) {
	&LogWarn("ldms_client version is different on the core, this could potentially lead to inventory problems.");
}

# Reading properties
my $Battery         = $Config->{_}->{Battery};
my $Netstat         = $Config->{_}->{Netstat};
my $PolicyList      = $Config->{_}->{PolicyList};
my $FindPST         = $Config->{_}->{FindPST};
my $NicDuplex       = $Config->{_}->{NicDuplex};
my $EnumerateGroups = $Config->{_}->{EnumerateGroups};
my $LANDeskInfo     = $Config->{_}->{LANDeskInfo};
my $RegistryReader  = $Config->{_}->{RegistryReader};

# my $one = $Config->{section}->{one};
# my $Foo = $Config->{section}->{Foo};

# Setup Windows OLE object for reading WMI
use constant HKEY_LOCAL_MACHINE => 0x80000002;
use constant EPOCH              => 25569;
use constant SEC_PER_DAY        => 86400;
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
open( FILE, ">$file" ) or die "Can't open $file: $!\n";

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

# Clean up... shut down OLE object, Registry object, and close my file
if ($DEBUG) { Log("Closing data file"); }	
close FILE;
$objShell = undef;
Log("$prog $ver exiting.\n");

#############################################################################
# Subroutines                                                               #
#############################################################################

### Get Battery Information ###################################################
sub CallBattery {

	my $x = 0;
	if ($DEBUG) { Log("CallBattery: Looking for battery information"); }	
    # First try to get data from the PortableBattery object
    my $BatteryList =
      $objWMIService->ExecQuery('SELECT * FROM Win32_PortableBattery');
    if ( $BatteryList->Count > 0 ) {
        foreach my $Battery ( in $BatteryList) {
			$x++;
			if ($Battery->Description) {
	            $BatteryLabel = $Battery->Description;
			} else {
				$BatteryLabel = "Portable Battery $x";
			}
            if ($Battery->DeviceID) {
				$BatteryID = $Battery->DeviceID;
               print FILE
                  "Battery - $BatteryLabel - DeviceID = $BatteryID\n";
            }
            if ($Battery->Manufacturer) {
				$BatteryManufacturer = $Battery->Manufacturer;
                print FILE
"Battery - $BatteryLabel - Manufacturer = $BatteryManufacturer\n";
            }
            if ($Battery->ManufactureDate) {

				$BatteryDate = $Battery->ManufactureDate;
                $BatteryDate  = WMIDateStringToDate($BatteryDate);
                print "Battery - $BatteryLabel - ManufactureDate = $BatteryDate\n";
            }
            if ($Battery->Name) {
				$BatteryName = $Battery->Name;
                print FILE "Battery - $BatteryLabel - Name = $BatteryName\n";
            }
            if ($Battery->Chemistry){ 

                $ChemistryCode = $Battery->Chemistry;
                # Get a useful value for Chemistry
                 &DecodeChemistry();
            }
            if ($Battery->Location) {
				$BatteryLocation = $Battery->Location;
                print FILE
                  "Battery - $BatteryLabel - Location = $BatteryLocation\n";
            }
            if ($Battery->DesignCapacity) {
                if ($Battery->FullChargeCapacity) {
                    $Capacity = &FormatPercent( $Battery->FullChargeCapacity / $Battery->DesignCapacity );
                    print FILE
"Battery - $BatteryLabel - Capacity = $Capacity\n";
                }
            }
            if ($Battery->Status) {
				$BatteryStatus = $BatteryStatus;
                print FILE
                  "Battery - $BatteryLabel - Status = $BatteryStatus\n";
            }
        }
    }
	$x = 0;
# Then see what the Battery object has. This may overwrite values found from PortableBattery.
    $BatteryList = $objWMIService->ExecQuery('SELECT * FROM Win32_Battery');
    if ( $BatteryList->Count > 0 ) {
        foreach my $Battery ( in $BatteryList) {
			if ($Battery->Description) {
            	$BatteryLabel = $Battery->Description;
			} else {
				$BatteryLabel = "Battery $x";
			}
			if ($Battery->DeviceID) {
				$BatteryID = $Battery->DeviceID;
				print FILE
              "Battery - $BatteryLabel - DeviceID = $BatteryID\n";
		  	}
            if ($Battery->Name) {
				$BatteryName = $Battery->Name;
            	print FILE "Battery - $BatteryLabel - Name = $BatteryName\n";
			}
            if ($Battery->InstallDate) {
                $BatteryDate = $Battery->InstallDate;
                $BatteryDate  = WMIDateStringToDate($BatteryDate);
                print FILE
                  "Battery - $BatteryLabel - InstallDate = $BatteryDate\n";
            }
            if ($Battery->Chemistry) {
                $ChemistryCode = $Battery->Chemistry;
                # Get a useful value for Chemistry.
                &DecodeChemistry();
            }
            if ($Battery->Location) {
				$BatteryLocation = $Battery->Location;
                print FILE
                  "Battery - $BatteryLabel - Location = $BatteryLocation\n";
            }
            if ($Battery->DesignCapacity) {
                if ($Battery->FullChargeCapacity) {
                    $Capacity = &FormatPercent( $Battery->FullChargeCapacity / $Battery->DesignCapacity);
                    print FILE "Battery - $BatteryLabel - Capacity = $Capacity\n";
                }
            }
            if ($Battery->Status) {
				$BatteryStatus = $Battery->Status;
                print FILE 
                  "Battery - $BatteryLabel - Status = $BatteryStatus\n";
            }
        }
    }
    return 0;
}
### End of CallBatteryInfo sub ################################################

### DecodeChemistry sub #######################################################
sub DecodeChemistry() {
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
	if ($DEBUG) { Log("DecodeChemistry: Received $ChemistryCode, Returned $Chemistry"); }
    print FILE "Battery - $BatteryLabel - Chemistry = $Chemistry\n";
    return 0;
}
### End of DecodeChemistry sub ################################################

###  CallNetstat sub ##########################################################
sub CallNetstat {
	if ($DEBUG) { Log("CallNetstat: Looking for open network ports"); }	
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
            print FILE
              "Netstat - Open Port - $line[0] - $port[1] = $line[0]/$port[1]\n";
        }
        if ( $line[0] =~ /UDP/i ) {
            @port = split( ':', $line[1] );
            print FILE
              "Netstat - Open Port - $line[0] - $port[1] = $line[0]/$port[1]\n";
        }
    }
    return 0;
}
### End of CallNetstat sub ####################################################

###  CallPolicyList sub #######################################################
sub CallPolicyList {
	
	if ($DEBUG) { Log("CallPolicyList: Looking for LANDesk policies"); }	

# What LANDesk version are we working with?
# Might be better to check for existence of policy.*.exe files in ldclient, but 8.7 service packs 4 and 5 may have had pre-work in them...
    my $ldms_version;
    my $versionfile = Win32::GetShortPathName($PROGRAMFILES);
	$versionfile .= "\\LANDesk\\LDClient\\ldiscn32.exe";
	if ($DEBUG) { Log("CallPolicyList: versionfile is $versionfile"); }
    my $version =
      GetFileVersionInfo( $versionfile );
    if ($version) {
        $ldms_version = $version->{FileVersion};

        # Remove the dots and convert to an integer so that we can do numerical
        # comparison... e.g., version 8.80.0.249 is rendered as 8800249
        $ldms_version =~ s/\.?(?=[0-9])//g;
        $ldms_version = &atoi($ldms_version);
        if ($DEBUG) { Log("DEBUG: LANDesk version is $ldms_version"); }
    } else {
		&LogWarn("Cannot determine LANDesk version from $versionfile");
		return 1;
	}

    # If it's pre-8.8, we're looking in the registry.
    if ( $ldms_version < 8800000 ) {

		if ($DEBUG) { Log("CallPolicyList: Searching in registry"); }	
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
            print FILE
"LANDesk Management - APM - Policies - $PolicyName - GUID = $PolicyGUID\n";
            print FILE
"LANDesk Management - APM - Policies - $PolicyName - Description = $PolicyInfoDesc\n";
            print FILE
"LANDesk Management - APM - Policies - $PolicyName - Status = $PolicyStatus\n";
        }
    }
    else {

        # If it's 8.8 or post, we're looking in SQLite
		if ($DEBUG) { Log("CallPolicyList: Searching in database"); }	
        my $policydir = $ALLUSERSPROFILE
          . "\\Application\ Data\\LANDesk\\ManagementSuite\\Database";
        $dir = Win32::GetShortPathName($dir);
        my $dbfile = $policydir . "\\LDClientDB.db3";

        my @rows;

        my $dbh = DBI->connect( "dbi:SQLite:dbname=$dbfile", "", "" );

        my $sql =
          "select name,filename,description,status from PortalTaskInformation";

        my $sth = $dbh->prepare($sql);
        $sth->execute();
        while ( my @row = $sth->fetchrow_array() ) {
            print FILE
"LANDesk Management - APM - Policies - $row[0] - GUID = $row[1]\n";
            print FILE
"LANDesk Management - APM - Policies - $row[0] - Description = $row[2]\n";
            print FILE
"LANDesk Management - APM - Policies - $row[0] - Status = $row[3]\n";
        }
    }

    # And we're all done here
    return 0;
}
### End of CallPolicyList sub #################################################

###  CallNicDuplex sub ########################################################
sub CallNicDuplex {
	
	if ($DEBUG) { Log("CallNicDuplex: Looking for NIC Settings"); }	
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
            print FILE "NIC - $DriverName - Duplex Mode = $ReportedMode\n";
        }

        # Just for giggles, let's see about Media Type and Wake on LAN status.
        # Media
        my $NICMedia = $DuplexRegEntry->GetValue("Media");
        if ($NICMedia) {
            print FILE "NIC - $DriverName - Media = $NICMedia\n";
        }
        my $NICMediaType = $DuplexRegEntry->GetValue("Media_Type");
        if ($NICMediaType) {
            print FILE "NIC - $DriverName - Media Type = $NICMediaType\n";
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
            print FILE "NIC - $DriverName - Wake On = $NICWOL\n";
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
            print FILE "NIC - $DriverName - Wake On Link = $NICWOLLink\n";
        }
    }
}
### End of CallNicDuplex sub ##################################################

###  CallLANDeskInfo sub ######################################################
sub CallLANDeskInfo {

	if ($DEBUG) { Log("CallLANDeskInfo: Looking for Broker Settings"); }	
    # What mode is brokerconfig in?
    my $brokerconfigfile = Win32::GetShortPathName($PROGRAMFILES);
	$brokerconfigfile .= "\\LANDesk\\Shared Files\\cbaroot\\broker\\brokerconf.xml";
	if ($DEBUG) { Log("CallLANDeskInfo: brokerconfigfile is $brokerconfigfile."); }
    if ( -e $brokerconfigfile ) {
        my $brokerxml  = new XML::Simple;
        my $brokerdata = $brokerxml->XMLin($brokerconfigfile);
        if ( $brokerdata->order == 1 ) {
            print FILE
"LANDesk Management - Broker Configuration Mode = Connect using the Management Gateway\n";
        }
        if ( $brokerdata->order == 2 ) {
            print FILE
"LANDesk Management - Broker Configuration Mode = Connect directly to LDMS core\n";
        }
        if ( $brokerdata->order == 0 ) {
            print FILE
"LANDesk Management - Broker Configuration Mode = Dynamically determine connection route\n";
        }
    }
}
### End of CallLANDeskInfo sub ################################################

###  CallEnumerateGroups sub ##################################################
sub CallEnumerateGroups {

	if ($DEBUG) { Log("CallEnumerateGroups: Looking for domain user and group names"); }	
    my ( $GroupList, $Group, $GroupName, $MemberList, $Member, $MemberName, $GroupMembers);
	my $Members = "";
    $GroupList = Win32::OLE->GetObject( 'WinNT://' . $strComputer . '' );
    $GroupList->{Filter} = ['group'];
    foreach $Group ( in $GroupList) {

        # For each group
		if ($Group->Name) {
        	$GroupName = $Group->Name;
			$MemberList = Win32::OLE->GetObject('WinNT://' . $strComputer . '/' . $GroupName);
			$GroupMembers = "";
			foreach $Member (in $MemberList->Members) {
	           	# Get each user name, returned as a comma-separated list
				if ($Member->Name) {
			    	$MemberName = $Member->Name;
			        $GroupMembers .= "$MemberName, ";
				}
		    }
			# Chop off that last comma and space
			$GroupMembers = substr($GroupMembers, 0, -2);
		    print FILE "Local Groups - $GroupName - Members = $GroupMembers\n";
		}
    }
}
### End of CallEnumerateGroups sub ############################################

###  CallFindPST sub ##########################################################
sub CallFindPST {

	if ($DEBUG) { Log("CallFindPST: Looking for PST Files"); }	
	# Find where user profiles are stored
	my $userdir = Win32::GetShortPathName($USERPROFILE);
	$userdir =~ s|\\[^\\]*$||;
	for my $user ( glob( $userdir . '/*' ) ) {
	    $user .= "/Local\ Settings/Application\ Data/Microsoft/Outlook";
    	if ( -d $user ) {

        	# Search that path recursively for .pst files
	        $user = Win32::GetShortPathName($user);
    	    find( \&ProcessPSTFile, $user );
	    }
	}
	print FILE "Email = PST Files - Total Disk Size = $totalpstsize\n";
}
### End of CallFindPST sub ####################################################

### ProcessPSTFile sub (File::Find uses this) #################################
sub ProcessPSTFile {

    # Each file needs to be looked at
    my ( undef, undef, $extension ) = fileparse( $_, qr{\..*} );
    if ( $extension ne ".pst" ) {
        return 0;
    }
    print FILE "Email - PST Files - $_ - File Location = $File::Find::name\n";

    # stat -- 7 is file size in bytes
    my $pstfilesize = ( stat($File::Find::name) )[7];
    print FILE "Email - PST Files - $_ - File Size = $pstfilesize\n";
    $totalpstsize += $pstfilesize;
}

### Logging subroutine ########################################################
sub Log {
    my $msg = shift;
    $event->Report(
        {
            EventID   => 0,
            Strings   => $msg,
            EventType => "Information",
        }
    );
}

### Logging with warning subroutine ###########################################
sub LogWarn {
    my $msg = shift;
    $event->Report(
        {
            EventID   => 0,
            Strings   => $msg,
            EventType => 2,
        }
    );
}

### Logging with death subroutine #############################################
sub LogDie {
    my $msg = shift;
    $event->Report(
        {
            EventID   => 0,
            Strings   => $msg,
            EventType => 1,
        }
    );
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

### Format numbers with commas ################################################
sub commify {
    local ($_) = shift;
    1 while s/^(-?\d+)(\d{3})/$1,$2/;
    return $_;
}

### ASCII to Integer subroutine ###############################################
sub atoi() {
    my $t = 0;
    foreach my $d ( split( //, shift() ) ) {
        $t = $t * 10 + $d;
    }
    return $t;
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
    my $v = FormatNumber( $number * 100, @_ );
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
}

