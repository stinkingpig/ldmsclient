#############################################################################
# ldms_client_core.pl                                                       #
# (c) 2008 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.monkeynoodle.org/comp/tools/ldms_whatever                      #
#############################################################################
#
# TODO -- Firewall status (enabled /disabled) (we do this in custom defs, but don’t put the status anywhere.
# TODO -- It would be interesting to see the firewall specifics broken down a bit by port and app, but that could be a ton of work and difficult to format in a useful state.
# TODO -- Return the client's FQDN into the network section
# TODO -- Custom vulnerability to install/update Produkey.

#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use strict;
use warnings;
use Win32;
use Win32::API::Prototype;
use Win32::GUI();
use Win32::EventLog::Carp;
use Win32::EventLog::Message;
use Win32::TieRegistry ( Delimiter => "/", ArrayValues => 1 );
use Win32::WebBrowser;
use Config::Tiny;
use LWP::Simple qw(!head !getprint !getstore !mirror);

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
my $ver = "1.5";
my ( $skipupdate, $updatemessage );
my $DEBUG = $A{d} || 0;

my ( $ldmain, $ldlogon );
my (
    $Battery,     $Netstat,        $PolicyList,
    $FindPST,     $NICDuplex,      $EnumerateGroups,
    $LANDeskInfo, $RegistryReader, $Produkey,
	$SID,         $RegistryInfo,   $Macintosh,
    $FindNSF,     $FindProfileSize
);
my ($MacNetstat,  $MacOptical);

my ( $main, $w, $h, $ncw, $nch, $dw, $dh, $desk, $wx, $wy, $btn_default,
    $btn_cancel, $btn_help, $sb, $update_available );
my (
    $lbl_Instructions,    $lbl_Battery,     $lbl_Netstat,
    $lbl_PolicyList,      $lbl_FindPST,     $lbl_NICDuplex,
    $lbl_EnumerateGroups, $lbl_LANDeskInfo, $lbl_RegistryReader,
    $lbl_RegistryInfo,    $lbl_Produkey,    $lbl_SID,
	$lbl_Macintosh,       $lbl_FindNSF,     $lbl_FindProfileSize
);
my ( $btn_RegistryReader,  $btn_RegistryInfo, $btn_Macintosh );
my (
    $form_Battery,     $form_Netstat,        $form_PolicyList,
    $form_FindPST,     $form_NICDuplex,      $form_EnumerateGroups,
    $form_LANDeskInfo, $form_RegistryReader, $form_Produkey,
	$form_SID,         $form_RegistryInfo,   $form_Macintosh,
    $form_FindNSF,     $form_FindProfileSize
);

my ( $lbl_MacInstructions, $lbl_MacNetstat, $lbl_MacOptical );
my ( $form_MacNetstat, $form_MacOptical );
my (
    $macmain,       $macw,        $mach,  $macncw,
    $macnch,        $macwx,       $macwy, $btn_macdefault,
    $btn_maccancel, $btn_machelp, $macsb
);

my @rr;
my (
    $rrmain,       $rrw,        $rrh,  $rrncw,
    $rrnch,        $rrwx,       $rrwy, $btn_rrdefault,
    $btn_rrcancel, $btn_rrhelp, $rrsb
);
my (
    $lbl_rrInstructions, $form_rr1, $form_rr2, $form_rr3,
    $form_rr4,           $form_rr5, $form_rr6, $form_rr7,
    $form_rr8,           $form_rr9, $form_rr10
);

my @ri;
my (
    $rimain,       $riw,        $rih,  $rincw,
    $rinch,        $riwx,       $riwy, $btn_ridefault,
    $btn_ricancel, $btn_rihelp, $risb
);
my (
    $lbl_riInstructions, $form_ri1, $form_ri2, $form_ri3,
    $form_ri4,           $form_ri5, $form_ri6, $form_ri7,
    $form_ri8,           $form_ri9, $form_ri10
);

# Prepare logging system
Win32::EventLog::Message::RegisterSource( 'Application', $prog );
my $event = Win32::EventLog->new($prog) || die "Can't open Event log!\n";
use Win32::EventLog::Carp qw(cluck carp croak click confess),
  { Source => $prog };

my $usage = <<EOD;

Usage: $prog [-d] [-skipupdate] [-h]
	-d			debug
    -skipupdate Don't check the website for updates
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

# Get the window handle so we can hide it
my ($DOS) = Win32::GUI::GetPerlWindow();

if ( !$DEBUG ) {

    # Hide console window
    Win32::GUI::Hide($DOS);

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

# Check the registry for ErrorDir
my $RegKey =
  $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup"};
if ($RegKey) {
    $ldmain  = $RegKey->GetValue("LDMainPath");
    $ldlogon = Win32::GetShortPathName($ldmain);
    $ldlogon .= "ldlogon";
}
else {
    Log("Can't find HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup");
    Win32::GUI::MessageBox(
        0,
"Can't find HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup. Are you sure this is the core?",
        "ldms_client_core",
        48
    );
    exit 1;
}
if ( !-e $ldlogon ) {
    Log("Can't find $ldlogon");
    Win32::GUI::MessageBox( 0,
        "Can't find $ldlogon. Are you sure this is the core?",
        "ldms_client_core", 48 );
    exit 1;
}

my $configfile = $ldlogon . "\\ldms_client.ini";
if ($DEBUG) { Log("DEBUG: Config file is $configfile"); }
my $Config = Config::Tiny->new();

# Read the configuration file if it already exists.
if ( -e $configfile ) {
    $Config = Config::Tiny->read($configfile)
      || &LogDie( "Can't read $configfile: ", Config::Tiny->errstr() );

    # Reading properties
    $Battery         = $Config->{_}->{Battery};
    $Netstat         = $Config->{_}->{Netstat};
    $PolicyList      = $Config->{_}->{PolicyList};
    $FindPST         = $Config->{_}->{FindPST};
    $FindNSF         = $Config->{_}->{FindNSF};
    $FindProfileSize = $Config->{_}->{FindProfileSize};
    $NICDuplex       = $Config->{_}->{NICDuplex};
    $EnumerateGroups = $Config->{_}->{EnumerateGroups};
    $LANDeskInfo     = $Config->{_}->{LANDeskInfo};
    $RegistryReader  = $Config->{_}->{RegistryReader};
    $RegistryInfo    = $Config->{_}->{RegistryInfo};
    $Produkey        = $Config->{_}->{Produkey};
    $SID             = $Config->{_}->{SID};
	$Macintosh       = $Config->{_}->{Macintosh};
	if ($RegistryReader) {
		foreach my $index (1..10) {
			if (length($Config->{RegistryReader}->{$index}) > 1 ) {
				$rr[$index] = $Config->{RegistryReader}->{$index};
			} else {
				# Gotta define it for the UI
				$rr[$index] = "";
			}
		if ($DEBUG) { Log("DEBUG: Registry entry $index is $rr[$index]"); }
		}
	}
	if ($RegistryInfo) {
		foreach my $index (1..10) {
			if (length($Config->{RegistryInfo}->{$index}) > 1 ) {
				$ri[$index] = $Config->{RegistryInfo}->{$index};
			} else {
				# Gotta define it for the UI
				$ri[$index] = "";
			}
		if ($DEBUG) { Log("DEBUG: Registry entry $index is $ri[$index]"); }
		}
	}
	if ($Macintosh) {
		$MacNetstat = $Config->{Macintosh}->{MacNetstat};
		$MacOptical = $Config->{Macintosh}->{MacOptical};
	}
}

if ($DEBUG) {
    &Log(
"From config file: Battery=$Battery, Netstat=$Netstat, "
. "PolicyList=$PolicyList, FindPST=$FindPST, NICDuplex=$NICDuplex, "
. "EnumerateGroups=$EnumerateGroups, LANDeskInfo=$LANDeskInfo, "
. "RegistryReader=$RegistryReader, RegistryInfo is $RegistryInfo, "
. "Produkey=$Produkey, SID=$SID, Macintosh=$Macintosh, FindNSF=$FindNSF, "
. "FindProfileSize=$FindProfileSize"
    );
	if ($RegistryReader) {
		&Log("RegistryReader targets: @rr");
	}
	if ($RegistryInfo) {
		&Log("RegistryInfo targets: @ri");
	}
	if ($Macintosh) {
		&Log("MacNetstat=$MacNetstat, MacOptical=$MacOptical");
	}
}

# Check to see if there's an update available
&IsUpdate;

my $ldms_client_icon = new Win32::GUI::Icon("grey.ico");   # replace default camel icon with my own

my $ldms_client_class = new Win32::GUI::Class(   # set up a class to use my icon throughout the program
       -name => "ldms_client Class",
       -icon => $ldms_client_icon,
);

&Show_MainWindow;
Win32::GUI::Dialog();

if ($DEBUG) {
    &Log(
"From user input: Battery=$Battery, Netstat=$Netstat, "
. "PolicyList=$PolicyList, FindPST=$FindPST, NICDuplex=$NICDuplex, "
. "EnumerateGroups=$EnumerateGroups, LANDeskInfo=$LANDeskInfo, "
. "RegistryReader=$RegistryReader, RegistryInfo is $RegistryInfo, "
. "Produkey=$Produkey, SID=$SID, Macintosh=$Macintosh, FindNSF=$FindNSF, "
. "FindProfileSize=$FindProfileSize"
    );
	if ($RegistryReader) {
		&Log("RegistryReader targets: @rr");
	}
	if ($RegistryInfo) {
		&Log("RegistryInfo targets: @ri");
	}
	if ($Macintosh) {
		&Log("MacNetstat=$MacNetstat, MacOptical=$MacOptical");
	}
}

# Write discovered data
$Config->{version}->{Version}   = $ver;
$Config->{_}->{Battery}         = $Battery;
$Config->{_}->{Netstat}         = $Netstat;
$Config->{_}->{PolicyList}      = $PolicyList;
$Config->{_}->{FindPST}         = $FindPST;
$Config->{_}->{FindNSF}         = $FindNSF;
$Config->{_}->{FindProfileSize} = $FindProfileSize;
$Config->{_}->{NICDuplex}       = $NICDuplex;
$Config->{_}->{EnumerateGroups} = $EnumerateGroups;
$Config->{_}->{LANDeskInfo}     = $LANDeskInfo;
$Config->{_}->{RegistryReader}  = $RegistryReader;
$Config->{_}->{RegistryInfo}    = $RegistryInfo;
$Config->{_}->{Produkey}        = $Produkey;
$Config->{_}->{SID}             = $SID;
$Config->{_}->{Macintosh}       = $Macintosh;
foreach my $index (1..10) {
	$Config->{RegistryReader}->{$index}  = $rr[$index];
}
foreach my $index (1..10) {
	$Config->{RegistryInfo}->{$index}  = $ri[$index];
}
if ($Macintosh) {
	$Config->{Macintosh}->{MacNetstat}	= $MacNetstat;
	$Config->{Macintosh}->{MacOptical}  = $MacOptical;
}
$Config->write($configfile)
  or &LogDie( "Can't write $configfile: ", Config::Tiny->errstr() );

if ( !$DEBUG ) {

    # Restore console window
    Win32::GUI::Show($DOS);

}
Log("$prog $ver exiting.\n");
exit 0;

#############################################################################
# Subroutines                                                               #
#############################################################################

### Logging subroutine ########################################################
sub Log {
    my $msg = shift;
    $event->Report(
        {
            EventID   => 0,
            Strings   => $msg,
            EventType => 4,
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


### ASCII to Integer subroutine ###############################################
sub atoi {
    my $t = 0;
    foreach my $d ( split( //, shift() ) ) {
        $t = $t * 10 + $d;
    }
    return $t;
}

### IsUpdate subroutine #####################################################
sub IsUpdate {

    if ($skipupdate) { 
        &Log("Update checking disabled via command line.");
        return 0; 
    }
    my $url = 'http://www.droppedpackets.org/inventory-and-slm/ldms_client/version';
    my $content = get $url;
    if ( defined($content) ) {
        my $myversion = $ver;
        $content =~ m{<p>latest version is ([\d.]+)<br /></p>};
        my $onlineversion = $1;

        if ($DEBUG) { &LogDebug("onlineversion is $onlineversion"); }

        # Remove the dots and convert to an integer so that we can do numerical
        # comparison... e.g., version 8.80.0.249 is rendered as 8800249
        $onlineversion =~ s/\.?       # substitute any dot
                            (?=[0-9]) # keep any number
                            //gx;
        $myversion     =~ s/\.?       # substitute any dot
                            (?=[0-9]) # keep any number
                            //gx;
        if ( &atoi($onlineversion) > &atoi($myversion) ) {
            $updatemessage = 
"Update available at http://www.droppedpackets.org/scripts/ldms_client";
            &LogWarn( $updatemessage );
        }
        if ( &atoi($onlineversion) < &atoi($myversion) ) {
            $updatemessage = "You're running beta code. "
            . "Please keep me informed via jack\@monkeynoodle.org.";
            &LogWarn( $updatemessage );
        }
        return 0;
    }
    else {
        &Log("Couldn't get $url");
        return 1;
    }
}

## Windowing Subroutines  ###################################################
sub Show_MainWindow {

    # build window
    $main = Win32::GUI::Window->new(
        -name     => 'Main',
        -text     => 'ldms_client_core $ver configuration',
        -width    => 350,
        -height   => 500,
		-class    => $ldms_client_class,
        -dialogui => 1,
    );

    # Add some stuff
    $lbl_Instructions = $main->AddLabel(
        -name => "lblInstructions",
        -text => "Please select the scan extensions you'd like to enable.",
        -pos  => [ 5, 5 ],
        -size => [ 300, 20 ],
    );

    # Begin Battery row
    $form_Battery = $main->AddCheckbox(
        -name    => "battery_field",
        -checked => $Battery,
        -tabstop => 1,
        -pos     => [ 10, 25 ],
        -size    => [ 15, 20 ],
    );
    $lbl_Battery = $main->AddLabel(
        -name => "lblBattery",
        -text => "Battery Information",
        -pos  => [ 28, 28 ],
        -size => [ 300, 20 ],
    );

    # End Battery row

    # Begin Netstat row
    $form_Netstat = $main->AddCheckbox(
        -name    => "netstat_field",
        -checked => $Netstat,
        -tabstop => 1,
        -pos     => [ 10, 50 ],
        -size    => [ 15, 20 ],
    );
    $lbl_Netstat = $main->AddLabel(
        -name => "lblNetstat",
        -text => "Netstat Information",
        -pos  => [ 28, 53 ],
        -size => [ 300, 20 ],
    );

    # End Netstat row

    # Begin NICDuplex row
    $form_NICDuplex = $main->AddCheckbox(
        -name    => "nicduplex_field",
        -checked => $NICDuplex,
        -tabstop => 1,
        -pos     => [ 10, 75 ],
        -size    => [ 15, 20 ],
    );
    $lbl_NICDuplex = $main->AddLabel(
        -name => "lblNNICDuplex",
        -text => "NIC Duplex Information",
        -pos  => [ 28, 78 ],
        -size => [ 300, 20 ],
    );

    # End NICDuplex row

    # Begin PolicyList row
    $form_PolicyList = $main->AddCheckbox(
        -name    => "policylist_field",
        -checked => $PolicyList,
        -tabstop => 1,
        -pos     => [ 10, 100 ],
        -size    => [ 15, 20 ],
    );
    $lbl_PolicyList = $main->AddLabel(
        -name => "lblPolicyList",
        -text => "LANDesk Policy List",
        -pos  => [ 28, 103 ],
        -size => [ 300, 20 ],
    );

    # End PolicyList row

    # Begin FindPST row
    $form_FindPST = $main->AddCheckbox(
        -name    => "findpst_field",
        -checked => $FindPST,
        -tabstop => 1,
        -pos     => [ 10, 125 ],
        -size    => [ 15, 20 ],
    );
    $lbl_FindPST = $main->AddLabel(
        -name => "lblFindPST",
        -text => "Find Microsoft Outlook PST Files",
        -pos  => [ 28, 128 ],
        -size => [ 300, 20 ],
    );

    # End FindPST row

    # Begin FindNSF row
    $form_FindNSF = $main->AddCheckbox(
        -name    => "findnsf_field",
        -checked => $FindNSF,
        -tabstop => 1,
        -pos     => [ 10, 150 ],
        -size    => [ 15, 20 ],
    );
    $lbl_FindNSF = $main->AddLabel(
        -name => "lblFindNSF",
        -text => "Find Lotus Notes NSF Files",
        -pos  => [ 28, 153 ],
        -size => [ 300, 20 ],
    );

    # End FindNSF row

    # Begin LANDeskInfo row
    $form_LANDeskInfo = $main->AddCheckbox(
        -name    => "landeskinfo_field",
        -checked => $LANDeskInfo,
        -tabstop => 1,
        -pos     => [ 10, 175 ],
        -size    => [ 15, 20 ],
    );
    $lbl_LANDeskInfo = $main->AddLabel(
        -name => "lblLANDeskInfo",
        -text => "LANDesk Client Information",
        -pos  => [ 28, 178 ],
        -size => [ 300, 20 ],
    );

    # End LANDeskInfo row

    # Begin EnumerateGroups row
    $form_EnumerateGroups = $main->AddCheckbox(
        -name    => "enumerategroups_field",
        -checked => $EnumerateGroups,
        -tabstop => 1,
        -pos     => [ 10, 200 ],
        -size    => [ 15, 20 ],
    );
    $lbl_EnumerateGroups = $main->AddLabel(
        -name => "lblEnumerateGroups",
        -text => "Resolve Domain Members in Local Groups",
        -pos  => [ 28, 203 ],
        -size => [ 300, 20 ],
    );

    # End EnumerateGroups row

    # Begin RegistryReader row
    $form_RegistryReader = $main->AddCheckbox(
        -name    => "registryreader_field",
        -checked => $RegistryReader,
        -tabstop => 1,
        -pos     => [ 10, 225 ],
        -size    => [ 15, 20 ],
    );
    $lbl_RegistryReader = $main->AddLabel(
        -name => "lblRegistryReader",
        -text => "Collect Registry Keys from HKCU",
        -pos  => [ 28, 228 ],
        -size => [ 300, 20 ],
    );

    # spawn the registry key configuration window
    $btn_RegistryReader = $main->AddButton(
        -name => "btn_RegistryReader",
        -text => "Configure Registry Keys",
        -pos  => [ 200, 225 ],
    );

    # End RegistryReader row

    # Begin RegistryInfo row
    $form_RegistryInfo = $main->AddCheckbox(
        -name    => "registryinfo_field",
        -checked => $RegistryInfo,
        -tabstop => 1,
        -pos     => [ 10, 250 ],
        -size    => [ 15, 20 ],
    );
    $lbl_RegistryInfo = $main->AddLabel(
        -name => "lblRegistryInfo",
        -text => "Collect Registry Keys from HKLM",
        -pos  => [ 28, 253 ],
        -size => [ 300, 20 ],
    );

    # spawn the registry key configuration window
    $btn_RegistryInfo = $main->AddButton(
        -name => "btn_RegistryInfo",
        -text => "Configure Registry Keys",
        -pos  => [ 200, 250 ],
    );

    # End RegistryReader row

    # Begin Produkey row
    $form_Produkey = $main->AddCheckbox(
        -name    => "produkey_field",
        -checked => $Produkey,
        -tabstop => 1,
        -pos     => [ 10, 275 ],
        -size    => [ 15, 20 ],
    );
    $lbl_Produkey = $main->AddLabel(
        -name => "lblProdukey",
        -text => "Collect Microsoft product keys (requires produkey.exe)",
        -pos  => [ 28, 278 ],
        -size => [ 300, 20 ],
    );

    # End Produkey row

    # Begin SID row
    $form_SID = $main->AddCheckbox(
        -name    => "sid_field",
        -checked => $SID,
        -tabstop => 1,
        -pos     => [ 10, 300 ],
        -size    => [ 15, 20 ],
    );
    $lbl_SID = $main->AddLabel(
        -name => "lblSID",
        -text => "Collect Machine SIDs",
        -pos  => [ 28, 303 ],
        -size => [ 300, 20 ],
    );

    # End SID row

    # Begin Profile Size row
    $form_FindProfileSize = $main->AddCheckbox(
        -name    => "profilesize_field",
        -checked => $FindProfileSize,
        -tabstop => 1,
        -pos     => [ 10, 325 ],
        -size    => [ 15, 20 ],
    );
    $lbl_FindProfileSize = $main->AddLabel(
        -name => "lblprofilesize",
        -text => "Find User Profile Sizes",
        -pos  => [ 28, 328 ],
        -size => [ 300, 20 ],
    );

    # End Profile Size row

    # Begin Macintosh row
    $form_Macintosh = $main->AddCheckbox(
        -name    => "macintosh_field",
        -checked => $Macintosh,
        -tabstop => 1,
        -pos     => [ 10, 350 ],
        -size    => [ 15, 20 ],
    );
    $lbl_Macintosh = $main->AddLabel(
        -name => "lblMacintosh",
        -text => "Extend Macintosh inventory",
        -pos  => [ 28, 353 ],
        -size => [ 300, 20 ],
    );

    # spawn the Macintosh inventory configuration window
    $btn_Macintosh = $main->AddButton(
        -name => "btn_Macintosh",
        -text => "Configure Mac Inventory",
        -pos  => [ 194, 350 ],
    );

    # End Macintosh row

    # Begin button row
    $btn_default = $main->AddButton(
        -name    => 'Default',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,             # Give button darker border
        -ok      => 1,             # press 'Return' to click this button
        -pos     => [ 50, 390 ],
        -size    => [ 60, 20 ],
    );

    $btn_cancel = $main->AddButton(
        -name    => 'Cancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,              # press 'Esc' to click this button
        -pos     => [ 150, 390 ],
        -size    => [ 60, 20 ],
    );

    $btn_help = $main->AddButton(
        -name    => 'Help',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 250, 390 ],
        -size    => [ 60, 20 ],
    );

    # End button row

    $sb = $main->AddStatusBar();
    if ($updatemessage) {
        $sb->Text($updatemessage);
    }

    # calculate its size
    $ncw = $main->Width() - $main->ScaleWidth();
    $nch = $main->Height() - $main->ScaleHeight();
    $w   = $lbl_Instructions->Width() + 30 + $ncw;
    $h =
      $lbl_Instructions->Height() +
      $lbl_Battery->Height() +
      $lbl_Netstat->Height() +
      $lbl_FindPST->Height() +
      $lbl_FindNSF->Height() +
      $lbl_FindProfileSize->Height() +
      $lbl_NICDuplex->Height() +
      $lbl_PolicyList->Height() +
      $lbl_LANDeskInfo->Height() +
      $lbl_EnumerateGroups->Height() +
      $lbl_RegistryReader->Height() +
      $lbl_RegistryInfo->Height() +
      $lbl_Produkey->Height() +
      $lbl_SID->Height() +
      $lbl_Macintosh->Height() +
      + 140 +
      $nch;

    # Don't let it get smaller than it should be
    $main->Change( -minsize => [ $w, $h ] );

    # calculate its centered position
    # Assume we have the main window size in ($w, $h) as before
    $desk = Win32::GUI::GetDesktopWindow();
    $dw   = Win32::GUI::Width($desk);
    $dh   = Win32::GUI::Height($desk);
    $wx   = ( $dw - $w ) / 2;
    $wy   = ( $dh - $h ) / 2;

    # Resize, position and display
    $main->Resize( $w, $h );
    $main->Move( $wx, $wy );

    $main->Show();
}

sub Main_Terminate {
    return -1;
}

sub Main_Resize {
    $sb->Move( 0, $main->ScaleHeight - $sb->Height );
    $sb->Resize( $main->ScaleWidth, $sb->Height );
}

sub btn_RegistryReader_Click {
    &Show_RRWindow;
}

sub btn_RegistryInfo_Click {
    &Show_RIWindow;
}

sub btn_Macintosh_Click {
    &Show_MacWindow;
}

sub Default_Click {

    if ($DEBUG) { Log("DEBUG: Okay clicked in MainWindow"); }

    # Read my variables
    $Battery         = $form_Battery->Checked();
    $Netstat         = $form_Netstat->Checked();
    $PolicyList      = $form_PolicyList->Checked();
    $FindPST         = $form_FindPST->Checked();
    $FindNSF         = $form_FindNSF->Checked();
    $FindProfileSize = $form_FindProfileSize->Checked();
    $NICDuplex       = $form_NICDuplex->Checked();
    $LANDeskInfo     = $form_LANDeskInfo->Checked();
    $EnumerateGroups = $form_EnumerateGroups->Checked();
    $RegistryReader  = $form_RegistryReader->Checked();
    $RegistryInfo    = $form_RegistryInfo->Checked();
    $Produkey        = $form_Produkey->Checked();
    $SID             = $form_SID->Checked();
    $Macintosh       = $form_Macintosh->Checked();

    $main->Hide();
    return -1;
}

sub Cancel_Click {
    if ($DEBUG) { Log("DEBUG: Cancel clicked in MainWindow"); }
    $main->Hide();

    # Restore console window
    Win32::GUI::Show($DOS);
    exit -1;
}

sub Help_Click {
    if ($DEBUG) { Log("DEBUG: Help clicked in MainWindow"); }
    open_browser(
'http://www.droppedpackets.org/inventory-and-slm/ldms_client/ldms_client-manual'
    );

    return 0;
}

### RegistryReader Window subroutines ########################################
sub Show_RRWindow {

    # Build the window
    $rrmain = Win32::GUI::Window->new(
        -name   => 'rrMain',
        -text   => 'ldms_client_core hkcu registry configuration',
        -width  => 450,
        -height => 400,
		-class  => $ldms_client_class,
    );

    # Add some stuff
    $lbl_rrInstructions = $rrmain->AddLabel(
        -name => "lblrrInstructions",
        -text => "Please select the HKEY_CURRENT_USER registry keys you'd like to gather.",
        -pos  => [ 5, 5 ],
        -size => [ 300, 40 ],
    );

    # Begin rr1 row
    $form_rr1 = $rrmain->AddTextfield(
        -name    => "rr1_field",
        -prompt  => "HKCU/",
        -text    => $rr[1],
        -tabstop => 1,
        -pos     => [ 50, 50 ],
        -size    => [ 300, 20 ],
    );

    # End rr1 row

    # Begin rr2 row
    $form_rr2 = $rrmain->AddTextfield(
        -name    => "rr2_field",
        -prompt  => "HKCU/",
        -text    => $rr[2],
        -tabstop => 1,
        -pos     => [ 50, 75 ],
        -size    => [ 300, 20 ],
    );

    # End rr2 row

    # Begin rr3 row
    $form_rr3 = $rrmain->AddTextfield(
        -name    => "rr3_field",
        -prompt  => "HKCU/",
        -text    => $rr[3],
        -tabstop => 1,
        -pos     => [ 50, 100 ],
        -size    => [ 300, 20 ],
    );

    # End rr3 row

    # Begin rr4 row
    $form_rr4 = $rrmain->AddTextfield(
        -name    => "rr4_field",
        -prompt  => "HKCU/",
        -text    => $rr[4],
        -tabstop => 1,
        -pos     => [ 50, 125 ],
        -size    => [ 300, 20 ],
    );

    # End rr4 row

    # Begin rr5 row
    $form_rr5 = $rrmain->AddTextfield(
        -name    => "rr5_field",
        -prompt  => "HKCU/",
        -text    => $rr[5],
        -tabstop => 1,
        -pos     => [ 50, 150 ],
        -size    => [ 300, 20 ],
    );

    # End rr5 row

    # Begin rr6 row
    $form_rr6 = $rrmain->AddTextfield(
        -name    => "rr6_field",
        -prompt  => "HKCU/",
        -text    => $rr[6],
        -tabstop => 1,
        -pos     => [ 50, 175 ],
        -size    => [ 300, 20 ],
    );

    # End rr6 row

    # Begin rr7 row
    $form_rr7 = $rrmain->AddTextfield(
        -name    => "rr7_field",
        -prompt  => "HKCU/",
        -text    => $rr[7],
        -tabstop => 1,
        -pos     => [ 50, 200 ],
        -size    => [ 300, 20 ],
    );

    # End rr7 row

    # Begin rr8 row
    $form_rr8 = $rrmain->AddTextfield(
        -name    => "rr8_field",
        -prompt  => "HKCU/",
        -text    => $rr[8],
        -tabstop => 1,
        -pos     => [ 50, 225 ],
        -size    => [ 300, 20 ],
    );

    # End rr8 row

    # Begin rr9 row
    $form_rr9 = $rrmain->AddTextfield(
        -name    => "rr9_field",
        -prompt  => "HKCU/",
        -text    => $rr[9],
        -tabstop => 1,
        -pos     => [ 50, 250 ],
        -size    => [ 300, 20 ],
    );

    # End rr9 row

    # Begin rr10 row
    $form_rr10 = $rrmain->AddTextfield(
        -name    => "rr10_field",
        -prompt  => "HKCU/",
        -text    => $rr[10],
        -tabstop => 1,
        -pos     => [ 50, 275 ],
        -size    => [ 300, 20 ],
    );

    # End rr10 row

    # Begin button row
    $btn_rrdefault = $rrmain->AddButton(
        -name    => 'rrDefault',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,             # Give button darker border
        -ok      => 1,             # press 'Return' to click this button
        -pos     => [ 50, 300 ],
        -size    => [ 60, 20 ],
    );

    $btn_rrcancel = $rrmain->AddButton(
        -name    => 'rrCancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,              # press 'Esc' to click this button
        -pos     => [ 150, 300 ],
        -size    => [ 60, 20 ],
    );

    $btn_rrhelp = $rrmain->AddButton(
        -name    => 'rrHelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 250, 300 ],
        -size    => [ 60, 20 ],
    );

    # End button row

    $rrsb = $rrmain->AddStatusBar();

    # calculate its size
    $rrncw = $rrmain->Width() - $rrmain->ScaleWidth();
    $rrnch = $rrmain->Height() - $rrmain->ScaleHeight();
    $rrw   = $lbl_rrInstructions->Width() + 75 + $rrncw;
    $rrh =
      $lbl_rrInstructions->Height() +
      $form_rr1->Height() +
      $form_rr2->Height() +
      $form_rr3->Height() +
      $form_rr4->Height() +
      $form_rr5->Height() +
      $form_rr6->Height() +
      $form_rr7->Height() +
      $form_rr8->Height() +
      $form_rr9->Height() +
      $form_rr10->Height() +
      +110 +
      $rrnch;

    # Don't let it get smaller than it should be
    $rrmain->Change( -minsize => [ $rrw, $rrh ] );

    # calculate its centered position
    # Assume we have the main window size in ($w, $h) as before
    $rrwx = ( $dw - $rrw ) / 2;
    $rrwy = ( $dh - $rrh ) / 2;

    # Resize, position and display
    $rrmain->Resize( $rrw, $rrh );
    $rrmain->Move( $rrwx, $rrwy );

    $rrmain->Show();
}

sub rrMain_Terminate {
    return -1;
}

sub rrMain_Resize {
    $rrsb->Move( 0, $rrmain->ScaleHeight - $rrsb->Height );
    $rrsb->Resize( $rrmain->ScaleWidth, $rrsb->Height );
}

sub rrDefault_Click {

    if ($DEBUG) { Log("DEBUG: Okay clicked in RRMainWindow"); }

    # Read my variables
    $rr[1]  = &trimkey($form_rr1->GetLine(0));
    $rr[2]  = &trimkey($form_rr2->GetLine(0));
    $rr[3]  = &trimkey($form_rr3->GetLine(0));
    $rr[4]  = &trimkey($form_rr4->GetLine(0));
    $rr[5]  = &trimkey($form_rr5->GetLine(0));
    $rr[6]  = &trimkey($form_rr6->GetLine(0));
    $rr[7]  = &trimkey($form_rr7->GetLine(0));
    $rr[8]  = &trimkey($form_rr8->GetLine(0));
    $rr[9]  = &trimkey($form_rr9->GetLine(0));
    $rr[10] = &trimkey($form_rr10->GetLine(0));

    $rrmain->Hide();
    return 0;
}

sub rrCancel_Click {
    if ($DEBUG) { Log("DEBUG: Cancel clicked in RRMainWindow"); }
    $rrmain->Hide();
    return 0;
}

sub rrHelp_Click {
    if ($DEBUG) { Log("DEBUG: Help clicked in RRWindow"); }
    open_browser(
'http://www.droppedpackets.org/inventory-and-slm/ldms_client/ldms_client-manual'
    );

    return 0;
}

### trimkey subroutine ######################################################
sub trimkey($) {
    my $input = my $string = shift;
    unless ( !defined($string) ) {
		# Replace backslashes with forward slashes
        $string =~ s/\\/\//g;
		# Remove beginning slashes (forward or backward)
        $string =~ s/^\/|^\\//g;
		# Remove beginning references to the registry hive
        $string =~ s/^HKCU\/|^HKEY_CURRENT_USER\///g;
        $string =~ s/^HKLM\/|^HKEY_LOCAL_MACHINE\///g;
    }
	if ($DEBUG) { &LogWarn("trimkey: trimmed $input to $string\n"); }
    return $string;
}

### RegistryInfo Window subroutines ##########################################
sub Show_RIWindow {

    # Build the window
    $rimain = Win32::GUI::Window->new(
        -name   => 'riMain',
        -text   => 'ldms_client_core hklm registry configuration',
        -width  => 450,
        -height => 400,
		-class  => $ldms_client_class,
    );

    # Add some stuff
    $lbl_riInstructions = $rimain->AddLabel(
        -name => "lblriInstructions",
        -text => "Please select the HKEY_LOCAL_MACHINE registry keys you'd like to gather.",
        -pos  => [ 5, 5 ],
        -size => [ 300, 40 ],
    );

    # Begin ri1 row
    $form_ri1 = $rimain->AddTextfield(
        -name    => "ri1_field",
        -prompt  => "HKLM/",
        -text    => $ri[1],
        -tabstop => 1,
        -pos     => [ 50, 50 ],
        -size    => [ 300, 20 ],
    );

    # End ri1 row

    # Begin ri2 row
    $form_ri2 = $rimain->AddTextfield(
        -name    => "ri2_field",
        -prompt  => "HKLM/",
        -text    => $ri[2],
        -tabstop => 1,
        -pos     => [ 50, 75 ],
        -size    => [ 300, 20 ],
    );

    # End ri2 row

    # Begin ri3 row
    $form_ri3 = $rimain->AddTextfield(
        -name    => "ri3_field",
        -prompt  => "HKLM/",
        -text    => $ri[3],
        -tabstop => 1,
        -pos     => [ 50, 100 ],
        -size    => [ 300, 20 ],
    );

    # End ri3 row

    # Begin ri4 row
    $form_ri4 = $rimain->AddTextfield(
        -name    => "ri4_field",
        -prompt  => "HKLM/",
        -text    => $ri[4],
        -tabstop => 1,
        -pos     => [ 50, 125 ],
        -size    => [ 300, 20 ],
    );

    # End ri4 row

    # Begin ri5 row
    $form_ri5 = $rimain->AddTextfield(
        -name    => "ri5_field",
        -prompt  => "HKLM/",
        -text    => $ri[5],
        -tabstop => 1,
        -pos     => [ 50, 150 ],
        -size    => [ 300, 20 ],
    );

    # End ri5 row

    # Begin ri6 row
    $form_ri6 = $rimain->AddTextfield(
        -name    => "ri6_field",
        -prompt  => "HKLM/",
        -text    => $ri[6],
        -tabstop => 1,
        -pos     => [ 50, 175 ],
        -size    => [ 300, 20 ],
    );

    # End ri6 row

    # Begin ri7 row
    $form_ri7 = $rimain->AddTextfield(
        -name    => "ri7_field",
        -prompt  => "HKLM/",
        -text    => $ri[7],
        -tabstop => 1,
        -pos     => [ 50, 200 ],
        -size    => [ 300, 20 ],
    );

    # End ri7 row

    # Begin ri8 row
    $form_ri8 = $rimain->AddTextfield(
        -name    => "ri8_field",
        -prompt  => "HKLM/",
        -text    => $ri[8],
        -tabstop => 1,
        -pos     => [ 50, 225 ],
        -size    => [ 300, 20 ],
    );

    # End ri8 row

    # Begin ri9 row
    $form_ri9 = $rimain->AddTextfield(
        -name    => "ri9_field",
        -prompt  => "HKLM/",
        -text    => $ri[9],
        -tabstop => 1,
        -pos     => [ 50, 250 ],
        -size    => [ 300, 20 ],
    );

    # End ri9 row

    # Begin ri10 row
    $form_ri10 = $rimain->AddTextfield(
        -name    => "ri10_field",
        -prompt  => "HKLM/",
        -text    => $ri[10],
        -tabstop => 1,
        -pos     => [ 50, 275 ],
        -size    => [ 300, 20 ],
    );

    # End ri10 row

    # Begin button row
    $btn_ridefault = $rimain->AddButton(
        -name    => 'riDefault',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,             # Give button darker border
        -ok      => 1,             # press 'Return' to click this button
        -pos     => [ 50, 300 ],
        -size    => [ 60, 20 ],
    );

    $btn_ricancel = $rimain->AddButton(
        -name    => 'riCancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,              # press 'Esc' to click this button
        -pos     => [ 150, 300 ],
        -size    => [ 60, 20 ],
    );

    $btn_rihelp = $rimain->AddButton(
        -name    => 'riHelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 250, 300 ],
        -size    => [ 60, 20 ],
    );

    # End button row

    $risb = $rimain->AddStatusBar();

    # calculate its size
    $rincw = $rimain->Width() - $rimain->ScaleWidth();
    $rinch = $rimain->Height() - $rimain->ScaleHeight();
    $riw   = $lbl_riInstructions->Width() + 75 + $rincw;
    $rih =
      $lbl_riInstructions->Height() +
      $form_ri1->Height() +
      $form_ri2->Height() +
      $form_ri3->Height() +
      $form_ri4->Height() +
      $form_ri5->Height() +
      $form_ri6->Height() +
      $form_ri7->Height() +
      $form_ri8->Height() +
      $form_ri9->Height() +
      $form_ri10->Height() +
      + 110 +
      $rinch;

    # Don't let it get smaller than it should be
    $rimain->Change( -minsize => [ $riw, $rih ] );

    # calculate its centered position
    # Assume we have the main window size in ($w, $h) as before
    $riwx = ( $dw - $riw ) / 2;
    $riwy = ( $dh - $rih ) / 2;

    # Resize, position and display
    $rimain->Resize( $riw, $rih );
    $rimain->Move( $riwx, $riwy );

    $rimain->Show();
}

sub riMain_Terminate {
    return -1;
}

sub riMain_Resize {
    $risb->Move( 0, $rimain->ScaleHeight - $risb->Height );
    $risb->Resize( $rimain->ScaleWidth, $risb->Height );
}

sub riDefault_Click {

    if ($DEBUG) { Log("DEBUG: Okay clicked in RIMainWindow"); }

    # Read my variables
    $ri[1]  = &trimkey($form_ri1->GetLine(0));
    $ri[2]  = &trimkey($form_ri2->GetLine(0));
    $ri[3]  = &trimkey($form_ri3->GetLine(0));
    $ri[4]  = &trimkey($form_ri4->GetLine(0));
    $ri[5]  = &trimkey($form_ri5->GetLine(0));
    $ri[6]  = &trimkey($form_ri6->GetLine(0));
    $ri[7]  = &trimkey($form_ri7->GetLine(0));
    $ri[8]  = &trimkey($form_ri8->GetLine(0));
    $ri[9]  = &trimkey($form_ri9->GetLine(0));
    $ri[10] = &trimkey($form_ri10->GetLine(0));

    $rimain->Hide();
    return 0;
}

sub riCancel_Click {
    if ($DEBUG) { Log("DEBUG: Cancel clicked in RIMainWindow"); }
    $rimain->Hide();
    return 0;
}

sub riHelp_Click {
    if ($DEBUG) { Log("DEBUG: Help clicked in RIWindow"); }
    open_browser(
'http://www.droppedpackets.org/inventory-and-slm/ldms_client/ldms_client-manual'
    );

    return 0;
}
### End of RegistryInfo Window subroutines ###################################

### Macintosh Window subroutines #############################################
sub Show_MacWindow {

    # Build the window
    $macmain = Win32::GUI::Window->new(
        -name   => 'macmain',
        -text   => 'ldms_client_core macintosh configuration',
        -width  => 450,
        -height => 200,
		-class  => $ldms_client_class,
    );

    # Add some stuff
    $lbl_MacInstructions = $macmain->AddLabel(
        -name => "lbl_MacInstructions",
        -text => "Please select the Macintosh inventory attributes you'd like to gather.",
        -pos  => [ 5, 5 ],
        -size => [ 400, 40 ],
    );


    # Begin MacNetstat row
    $form_MacNetstat = $macmain->AddCheckbox(
        -name    => "MacNetstat_field",
        -checked => $MacNetstat,
        -tabstop => 1,
        -pos     => [ 10, 25 ],
        -size    => [ 15, 20 ],
    );
    $lbl_MacNetstat = $macmain->AddLabel(
        -name => "lbl_Macnetstat",
        -text => "Macintosh Netstat Information",
        -pos  => [ 28, 28 ],
        -size => [ 300, 20 ],
    );
    # End MacNetstat row

    # Begin MacOptical row
    $form_MacOptical = $macmain->AddCheckbox(
        -name    => "MacOptical_field",
        -checked => $MacOptical,
        -tabstop => 1,
        -pos     => [ 10, 50 ],
        -size    => [ 15, 20 ],
    );
    $lbl_MacOptical = $macmain->AddLabel(
        -name => "lbl_MacOptical",
        -text => "Optical Drive Information",
        -pos  => [ 28, 53 ],
        -size => [ 300, 20 ],
    );
    # End MacOptical row

    # Begin button row
    $btn_macdefault = $macmain->AddButton(
        -name    => 'macdefault',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,             # Give button darker border
        -ok      => 1,             # press 'Return' to click this button
        -pos     => [ 50, 75 ],
        -size    => [ 60, 20 ],
    );

    $btn_maccancel = $macmain->AddButton(
        -name    => 'maccancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,              # press 'Esc' to click this button
        -pos     => [ 150, 75 ],
        -size    => [ 60, 20 ],
    );

    $btn_machelp = $macmain->AddButton(
        -name    => 'machelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 250, 75 ],
        -size    => [ 60, 20 ],
    );
    # End button row

    $macsb = $macmain->AddStatusBar();

    # calculate its size
    $macncw = $macmain->Width() - $macmain->ScaleWidth();
    $macnch = $macmain->Height() - $macmain->ScaleHeight();
    $macw   = $lbl_MacInstructions->Width() + $macncw;
    $mach =
      $lbl_MacInstructions->Height() +
      $lbl_MacNetstat->Height() +
      $lbl_MacOptical->Height() +
      + 50 +
      $macnch;

    # Don't let it get smaller than it should be
    $macmain->Change( -minsize => [ $macw, $mach ] );

    # calculate its centered position
    # Assume we have the main window size in ($macw, $mach) as before
    $macwx = ( $dw - $macw ) / 2;
    $macwy = ( $dh - $mach ) / 2;

    # Resize, position and display
    $macmain->Resize( $macw, $mach );
    $macmain->Move( $macwx, $macwy );

    $macmain->Show();
}

sub macmain_Terminate {
    return -1;
}

sub macmain_Resize {
    $macsb->Move( 0, $macmain->ScaleHeight - $macsb->Height );
    $macsb->Resize( $macmain->ScaleWidth, $macsb->Height );
}

sub macdefault_Click {

    if ($DEBUG) { Log("DEBUG: Okay clicked in MacMainWindow"); }

    # Read my variables
    $MacNetstat      = $form_MacNetstat->Checked();
    $MacOptical      = $form_MacOptical->Checked();

    $macmain->Hide();
    return 0;
}

sub maccancel_Click {
    if ($DEBUG) { Log("DEBUG: Cancel clicked in MacMainWindow"); }
    $macmain->Hide();
    return 0;
}

sub machelp_Click {
    if ($DEBUG) { Log("DEBUG: Help clicked in MacWindow"); }
    open_browser(
'http://www.droppedpackets.org/inventory-and-slm/ldms_client/ldms_client-manual'
    );

    return 0;
}
