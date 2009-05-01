#############################################################################
# ldms_client_core.pl, v 1.0.1                                              #
# (c) 2008 Jack Coates, jack@monkeynoodle.org                               #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.monkeynoodle.org/comp/tools/ldms_whatever                      #
#############################################################################
#

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
my $ver = "1.0.1";
my $DEBUG = $A{d} || 0;

# TODO :: Add Produkey support?

my ($ldmain, $ldlogon);
my ($Battery, $Netstat, $PolicyList, $FindPST, $NICDuplex, $EnumerateGroups, $LANDeskInfo, $RegistryReader);
my ($main, $w, $h, $ncw, $nch, $dw, $dh, $desk, $wx, $wy, $btn_default, $btn_cancel, $btn_help, $sb );
my ($lbl_Instructions, $lbl_Battery, $lbl_Netstat, $lbl_PolicyList, $lbl_FindPST, $lbl_NICDuplex, $lbl_EnumerateGroups, $lbl_LANDeskInfo, $lbl_RegistryReader );
my ($form_Battery, $form_Netstat, $form_PolicyList, $form_FindPST, $form_NICDuplex, $form_EnumerateGroups, $form_LANDeskInfo, $form_RegistryReader);

# Prepare logging system
Win32::EventLog::Message::RegisterSource( 'Application', $prog );
my $event = Win32::EventLog->new($prog) || die "Can't open Event log!\n";
use Win32::EventLog::Carp qw(cluck carp croak click confess),
  { Source => $prog };

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
    $ldmain = $RegKey->GetValue("LDMainPath");
    $ldlogon =
      Win32::GetShortPathName($ldmain);
    $ldlogon   .= "ldlogon";
} else {
	Log("Can't find HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup");
	Win32::GUI::MessageBox(
        0,
        "Can't find HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup. Are you sure this is the core?",
        "ldms_client_core", 48
    );
	exit 1;
}
if (! -e $ldlogon) {
	Log("Can't find $ldlogon");
	Win32::GUI::MessageBox(
        0,
        "Can't find $ldlogon. Are you sure this is the core?",
        "ldms_client_core", 48
    );
	exit 1;
}

my $configfile = $ldlogon."\\ldms_client.ini";
if ($DEBUG) { Log("DEBUG: Config file is $configfile"); }
my $Config = Config::Tiny->new();

# Read the configuration file if it already exists.
if (-e $configfile) {
	$Config = Config::Tiny->read( $configfile ) || &LogDie ("Can't read $configfile: ",Config::Tiny->errstr());
	# Reading properties
	$Battery = $Config->{_}->{Battery};
	$Netstat = $Config->{_}->{Netstat};
	$PolicyList = $Config->{_}->{PolicyList};
	$FindPST = $Config->{_}->{FindPST};
	$NICDuplex = $Config->{_}->{NICDuplex};
	$EnumerateGroups = $Config->{_}->{EnumerateGroups};
	$LANDeskInfo = $Config->{_}->{LANDeskInfo};
	$RegistryReader = $Config->{_}->{RegistryReader};
	# my $one = $Config->{section}->{one};
	# my $Foo = $Config->{section}->{Foo};
}

if ($DEBUG) {
	&Log("From config file: Battery=$Battery, Netstat=$Netstat, PolicyList=$PolicyList, FindPST=$FindPST, NICDuplex=$NICDuplex, EnumerateGroups=$EnumerateGroups, LANDeskInfo=$LANDeskInfo");
}

&Show_MainWindow;
Win32::GUI::Dialog();

if ($DEBUG) {
	&Log("From user input: Battery=$Battery, Netstat=$Netstat, PolicyList=$PolicyList, FindPST=$FindPST, NICDuplex=$NICDuplex, EnumerateGroups=$EnumerateGroups, LANDeskInfo=$LANDeskInfo");
}
# Write discovered data
$Config->{version}->{Version} = $ver;
$Config->{_}->{Battery} = $Battery;
$Config->{_}->{Netstat} = $Netstat;
$Config->{_}->{PolicyList} = $PolicyList;
$Config->{_}->{FindPST} = $FindPST;
$Config->{_}->{NICDuplex} = $NICDuplex;
$Config->{_}->{EnumerateGroups} = $EnumerateGroups;
$Config->{_}->{LANDeskInfo} = $LANDeskInfo;
$Config->{_}->{RegistryReader} = $RegistryReader;
$Config->write($configfile) or &LogDie ("Can't write $configfile: ",Config::Tiny->errstr());

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

## Windowing Subroutines  ###################################################
sub Show_MainWindow {

    # build window
    $main = Win32::GUI::Window->new(
        -name   => 'Main',
        -text   => 'ldms_client_core configuration',
        -width  => 350,
        -height => 300,
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

    # Begin LANDeskInfo row
    $form_LANDeskInfo = $main->AddCheckbox(
        -name    => "landeskinfo_field",
        -checked => $LANDeskInfo,
        -tabstop => 1,
        -pos     => [ 10, 150 ],
        -size    => [ 15, 20 ],
    );
	$lbl_LANDeskInfo = $main->AddLabel(
		-name => "lblLANDeskInfo",
        -text => "LANDesk Client Information",
		-pos  => [ 28, 153 ],
		-size => [ 300, 20 ],
	);
    # End LANDeskInfo row

    # Begin EnumerateGroups row
    $form_EnumerateGroups = $main->AddCheckbox(
        -name    => "enumerategroups_field",
        -checked => $EnumerateGroups,
        -tabstop => 1,
        -pos     => [ 10, 175 ],
        -size    => [ 15, 20 ],
    );
	$lbl_EnumerateGroups = $main->AddLabel(
		-name => "lblEnumerateGroups",
        -text => "Resolve Domain Members in Local Groups",
		-pos  => [ 28, 178 ],
		-size => [ 300, 20 ],
	);
    # End EnumerateGroups row

	# Begin RegistryReader row
	# Greyed out
    $form_RegistryReader = $main->AddCheckbox(
        -name    => "registryreader_field",
        -checked => $RegistryReader,
		-disabled => 1,
        -tabstop => 1,
        -pos     => [ 10, 200 ],
        -size    => [ 15, 20 ],
    );
	$lbl_RegistryReader = $main->AddLabel(
		-name => "lblRegistryReader",
        -text => "Collect Registry Keys from HKCU",
		-pos  => [ 28, 203 ],
		-size => [ 300, 20 ],
	);
    # End EnumerateGroups row

    # Begin button row
    $btn_default = $main->AddButton(
        -name    => 'Default',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,              # Give button darker border
        -ok      => 1,              # press 'Return' to click this button
        -pos     => [ 50, 235 ],
        -size    => [ 60, 20 ],
    );

    $btn_cancel = $main->AddButton(
        -name    => 'Cancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,              # press 'Esc' to click this button
        -pos     => [ 150, 235 ],
        -size    => [ 60, 20 ],
    );

    $btn_help = $main->AddButton(
        -name    => 'Help',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 250, 235 ],
        -size    => [ 60, 20 ],
    );
    # End button row

    $sb = $main->AddStatusBar();

    # calculate its size
    $ncw = $main->Width() - $main->ScaleWidth();
    $nch = $main->Height() - $main->ScaleHeight();
    $w   = $lbl_Instructions->Width() + 30 + $ncw;
    $h =
      $lbl_Instructions->Height() +
      $lbl_Battery->Height() +
      $lbl_Netstat->Height() +
      $lbl_FindPST->Height() +
	  $lbl_NICDuplex->Height() +
      $lbl_PolicyList->Height() +
      $lbl_LANDeskInfo->Height() +
      $lbl_EnumerateGroups->Height() +
      $lbl_RegistryReader->Height() +
      + 100 + $nch;

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

sub Default_Click {

    if ($DEBUG) { Log("DEBUG: Okay clicked in MainWindow"); }
    # Read my variables
	$Battery = $form_Battery->Checked();
	$Netstat = $form_Netstat->Checked();
	$PolicyList = $form_PolicyList->Checked();
	$FindPST = $form_FindPST->Checked();
	$NICDuplex = $form_NICDuplex->Checked();
	$LANDeskInfo = $form_LANDeskInfo->Checked();
	$EnumerateGroups = $form_EnumerateGroups->Checked();
	$RegistryReader = $form_RegistryReader->Checked();

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
	open_browser('http://www.droppedpackets.org/inventory-and-slm/ldms_client/ldms_client_manual');

    return 0;
}
