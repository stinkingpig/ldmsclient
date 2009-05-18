#############################################################################
# ldms_client_core.pl                                                       #
# (c) 2008-2009 Jack Coates, jack@monkeynoodle.org                          #
# Released under GPL, see http://www.gnu.org/licenses/gpl.html for license  #
# Patches welcome at the above email address, current version available at  #
# http://www.monkeynoodle.org/comp/tools/ldms_whatever                      #
#############################################################################
#
# TODO -- Firewall status (enabled /disabled) (we do this in custom defs, but don’t put the status anywhere.
# TODO -- It would be interesting to see the firewall specifics broken down a bit by port and app, but that could be a ton of work and difficult to format in a useful state.
# TODO -- Capture the connected SSID
# TODO -- Custom vulnerability to install/update Produkey.

package ldms_client_core;
#############################################################################
# Pragmas and Modules                                                       #
#############################################################################
use strict;
use warnings;
use Getopt::Long;
use Win32;
use Win32::API;
use Win32::GUI();
use Win32::EventLog::Message;
use Win32::TieRegistry ( Delimiter => "/", ArrayValues => 1 );
use Win32::WebBrowser;
use Carp;
use Config::Tiny;
use LWP::Simple qw(!head !getprint !getstore !mirror);

# It takes a long time to do all this preprocessing stuff before setup starts,
# so I want to show an hourglass cursor.
my ( $loadImage, $waitCursor, $oldCursor );
$loadImage =
  new Win32::API( 'user32', 'LoadImage', [ 'N', 'N', 'I', 'I', 'I', 'I' ], 'N' )
  or croak("cannot find LoadImage function");
$waitCursor = $loadImage->Call( 0, 32514, 2, 0, 0, 0x8040 );
$oldCursor = &Win32::GUI::SetCursor($waitCursor);    #show hourglass ...

#############################################################################
# Variables                                                                 #
#############################################################################
my ( $DEBUG, $skipupdate, $help ) = '';
GetOptions(
    '/',
    'debug'      => \$DEBUG,
    'skipupdate' => \$skipupdate,
    'help'       => \$help,
);

( my $prog = $0 ) =~ s/^.*[\\\/]//x;
my $VERSION = "2.4.8";

my (
    $ldmain,              $ldlogon,              $updatemessage,
    $Battery,             $Netstat,              $PolicyList,
    $FindPST,             $NICDuplex,            $EnumerateGroups,
    $LANDeskInfo,         $RegistryReader,       $Produkey,
    $SID,                 $RegistryInfo,         $Macintosh,
    $FindNSF,             $FindProfileSize,      $AggroMailSearch,
    $ProdukeyBinary,      $DCCUWol,              $DCCUWolBinary,
    $MacNetstat,          $MacOptical,           $Main,
    $MainTab, 
    $w,                   $h,                    $ncw,
    $nch,                 $dw,                   $dh,
    $desk,                $wx,                   $wy,
    $btn_default,         $btn_cancel,           $btn_help,
    $sb,                  $lbl_Instructions,     $lbl_Battery,
    $lbl_Netstat,         $lbl_PolicyList,       $lbl_FindPST,
    $lbl_NICDuplex,       $lbl_EnumerateGroups,  $lbl_LANDeskInfo,
    $lbl_RegistryReader,  $lbl_RegistryInfo,     $lbl_Produkey,
    $lbl_SID,             $lbl_Macintosh,        $lbl_FindNSF,
    $lbl_FindProfileSize, $lbl_AggroMailSearch,  $lbl_DCCUWol,
    $btn_RegistryReader,  $btn_RegistryInfo,     $btn_Macintosh,
    $form_Battery,        $form_Netstat,         $form_PolicyList,
    $form_FindPST,        $form_NICDuplex,       $form_EnumerateGroups,
    $form_LANDeskInfo,    $form_RegistryReader,  $form_Produkey,
    $form_SID,            $form_RegistryInfo,    $form_Macintosh,
    $form_FindNSF,        $form_FindProfileSize, $form_AggroMailSearch,
    $form_ProdukeyBinary, $form_DCCUWol,         $form_DCCUWolBinary,
    $lbl_MacInstructions, $lbl_MacNetstat,       $lbl_MacOptical,
    $form_MacNetstat,     $form_MacOptical,      $macmain,
    $macw,                $mach,                 $macncw,
    $macnch,              $macwx,                $macwy,
    $btn_macdefault,      $btn_maccancel,        $btn_machelp,
    $macsb,               @rr,                   $rrmain,
    $rrw,                 $rrh,                  $rrncw,
    $rrnch,               $rrwx,                 $rrwy,
    $btn_rrdefault,       $btn_rrcancel,         $btn_rrhelp,
    $rrsb,                $lbl_rrInstructions,   $form_rr1,
    $form_rr2,            $form_rr3,             $form_rr4,
    $form_rr5,            $form_rr6,             $form_rr7,
    $form_rr8,            $form_rr9,             $form_rr10,
    @ri,                  $rimain,               $riw,
    $rih,                 $rincw,                $rinch,
    $riwx,                $riwy,                 $btn_ridefault,
    $btn_ricancel,        $btn_rihelp,           $risb,
    $lbl_riInstructions,  $form_ri1,             $form_ri2,
    $form_ri3,            $form_ri4,             $form_ri5,
    $form_ri6,            $form_ri7,             $form_ri8,
    $form_ri9,            $form_ri10,            $form_NonAdminBail,
    $lbl_NonAdminBail,    $NonAdminBail,         $FindOST,
    $lbl_FindOST,         $form_FindOST,         $MappedDrives,
    $lbl_MappedDrives,    $form_MappedDrives,    $CrashReport,
    $lbl_CrashReport,     $form_CrashReport, $DefragNeeded, 
    $lbl_DefragNeeded,  $form_DefragNeeded
);

# Prepare logging system
Win32::EventLog::Message::RegisterSource( 'Application', $prog );
my $event = Win32::EventLog->new($prog) || die "Can't open Event log!\n";

my $usage = <<"EOD";

Usage: $prog [/d] [/skipupdate] [/h]
	/d(ebug)      debug
    /s(kipupdate) Don't check the website for updates
	/h(elp)		  this display

$prog v $VERSION
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

croak($usage) if $help;

&Log("$prog $VERSION starting.\n");

my $configfile = &FindConfigFile;
my $Config     = Config::Tiny->new();

# Read the configuration file if it already exists.
if ( -e $configfile ) { &ReadConfigFile; }

# Default values if user didn't specify
if ( !$ProdukeyBinary ) {
    $ProdukeyBinary = "C:\\Progra~1\\LANDesk\\LDClient\\produkey.exe";
}
if ( !$DCCUWolBinary ) {
    $DCCUWolBinary = "C:\\Progra~1\\LANDesk\\LDClient\\getwol.exe";
}

# Default mail search aggressiveness is low
if ( !$AggroMailSearch ) { $AggroMailSearch = 1; }

# Check to see if there's an update available
&IsUpdate;

my $ldms_client_icon =
  new Win32::GUI::Icon("grey.ico");    # replace default camel icon with my own

my $ldms_client_class =
  new Win32::GUI::Class(  # set up a class to use my icon throughout the program
    -name => "ldms_client Class",
    -icon => $ldms_client_icon,
  );

&Show_MainWindow;
&Main_InsertTabs;
&Main_Hide;
&MainTab_Users;
Win32::GUI::Dialog();

# Write discovered data
&WriteConfigFile;

if ( !$DEBUG ) {

    # Restore console window
    Win32::GUI::Show($DOS);

}
&Log("$prog $VERSION exiting.\n");
exit 0;

#############################################################################
# Subroutines                                                               #
#############################################################################

### Utility subroutines #####################################################
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
        $string =~ s/^HKLM\/|^HKEY_LOCAL_MACHINE\///gx;
    }
    if ($DEBUG) { &LogWarn("trimkey: trimmed $input to $string\n"); }
    return $string;
}

### Logging subroutine ######################################################
sub Log {
    my $msg = shift;
    $event->Report(
        {
            EventID   => 0,
            Strings   => $msg,
            EventType => 4,
        }
    );
    return 0;
}

### Logging with warning subroutine #########################################
sub LogWarn {
    my $msg = shift;
    $event->Report(
        {
            EventID   => 0,
            Strings   => $msg,
            EventType => 2,
        }
    );
    return 0;
}

### Logging with death subroutine ###########################################
sub LogDie {
    my $msg = shift;
    $event->Report(
        {
            EventID   => 0,
            Strings   => $msg,
            EventType => 1,
        }
    );
    croak($msg);
}

### ASCII to Integer subroutine #############################################
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
    my $url =
      'http://www.droppedpackets.org/inventory-and-slm/ldms_client/version';
    my $content = get $url;
    my $onlineversion;
    if ( defined($content) ) {
        my $myversion = $VERSION;
        ## no critic
        # Doesn't like /x
        $content =~ m{<p>latest version is ([\d.]+)};
        ## use critic
        if ($1) {
            $onlineversion = $1;
        }
        else {
            &LogWarn("didn't recognize version value at $url");
            return 1;
        }
        if ($DEBUG) { &Log("onlineversion is $onlineversion"); }

        # Remove the dots and convert to an integer so that we can do numerical
        # comparison... e.g., version 8.80.0.249 is rendered as 8800249
        $onlineversion =~ s/\.?       # substitute any dot
                            (?=[0-9]) # keep any number
                            //gx;
        $myversion =~ s/\.?       # substitute any dot
                            (?=[0-9]) # keep any number
                            //gx;
        if ( &atoi($onlineversion) > &atoi($myversion) ) {
            $updatemessage =
"Update available at http://www.droppedpackets.org/scripts/ldms_client";
            &LogWarn($updatemessage);
        }
        if ( &atoi($onlineversion) < &atoi($myversion) ) {
            $updatemessage = "You're running beta code. "
              . "Please keep me informed via jack\@monkeynoodle.org.";
            &LogWarn($updatemessage);
        }
        return 0;
    }
    else {
        &Log("Couldn't get $url");
        return 1;
    }
}

### Functionality subroutines ###############################################

### Find the configuration file #############################################
sub FindConfigFile {

    # Check the registry for core location
    my $RegKey =
      $Registry->{"HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup"};
    if ($RegKey) {
        $ldmain  = $RegKey->GetValue("LDMainPath");
        $ldlogon = Win32::GetShortPathName($ldmain);
        $ldlogon .= "ldlogon";
    }
    else {
        &Log(
"Can't find HKEY_LOCAL_MACHINE/Software/LANDesk/ManagementSuite/Setup"
        );
        my $msg = "Can't find HKEY_LOCAL_MACHINE/Software/LANDesk/"
            . "ManagementSuite/Setup. Are you sure this is the core?";
        Win32::GUI::MessageBox(
            0,
            $msg,
            "ldms_client_core",
            48
        );
        croak($msg);
    }
    if ( !-e $ldlogon ) {
        &Log("Can't find $ldlogon");
        my $msg = "Can't find $ldlogon. Are you sure this is the core?";
        Win32::GUI::MessageBox( 0,
            $msg,
            "ldms_client_core", 48 );
        croak($msg);
    }
    my $output = $ldlogon . "\\ldms_client.ini";
    if ($DEBUG) { Log("DEBUG: Config file is $output"); }
    return $output;
}
### End of FindConfigFile ###################################################

### Read the configuration file #############################################
sub ReadConfigFile {

    $Config = Config::Tiny->read($configfile)
      or &LogDie( "Can't read $configfile: ", &Config::Tiny->errstr() );

    # Reading properties
    $Battery         = $Config->{_}->{Battery};
    $Netstat         = $Config->{_}->{Netstat};
    $PolicyList      = $Config->{_}->{PolicyList};
    $FindPST         = $Config->{_}->{FindPST};
    $FindOST         = $Config->{_}->{FindOST};
    $FindNSF         = $Config->{_}->{FindNSF};
    $AggroMailSearch = $Config->{_}->{AggroMailSearch};
    $FindProfileSize = $Config->{_}->{FindProfileSize};
    $NICDuplex       = $Config->{_}->{NICDuplex};
    $EnumerateGroups = $Config->{_}->{EnumerateGroups};
    $LANDeskInfo     = $Config->{_}->{LANDeskInfo};
    $RegistryReader  = $Config->{_}->{RegistryReader};
    $RegistryInfo    = $Config->{_}->{RegistryInfo};
    $Produkey        = $Config->{_}->{Produkey};
    $ProdukeyBinary  = $Config->{_}->{ProdukeyBinary};
    $DCCUWol         = $Config->{_}->{DCCUWol};
    $DCCUWolBinary   = $Config->{_}->{DCCUWolBinary};
    $SID             = $Config->{_}->{SID};
    $Macintosh       = $Config->{_}->{Macintosh};
    $NonAdminBail    = $Config->{_}->{NonAdminBail};
    $MappedDrives    = $Config->{_}->{MappedDrives};
    $CrashReport     = $Config->{_}->{CrashReport};
    $DefragNeeded    = $Config->{_}->{DefragNeeded};
    if ($RegistryReader) {

        foreach my $index ( 1 .. 10 ) {
            if ( length( $Config->{RegistryReader}->{$index} ) > 1 ) {
                $rr[$index] = $Config->{RegistryReader}->{$index};
            }
            else {

                # Gotta define it for the UI
                $rr[$index] = "";
            }
            if ($DEBUG) { Log("DEBUG: Registry entry $index is $rr[$index]"); }
        }
    }
    if ($RegistryInfo) {
        foreach my $index ( 1 .. 10 ) {
            if ( length( $Config->{RegistryInfo}->{$index} ) > 1 ) {
                $ri[$index] = $Config->{RegistryInfo}->{$index};
            }
            else {

                # Gotta define it for the UI
                $ri[$index] = "";
            }
            if ($DEBUG) { &Log("DEBUG: Registry entry $index is $ri[$index]"); }
        }
    }
    if ($Macintosh) {
        $MacNetstat = $Config->{Macintosh}->{MacNetstat};
        $MacOptical = $Config->{Macintosh}->{MacOptical};
    }

    if ($DEBUG) { &Log("Finished reading config file"); }
    return 0;
}
### End of ReadConfigFile ###################################################

### Write the configuration file ############################################
sub WriteConfigFile {
    $Config->{version}->{Version}   = $VERSION;
    $Config->{_}->{Battery}         = $Battery;
    $Config->{_}->{Netstat}         = $Netstat;
    $Config->{_}->{PolicyList}      = $PolicyList;
    $Config->{_}->{FindPST}         = $FindPST;
    $Config->{_}->{FindOST}         = $FindOST;
    $Config->{_}->{FindNSF}         = $FindNSF;
    $Config->{_}->{AggroMailSearch} = $AggroMailSearch;
    $Config->{_}->{FindProfileSize} = $FindProfileSize;
    $Config->{_}->{NICDuplex}       = $NICDuplex;
    $Config->{_}->{EnumerateGroups} = $EnumerateGroups;
    $Config->{_}->{LANDeskInfo}     = $LANDeskInfo;
    $Config->{_}->{RegistryReader}  = $RegistryReader;
    $Config->{_}->{RegistryInfo}    = $RegistryInfo;
    $Config->{_}->{Produkey}        = $Produkey;
    $Config->{_}->{ProdukeyBinary}  = $ProdukeyBinary;
    $Config->{_}->{DCCUWol}         = $DCCUWol;
    $Config->{_}->{DCCUWolBinary}   = $DCCUWolBinary;
    $Config->{_}->{SID}             = $SID;
    $Config->{_}->{Macintosh}       = $Macintosh;
    $Config->{_}->{NonAdminBail}    = $NonAdminBail;
    $Config->{_}->{MappedDrives}    = $MappedDrives;
    $Config->{_}->{CrashReport}     = $CrashReport;
    $Config->{_}->{DefragNeeded}    = $DefragNeeded;
    foreach my $index ( 1 .. 10 ) {
        $Config->{RegistryReader}->{$index} = $rr[$index];
    }
    foreach my $index ( 1 .. 10 ) {
        $Config->{RegistryInfo}->{$index} = $ri[$index];
    }
    if ($Macintosh) {
        $Config->{Macintosh}->{MacNetstat} = $MacNetstat;
        $Config->{Macintosh}->{MacOptical} = $MacOptical;
    }
    $Config->write($configfile)
      or &LogDie( "Can't write $configfile: ", &Config::Tiny->errstr() );
    return 0;
}
### End of WriteConfigFile ##################################################

## Windowing Subroutines  ###################################################

### Show the main window ####################################################
sub Show_MainWindow {

    my $leftmargin   = 30;
    my $rightmargin  = 80;
    my $bottommargin = 80;
    my $nexthoriz    = 5;

    # build window
    $Main = Win32::GUI::Window->new(
        -name        => 'Main',
        -text        => "ldms_client_core $VERSION configuration",
        -class       => $ldms_client_class,
        -dialogui    => 1,
        -onTerminate => \&Window_Terminate,
        -onResize    => \&Main_Resize,
    );

    # Instructions for use
    $lbl_Instructions = $Main->AddLabel(
        -name => "lblInstructions",
        -text => "Please select the scan extensions you'd like to enable.",
        -pos  => [ $leftmargin, $nexthoriz ],
        -size => [ 400, 20 ],
    );

    # BEGIN USERS TAB #######
    $nexthoriz    = 35;

    # Begin FindPST row
    $form_FindPST = $Main->AddCheckbox(
        -name    => "findpst_field",
        -checked => $FindPST,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_FindPST = $Main->AddLabel(
        -name => "lblFindPST",
        -text => "Find Microsoft Outlook PST Files",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );

    # End FindPST row

    # Begin FindOST row
    $form_FindOST = $Main->AddCheckbox(
        -name    => "findost_field",
        -checked => $FindOST,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_FindOST = $Main->AddLabel(
        -name => "lblFindOST",
        -text => "Find Microsoft Outlook OST Files",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );

    # End FindOST row

    # Begin FindNSF row
    $form_FindNSF = $Main->AddCheckbox(
        -name    => "findnsf_field",
        -checked => $FindNSF,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_FindNSF = $Main->AddLabel(
        -name => "lblFindNSF",
        -text => "Find Lotus Notes NSF Files",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );

    # End FindNSF row

    # Begin AggroMailSearch row
    $lbl_AggroMailSearch = $Main->AddLabel(
        -name => "lblAggroMailSearch",
        -text => "Email search: Default location, user profiles, system drive",
        -pos  => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 300, 20 ],
    );
    $form_AggroMailSearch = $Main->AddSlider(
        -name     => "aggromailsearch_field",
        -selrange => 0,
        -tabstop  => 1,
        -size     => [ 200, 20 ],
        -pos      => [ $leftmargin + 50, $nexthoriz += 25 ],
    );
    $form_AggroMailSearch->SetRange( 1, 3 );
    $form_AggroMailSearch->SetPos($AggroMailSearch);
    $form_AggroMailSearch->SetBuddy( 0,
        $Main->AddLabel( 
            -name => "lbl_aggromailsearch_left",
            -text => "Accuracy" ) );
    $form_AggroMailSearch->SetBuddy( 1,
        $Main->AddLabel( 
            -name => "lbl_aggromailsearch_right",
            -text => "Performance" ) );
    # End AggroMailSearch row

    # Begin RegistryReader row
    $form_RegistryReader = $Main->AddCheckbox(
        -name    => "registryreader_field",
        -checked => $RegistryReader,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_RegistryReader = $Main->AddLabel(
        -name => "lblRegistryReader",
        -text => "Collect Registry Keys from HKCU",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 180, 20 ],
    );

    # spawn the registry key configuration window
    $btn_RegistryReader = $Main->AddButton(
        -name    => "btn_RegistryReader",
        -text    => "Configure Registry Keys",
        -pos     => [ $lbl_RegistryReader->Width() + $leftmargin, $nexthoriz ],
        -onClick => \&Show_RRWindow,
    );

    # End RegistryReader row

    # Begin MappedDrives row
    $form_MappedDrives = $Main->AddCheckbox(
        -name    => "mappeddrives_field",
        -checked => $MappedDrives,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_MappedDrives = $Main->AddLabel(
        -name => "lblMappedDrives",
        -text => "Report on mapped drives",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );

    # End MappedDrives row

    # Begin Profile Size row
    $form_FindProfileSize = $Main->AddCheckbox(
        -name    => "profilesize_field",
        -checked => $FindProfileSize,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_FindProfileSize = $Main->AddLabel(
        -name => "lblprofilesize",
        -text => "Find User Profile Sizes",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );

    # End Profile Size row

    # BEGIN SYSTEM TAB #######
    $nexthoriz    = 35;

    # Begin PolicyList row
    $form_PolicyList = $Main->AddCheckbox(
        -name    => "policylist_field",
        -checked => $PolicyList,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_PolicyList = $Main->AddLabel(
        -name => "lblPolicyList",
        -text => "LANDesk Policy List",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );
    # End PolicyList row

    # Begin LANDeskInfo row
    $form_LANDeskInfo = $Main->AddCheckbox(
        -name    => "landeskinfo_field",
        -checked => $LANDeskInfo,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_LANDeskInfo = $Main->AddLabel(
        -name => "lblLANDeskInfo",
        -text => "LANDesk Client Information",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );

    # End LANDeskInfo row

    # Begin EnumerateGroups row
    $form_EnumerateGroups = $Main->AddCheckbox(
        -name    => "enumerategroups_field",
        -checked => $EnumerateGroups,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_EnumerateGroups = $Main->AddLabel(
        -name => "lblEnumerateGroups",
        -text => "Resolve Domain Members in Local Groups",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );

    # End EnumerateGroups row

    # Begin RegistryInfo row
    $form_RegistryInfo = $Main->AddCheckbox(
        -name    => "registryinfo_field",
        -checked => $RegistryInfo,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_RegistryInfo = $Main->AddLabel(
        -name => "lblRegistryInfo",
        -text => "Collect Registry Keys from HKLM",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 180, 20 ],
    );

    # spawn the registry key configuration window
    $btn_RegistryInfo = $Main->AddButton(
        -name    => "btn_RegistryInfo",
        -text    => "Configure Registry Keys",
        -pos     => [ $lbl_RegistryInfo->Width() + $leftmargin, $nexthoriz ],
        -onClick => \&Show_RIWindow,
    );

    # End RegistryReader row

    # Begin Produkey rows
    $form_Produkey = $Main->AddCheckbox(
        -name    => "produkey_field",
        -checked => $Produkey,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_Produkey = $Main->AddLabel(
        -name => "lblProdukey",
        -text => "Collect Microsoft product keys",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );
    $form_ProdukeyBinary = $Main->AddTextfield(
        -name    => "produkeybinary_field",
        -prompt  => "Location of produkey.exe",
        -text    => $ProdukeyBinary,
        -tabstop => 1,
        -pos     => [ $leftmargin + 150, $nexthoriz += 25 ],
        -size => [ 300, 20 ],
    );

    # End Produkey rows

    # Begin SID row
    $form_SID = $Main->AddCheckbox(
        -name    => "sid_field",
        -checked => $SID,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_SID = $Main->AddLabel(
        -name => "lblSID",
        -text => "Collect Machine SIDs and FQDNs",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );

    # End SID row

    # BEGIN HARDWARE TAB #######
    $nexthoriz    = 35;

    # Begin Battery row
    $form_Battery = $Main->AddCheckbox(
        -name    => "battery_field",
        -checked => $Battery,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_Battery = $Main->AddLabel(
        -name => "lblBattery",
        -text => "Battery Information",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ]
    );
    # End Battery row

    # Begin NICDuplex row
    $form_NICDuplex = $Main->AddCheckbox(
        -name    => "nicduplex_field",
        -checked => $NICDuplex,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_NICDuplex = $Main->AddLabel(
        -name => "lblNNICDuplex",
        -text => "NIC Duplex Information",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );
    # End NICDuplex row

    # Begin Netstat row
    $form_Netstat = $Main->AddCheckbox(
        -name    => "netstat_field",
        -checked => $Netstat,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_Netstat = $Main->AddLabel(
        -name => "lblNetstat",
        -text => "Netstat Information",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );
    # End Netstat row

    # Begin CrashReport row
    $form_CrashReport = $Main->AddCheckbox(
        -name    => "crashreport_field",
        -checked => $CrashReport,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_CrashReport = $Main->AddLabel(
        -name => "lblCrashReport",
        -text => "Report number of crashes within the last week",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );

    # End CrashReport row

    # Begin DCCUWol rows
    $form_DCCUWol = $Main->AddCheckbox(
        -name    => "dccuwol_field",
        -checked => $DCCUWol,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_DCCUWol = $Main->AddLabel(
        -name => "lblDCCUWol",
        -text => "Collect Dell Wake-On-LAN status",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );
    $form_DCCUWolBinary = $Main->AddTextfield(
        -name    => "dccuwolbinary_field",
        -prompt  => "getwol.exe or inventory.exe",
        -text    => $DCCUWolBinary,
        -tabstop => 1,
        -pos     => [ $leftmargin + 150, $nexthoriz += 25 ],
        -size => [ 300, 20 ],
    );

    # End DCCUWol rows

    # Begin Defrag Needed row
    $form_DefragNeeded = $Main->AddCheckbox(
        -name    => "profilesize_field",
        -checked => $DefragNeeded,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_DefragNeeded = $Main->AddLabel(
        -name => "lbldefragneeded",
        -text => "Report disk fragmentation?",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );

    # End Defrag Needed row

    # BEGIN GENERAL TAB #######
    $nexthoriz    = 35;

    # Begin Macintosh row
    $form_Macintosh = $Main->AddCheckbox(
        -name    => "macintosh_field",
        -checked => $Macintosh,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_Macintosh = $Main->AddLabel(
        -name => "lblMacintosh",
        -text => "Extend Macintosh inventory",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 180, 20 ],
    );

    # spawn the Macintosh inventory configuration window
    $btn_Macintosh = $Main->AddButton(
        -name    => "btn_Macintosh",
        -text    => "Configure Mac Inventory",
        -pos     => [ $lbl_Macintosh->Width() + $leftmargin, $nexthoriz ],
        -onClick => \&Show_MacWindow,
    );

    # End Macintosh row

    # Begin Non-Admin Bail configuration row
    $form_NonAdminBail = $Main->AddCheckbox(
        -name    => "nonadminbail_field",
        -checked => $NonAdminBail,
        -tabstop => 1,
        -pos     => [ $leftmargin, $nexthoriz += 25 ],
        -size => [ 15, 20 ],
    );
    $lbl_NonAdminBail = $Main->AddLabel(
        -name => "lblnonadminbail",
        -text => "Should it silently exit if launched without admin rights?",
        -pos  => [ $leftmargin + 20, $nexthoriz + 3 ],
        -size => [ 300, 20 ],
    );

    # End Non-Admin Bail configuration row

    # Begin button row
    $btn_default = $Main->AddButton(
        -name    => 'Default',
        -text    => 'Ok',
        -tabstop => 1,
        -default => 1,           # Give button darker border
        -ok      => 1,           # press 'Return' to click this button
        -pos => [ 50, 275 ],
        -size    => [ 60, 20 ],
        -onClick => \&Default_Click,
    );

    $btn_cancel = $Main->AddButton(
        -name    => 'Cancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,                     # press 'Esc' to click this button
        -pos     => [ 150, 275 ],
        -size    => [ 60, 20 ],
        -onClick => \&Cancel_Click,
    );

    $btn_help = $Main->AddButton(
        -name    => 'Help',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 250, 275 ],
        -size    => [ 60, 20 ],
        -onClick => \&Help_Click,
    );

    # End button row

    $sb = $Main->AddStatusBar();
    if ($updatemessage) {
        $sb->Text($updatemessage);
    }

    # calculate its size
    $ncw = $Main->Width() - $Main->ScaleWidth();
    $nch = $Main->Height() - $Main->ScaleHeight();
    $w   = $leftmargin + $lbl_Instructions->Width() + $rightmargin + $ncw;
    $h   = 275 + $bottommargin;

    # Don't let it get smaller than it should be
    $Main->Change( -minsize => [ $w, $h ] );

    # calculate its centered position
    # Assume we have the main window size in ($w, $h) as before
    $desk = Win32::GUI::GetDesktopWindow();
    $dw   = Win32::GUI::Width($desk);
    $dh   = Win32::GUI::Height($desk);
    $wx   = ( $dw - $w ) / 2;
    $wy   = ( $dh - $h ) / 2;

    # Resize, position and display
    $Main->Resize( $w, $h );
    $Main->Move( $wx, $wy );

    Win32::GUI::SetCursor($oldCursor);    #show previous arrow cursor again

    $Main->Show();
    return 0;
}
### End of Show Main Window #################################################

### Resize the Main Window ##################################################
sub Main_Resize {
    $sb->Move( 0, $Main->ScaleHeight - $sb->Height );
    $sb->Resize( $Main->ScaleWidth, $sb->Height );
    return 0;
}

## Create the tab bar #########################################################
sub Main_InsertTabs {
    $MainTab = $Main->AddTabStrip(
        -left     => 10,
        -top      => 30,
        -width    => $Main->ScaleWidth - 20,
        -height   => $Main->ScaleHeight - 50,
        -name     => "Main_Tab",
        -onChange => \&Main_TabChanged,
    );

    # tab 0
    $MainTab->InsertItem( -text => "Users" );

    # tab 1
    $MainTab->InsertItem( -text => "System" );

    # tab 2
    $MainTab->InsertItem( -text => "Hardware" );

    # tab 3
    $MainTab->InsertItem( -text => "General" );
    return 0;
}
###############################################################################

### Handle changes in the tab bar #############################################
sub Main_TabChanged {

    if ($DEBUG) { Log("DEBUG: Main_TabChanged"); }
    &Main_Hide;

    #what tab is it now?
    my $newtab = $MainTab->SelectedItem();

    # Users tab
    if ( $newtab == 0 ) {
        &MainTab_Users;
    }

    # System tab
    if ( $newtab == 1 ) {
        &MainTab_System;
    }

    # Hardware tab
    if ( $newtab == 2 ) {
        &MainTab_Hardware;
    }

    # General tab
    if ( $newtab == 3 ) {
        &MainTab_General;
    }
    return 0;
}
###############################################################################

###############################################################################
sub MainTab_Users {

    if ($DEBUG) { Log("DEBUG: MainTab_Users"); }
    $form_FindPST->Show();
    $lbl_FindPST->Show();
    $form_FindOST->Show();
    $lbl_FindOST->Show();
    $form_FindNSF->Show();
    $lbl_FindNSF->Show();
    $lbl_AggroMailSearch->Show();
    $form_AggroMailSearch->Show();
   # Some of the visible items on the window are automagically created and don't
   # have associated objects... so they have to be called directly via name
    Win32::GUI::Show( $Main->lbl_aggromailsearch_left()->{-handle} );
    Win32::GUI::Show( $Main->lbl_aggromailsearch_right()->{-handle} );
    $form_RegistryReader->Show();
    $lbl_RegistryReader->Show();
    $form_MappedDrives->Show();
    $lbl_MappedDrives->Show();
    $btn_RegistryReader->Show();
    $form_FindProfileSize->Show();
    $lbl_FindProfileSize->Show();
    return 0;
}
###############################################################################

###############################################################################
sub MainTab_System {

    if ($DEBUG) { Log("DEBUG: MainTab_System"); }
    $form_PolicyList->Show();
    $lbl_PolicyList->Show();
    $form_LANDeskInfo->Show();
    $lbl_LANDeskInfo->Show();
    $form_EnumerateGroups->Show();
    $lbl_EnumerateGroups->Show();
    $form_RegistryInfo->Show();
    $lbl_RegistryInfo->Show();
    $btn_RegistryInfo->Show();
    $form_Produkey->Show();
    $lbl_Produkey->Show();
    $form_ProdukeyBinary->Show();
   # Some of the visible items on the window are automagically created and don't
   # have associated objects... so they have to be called directly via name
    Win32::GUI::Show( $Main->produkeybinary_field_Prompt()->{-handle} );
    $form_SID->Show();
    $lbl_SID->Show();
    return 0;
}
###############################################################################

###############################################################################
sub MainTab_Hardware {

    if ($DEBUG) { Log("DEBUG: MainTab_Hardware"); }
    $form_Battery->Show();
    $lbl_Battery->Show();
    $form_NICDuplex->Show();
    $lbl_NICDuplex->Show();
    $form_Netstat->Show();
    $lbl_Netstat->Show();
    $form_CrashReport->Show();
    $lbl_CrashReport->Show();
    $form_DCCUWol->Show();
    $lbl_DCCUWol->Show();
    $form_DCCUWolBinary->Show();
   # Some of the visible items on the window are automagically created and don't
   # have associated objects... so they have to be called directly via name
    Win32::GUI::Show( $Main->dccuwolbinary_field_Prompt()->{-handle} );
    $form_DefragNeeded->Show();
    $lbl_DefragNeeded->Show();
    return 0;
}
###############################################################################

###############################################################################
sub MainTab_General {

    if ($DEBUG) { Log("DEBUG: MainTab_General"); }
    $form_Macintosh->Show();
    $lbl_Macintosh->Show();
    $btn_Macintosh->Show();
    $form_NonAdminBail->Show();
    $lbl_NonAdminBail->Show();
    return 0;
}
###############################################################################

## Hide everything except the tab bar #########################################
sub Main_Hide {

    if ($DEBUG) { Log("DEBUG: Main_Hide"); }
    # Users Tab
    $form_FindPST->Hide();
    $lbl_FindPST->Hide();
    $form_FindOST->Hide();
    $lbl_FindOST->Hide();
    $form_FindNSF->Hide();
    $lbl_FindNSF->Hide();
    $lbl_AggroMailSearch->Hide();
    $form_AggroMailSearch->Hide();
   # Some of the visible items on the window are automagically created and don't
   # have associated objects... so they have to be called directly via name
    Win32::GUI::Hide( $Main->lbl_aggromailsearch_left()->{-handle} );
    Win32::GUI::Hide( $Main->lbl_aggromailsearch_right()->{-handle} );
    $form_RegistryReader->Hide();
    $lbl_RegistryReader->Hide();
    $form_MappedDrives->Hide();
    $lbl_MappedDrives->Hide();
    $btn_RegistryReader->Hide();
    $form_FindProfileSize->Hide();
    $lbl_FindProfileSize->Hide();

    # System Tab
    $form_PolicyList->Hide();
    $lbl_PolicyList->Hide();
    $form_LANDeskInfo->Hide();
    $lbl_LANDeskInfo->Hide();
    $form_EnumerateGroups->Hide();
    $lbl_EnumerateGroups->Hide();
    $form_RegistryInfo->Hide();
    $lbl_RegistryInfo->Hide();
    $btn_RegistryInfo->Hide();
    $form_Produkey->Hide();
    $lbl_Produkey->Hide();
    $form_ProdukeyBinary->Hide();
   # Some of the visible items on the window are automagically created and don't
   # have associated objects... so they have to be called directly via name
    Win32::GUI::Hide( $Main->produkeybinary_field_Prompt()->{-handle} );
    $form_SID->Hide();
    $lbl_SID->Hide();

    # Hardware Tab
    $form_Battery->Hide();
    $lbl_Battery->Hide();
    $form_NICDuplex->Hide();
    $lbl_NICDuplex->Hide();
    $form_Netstat->Hide();
    $lbl_Netstat->Hide();
    $form_CrashReport->Hide();
    $lbl_CrashReport->Hide();
    $form_DCCUWol->Hide();
    $lbl_DCCUWol->Hide();
    $form_DCCUWolBinary->Hide();
   # Some of the visible items on the window are automagically created and don't
   # have associated objects... so they have to be called directly via name
    Win32::GUI::Hide( $Main->dccuwolbinary_field_Prompt()->{-handle} );
    $form_DefragNeeded->Hide();
    $lbl_DefragNeeded->Hide();

    # General Tab
    $form_Macintosh->Hide();
    $lbl_Macintosh->Hide();
    $btn_Macintosh->Hide();
    $form_NonAdminBail->Hide();
    $lbl_NonAdminBail->Hide();
    return 0;
}
###############################################################################

### open the registry reader Window (HKCU) ##################################
sub btn_RegistryReader_Click {
    &Show_RRWindow;
    return 0;
}

### open the registry info Window (HKLM) ####################################
sub btn_RegistryInfo_Click {
    &Show_RIWindow;
    return 0;
}

### open the Macintosh Window ###############################################
sub btn_Macintosh_Click {
    &Show_MacWindow;
    return 0;
}

### Gather the data from the Main Window ####################################
sub Default_Click {

    if ($DEBUG) { Log("DEBUG: Okay clicked in MainWindow"); }

    # Read my variables
    $Battery         = $form_Battery->Checked();
    $Netstat         = $form_Netstat->Checked();
    $PolicyList      = $form_PolicyList->Checked();
    $FindPST         = $form_FindPST->Checked();
    $FindOST         = $form_FindOST->Checked();
    $FindNSF         = $form_FindNSF->Checked();
    $AggroMailSearch = $form_AggroMailSearch->GetPos();
    $FindProfileSize = $form_FindProfileSize->Checked();
    $NICDuplex       = $form_NICDuplex->Checked();
    $LANDeskInfo     = $form_LANDeskInfo->Checked();
    $EnumerateGroups = $form_EnumerateGroups->Checked();
    $RegistryReader  = $form_RegistryReader->Checked();
    $RegistryInfo    = $form_RegistryInfo->Checked();
    $Produkey        = $form_Produkey->Checked();
    $ProdukeyBinary  = $form_ProdukeyBinary->GetLine(0);
    $DCCUWol         = $form_DCCUWol->Checked();
    $DCCUWolBinary   = $form_DCCUWolBinary->GetLine(0);
    $SID             = $form_SID->Checked();
    $Macintosh       = $form_Macintosh->Checked();
    $NonAdminBail    = $form_NonAdminBail->Checked();
    $MappedDrives    = $form_MappedDrives->Checked();
    $CrashReport     = $form_CrashReport->Checked();
    $DefragNeeded    = $form_DefragNeeded->Checked();

    $Main->Hide();
    return -1;
}

### Cancel from the Main Window #############################################
sub Cancel_Click {

    # Restore console window
    Win32::GUI::Show($DOS);
    exit 0;
}

### Cancel from the registry reader Window (HKCU) ###########################
sub rrCancel_Click {
    if ($DEBUG) { Log("DEBUG: Cancel clicked in RRMainWindow"); }
    $rrmain->Hide();
    return 0;
}

### Cancel from the registry info Window (HKLM) #############################
sub riCancel_Click {
    if ($DEBUG) { Log("DEBUG: Cancel clicked in RIMainWindow"); }
    $rimain->Hide();
    return 0;
}

### Cancel from the macintosh info Window ###################################
sub macmainCancel_Click {
    if ($DEBUG) { Log("DEBUG: Cancel clicked in macmainWindow"); }
    $macmain->Hide();
    return 0;
}

### RegistryReader Window subroutines ########################################
sub Show_RRWindow {

    # Build the window
    $rrmain = Win32::GUI::Window->new(
        -name        => 'rrMain',
        -text        => 'ldms_client_core hkcu registry configuration',
        -width       => 450,
        -height      => 400,
        -class       => $ldms_client_class,
        -onTerminate => \&Window_Terminate,
        -onResize    => \&rrMain_Resize,
    );

    # Add some stuff
    $lbl_rrInstructions = $rrmain->AddLabel(
        -name => "lblrrInstructions",
        -text =>
"Please select the HKEY_CURRENT_USER registry keys you'd like to gather.",
        -pos  => [ 5,   5 ],
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
        -default => 1,                   # Give button darker border
        -ok      => 1,                   # press 'Return' to click this button
        -pos     => [ 50, 300 ],
        -size    => [ 60, 20 ],
        -onClick => \&rrDefault_Click,
    );

    $btn_rrcancel = $rrmain->AddButton(
        -name    => 'rrCancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,                   # press 'Esc' to click this button
        -pos     => [ 150, 300 ],
        -size    => [ 60, 20 ],
        -onClick => \&rrCancel_Click,
    );

    $btn_rrhelp = $rrmain->AddButton(
        -name    => 'rrHelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 250, 300 ],
        -size    => [ 60, 20 ],
        -onClick => \&Help_Click,
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
      $form_rr10->Height() + +110 +
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
    return 0;
}

### Resize the registry reader window (HKCU) ################################
sub rrMain_Resize {
    $rrsb->Move( 0, $rrmain->ScaleHeight - $rrsb->Height );
    $rrsb->Resize( $rrmain->ScaleWidth, $rrsb->Height );
    return 0;
}

### Gather data from the registry reader window (HKCU) ######################
sub rrDefault_Click {

    if ($DEBUG) { Log("DEBUG: Okay clicked in RRMainWindow"); }

    # Read my variables
    $rr[1]  = &trimkey( $form_rr1->GetLine(0) );
    $rr[2]  = &trimkey( $form_rr2->GetLine(0) );
    $rr[3]  = &trimkey( $form_rr3->GetLine(0) );
    $rr[4]  = &trimkey( $form_rr4->GetLine(0) );
    $rr[5]  = &trimkey( $form_rr5->GetLine(0) );
    $rr[6]  = &trimkey( $form_rr6->GetLine(0) );
    $rr[7]  = &trimkey( $form_rr7->GetLine(0) );
    $rr[8]  = &trimkey( $form_rr8->GetLine(0) );
    $rr[9]  = &trimkey( $form_rr9->GetLine(0) );
    $rr[10] = &trimkey( $form_rr10->GetLine(0) );

    $rrmain->Hide();
    return 0;
}

### RegistryInfo Window subroutines ##########################################
sub Show_RIWindow {

    # Build the window
    $rimain = Win32::GUI::Window->new(
        -name        => 'riMain',
        -text        => 'ldms_client_core hklm registry configuration',
        -width       => 450,
        -height      => 400,
        -class       => $ldms_client_class,
        -onTerminate => \&Window_Terminate,
        -onResize    => \&riMain_Resize,
    );

    # Add some stuff
    $lbl_riInstructions = $rimain->AddLabel(
        -name => "lblriInstructions",
        -text =>
"Please select the HKEY_LOCAL_MACHINE registry keys you'd like to gather.",
        -pos  => [ 5,   5 ],
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
        -default => 1,                   # Give button darker border
        -ok      => 1,                   # press 'Return' to click this button
        -pos     => [ 50, 300 ],
        -size    => [ 60, 20 ],
        -onClick => \&riDefault_Click,
    );

    $btn_ricancel = $rimain->AddButton(
        -name    => 'riCancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,                   # press 'Esc' to click this button
        -pos     => [ 150, 300 ],
        -size    => [ 60, 20 ],
        -onClick => \&riCancel_Click,
    );

    $btn_rihelp = $rimain->AddButton(
        -name    => 'riHelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 250, 300 ],
        -size    => [ 60, 20 ],
        -onClick => \&Help_Click,
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
      $form_ri10->Height() + 110 +
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
    return 0;
}

### Resize the registry info window (HKLM) ##################################
sub riMain_Resize {
    $risb->Move( 0, $rimain->ScaleHeight - $risb->Height );
    $risb->Resize( $rimain->ScaleWidth, $risb->Height );
    return 0;
}

### Gather data from the registry info window (HKLM) ########################
sub riDefault_Click {

    if ($DEBUG) { Log("DEBUG: Okay clicked in RIMainWindow"); }

    # Read my variables
    $ri[1]  = &trimkey( $form_ri1->GetLine(0) );
    $ri[2]  = &trimkey( $form_ri2->GetLine(0) );
    $ri[3]  = &trimkey( $form_ri3->GetLine(0) );
    $ri[4]  = &trimkey( $form_ri4->GetLine(0) );
    $ri[5]  = &trimkey( $form_ri5->GetLine(0) );
    $ri[6]  = &trimkey( $form_ri6->GetLine(0) );
    $ri[7]  = &trimkey( $form_ri7->GetLine(0) );
    $ri[8]  = &trimkey( $form_ri8->GetLine(0) );
    $ri[9]  = &trimkey( $form_ri9->GetLine(0) );
    $ri[10] = &trimkey( $form_ri10->GetLine(0) );

    $rimain->Hide();
    return 0;
}

### End of RegistryInfo Window subroutines ###################################

### Macintosh Window subroutines #############################################
sub Show_MacWindow {

    # Build the window
    $macmain = Win32::GUI::Window->new(
        -name        => 'macmain',
        -text        => 'ldms_client_core macintosh configuration',
        -width       => 450,
        -height      => 200,
        -class       => $ldms_client_class,
        -onTerminate => \&Window_Terminate,
        -onResize    => \&macmain_Resize,
    );

    # Add some stuff
    $lbl_MacInstructions = $macmain->AddLabel(
        -name => "lbl_MacInstructions",
        -text =>
"Please select the Macintosh inventory attributes you'd like to gather.",
        -pos  => [ 5,   5 ],
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
        -default => 1,                    # Give button darker border
        -ok      => 1,                    # press 'Return' to click this button
        -pos     => [ 50, 75 ],
        -size    => [ 60, 20 ],
        -onClick => \&macdefault_Click,
    );

    $btn_maccancel = $macmain->AddButton(
        -name    => 'maccancel',
        -text    => 'Cancel',
        -tabstop => 1,
        -cancel  => 1,                       # press 'Esc' to click this button
        -pos     => [ 150, 75 ],
        -size    => [ 60, 20 ],
        -onClick => \&macmainCancel_Click,
    );

    $btn_machelp = $macmain->AddButton(
        -name    => 'machelp',
        -text    => 'Help',
        -tabstop => 1,
        -pos     => [ 250, 75 ],
        -size    => [ 60, 20 ],
        -onClick => \&Help_Click,
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
      $lbl_MacOptical->Height() + +50 +
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
    return 0;
}

### Resize the Macintosh window #############################################
sub macmain_Resize {
    $macsb->Move( 0, $macmain->ScaleHeight - $macsb->Height );
    $macsb->Resize( $macmain->ScaleWidth, $macsb->Height );
    return 0;
}

### gather data from the Macintosh window ###################################
sub macdefault_Click {

    if ($DEBUG) { Log("DEBUG: Okay clicked in MacMainWindow"); }

    # Read my variables
    $MacNetstat = $form_MacNetstat->Checked();
    $MacOptical = $form_MacOptical->Checked();

    $macmain->Hide();
    return 0;
}

### Universal Window Termination ############################################
sub Window_Terminate {
    return -1;
}

### Universal Help click routine ############################################
sub Help_Click {
    open_browser(
'http://www.droppedpackets.org/inventory-and-slm/ldms_client/ldms_client-manual'
    );

    return 0;
}

1;
