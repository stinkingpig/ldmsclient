#############################################################################
# ldms_client_regreader.pl                                                  #
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
use Win32::API::Prototype;
use Win32::TieRegistry ( Delimiter => "/", ArrayValues => 1, qw(KEY_READ) );

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
my $ver = "2.3";
my $DEBUG = $A{d} || 0;

# Prepare logging system
my $logfile = "ldms_client_regreader.log";
my $LOG;
open( $LOG, '>', $logfile ) or die "Cannot open $logfile - $!";

my $usage = <<EOD;

Usage: $prog [-d] [-h] -keyfile="PATH/TO/KEYFILE"
	-d			debug
	-keyfile    The temp file containing keys and values we should read
	-h(elp)		this display

$prog v $ver
Jack Coates, jack\@monkeynoodle.org, released under GPL
This program is a helper application to ldms_client. It is used in conjuction 
with startasuser.exe to read registry values from HKCU and write them into
the LANDesk Management Suite database.
The latest version lives at 
http://www.droppedpackets.org/inventory-and-slm/ldms_client/

EOD

my ( $value, $type, $keyfile, $KEYFILE, $key, $subkey );

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
    &Log("Unable to set master PID scheduling priority to low.\n");
}
else {
    &Log("$prog $ver starting, master PID scheduling priority set to low.\n");
}
CloseHandle($hProcess);

if ( $A{keyfile} ) {
    $keyfile = $A{keyfile};
}
else {
    print "I need a keyfile!\n";
    exit 0;
}

open( $KEYFILE, '<', "$keyfile" )
  or &LogDie("cannot open $keyfile for reading: $!");

my $RegKey = $Registry->{"HKEY_CURRENT_USER/"}
  or &LogDie("Cannot open the HKCU hive for reading! $^E");

my $results;

while (<$KEYFILE>) {
    chomp;
    ( $key, $subkey ) = split(/,/);
    if ( defined($key) && defined($subkey) ) {
        if ($DEBUG) { &Log("read $key, $subkey from config file"); }
        $key = "HKEY_CURRENT_USER/" . $key;
        $RegKey = $Registry->{"$key"};
        if ( $RegKey ) {
            ( $value, $type ) = $RegKey->GetValue($subkey)
              or &LogDie("Can't read $key $subkey key: $^E");
            if ( defined($value) ) {
                if (   $type eq "REG_SZ"
                    or $type eq "REG_EXPAND_SZ"
                    or $type eq "REG_MULTI_SZ" )
                {

                    # It's a string, nothing further needed
                    if ($DEBUG) {
                        &Log(   "Found type $type value of "
                              . "$value at $key $subkey" );
                    }
                }
                elsif ( $type eq "REG_DWORD" or $type eq "REG_BINARY" ) {

                    # It's a binary value and must be unpacked
                    # This will only work if it's four bytes or less
                    $value = unpack( "L", $value );
                }
                else {
                    &LogWarn("$key $subkey is an unsupported type: $type");
                }
                if ($DEBUG) { &Log("Read output of $value"); }
            }
            else {
                &LogWarn("$key $subkey contains no value");
                $value = "NULL";
            }
        }
        else {
            if ($DEBUG) { &Log("Found nothing at $key $subkey"); }
            $value = "NULL";
        }
        $results .= "$key,$subkey,$value\n";
        if ($DEBUG) { &Log("recorded $key, $subkey, $value"); }
    }
}
close($KEYFILE);
open( $KEYFILE, '>', "$keyfile" )
  or &LogDie("cannot open $keyfile for writing: $!");
print $KEYFILE "$results";
close($KEYFILE);

&Log("$prog $ver exiting.\n");
exit 0;

#############################################################################
# Subroutines                                                               #
#############################################################################

### Logging subroutine ######################################################
sub Log {
    my $msg = shift;
    if ( !defined($msg) ) { $msg = "Log: Can't report nothing"; }
    print $LOG localtime() . ": $msg\n";
    return 0;
}

### Logging with warning subroutine #########################################
sub LogWarn {
    my $msg = shift;
    if ( !defined($msg) ) { $msg = "LogWarn: Can't report nothing"; }
    print $LOG localtime() . ":WARN: $msg\n";
    return 0;
}

### Logging with death subroutine ###########################################
sub LogDie {
    my $msg = shift;
    if ( !defined($msg) ) { $msg = "LogDie Can't report nothing"; }
    print $LOG localtime() . ":DIE: $msg\n";
    exit 1;
}

