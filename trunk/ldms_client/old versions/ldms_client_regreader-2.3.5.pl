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
use Env;
use IO::Handle;
use Win32::TieRegistry ( Delimiter => "/", ArrayValues => 1, qw(KEY_READ) );
use Carp ();
local $SIG{__WARN__} = \&Carp::cluck;

#############################################################################
# Variables                                                                 #
#############################################################################
my ( $keyfile ) = shift;
( my $prog = $0 ) =~ s/^.*[\\\/]//x;

my $VERSION = "2.3.5";

my $usage = <<"EOD";

Usage: $prog "PATH/TO/KEYFILE"
	-keyfile    The temp file containing keys and values we should read

$prog v $VERSION
Jack Coates, jack\@monkeynoodle.org, released under GPL
This program is a helper application to ldms_client. It is used in conjuction 
with startasuser.exe to read registry values from HKCU.
The latest version lives at 
http://www.droppedpackets.org/inventory-and-slm/ldms_client/

EOD

# Prepare logging system
my $logfile = $PROGRAMFILES . "/LANDesk/LDClient/ldms_client_regreader.log";
my $LOG;
open( $LOG, '>', $logfile ) or croak("Cannot open $logfile - $!");
close $LOG;

my ( $value, $type, $KEYFILE, $key, $subkey );

#############################################################################
# Main Loop                                                                 #
#############################################################################

if (! $keyfile ) {
    print $usage;
    &LogDie("called without a keyfile");
}

# Suppress DOS Windows
BEGIN {
    Win32::SetChildShowWindow(0) if defined &Win32::SetChildShowWindow;
}

&Log("$prog $VERSION using $keyfile");

open( $KEYFILE, '<', "$keyfile" )
  or &LogDie("cannot open $keyfile for reading: $!");

my $RegKey = $Registry->{"HKEY_CURRENT_USER/"}
  or &LogDie("Cannot open the HKCU hive for reading! $^E");

my $results;

while (<$KEYFILE>) {
    chomp;
    ( $key, $subkey ) = split(/,/x);
    if ( defined($key) && defined($subkey) ) {
        if ($subkey =~ m/\(default\)/ix ) {
            $subkey = "";
        }        
        $key = "HKEY_CURRENT_USER/" . $key;
        $RegKey = $Registry->{"$key"};
        if ( $RegKey ) {
            ( $value, $type ) = $RegKey->GetValue($subkey)
              or &LogWarn("Can't read $key $subkey key: $^E");
            if ( defined($value) ) {
                $value = &ParseRegistryValue( $type, $value );
             }
             else {
                $value = "NULL";
             }
             if ($subkey eq "") { $subkey = "(Default)"; }
            $results .= "$key,$subkey,$value\n";
        }
    }
}
close($KEYFILE);
open( $KEYFILE, '>', "$keyfile" )
  or &LogDie("cannot open $keyfile for writing: $!");
print $KEYFILE "$results";
close($KEYFILE);

&Log("$prog $VERSION exiting.\n");
exit 0;

#############################################################################
# Subroutines                                                               #
#############################################################################

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

