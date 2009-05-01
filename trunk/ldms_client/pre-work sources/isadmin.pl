use strict;
use warnings;
use Win32API::Net;

if (&IsAdmin) {
    print "I have rights\n";
} else {
    print "I don't have rights\n";
}

sub IsAdmin {
    my $Server = "";
    my %CallerUserInfo;
    my $Caller = getlogin;
    # LocalSystem isn't an admin, but is still able to do the deeds
    if ($Caller eq "SYSTEM") { return 1; }    
    Win32API::Net::UserGetInfo (
				$Server,
				$Caller,
				"1",
				\%CallerUserInfo 
			       );

    return $CallerUserInfo{priv};
}

