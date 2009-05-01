use Win32::NetAdmin qw(GetUsers GroupIsMember
                           UserGetAttributes UserSetAttributes);

    my %hash;
    GetUsers("", FILTER_NORMAL_ACCOUNT , \%hash)
        or die "GetUsers() failed: $^E";

    foreach (keys %hash) {
        my ($password, $passwordAge, $privilege,
            $homeDir, $comment, $flags, $scriptPath);
#        if (GroupIsMember("", "Domain Users", $_)) {
#            print "Updating $_ ($hash{$_})\n";
            UserGetAttributes("", $_, $password, $passwordAge, $privilege,
                              $homeDir, $comment, $flags, $scriptPath)
                or die "UserGetAttributes() failed: $^E";
			print "$_ $password $passwordAge $privilege $homeDir $comment $flags $scriptPath\n";
#            $scriptPath = "dnx_login.bat"; # this is the new login script
#           UserSetAttributes("", $_, $password, $passwordAge, $privilege,
#                              $homeDir, $comment, $flags, $scriptPath)
#                or die "UserSetAttributes() failed: $^E";
#        }
    }

