use strict;
use warnings;
use Env;
use Win32;
use File::Find;
use File::Basename;

my $totalpstsize = 0;

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
print "Email = PST Files - Total Disk Size = $totalpstsize\n";

sub ProcessPSTFile {

    # Each file needs to be looked at
    my ( undef, undef, $extension ) = fileparse( $_, qr{\..*} );
    if ( $extension ne ".pst" ) {
        return 0;
    }
    print "Email - PST Files - $_ - File Location = $File::Find::name\n";

    # stat -- 7 is file size in bytes
    my $pstfilesize = ( stat($File::Find::name) )[7];
    print "Email - PST Files - $_ - File Size = $pstfilesize\n";
    $totalpstsize += $pstfilesize;
}
