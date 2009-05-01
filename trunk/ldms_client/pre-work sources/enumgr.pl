use strict;
use warnings;
use Win32::OLE qw(in);

my $strComputer = '.';

my $GroupList = Win32::OLE->GetObject('WinNT://' . $strComputer . '');
$GroupList->{Filter} = ['group'];
foreach my $Group (in $GroupList) {
    my $GroupName = $Group->Name;
	my $MemberList = Win32::OLE->GetObject('WinNT://' . $strComputer . '/' . $GroupName);
	my $GroupMembers = "";
	foreach my $Member (in $MemberList->Members) {
    	my $MemberName = $Member->Name;
        $GroupMembers .= "$MemberName, ";
    }
	$GroupMembers = substr($GroupMembers, 0, -2);
    print "Local Groups - $GroupName - Members = $GroupMembers\n";
}



