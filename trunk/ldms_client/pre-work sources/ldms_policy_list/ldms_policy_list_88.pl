use strict;
use warnings;
use Env;
use DBI;
use Win32;
my $dir = $ALLUSERSPROFILE . "\\Application\ Data\\LANDesk\\ManagementSuite\\Database";
$dir = Win32::GetShortPathName($dir);
my $dbfile =  $dir . "\\LDClientDB.db3";

my @rows;

my $dbh = DBI->connect("dbi:SQLite:dbname=$dbfile","","");

my $sql = "select name,filename,description,status from PortalTaskInformation";

my $sth = $dbh->prepare($sql);
  $sth->execute();
while ( @rows = $sth->fetchrow_array() ) {
	print "@rows\n";
}

