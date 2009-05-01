use strict;
use Readonly;
#use Win32::OLE qw(in with);

my $strComputer = ".";

sub method1 {
my $WMI = Win32::OLE->new('WbemScripting.SWbemLocator') ||
 die "Cannot access WMI on local machine: ", Win32::OLE->LastError; 
 
my $Services = $WMI->ConnectServer($strComputer) ||
 die "Cannot access WMI on remote machine: ", Win32::OLE->LastError; 

my $sys_set = $Services->InstancesOf("Win32_ComputerSystem");
foreach my $sys (in($sys_set)) 
 {  
  my $system_manufacturer = $sys->{'Manufacturer'};
  print "$system_manufacturer\n";
 }
}

sub method2 {
use Win32::OLE::NLS qw(:TIME
  :DATE
  GetLocaleInfo GetUserDefaultLCID
  LOCALE_SMONTHNAME1 LOCALE_SABBREVMONTHNAME1
  LOCALE_SDAYNAME1 LOCALE_SABBREVDAYNAME1
  LOCALE_IFIRSTDAYOFWEEK
  LOCALE_SDATE LOCALE_IDATE
  LOCALE_SGROUPING
);

# Setup Windows OLE object for reading WMI
Readonly my $HKEY_LOCAL_MACHINE => 0x80000002;
Readonly my $EPOCH              => 25569;
Readonly my $SEC_PER_DAY        => 86400;
my $objWMIService =
  Win32::OLE->GetObject( 'winmgmts:'
      . '{impersonationLevel=impersonate}!\\\\'
      . $strComputer
      . '\\root\\cimv2' );
my $objShell = Win32::OLE->new('WScript.Shell');

my $lcid;

BEGIN {
    $lcid = GetUserDefaultLCID();
    Win32::OLE->Option( LCID => $lcid );
}

my $SystemList = $objWMIService->ExecQuery("SELECT * FROM Win32_ComputerSystem");
if ( $SystemList->Count > 0 ) {
    foreach my $System ( in $SystemList) {
        print $System->Manufacturer;
    }
}
}

&method2;
exit 0;
