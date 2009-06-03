use strict;
use warnings;
use Win32;
use Win32::EventLog;
use Win32API::Net;
use Win32::File::VersionInfo;
use Win32::FileSecurity;
use Win32::OLE qw(in);
use Win32::OLE::Variant;
use Win32::Security::SID;
use Win32::OLE::NLS qw(:TIME
  :DATE
  GetLocaleInfo GetUserDefaultLCID
  LOCALE_SMONTHNAME1 LOCALE_SABBREVMONTHNAME1
  LOCALE_SDAYNAME1 LOCALE_SABBREVDAYNAME1
  LOCALE_IFIRSTDAYOFWEEK
  LOCALE_SDATE LOCALE_IDATE
  LOCALE_SGROUPING
);
use Win32::OLE::Variant;
use Win32::TieRegistry ( Delimiter => "/", ArrayValues => 1, qw(KEY_READ) );
use Win32 qw(CSIDL_COMMON_APPDATA);

use constant wbemFlagReturnImmediately => 0x10;
use constant wbemFlagForwardOnly => 0x20;

my @computers = (".");
my $strComputer = ".";

foreach my $computer (@computers) {
   print "\n";
   print "==========================================\n";
   print "Computer: $computer\n";
   print "==========================================\n";

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


#   my $objWMIService = Win32::OLE->GetObject("winmgmts:\\\\$computer\\root\\WMI") or die "WMI connection failed.\n";
   my $colItems = $objWMIService->ExecQuery("SELECT * FROM MSStorageDriver_FailurePredictStatus", "WQL",
                  wbemFlagReturnImmediately | wbemFlagForwardOnly);

   foreach my $objItem (in $colItems) {
      print "Active: $objItem->{Active}\n";
      print "InstanceName: $objItem->{InstanceName}\n";
      print "PredictFailure: $objItem->{PredictFailure}\n";
      print "Reason: $objItem->{Reason}\n";
      print "\n";
   }
}

