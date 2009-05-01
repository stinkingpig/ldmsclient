 use strict; use warnings;
use Win32;
use Config::Tiny;

my $path= Win32::GetShortPathName("C:/Documents and Settings/Jack Coates/My Documents/code/ldms_client");

my $oldfile = $path."/MyProg.ini";
my $newfile = $path."/MyOtherProg.ini";

my $config = Config::Tiny->read($oldfile) or die 'Oops:',Config::Tiny->errstr();

my @sections = sort keys %{$config};
print "   The sections are:\n";
print "$_\n" for @sections;
print "\n\n";

foreach my $section (@sections) {
   print "Section '$section':\n";
   my $href = $config->{$section} or next;
   my @keys = keys %$href;
   printf "%20s = %s\n", $_, $config->{$section}{$_} for sort @keys;
   print "End     $section\n\n";
} 

$config->write($newfile) or die 'Oops:',Config::Tiny->errstr();
