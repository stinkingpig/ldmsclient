#!perl

#### Warning: onError unsupported

use Win32::OLE;
use Win32::TieRegistry ( Delimiter => "/", ArrayValues => 1 );

my $DuplexRegHive =
  $Registry->{
"HKEY_LOCAL_MACHINE/System/Currentcontrolset/Control/Class/{4D36E972-E325-11CE-BFC1-08002bE10318}"
  };
my @nic_names = $DuplexRegHive->SubKeyNames;
foreach my $nic (@nic_names) {
    my $DuplexRegEntry = $DuplexRegHive->{$nic};
    my $DriverName     = $DuplexRegEntry->GetValue("DriverDesc");
    if ( !$DriverName ) {
        next;
    }
    if ( $DriverName eq '1394 Net Adapter' ) {
        next;
    }
    if ( $DriverName eq 'Direct Parallel' ) {
        next;
    }
    if ( $DriverName eq 'RAS Async Adapter' ) {
        next;
    }
    if ( $DriverName =~ m/VPN/ ) {
        next;
    }
    if ( $DriverName =~ m/Miniport/ ) {
        next;
    }
    if ( $DriverName =~ m/Virtual Ethernet Adapter/ ) {
        next;
    }

    # Not one of the bogus drivers, so let's look at DuplexMode
    my ( $ReportedMode, $drivertype );

    # Realtek, 3Com
    my $DuplexMode = $DuplexRegEntry->GetValue("DuplexMode");
    if ($DuplexMode) {
        $drivertype = 1;
    }

    # Intel cards
    $DuplexMode = $DuplexRegEntry->GetValue("SpeedDuplex");
    if ($DuplexMode) {
        $drivertype = 1;
    }

    # Broadcom NetXtreme Gigabit Ethernet
    $DuplexMode = $DuplexRegEntry->GetValue("RequestedMediaType");
    if ($DuplexMode) {
        $drivertype = 2;
    }

    # AMD, VMWare (though VMWare is filtered out anyway)
    $DuplexMode = $DuplexRegEntry->GetValue("EXTPHY");
    if ($DuplexMode) {
        $drivertype = 3;
    }

    # VIA, Davicom
    $DuplexMode = $DuplexRegEntry->GetValue("ConnectionType");
    if ($DuplexMode) {
        $drivertype = 3;
    }

# If nothing was detected at all, the interface is probably defaulting to auto-detect
    if ( !$drivertype ) {
        $ReportedMode = 'Auto Detect';
    }

    # Decode the number to something useful.
    if ( $drivertype == 1 ) {

        # Most cards seem to follow this
        if ( $DuplexMode == '0' ) {
            $ReportedMode = 'Auto Detect';
        }
        if ( $DuplexMode == '1' ) {
            $ReportedMode = '10Mbps \\ Half Duplex';
        }
        if ( $DuplexMode == '2' ) {
            $ReportedMode = '10Mbps \\ Full Duplex';
        }
        if ( $DuplexMode == '3' ) {
            $ReportedMode = '100Mbps \\ Half Duplex';
        }
        if ( $DuplexMode == '4' ) {
            $ReportedMode = '100Mbps \\ Full Duplex';
        }
        if ( $DuplexMode == '5' ) {
            $ReportedMode = '1000Mbps \\ Auto-Negotiate';
        }
    }
    if ( $drivertype == 2 ) {

        # Broadcom has to be special, though
        if ( $DuplexMode == '0' ) {
            $ReportedMode = 'Auto Detect';
        }
        if ( $DuplexMode == '3' ) {
            $ReportedMode = '10Mbps \\ Half Duplex';
        }
        if ( $DuplexMode == '4' ) {
            $ReportedMode = '10Mbps \\ Full Duplex';
        }
        if ( $DuplexMode == '5' ) {
            $ReportedMode = '100Mbps \\ Half Duplex';
        }
        if ( $DuplexMode == '6' ) {
            $ReportedMode = '100Mbps \\ Full Duplex';
        }
    }
    if ( $drivertype == 3 ) {

        # Who knows what they're smoking at VIA, AMD and Davicom
        if ( $DuplexMode == '0' ) {
            $ReportedMode = 'Auto Detect';
        }
        if ( $DuplexMode == '2' ) {
            $ReportedMode = '100Mbps \\ Full Duplex';
        }
        if ( $DuplexMode == '4' ) {
            $ReportedMode = '100Mbps \\ Full Duplex';
        }
        if ( $DuplexMode == '9' ) {
            $ReportedMode = '100Mbps \\ Full Duplex';
        }
    }

    # Okay to report
    if ($ReportedMode) {
        print "NIC - $DriverName - Duplex Mode = $ReportedMode\n";
    }

    # Just for giggles, let's see about Media Type and Wake on LAN status.
    # Media
    my $NICMedia = $DuplexRegEntry->GetValue("Media");
    if ($NICMedia) {
        print "NIC - $DriverName - Media = $NICMedia\n";
    }
    my $NICMediaType = $DuplexRegEntry->GetValue("Media_Type");
    if ($NICMediaType) {
        print "NIC - $DriverName - Media Type = $NICMediaType\n";
    }

    # Wake On LAN
    my $NICWOL = $DuplexRegEntry->GetValue("WakeOn");
    if ($NICWOL) {

# This has to be decoded too... $DIETY grant that it's more standard than duplex mode
        if ( $NICWOL == '0' ) {
            $NICWOL = 'Disabled';
        }
        if ( $NICWOL == '6' ) {
            $NICWOL = 'Wake on Magic Packet';
        }
        if ( $NICWOL == '116' ) {
            $NICWOL = 'Wake on Directed Packet';
        }
        if ( $NICWOL == '118' ) {
            $NICWOL = 'Wake on Magic or Directed Packet';
        }
        if ( $NICWOL == '246' ) {
            $NICWOL = 'OS Directed';
        }
        print "NIC - $DriverName - Wake On = $NICWOL\n";
    }
    my $NICWOLLink = $DuplexRegEntry->GetValue("WakeOnLink");
    if ($NICWOLLink) {
        if ( $NICWOLLink == '0' ) {
            $NICWOLLink = 'Disabled';
        }
        if ( $NICWOLLink == '1' ) {
            $NICWOLLink = 'OS Controlled';
        }
        if ( $NICWOLLink == '2' ) {
            $NICWOLLink = 'Forced';
        }
        print "NIC - $DriverName - Wake On Link = $NICWOLLink\n";
    }
}

