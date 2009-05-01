#!perl

#### Warning: onError unsupported

use Win32::OLE;

use constant HKEY_LOCAL_MACHINE => 0x80000002;

$strComputer = '.';
$objReg = Win32::OLE->GetObject('winmgmts:{impersonationLevel=impersonate}!\\\\' . $strComputer . '\\root\\default:StdRegProv');
$strKeyPath = 'SOFTWARE\\Intel\\LANDesk\\LDWM\\AppHealing\\Agent\\AMClient\\APM\\PolicyCache';
$strName = 'Name';
$strGUID = 'GUID';
$strInfoDesc = 'Informational Description';
$strStatus = 'Status';
$strPath = 'C:\\Program Files\\LANDesk\\LDCLIENT\\';
$strFile = $strPath . 'policylisting.dat';

$objFSO = Win32::OLE->new('Scripting.FileSystemObject');
if ($objFSO->FileExists($strFile) == 0) {
    if (!$objFSO->FolderExists($strPath)) {
        $objFSO->CreateFolder($strPath)->Path;
        $objFSO->CreateTextFile($strFile);
    }
    else {
        $objFSO->CreateTextFile($strFile);
    }
}
else {
    $objFSO->DeleteFile($strFile);
    $objFSO->CreateTextFile($strFile);
}

$filetxt = $objFSO->OpenTextFile($strFile, 8, 1);

$objReg->EnumKey(HKEY_LOCAL_MACHINE, $strKeyPath, $arrSubKeys);

foreach my $subkey (@{$arrSubKeys}) {
    $objReg->GetStringvalue(HKEY_LOCAL_MACHINE, $strKeyPath . '\\' . $subkey, 'Name', $strName);
    $objReg->GetStringvalue(HKEY_LOCAL_MACHINE, $strKeyPath . '\\' . $subkey, 'GUID', $strGUID);
    $filetxt->WriteLine('LANDesk Management - APM - Policies - ' . $strName . ' - GUID = ' . $strGUID);
    $objReg->GetStringvalue(HKEY_LOCAL_MACHINE, $strKeyPath . '\\' . $subkey, 'Informational Description', $strInfoDesc);
    $filetxt->WriteLine('LANDesk Management - APM - Policies - ' . $strName . ' - Description = ' . $strInfoDesc);
    $objReg->GetStringvalue(HKEY_LOCAL_MACHINE, $strKeyPath . '\\' . $subkey, 'Status', $strStatus);
    $filetxt->WriteLine('LANDesk Management - APM - Policies - ' . $strName . ' - Status = ' . $strStatus);
}

