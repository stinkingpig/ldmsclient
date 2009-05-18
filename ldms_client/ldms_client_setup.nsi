;NSIS Modern User Interface
;Script automatically created by Mihov NSIS Helper 3.3
;http://freeware.mihov.com
;-----------------------------------------------------
!include "MUI.nsh"
SetCompressor /SOLID lzma
SetCompress force
Name "ldms_client version 2.4.8"
OutFile "ldms_client_setup.exe"
InstallDir "$PROGRAMFILES\Monkeynoodle\ldms_client"

;Get install folder from registry for updates
InstallDirRegKey HKCU "Software\ldms_client" ""
 
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\ldms_client_core.exe"
!define MUI_FINISHPAGE_RUN_PARAMETERS ""
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
ShowUninstDetails show

Section "Program Files"
  SetOutPath "$INSTDIR"
  File "ldms_client.exe"
  File "ldms_client_regreader.exe"
  File "ldms_client_core.exe"
  File "ldms_client.pl"
  File "ldms_client_core.pl"
  File "ldms_client_regreader.pl"
  File "ldms_client.perlapp"
  File "ldms_client_core.perlapp"
  File "ldms_client_regreader.perlapp"
  File "ldms_client_setup.nsi"
  File "ldms_client_node_install.nsi"
  File "ldms_client.bat"
  File "defrag.bat"
  File "grey.ico"
  File "desktop.ico"
  File "LDSCNHLP.INI"
 
  ;Store install folder
  WriteRegStr HKCU "Software\ldms_client" "" $INSTDIR
 
 ;Create uninstaller
 WriteUninstaller "$INSTDIR\Uninst.exe"
 
  WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\ldms_client" "DisplayName" "ldms_client 2.4.8 (remove only)"
  WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\ldms_client" "UninstallString" '"$INSTDIR\uninst.exe"'
  WriteUnInstaller "uninst.exe"
SectionEnd
 
Section "Start Menu Shortcuts"
  CreateDirectory "$SMPROGRAMS\Monkeynoodle\ldms_client"
  CreateShortCut "$SMPROGRAMS\Monkeynoodle\ldms_client\Uninstall ldms_client.lnk" "$INSTDIR\uninst.exe" "" "$INSTDIR\uninst.exe" 0
  CreateShortCut "$SMPROGRAMS\Monkeynoodle\ldms_client\Configure ldms_client.lnk" "$INSTDIR\ldms_client_core.exe" "" "$INSTDIR\ldms_client_core.exe" 0
SectionEnd
 
Section "Uninstall"
  Delete $INSTDIR\uninst.exe
  Delete $INSTDIR\ldms_client.exe
  Delete $INSTDIR\ldms_client_regreader.exe
  Delete $INSTDIR\ldms_client_core.exe
  Delete $INSTDIR\ldms_client.bat
  Delete $INSTDIR\defrag.bat
  Delete $INSTDIR\LDSCNHLP.INI
  Delete $INSTDIR\ldms_client.pl
  Delete $INSTDIR\ldms_client_core.pl
  Delete $INSTDIR\ldms_client_regreader.pl
  Delete $INSTDIR\ldms_client.perlapp
  Delete $INSTDIR\ldms_client_core.perlapp
  Delete $INSTDIR\ldms_client_regreader.perlapp
  Delete $INSTDIR\ldms_client_setup.nsi
  Delete $INSTDIR\ldms_client_node_install.nsi
  Delete $INSTDIR\Uninst.exe
  RMDir "$INSTDIR"
 
  ; remove shortcuts, if any.
  Delete "$SMPROGRAMS\Monkeynoodle\Uninstall ldms_client.lnk"
  Delete "$SMPROGRAMS\Monkeynoodle\Configure ldms_client.lnk"
  RMDir "$SMPROGRAMS\Monkeynoodle"
 
  DeleteRegKey HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ldms_client"
  DeleteRegKey /ifempty HKCU "Software\ldms_client"
SectionEnd

