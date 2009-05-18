;NSIS Modern User Interface
;-----------------------------------------------------
!include "MUI.nsh"
SetCompressor /SOLID lzma
SetCompress force
Name "ldms_client version 2.4.8"
OutFile "ldms_client_node_install.exe"
InstallDir "$PROGRAMFILES\LANDesk\ldclient"
SilentInstall "silent"

!insertmacro MUI_LANGUAGE "English"

Section "Program Files"
  SetOutPath "$INSTDIR"
  File "ldms_client.exe"
  File "ldms_client_regreader.exe"
  File "LDSCNHLP.INI"

  ReadRegStr $0 HKLM "Software\Intel\LANDesk\LDWM" "CoreServer"
  Exec '"$INSTDIR\ldiscn32.exe" /NTT=$0:5007 /S=$0'  
SectionEnd
 

