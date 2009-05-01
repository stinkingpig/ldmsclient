;NSIS Modern User Interface
;-----------------------------------------------------
!include "MUI.nsh"
SetCompressor /SOLID lzma
SetCompress force
Name "ldms_client version 2.4.5"
OutFile "ldms_client_node_install.exe"
InstallDir "$PROGRAMFILES\LANDesk\ldclient"
SilentInstall "silent"

!insertmacro MUI_LANGUAGE "English"

Section "Program Files"
  SetOutPath "$INSTDIR"
  File "ldms_client.exe"
  File "ldms_client_regreader.exe"
  File "LDSCNHLP.INI"
SectionEnd
 
