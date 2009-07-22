@ECHO OFF

REM defrag.bat defragments any attached hard drives (including external USB
REM or Firewire drives,  unless they're removable)
REM 2009 Jared Barneck, jared.barneck@landesk.com

 
REM Skip functions as they are not to be used when the batch file is started. 
GOTO main 
 
:f_defrag 
  defrag.exe %1: -f -v
  IF NOT "%ERRORLEVEL%"=="0" EXIT /B 0 
  GOTO end
 
REM Makes sure the drive is a hard drive and not a CD-Rom or mapped drive. 
:f_isHD 
  fsutil fsinfo drivetype %1: |FINDSTR /C:"Fixed Drive" 
  IF "%ERRORLEVEL%"=="0" (CALL :f_defrag %1) 
  GOTO end 
 
:main
  FOR /D %%d IN ('A B C D E F G H I J K L M N O P Q R S T U V W X Y Z') DO CALL :f_isHD %%d 
 
:end 
  exit /b 0
