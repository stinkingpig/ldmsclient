@ECHO OFF

copy /Y "%PROGRAMFILES%\LANDesk\ldclient\sdmcache\ldlogon\packages\ldms_client.exe" "%PROGRAMFILES%\LANDesk\ldclient\"

copy /Y "%PROGRAMFILES%\LANDesk\ldclient\sdmcache\ldlogon\packages\ldms_client_regreader.exe" "%PROGRAMFILES%\LANDesk\ldclient\"

copy /Y "%PROGRAMFILES%\LANDesk\ldclient\ldscnhlp.ini" "%PROGRAMFILES%\LANDesk\ldclient\ldscnhlp.ini.old"
copy /Y "%PROGRAMFILES%\LANDesk\ldclient\sdmcache\ldlogon\packages\ldscnhlp.ini" "%PROGRAMFILES%\LANDesk\ldclient\"

SET ERRORLEVEL=0
