'-------------------------------------------------------------------------------
' EnumerateGrp.vbs
'
' Developer: Denny Cannon
' Developed: 2004-03-17
' Modified: 2004-03-17
' Version: 1.0
'
' Description: Finds all users in a domain that are members of a group.
'
' Modified: 2004-06-23
' Version: 2.0
'-------------------------------------------------------------------------------

'-------------------------------------------------------------------------------
' *** Declariations ***
'-------------------------------------------------------------------------------
dim strComputer
dim mbrlist, grpName
dim wshshell
dim fso
dim oGroupFile
dim CoreServer
'-------------------------------------------------------------------------------
' *** Main Script ***
'-------------------------------------------------------------------------------
'Define objects
Set wshshell = wscript.createobject("Wscript.shell")
Set fso = wscript.createobject("scripting.filesystemobject")

'Define Variables
CoreServer = "LANDeskcore"
OutputFile = "C:\Program Files\LANDesk\ldclient\groups.txt"
strComputer = "."

If fso.FileExists(OutputFile) <> True then
	Set objFile = fso.CreateTextFile(OutputFile)
Else
	fso.deletefile OutputFile,true
	Set objFile = fso.CreateTextFile(OutputFile)
End if

objFile.close

'ForAppending=8, ForReading=1, ForWriting = 2
Set oGroupFile = fso.opentextfile(OutputFile,8, False)
Set colGroups = GetObject("WinNT://" & strComputer & "")

colGroups.Filter = Array("group")
For Each objGroup In colGroups
    Wscript.Echo objGroup.Name
    grpName = objGroup.Name 
    For Each objUser in objGroup.Members
        Wscript.Echo vbTab & objUser.Name
	mbrlist = mbrlist + objUser.Name + ", "
    Next
    oGroupFile.WriteLine "Local Groups - " & grpName & " - Members = " & mbrlist
Next



oGroupFile.Close


fso.deletefile "c:\Program Files\LANDesk\ldclient\groups.txt",true
