On Error Resume Next

Const HKEY_LOCAL_MACHINE = &H80000002

strComputer = "."
Set objReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\default:StdRegProv")
strKeyPath = "SOFTWARE\Intel\LANDesk\LDWM\AppHealing\Agent\AMClient\APM\PolicyCache"
strName = "Name"
strGUID = "GUID"
strInfoDesc = "Informational Description"
strStatus = "Status"
strPath = "C:\Program Files\LANDesk\LDCLIENT\"
strFile = strPath & "policylisting.dat"

Set objFSO = CreateObject("Scripting.FileSystemObject")
If objFSO.FileExists(strFile) = False Then
   If NOT objFSO.FolderExists(strPath) Then
      objFSO.CreateFolder(strPath)
      objFSO.CreateTextFile(strFile)
   Else
      objFSO.CreateTextFile(strFile)
   End If
Else
   objFSO.DeleteFile(strFile)
   objFSO.CreateTextFile(strFile)
End If

Set filetxt = objFSO.OpenTextFile(strFile, 8, True)

objReg.EnumKey HKEY_LOCAL_MACHINE, strKeyPath, arrSubKeys

For Each subkey In arrSubKeys
	objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"Name", strName
	objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"GUID", strGUID
	filetxt.WriteLine("LANDesk Management - APM - Policies - " & strName & " - GUID = " & strGUID)
	objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"Informational Description", strInfoDesc
	filetxt.WriteLine("LANDesk Management - APM - Policies - " & strName & " - Description = " & strInfoDesc)
	objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"Status", strStatus
	filetxt.WriteLine("LANDesk Management - APM - Policies - " & strName & " - Status = " & strStatus)
Next

