On Error Resume Next
strComputer = "."
strExtension = "pst" ' file extension - use lowercase
strPath = "C:\Progra~1\LANDesk\LDClient\"
strFile = strPath & "pstfiles.dat"

Set objFSO = CreateObject("Scripting.FileSystemObject")

Set objWMIService = GetObject("winmgmts:" _
    & "{impersonationLevel=impersonate}!\\" _
    & strComputer & "\root\cimv2")

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

Set colFiles = objWMIService.ExecQuery("Select * from CIM_Datafile where extension = '"&strExtension&"'")

For Each objFile in colFiles
	if Not InStr(objFile.Name, "corel") > 0 Then
    	filetxt.WriteLine("Email - PST Files - " & objFile.FileName & " - File Location = " & objFile.Name)
    	filetxt.WriteLine("Email - PST Files - " & objFile.FileName & " - File Size = " & objFile.FileSize)
    	strTotalSpace = strTotalSpace + objFile.FileSize
	End If
Next

file.txt.WriteLine("Email - PST Files - Total Disk Size = " & strTotalSpace)

filetxt.Close
