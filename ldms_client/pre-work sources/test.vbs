strComputer = "."

Set objLocator = CreateObject("WbemScripting.SWbemLocator")
Set objWMIService = objLocator.ConnectServer(strComputer,"root\cimv2")
objWMIService.Security_.ImpersonationLevel = 3

Set colSoftware = objWMIService.ExecQuery ("SELECT * FROM Win32_Product")

If colSoftware.Count > 0 Then

    Set objFSO = CreateObject("Scripting.FileSystemObject")
    Set objTextFile = objFSO.CreateTextFile("c:\SoftwareList.txt", True)

    For Each objSoftware in colSoftware
        objTextFile.WriteLine objSoftware.Caption & vbtab & _
        colSoftware.ProductID

    Next

    objTextFile.Close

Else
    WScript.Echo "Cannot retrieve software from this computer."

End If 

