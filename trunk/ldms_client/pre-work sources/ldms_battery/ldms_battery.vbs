' ldms_battery, gather some useful laptop battery information and post it into the LANDesk database
' version 0.80, Jack Coates, jack@monkeynoodle.org, released under GPLv2
On Error Resume Next
strComputer = "."
strPath = "C:\Program Files\LANDesk\LDCLIENT\"
strFile = strPath & "battery.dat"

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

set objShell = WScript.CreateObject("WScript.Shell")

' First try to get data from the PortableBattery object
Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_PortableBattery")
If colItems.Count > 0 Then
	For Each objItem In colItems
		strBattDesc = objItem.Description
		If Len(Trim(objItem.DeviceID)) > 0 Then
	    	filetxt.WriteLine("Battery - " & strBattDesc & " - DeviceID = " & objItem.DeviceID)
		End If
		If Len(Trim(objItem.Manufacturer)) > 0 Then
	    	filetxt.WriteLine("Battery - " & strBattDesc & " - Manufacturer = " & objItem.Manufacturer)
		End If
		If Len(Trim(objItem.ManufactureDate)) > 0 Then
		    dtmWMIDate = objItem.ManufactureDate
	    	strReturn = WMIDateStringToDate(dtmWMIDate)
		    filetxt.WriteLine("Battery - " & strBattDesc & " - ManufactureDate = " & strReturn)
		End If
		If Len(Trim(objItem.Name)) > 0 Then
		    filetxt.WriteLine("Battery - " & strBattDesc & " - Name = " & objItem.Name)
		End If
		If Len(Trim(objItem.Chemistry)) > 0 Then
			strChemCode = objItem.Chemistry
			' Report a useful value for Chemistry.
			If strChemCode = 1 Then
				strChemistry = "Other"
			End If
			If strChemCode = 2 Then
				strChemistry = "Unknown"
			End If
			If strChemCode = 3 Then
				strChemistry = "Lead Acid"
			End If
			If strChemCode = 4 Then
				strChemistry = "Nickel Cadmium"
			End If
			If strChemCode = 5 Then
				strChemistry = "Nickel Metal Hydride"
			End If
			If strChemCode = 6 Then
				strChemistry = "Lithium Ion"
			End If
			If strChemCode = 7 Then
				strChemistry = "Zinc Air"
			End If
			If strChemCode = 8 Then
				strChemistry = "Lithium Polymer"
			End If
			filetxt.WriteLine("Battery - " & strBattDesc & " - Chemistry = " & strChemistry)

		End If
		If Len(Trim(objItem.Location)) > 0 Then
			filetxt.WriteLine("Battery - " & strBattDesc & " - Location = " & objItem.Location)
		End If
		If Len(Trim(objItem.DesignCapacity)) > 0 Then
			If Len(Trim(objItem.FullChargeCapacity)) > 0 Then
				pctCapacity = objItem.FullChargeCapacity / objItem.DesignCapacity
				filetxt.WriteLine("Battery - " & strBattDesc & " - Capacity = " & FormatPercent(pctCapacity))
			End If
		End If
		If Len(Trim(objItem.Status)) > 0 Then
			filetxt.WriteLine("Battery - " & strBattDesc & " - Status = " & objItem.Status)
		End If
	Next
End If

' Then see what the Battery object has. This may overwrite values found from PortableBattery.
Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_Battery")
If colItems.Count > 0 Then
	For Each objItem In colItems
		strBattDesc = objItem.Description
	    filetxt.WriteLine("Battery - " & strBattDesc & " - DeviceID = " & objItem.DeviceID)
	    filetxt.WriteLine("Battery - " & strBattDesc & " - Name = " & objItem.Name)
		If Len(Trim(objItem.InstallDate)) > 0 Then
		    dtmWMIDate = objItem.InstallDate
	    	strReturn = WMIDateStringToDate(dtmWMIDate)
		    filetxt.WriteLine("Battery - " & strBattDesc & " - InstallDate = " & strReturn)
		End If
		If Len(Trim(objItem.Chemistry)) > 0 Then
			strChemCode = objItem.Chemistry
			' Report a useful value for Chemistry.
			If strChemCode = 1 Then
				strChemistry = "Other"
			End If
			If strChemCode = 2 Then
				strChemistry = "Unknown"
			End If
			If strChemCode = 3 Then
				strChemistry = "Lead Acid"
			End If
			If strChemCode = 4 Then
				strChemistry = "Nickel Cadmium"
			End If
			If strChemCode = 5 Then
				strChemistry = "Nickel Metal Hydride"
			End If
			If strChemCode = 6 Then
				strChemistry = "Lithium Ion"
			End If
			If strChemCode = 7 Then
				strChemistry = "Zinc Air"
			End If
			If strChemCode = 8 Then
				strChemistry = "Lithium Polymer"
			End If
			filetxt.WriteLine("Battery - " & strBattDesc & " - Chemistry = " & strChemistry)

		End If
		If Len(Trim(objItem.Location)) > 0 Then
			filetxt.WriteLine("Battery - " & strBattDesc & " - Location = " & objItem.Location)
		End If
		If Len(Trim(objItem.DesignCapacity)) > 0 Then
			If Len(Trim(objItem.FullChargeCapacity)) > 0 Then
				pctCapacity = objItem.FullChargeCapacity / objItem.DesignCapacity
				filetxt.WriteLine("Battery - " & strBattDesc & " - Capacity = " & FormatPercent(pctCapacity))
			End If
		End If
		If Len(Trim(objItem.Status)) > 0 Then
			filetxt.WriteLine("Battery - " & strBattDesc & " - Status = " & objItem.Status)
		End If
	Next
End If


set objShell = Nothing
filetxt.Close

Function WMIDateStringToDate(dtmWMIDate)
    If Not IsNull(dtmWMIDate) Then
        WMIDateStringToDate = CDate(Mid(dtmWMIDate, 5, 2) & "/" & _
            Mid(dtmWMIDate, 7, 2) & "/" & Left(dtmWMIDate, 4) _
                & " " & Mid (dtmWMIDate, 9, 2) & ":" & _
                    Mid(dtmWMIDate, 11, 2) & ":" & Mid(dtmWMIDate,13, 2))
    End If
End Function

