On Error Resume Next

Const HKEY_LOCAL_MACHINE = &H80000002

strComputer = "."
Set objReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\default:StdRegProv")
strKeyPath = "System\Currentcontrolset\Control\Class\{4D36E972-E325-11CE-BFC1-08002be10318}"
strNICName = "Name"
strDuplexMode = "DuplexMode"
strSpeedDuplex = "SpeedDuplex"
strReqMediaType = "RequestedMediaType"
strMedia = "Media"
strMediaType = "MediaType"
strEXTPHY = "EXTPHY"
strConnectionType = "ConnectionType"
strWakeOn = "WakeOn"
strWakeOnLink = "WakeOnLink"
strPath = "C:\Program Files\LANDesk\LDCLIENT\"
strFile = strPath & "duplex.dat"

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
	objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"DriverDesc", strNICName
	wscript.echo strNICName
	if strNICName = "RAS Async Adapter" Then
		strNICName = null
	End If
	if strNICName = "WAN Miniport (L2TP)" Then
		strNICName = null
	End If
	if strNICName = "WAN Miniport (PPTP)" Then
		strNICName = null
	End If
	if strNICName = "WAN Miniport (PPPOE)" Then
		strNICName = null
	End If
	if strNICName = "WAN Miniport (IP)" Then
		strNICName = null
	End If
	if strNICName = "WAN Miniport (Network Monitor)" Then
		strNICName = null
	End If
	if strNICName = "Direct Parallel" Then
		strNICName = null
	End If
	if strNICName = "Packet Scheduler Miniport" Then
		strNICName = null
	End If
	wscript.echo "after tests " & strNICName
	if not isnull(strNICName) Then
		' DuplexMode
		' 
		objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"DuplexMode", strDuplexMode
		' Realtek, 3Com
		If strDuplexMode = "0" Then
			strDuplexMode = "Auto Detect"
		End If
		If strDuplexMode = "1" Then
			strDuplexMode = "10Mbps \ Half Duplex"
		End If
		If strDuplexMode = "2" Then
			strDuplexMode = "10Mbps \ Full Duplex"
		End If
		If strDuplexMode = "3" Then
			strDuplexMode = "100Mbps \ Half Duplex"
		End If
		If strDuplexMode = "4" Then
			strDuplexMode = "100Mbps \ Full Duplex"
		End If
		' Realtek RTL8139 Family PCI Fast Ethernet NIC 
		If strDuplexMode = "5" Then
			strDuplexMode = "100Mbps \ Full Duplex"
		End If
		If strDuplexMode <> "" Then
			filetxt.WriteLine("NIC - " & strNICName & " - Duplex Mode = " & strDuplexMode)
		End If
		' SpeedDuplex
		'
		objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"SpeedDuplex", strSpeedDuplex
		' Intel PRO/1000 Gigabit Desktop Adapter
		If strSpeedDuplex = "0" Then
			strSpeedDuplex = "Auto Detect"
		End If
		If strSpeedDuplex = "5" Then
			strSpeedDuplex = "100Mbps \ Full Duplex"
		End If
		if strSpeedDuplex <> "" Then
			filetxt.WriteLine("NIC - " & strNICName & " - Speed Duplex = " & strSpeedDuplex)
		End If
		' RequestedMediaType
		'
		objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"RequestedMediaType", strReqMediaType
		' Broadcom NetXtreme Gigabit Ethernet
		if strReqMediaType = "0" Then
			strReqMediaType = "Auto Detect"
		End If
		if strReqMediaType = "6" Then
			strReqMediaType = "100Mbps \ Full Duplex"
		End If
		If strReqMediaType <> "" Then 
			filetxt.WriteLine("NIC - " & strNICName & " - Requested Media Type = " & strReqMediaType)
		End If
		' Media
		'
		objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"Media", strMedia
		If strMedia <> "" Then
			filetxt.WriteLine("NIC - " & strNICName & " - Media = " & strMedia)
		End If
		objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"Media_Type", strMediaType
		If strMediaType <> "" Then
			filetxt.WriteLine("NIC - " & strNICName & " - Media Type = " & strMediaType)
		End If
		' EXTPHY
		'
		objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"EXTPHY", strEXTPHY
		' AMD, VMWare
		if strEXTPHY = "0" Then
			strEXTPHY = "Auto Detect"
		End If
		if strEXTPHY = "2" Then
			strEXTPHY = "100Mbps \ Full Duplex"
		End If
		If strEXTPHY <> "" Then
			filetxt.WriteLine("NIC - " & strNICName & " - EXTPHY = " & strEXTPHY)
		End If
		' ConnectionType
		'
		objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"ConnectionType", strConnectionType
		' Davicom, VIA
		if strConnectionType = "0" Then
			strConnectionType = "Auto Detect"
		End If
		if strConnectionType = "2" Then
			strConnectionType = "100Mbps \ Full Duplex"
		End If
		if strConnectionType = "4" Then
			strConnectionType = "100Mbps \ Full Duplex"
		End If
		if strConnectionType = "9" Then
			strConnectionType = "100Mbps \ Full Duplex"
		End If
		If strConnectionType <> "" Then
			filetxt.WriteLine("NIC - " & strNICName & " - ConnectionType = " & strConnectionType)
		End If
		' WakeON
		'
		objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"WakeOn", strWakeOn
		If strWakeOn = "0" Then
			strWakeOn = "Disabled"
		End If
		If strWakeOn = "6" Then
			strWakeOn = "Wake on Magic Packet"
		End If
		If strWakeOn = "116" Then
			strWakeOn = "Wake on Directed Packet"
		End If
		If strWakeOn = "118" Then
			strWakeOn = "Wake on Magic or Directed Packet"
		End If
		If strWakeOn = "246" Then
			strWakeOn = "OS Directed"
		End If
		If strWakeOn <> "" Then
			filetxt.WriteLine("NIC - " & strNICName & " - Wake On = " & strWakeOn)
		End If
		' WakeOnLink
		'
		objReg.GetStringvalue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey,"WakeOnLink", strWakeOnLink
		If strWakeOnLink = "0" Then
			strWakeOnLink = "Disabled"
		End If
		If strWakeOnLink = "1" Then
			strWakeOnLink = "OS Controlled"
		End If
		If strWakeOnLink = "2" Then
			strWakeOnLink = "Forced"
		End If
		If strWakeOnLink <> "" Then
			filetxt.WriteLine("NIC - " & strNICName & " - Wake On Link = " & strWakeOnLink)
		End If
	End If
Next

