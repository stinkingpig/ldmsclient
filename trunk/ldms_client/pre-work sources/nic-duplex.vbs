Break On
Dim $SO,$Pause
$SO=SetOption('Explicit','On')
$SO=SetOption('NoVarsInStrings','On')
$SO=SetOption('WrapAtEOL','On')

Dim $Array, $X, $Y
; Declare the COMPUTER var if not defined on the command line
If Not IsDeclared($COMPUTER)
  Global $COMPUTER
EndIf
$Array = NicInfo($COMPUTER)
If UBound($Array) < 0
  @SERROR ?
Else
  UBound($Array) ' elements returned.' ?
  For $X = 0 to UBound($Array)
    For $Y = 0 to UBound($Array[$X])
      $y '. ' $Array[$X][$Y] ?
    Next
  Next
EndIf



;;======================================================================
;;
;;FUNCTION       NicInfo()
;;
;;ACTION         Returns an array NIC information
;;
;;AUTHOR         Glenn Barnas / NTDoc
;;
;;VERSION        1.0
;;
;;DATE CREATED   2005/03/17
;;
;;DATE MODIFIED  
;;
;;SYNTAX         NicInfo(target)
;;
;;PARAMETERS     target		- name of sysetm to query
;;
;;REMARKS        Array of arrays is returned - a collection of arrays for each physical or virtual NIC 
;;               WAN/RAS, and Miniport drivers are ignored
;;
;;RETURNS        Array of Arrays
;;
;;DEPENDENCIES   none
;;
;;TESTED WITH    NT4, W2K, WXP
;;
;;EXAMPLES       $Array = NicInfo($COMPUTER)
;;
;;               If UBound($Array) < 0
;;                 @SERROR ?
;;               Else
;;               
;;                 UBound($Array) ' elements returned.' ?
;;               
;;                 For $X = 0 to UBound($Array)
;;                   For $Y = 0 to UBound($Array[$X])
;;                     $y '. ' $Array[$X][$Y] ?
;;                   Next
;;                 Next
;;               EndIf
;;             
;
Function NicInfo(OPTIONAL $Target)

  Dim $Regkey, $SubKeyCounter, $NicArray, $CurrentSubKey, $Index
  Dim $Name, $Key, $WorkRegKey, $SubKey

  ; Insure $Target uses the format "\\target\" if specified
  $Target =  IIf($Target <> '', '\\' + Join(Split($Target, '\'), '', 3) + '\', '')

  ; Define the primary registry key
  $RegKey = $Target + 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}'


  ; init the enumeration index and array index
  $SubKeyCounter = 0
  $Index = 0


  ; Enumerate all of the keys that are LAN adapters
  $CurrentSubKey = EnumKey($RegKey, $SubKeyCounter)
  If @ERROR
    Exit @ERROR							; exit now if can't read registry!
  EndIf

  $CurrentSubKey = EnumKey($RegKey, $SubKeyCounter)
  While @ERROR = 0
    $Key = ReadValue($RegKey + '\' + $CurrentSubKey, 'Characteristics')
    If $Key = 132 Or $Key = 32769				; physical nic or virtual team
      ReDim Preserve $NicArray[$Index]				; increase the array size
      $NicArray[$Index] = $CurrentSubKey			; add the subkey to the array
      $Index = $Index + 1					; increment the array index
    EndIf
    $SubKeyCounter = $SubKeyCounter + 1				; increment the enumeration index
    $CurrentSubKey = EnumKey($RegKey, $SubKeyCounter)		; get the next key
  Loop

  ; Have an array of all the NIC subkeys now... Gather some appropriate data on each
  Dim $NicData[UBound($NicArray)]

  $Index = 0
  Dim $WorkArray[14]
  For Each $SubKey In $NicArray
    ; Start by determining the Speed/Duplex value name
    $SubKeyCounter = 0
    $Name = ''
    $WorkRegKey = $RegKey + '\' + $SubKey + '\Ndi\Params'

    ; Enumerate all of the subkeys to locate the Speed/Duplex value name
    $CurrentSubKey = EnumKey($WorkRegKey, $SubKeyCounter)
    While @ERROR = 0 And $Name = ''
      $Key = ReadValue($WorkRegKey + '\' + $CurrentSubKey, 'ParamDesc')
      If InStr($Key, 'Duplex') Or InStr($Key, 'Connection Type')
        $Name = $CurrentSubKey					; Save the Key Name
      EndIf
      $SubKeyCounter = $SubKeyCounter + 1				; increment the enumeration index
      $CurrentSubKey = EnumKey($WorkRegKey, $SubKeyCounter)	; get the next key
    Loop	; enumerate subkeys

    ; Collect the data for this adapter
    $WorkArray[0] = ReadValue($RegKey + '\' + $SubKey, 'DriverDesc')			; Adapter Description
    $WorkArray[1] = ReadValue($RegKey + '\' + $SubKey, 'ProviderName')			; Manufacturer
    $WorkArray[2] = ReadValue($RegKey + '\' + $SubKey, 'NetCfgInstanceId')		; NIC GUID
    $WorkArray[3] = ReadValue($RegKey + '\' + $SubKey, $Name)				; Speed/Duplex value
    $WorkArray[4] = ReadValue($WorkRegKey + '\' + $Name + '\Enum', $WorkArray[3])	; Speed/Duplex text
    $WorkArray[5] = ReadValue($RegKey + '\' + $SubKey, 'DriverVersion')		; Driver Version

    $WorkRegKey = $Target + 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $WorkArray[2]
    $WorkArray[6] = ReadValue($WorkRegKey, 'EnableDHCP')				; DHCP boolean
    $Key = IIf($WorkArray[6] = 1, 'Dhcp', '')
    $WorkArray[7] = ReadStringValue($WorkRegKey, $Key + 'IPAddress') + ',' +
                    ReadStringValue($WorkRegKey, $Key + 'SubnetMask') + ',' +
                    ReadStringValue($WorkRegKey, $Key + 'DefaultGateway')		; IP settings
    $WorkArray[8] = ReadStringValue($WorkRegKey, $Key + 'Domain')			; Domain Name
    $WorkArray[9] = ReadStringValue($WorkRegKey, $Key + 'NameServer')			; DNS Server list

    ; handle an undefined speed/duplex setting
    If $WorkArray[4] = ''
      $WorkArray[4] = 'Undefined'
    EndIf	; undefined speed

    ; Special values for Compaq/HP Team
    If ReadValue($RegKey + '\' + $SubKey, 'Characteristics') = 32769
      $WorkArray[10] = 'HPTEAM'								; special flag
      $WorkArray[11] = ReadValue($RegKey + '\' + $SubKey, 'TeamAdapters')		; # of adapters in team
      $WorkArray[12] = ReadValue($RegKey + '\' + $SubKey, 'TeamInstances')		; ID of adapters in team
    EndIf

    $NicData[$Index] = $WorkArray
    $Index = $Index + 1

    ReDim $WorkArray[14]

  Next	; CurrentSubKey

  ; Return the array of arrays
  ReDim Preserve $NicData[$Index - 1]
  $NicInfo = $NicData

EndFunction
  
 
; Read a String_Multi_SZ val and return a space-delimited string
Function ReadStringValue($Key, $Val)
  $ReadStringValue = Trim(Join(Split(ReadValue($Key, $Val), '|'), ' '))
EndFunction

