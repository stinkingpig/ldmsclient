' Run netstat and dump the output into a LANDesk custom data form.
' Jack Coates, jack@monkeynoodle.org
' version 0.5, initial implementation

' run netstat
Set objShell = CreateObject("WScript.Shell")
Set objExec = objShell.Exec("netstat -an")
strResults = LCase(objExec.StdOut.ReadAll)
' arrange results

' write ldcustom.dat
set fso = wscript.createobject("scripting.filesystemobject")
Set fh = fso.opentextfile("foo.txt",2,True)
fh.writeline strResults
fh.close
