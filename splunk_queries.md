# BLUELIGHT Detection Queries — Splunk SPL
**Malware:** BLUELIGHT (S0657) | **Actor:** APT37  
**Platform:** Windows | **Log Sources:** Sysmon + Windows Event Logs

---

## T1189 — Drive-by Compromise (Initial Access)
**Objective:** Detect iexplore.exe connecting to non-Microsoft domains
```spl
index=sysmon EventCode=3 
Image="*iexplore.exe" 
NOT DestinationHostname IN ("*.microsoft.com","*.windows.com","*.bing.com")
| stats count by DestinationHostname, SourceIp
```

---

## T1203 — Exploitation for Client Execution
**Objective:** Detect iexplore.exe spawning suspicious child processes
```spl
index=sysmon EventCode=1 
ParentImage="*iexplore.exe" 
Image IN ("*cmd.exe","*powershell.exe","*wscript.exe","*mshta.exe")
| table _time, ParentImage, Image, CommandLine, User
```

---

## T1027 — Obfuscated Files or Information
**Objective:** Detect obfuscated script execution from browser processes
```spl
index=wineventlog EventCode=4688 
NewProcessName IN ("*powershell.exe","*wscript.exe","*iexplore.exe")
CommandLine IN ("*FromBase64String*","*SVG*","*XOR*","*char*")
| table _time, NewProcessName, CommandLine, SubjectUserName
```

---

## T1071.001 — C2 via Microsoft Graph API
**Objective:** Detect non-standard processes connecting to Graph API
```spl
index=sysmon EventCode=3 
DestinationHostname IN ("graph.microsoft.com","login.microsoftonline.com")
NOT Image IN ("*onedrive.exe","*teams.exe","*outlook.exe","*msedge.exe")
| stats count by Image, DestinationHostname, DestinationPort
```

---

## T1082 — System Information Discovery
**Objective:** Detect WMI system enumeration from browser child processes
```spl
index=sysmon EventCode=1
Image IN ("*wmic.exe","*powershell.exe")
CommandLine IN ("*Win32_ComputerSystem*","*Win32_OperatingSystem*","*Win32_Processor*")
ParentImage IN ("*iexplore.exe","*wscript.exe")
| table _time, Image, CommandLine, ParentImage
```

---

## T1012 — Query Registry
**Objective:** Detect registry enumeration targeting AV/software keys
```spl
index=sysmon EventCode=13
TargetObject IN (
"*\\CurrentVersion\\Uninstall*",
"*\\CurrentControlSet\\Services*",
"*SecurityCenter2*"
)
NOT Image IN ("*MsMpEng.exe","*svchost.exe","*TrustedInstaller.exe")
| table _time, Image, TargetObject, User
```

---

## T1083 — File and Directory Discovery
**Objective:** Detect recursive directory enumeration from suspicious parents
```spl
index=sysmon EventCode=1
Image IN ("*cmd.exe","*powershell.exe")
CommandLine IN ("*dir *","*tree *","*Get-ChildItem*","*ls *")
ParentImage IN ("*iexplore.exe","*wscript.exe","*powershell.exe")
| table _time, Image, CommandLine, ParentImage, User
```

---

## T1113 — Screen Capture
**Objective:** Detect periodic .jpg creation by non-image processes
```spl
index=sysmon EventCode=11
TargetFilename="*.jpg"
NOT Image IN ("*chrome.exe","*msedge.exe","*Photos.exe","*SnippingTool.exe")
| bucket _time span=1m
| stats count by _time, Image, TargetFilename
| where count > 3
```

---

## T1555.003 — Credentials from Web Browsers
**Objective:** Detect non-browser process accessing browser memory
```spl
index=sysmon EventCode=10
TargetImage IN ("*chrome.exe","*msedge.exe","*iexplore.exe","*firefox.exe")
NOT SourceImage IN ("*chrome.exe","*msedge.exe","*iexplore.exe","*firefox.exe")
GrantedAccess="0x1fffff"
| table _time, SourceImage, TargetImage, GrantedAccess, User
```

---

## T1105 — Ingress Tool Transfer
**Objective:** Detect executable dropped from OneDrive then launched
```spl
index=sysmon EventCode=11
TargetFilename IN ("*\\Temp\\*.exe","*\\AppData\\*.exe","*\\Temp\\*.dll")
| join Image 
    [search index=sysmon EventCode=3 
     DestinationHostname="graph.microsoft.com"]
| table _time, Image, TargetFilename, DestinationHostname
```

---

## T1567.002 — Exfiltration Over OneDrive
**Objective:** Detect large uploads to Graph API from non-OneDrive processes
```spl
index=sysmon EventCode=3
DestinationHostname="graph.microsoft.com"
NOT Image IN ("*onedrive.exe","*teams.exe","*outlook.exe")
| stats sum(bytes_out) as TotalUpload by Image, SourceIp
| where TotalUpload > 5000000
| sort - TotalUpload
```

---

## Notes
- All queries written in **Splunk SPL**
- Tested against **Sysmon v15+** and **Windows Event Log**
- Mutable fields (paths, thresholds) should be tuned per environment
- Run in **Audit mode** first to baseline false positives
