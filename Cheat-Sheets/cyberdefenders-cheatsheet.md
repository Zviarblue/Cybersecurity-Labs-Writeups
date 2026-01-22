# Cyberdefenders-cheatsheet

What used or learned on labs via finding or writeup (about tools mostly)

### Tools
```bash
Navigate on eventLog (sysmon) : Event Log Explorer (used event 1) on .evtx
Used Registry explorer to find malicious GPO ( SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0 )

for asyncRAT : used https://obf-io.deobfuscate.io/ to deobfuscate the code and after used the ChromeConsole and put the code in it and behind use the console.log( "var strings") 



```
### Sigma rules (from Sigma 101 Lab)

```
Lets get two different sigma rules for example in the future (use the eventLog details to get the name for the selection in detection)

title: 'Suspicious Deletion of Powershell CLM Registry Key'                                                                    //  The title of the rule. When the rule is triggered, this will be shown.
id: '8b4c7671-178d-4f6d-b36f-3d165c2967ef'                                                                                     // The unique ID for this rule. You can create one yourself at https://www.uuidgenerator.net/version4
status: 'experimental'                                                                                                         // The status of the rule. Options are stable, test, experimental, deprecatedunsupported
description: 'Detects the removal of an important registry key in regards to Powershell defensive measures'                    // Description of the rule (why does this rule exist and what does it do)
author: 'ZviarBlue'                                                                                                            // Name and/or credentials of whoever wrote this rule
date: 22-01-2026
modified: 22-01-2026
tags:
    - attack.defense_evasion                                                                                                   // Used to map different frameworks to the Sigma rule
    - attack.t1112
logsource:
    category: file_event                                                                                                       // Where the rule is scoped to (a.k.a. where is it looking for detection?)
    product: windows
detection:                                                                                                                     // What the rule is trying to detect
    selection:
        EventType: 'DeleteValue'
        TargetObject|contains: "PSLockdownPolicy"
        Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    condition: selection
falsepositives:                                                                                                                // List of possible false positives that may occur by this rule
    - "None"
level: high                                                                                                                    // Criticality of the rule. Options are informational, low, medium, high and critical

title: 'Suspicious Powershell execution via WScript.exe'
id: 'e5ba9e35-6e5c-498c-a999-cd3a238cc18e'
status: 'experimental'
description: 'Detects the execution of Powershell commands via Wscript.exe, when invoked by Explorer.exe'
author: 'ZviarBlue'
date: 22-01-2026
modified: 22-01-2026
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: 'C:\Windows\explorer.exe'
        Image: 'C:\Windows\System32\wscript.exe'
        CommandLine|contains: "powershell -exec bypass -c"
    condition: selection
falsepositives: 
    - "May detect legitimate Powershell processes"
level: high


```

