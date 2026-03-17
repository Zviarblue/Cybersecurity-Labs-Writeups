ShadowRoast

Platform: CyberDefenders

Difficulty: Medium

Category: Threat Hunting

Scenario: As a cybersecurity analyst at TechSecure Corp, you have been alerted to unusual activities within the company's Active Directory environment. Initial reports suggest unauthorized access and possible privilege escalation attempts.
Your task is to analyze the provided logs to uncover the attack's extent and identify the malicious actions taken by the attacker. Your investigation will be crucial in mitigating the threat and securing the network.

## Tools Used

- Splunk
- Event Log Explorer

## Investigation Methodology

### Question 1: What's the malicious file name utilized by the attacker for initial access?

We search for the specific filename of the malicious file that the attacker used to gain access. We search first for the field a creation or modification events logs (Sysmon ID 1) and between the 3 machines we aim first for the Office to check because its the most probable to be used, after we search for the event data image where we can see command line so we check for cmd and powershell (for our case its "winlog.event_data.Image"="*cmd*" OR "winlog.event_data.Image"="*powershell*")

our final filter is : index=shadowroast AND "event.code"=1 AND "winlog.computer_name"="Office-PC.CORPNET.local" AND ("winlog.event_data.Image"="*cmd*" OR "winlog.event_data.Image"="*powershell*")

<img width="1517" height="830" alt="2026-03-16_15-53" src="https://github.com/user-attachments/assets/652a42e5-8da6-47fb-9bb7-ff0dca8ae5cd" />

We see a suspicious process, the AdobeUpdater from sanderson and there a powershell proccesses under it

**Answer:** AdobeUpdater.exe

---

### Question 2: What's the registry run key name created by the attacker for maintaining persistence?

For this question we use the event id 13 to the change in registry and after some research i used another filter to check in the paths who are related to persistance, which is Run
so our filtre used for this question is : index=shadowroast AND "event.code"=13 AND "winlog.computer_name"="Office-PC.CORPNET.local" AND winlog.event_data.TargetObject=*Run*

<img width="1098" height="337" alt="image" src="https://github.com/user-attachments/assets/4d271561-bc45-4ab2-b062-d73ef92f2a98" />

We see only one entry for this filter and checking in we see that the entry is tied to our malicious file with the key name.

**Answer:** wyW5PZyF

---

### Question 3: What's the full path of the directory used by the attacker for storing his dropped tools?

for this question we return a bit on the question 1 where we check the processID of the entry where we saw the powershell process tied to our AdobeUpdater.exe and we have the ID 4780 which help to make our filter with
so our filter for this case will be : index="shadowroast" AND event.code=1 AND winlog.computer_name=Office-PC.CORPNET.local AND (winlog.event_data.ProcessId=4780 OR winlog.event_data.ParentProcessId=4780)

<img width="1366" height="628" alt="image" src="https://github.com/user-attachments/assets/0ca6774a-ea71-4674-bcfb-be33ee903fcc" />

We got 2 entry, one is irrevelant but the other one we can see that we get a mimikatz in it which a it a tools used by hackers so we see where the attacker store his tools in.

**Answer:** C:\Users\Default\AppData\Local\Temp\

---

### Question 4: What tool was used by the attacker for privilege escalation and credential harvesting?

this questions and the other 2 next are tied but for we found the path where the tools are stocked in the previous question so we will research everything tied from this one.
our filter will be : index="shadowroast" AND event.code=1 AND winlog.computer_name=Office-PC.CORPNET.local AND "winlog.event_data.CurrentDirectory"="C:\\Users\\Default\\AppData\\Local\\Temp\\" (double \\ because of the syntax apparently)

<img width="1244" height="543" alt="image" src="https://github.com/user-attachments/assets/c3f7633f-3cb2-4594-9e0b-0c0be06455fc" />

We found two different tools on the result, first one is the mimikatz and the other like on the screen est Rubeus where he's hiding under the name BackupUtility.exe 
Rubeus was used to perform an AS-REP Roasting attack, a technique targeting accounts with Kerberos pre-authentication disabled to extract hashes that can be cracked offline.
After executing Rubeus, the attacker was seen executing Mimikatz (Under the name of “DefragTool.exe”) revealing a different parent user, confirming a second compromised user, CORPNET\tcooper. This is in addition to the earlier identified account, CORPNET\sanderson

**Answer:** Rubeus

---

### Question 5: Was the attacker's credential harvesting successful? If so, can you provide the compromised domain account username?

We answered in the previous question so the compromised account is tcooper

**Answer:** tcooper

---

### Question 6: What's the tool used by the attacker for registering a rogue Domain Controller to manipulate Active Directory data?

for this one i used a bit of the writeup but with mimikatz we can make a attack technique called DCShadow and for that the event code number to detect a active directory schema changes we use 4929

our filter for this one will be  index="shadowroast" AND event.code=4929

<img width="1260" height="639" alt="image" src="https://github.com/user-attachments/assets/dc594418-cb09-4559-91af-80e44581b378" />

This log confirm the use of mimikatz for the attack.

**Answer:** mimikatz

---

### Question 7: What's the first command used by the attacker for enabling RDP on remote machines for lateral movement?

On google we can find that the registry value for enabling the RDP is fDenyTSConnection and it need to be set to 0 to enable it.

so our filter for this one will be: index="shadowroast" AND event.code=1 AND winlog.event_data.CommandLine=*fDenyTSConnections*

<img width="1619" height="828" alt="image" src="https://github.com/user-attachments/assets/f26c85ff-9d56-46a5-975c-baca623c5ccb" />

From the result of the filter we can see that it was executed on the DC01 and fileserver probably for a lateral movement.

**Answer:** reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0

---

### Question 8: What's the file name created by the attacker after compressing confidential files?

For this one because it aim for file we will search first for the FileServer in the filter (beside the DC01) and because files got compressed we search for the extension like zip, 7z or rar 
our filter will be : index="shadowroast" AND winlog.computer_name=FileServer.CORPNET.local AND event.code=11 AND (winlog.event_data.TargetFilename=*.zip OR winlog.event_data.TargetFilename=*.7z OR winlog.event_data.TargetFilename=*.rar)

event code 11 is for the file creation events

<img width="973" height="470" alt="image" src="https://github.com/user-attachments/assets/2509568e-138b-4377-9d17-1a27393fc502" />

In the log we see the name of the compressed file which is CrashDump.zip

**Answer:** CrashDump.zip

---

## Lessons Learned

- Search of the attacks (like DCshadow)
- analyse of log 

--- 

## References

- [Link to challenge](https://cyberdefenders.org/blueteam-ctf-challenges/shadowroast/)

---

**Completion Date**: 16/03/2026 
**Time Spent**: 2 hours
