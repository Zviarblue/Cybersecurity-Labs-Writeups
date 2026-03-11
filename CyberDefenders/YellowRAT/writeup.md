YellowRAT

Platform: CyberDefenders

Difficulty: Easy
Category: Threat Intel
Scenario: During a regular IT security check at GlobalTech Industries, abnormal network traffic was detected from multiple workstations. Upon initial investigation, it was discovered that certain employees' search queries were being redirected to unfamiliar websites. This discovery raised concerns and prompted a more thorough investigation. Your task is to investigate this incident and gather as much information as possible.

## Tools Used

- VirusTotal

## Investigation Methodology

### Question 1: Understanding the adversary helps defend against attacks. What is the name of the malware family that causes abnormal network traffic?

This challenge gave us file hash of a malware so we can start by searching it on VirusTotal which we can see that popular threat label of this file is not match the answer format at all but at least we know that this is Jupyter Infostealer.

<img width="1846" height="1117" alt="2026-03-11_16-32" src="https://github.com/user-attachments/assets/1beff97a-9095-4013-9522-edf0bfba6655" />

And we could go to “Community” tab to find out the answer since there are so many community comments on this file.

<img width="763" height="170" alt="2026-03-11_16-32_12" src="https://github.com/user-attachments/assets/40629763-0a36-48e5-9fa1-23cd56a03413" />

After scrolling for a bit, now we got the name and also reference links to do our own research.

---

### Question 2: As part of our incident response, knowing common filenames the malware uses can help scan other workstations for potential infection. What is the common filename associated with the malware discovered on our workstations?

<img width="2185" height="297" alt="2026-03-11_16-33" src="https://github.com/user-attachments/assets/6d9db11e-3930-40d9-94df-97c9a4836641" />

We can see that the Name itself is the answer for the question.

---

### Question 3: Determining the compilation timestamp of malware can reveal insights into its development and deployment timeline. What is the compilation timestamp of the malware that infected our network?

<img width="1534" height="420" alt="2026-03-11_16-50" src="https://github.com/user-attachments/assets/d35576d5-dd60-4eae-8b9b-5547159c8dee" />

Under the "Details tab" scroll down a little bit, you will se a section named as Portable Executable Info
When you carefully look at the details under this section you will see a sub-heading Header, under this section you will see Compilation time. 

---

### Question 4: Understanding when the broader cybersecurity community first identified the malware could help determine how long the malware might have been in the environment before detection. When was the malware first submitted to VirusTotal?

<img width="2178" height="428" alt="2026-03-11_16-33_1" src="https://github.com/user-attachments/assets/20819887-b568-469f-9c59-a9d112929260" />

Under the "Details tab" scroll down a little bit, you will see a sub-heading History, under this section you will see First Submission. Under First Submission details pane you will see date and time there. 

---

### Question 5: To completely eradicate the threat from Industries' systems, we need to identify all components dropped by the malware. What is the name of the .dat file that the malware dropped in the AppData folder?

<img width="897" height="688" alt="2026-03-11_16-44" src="https://github.com/user-attachments/assets/6ec9676c-6f09-45e9-bc87-932ff97a1696" />

We still have threat intel report from Red Canary (https://redcanary.com/blog/yellow-cockatoo/) that already conducted malware analysis for us and here is the file that dropped in Appdata folder. 

---

### Question 6: It is crucial to identify the C2 servers with which the malware communicates to block its communication and prevent further data exfiltration. What is the C2 server that the malware is communicating with?

<img width="954" height="620" alt="2026-03-11_16-44_1" src="https://github.com/user-attachments/assets/eb88eec1-47f6-4e89-b1d5-04c3aea2c49e" />

Red Canary also noted C2 url for their audience to add them to blacklist so we can use this as the answer of this question too!

---

## References

- [[Link to challenge]]((https://cyberdefenders.org/blueteam-ctf-challenges/yellow-rat/))

---

**Completion Date**: 24/12/2025
