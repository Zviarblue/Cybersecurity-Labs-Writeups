QBot
Challenge Information
Platform: CyberDefenders
Difficulty: Medium
Category: Endpoint Forensics
Scenario: A company's security team detected unusual network activity linked to a potential malware infection. As a forensic analyst, your mission is to investigate a memory dump, identify the malicious process, extract artifacts, and uncover Command and Control (C2) communications. Using Volatility3, analyze the attack, trace its origin, and provide actionable intelligence.


## Tools Used

- Votality3

## Investigation Methodology

### Question 1: Our first step is identifying the initial point of contact the malware made with an external server. Can you specify the first IP address the malware attempted to communicate with?

We see via a netscan on the dump that there a connection on a port 80 (http) who are closed that give us the hint that it's the IP the malware contacted.

<img width="1267" height="357" alt="2026-02-12_16-15" src="https://github.com/user-attachments/assets/f6f6458e-5806-4877-86e7-ddcce580e560" />

**Answer:** `94.140.112.73`

---

### Question 2: We need to determine if the malware attempted to communicate with another IP. Which IP address did the malware attempt to communicate with again?


**Answer:** ``

---

### Question 3: Identifying the process responsible for this suspicious behavior helps reconstruct the sequence of events leading to the execution of the malware and its source. What is the name of the process that initiated the malware?


**Answer:** ``

---

### Question 4: The malware's file name is crucial for further forensic analysis and extracting the malware. Can you provide its file name?


**Answer:** ``

---

### Question 5: Hashes are like digital fingerprints for files. Once the hash is known, it can be used to scan other systems within the network to identify if the same malicious file exists elsewhere. What is the SHA256 hash of the malware?


**Answer:** ``

---

### Question 6: To trace the origin of the malware and understand its development timeline, can you provide the UTC creation time of the malware file?

**Answer:** ``

---

## Lessons Learned

- 

## References

- [[Link to challenge]](https://cyberdefenders.org/blueteam-ctf-challenges/qbot/)

---

**Completion Date**: ../../2026 
**Time Spent**: 2 hours
