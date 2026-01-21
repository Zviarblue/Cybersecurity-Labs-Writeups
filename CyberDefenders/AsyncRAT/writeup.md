AsyncRAT
Challenge Information
Platform: CyberDefenders
Difficulty: Medium
Category: Malware Analysis
Scenario: You are a cybersecurity analyst at Globex Corp. A concerning report has come in: an employee opened an email with an attachment claiming to be an order specification, which actually harbored a JavaScript file designed to deploy AsyncRAT. This malware evades detection with alarming efficiency. To secure Globex's network and data, you must analyze the attachment, reverse-engineer the AsyncRAT’s obfuscation techniques, and determine the scope of AsyncRAT's infiltration.

![test](screenshot/test.png)

## Tools Used

- [deobfuscate](https://obf-io.deobfuscate.io/)
- [Cyberchef](https://gchq.github.io/CyberChef/)
- Tool 3

## Investigation Methodology

### Question 1: In the process of dissecting the AsyncRAT payload, you discover a variable in the PowerShell script shrouded in complexity. What is the name of this variable that conceals the malicious obfuscated code?

**Answer:** `[Your answer]`

---

### Question 2: As you trace the AsyncRAT’s steps, you come across a pivotal moment where it reaches out to the internet, fetching the next phase of its invasion. Identify the URL used to download the second stage of this malicious campaign.

**Answer:** `[Your answer]`

---

### Question 3: Within the chaos of encoded data retrieved during your investigation, there's a string that signals the beginning of the encoded code. What is this marker indicating where the encoded treasure lies within the downloaded file?

**Answer:** `[Your answer]`---

### Question 4: The second stage of AsyncRAT has been meticulously unpacked, revealing an extracted Portable Executable (PE). To understand this stage's uniqueness, what is the MD5 hash of this extracted PE?

**Answer:** `[Your answer]`

---

### Question 5: AsyncRAT seeks to embed itself within the system for long-term espionage. During your sweep, you stumble upon a registry key intended for persistence. Can you provide the full path of this registry key where the malware attempts to solidify its presence?

**Answer:** `[Your answer]`

---

### Question 6: Your analysis doesn't stop at the second stage; the malware has more secrets to unveil. A third stage is downloaded from a URL you need to uncover. What is the URL from which the malware downloads the third stage?

**Answer:** `[Your answer]`

---

### Question 7: With the third stage of AsyncRAT now in focus, another Portable Executable (PE) comes to light. For a comprehensive understanding of this stage, what is the MD5 hash of the extracted PE from the third stage?

**Answer:** `[Your answer]`

## Lessons Learned

- Key takeaway 1
- Key takeaway 2
- Skills developed or reinforced

## References

- [[Link to challenge]](https://cyberdefenders.org/blueteam-ctf-challenges/asyncrat/)

---

**Completion Date**: 21/01/2026 
**Time Spent**: 2 hours
