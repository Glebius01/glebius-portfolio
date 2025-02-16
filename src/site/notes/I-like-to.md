---
{"dg-publish":true,"permalink":"/i-like-to/"}
---


1. I started from investigating the source files. We have .vmem which indicates that it is obtained from a Virtual Machine. Besides, we have KAPE output thus we have MFT.

2. I parcelled MFT using MFTCmd and then opened it with TimeLine Explorer. The first question is to find ASPX web shell, I filtered files' extension to .aspx and the first file in the output had missing 0x30 ($Filename information) timestamp which indicates that it was likely uploaded from a different host.

3. To find the attackers IP address I had to find Microsoft Internet Information Service, open it with a text editor and find the uploaded file. Also, there are a lot of signs of network enumeration conducted by the threat actor. It's worth noting that I've tried to find the IP address initially by multiplying the file's entry number by 1024 and converting it to hex, then looking for this offset number in the MFT hex dump (using HxD). Also, by running `Get-Item (file path) -Stream *` and `Get-Content`

4. I continued investigating IIS logs and indicators of compromise for the exploit. I found one of them (machine2.aspx) in the logs and User Agent in the lines below.

5. Using Timeline explorer at first found file's entry number and then investigated its timestamps using MFTECmd (especially $FILE_NAME or 0x30 information) to identify the time when the script was uploaded. `.\MFTECmd -f 'C:\Users\glebas\Desktop\$MFT' --de 1293` ![Pasted image 20250210105019.png](/img/user/Pasted%20Images/Pasted%20image%2020250210105019.png)

6. Filtered MFT entries to display the same day when 'move.aspx' was uploaded. The next entry is another malicious file 'moveit.asp' and it has file size specified in the entry.

7. Numerous attempts of port enumeration using nmap can be seen in IIS and DMZ_FTP log files

8. Using EvtxECmd converted directory with Windows event logs (included logs IDs related to password change 4723, 4724... etc) into a CSV file, opened it with Timeline Explorer and found there service account password attempt.

9. To identify internet protocol the adversary used to connect, I had to re-process evtx logs once again including all the events this time (with the thought of the future usage). Then, I filtered events 4624 that identify successful connections and using logon type 10 is typically mark of RDP connection.

10. Timestamp can be found in previous question.

11. I installed MySQL server and workbench to analyse moveit.sql file and found the ID among the entries. You shall look for attacker's nickname.

12. The user agent can be found in IIS logs, in particular near malicious files with GET or POST requests.

13. I found new password by conducting strings analysis of vmem file and with the search for "net user 'moveitsvc' " because password follows it

14. To find a header I used command `strings "C:\Users\glebas\Desktop\I-like-to-27a787c5.vmem" | Select-String "move.aspx" -Context 20, 20` -- it allows to see 20 lines above and below from the target line (move.aspx) in this case