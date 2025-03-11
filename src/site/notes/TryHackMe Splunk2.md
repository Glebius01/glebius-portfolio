---
{"dg-publish":true,"permalink":"/try-hack-me-splunk2/"}
---

### Scenario:
In this exercise, you assume the persona of Alice Bluebird, the analyst who successfully assisted Wayne Enterprises and was recommended to Grace Hoppy at Frothly (_a beer company_) to assist them with their recent issues.
### Walkthrough:
#### 100-series questions

Search the botsv2 index and return a listing of all the source types that can be found as well as a count of events and the first time and last time seen.

| metadata type=sourcetypes index=botsv2 | eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S") | eval lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S") | eval recentTime=strftime(recentTime,"%Y-%m-%d %H:%M:%S") | sort - totalCount

Amber Turing was hoping for Frothly to be acquired by a potential competitor which fell through, but visited their website to find contact information for their executive team. What is the website domain that she visited?

index="botsv2" sourcetype="stream:http" src_ip="10.0.2.101" 
| dedup site
| table site, _time

Answer: www.berkbeer.com

Amber found the executive contact information and sent him an email. What image file displayed the executive's contact information? Answer example: /path/image.ext

index="botsv2" sourcetype="stream:http" src_ip="10.0.2.101"  site="www.berkbeer.com" | table uri_path

Answer: /images/ceoberk.png

For the next query I had to find Amber's email first:

	index="botsv2" sourcetype="stream:smtp" "Amber"

After that the query for the next questions remained the same:

	index="botsv2" sourcetype="stream:smtp" "aturing@froth.ly" "*berkbeer*"

What is the CEO's name? Provide the first and last name.

I found response email from mbrek@berkbeer.com, and looked through content field within a SMTP-type event.

Answer: Martin Berk

What is the CEO's email address?

Simply look for outbounds emails from Amber Turing, there are few options.

Answer: mberk@berkbeer.com

After the initial contact with the CEO, Amber contacted another employee at this competitor. What is that employee's email address?

Incoming email from the competitor's domain. Also, can be verified by reading content field.

Answer: hbernhard@berkbeer.com

What is the name of the file attachment that Amber sent to a contact at the competitor?

The document was attached to one of the emails (attachment field).

Answer: Saccharomyces_cerevisiae_patent.docx

What is Amber's personal email address?

While investigating contents of the email exchange I have come across base64 encoded plain text. I was able to decode it easily using an online tool.

![Pasted image 20250303093556.png](/img/user/Pasted%20image%2020250303093556.png)

Answer: ambersthebest@yeastiebeastie.com

#### 200-series questions

What version of TOR Browser did Amber install to obfuscate her web browsing? Answer guidance: Numeric with one or more delimiter.

I used a hint query (to search for key words like "Amber" and "Tor"). Then, I added event code 1 - creation of a new process. It narrowed down number of events from 300 to 4. I was able to see the answer in the parent command line.

	index="botsv2" "Amber" "Tor" EventCode=1 | reverse

![Pasted image 20250303100553.png](/img/user/Pasted%20image%2020250303100553.png)

Answer: 7.0.4

What is the public IPv4 address of the server running www.brewertalk.com?

I used number of digits and destination headers as a hint.

Answer: 52.42.208.228

 
Provide the IP address of the system used to run a web vulnerability scan against www.brewertalk.com.

If we type in www.brewertalk.com and look at user agents, *Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; w3af.org)* has the largest amount of queries. Googling also showed that w3af.org is an open source application used for web vulnerability scanning

Its source IP is the answer: 45.77.65.211

The IP address from Q#2 is also being used by a likely different piece of software to attack a URI path. What is the URI path? Answer guidance: Include the leading forward slash in your answer. Do not include the query string or other parts of the URI. Answer example: /phpinfo.php

AND

What SQL function is being abused on the URI path from the previous question?

This question confused me in the beginning by saying "IP address from Q2 is also being used by another malware to attack..." but IP address from Q2 is public IPv4 address of www.brewertalk.com. I supposed source IP address from Q3 was meant.

	index="botsv2" src_ip=45.77.65.211

The query narrows search to about 18,000 entries. The URI path "/member.php" has the largest count, and we know that previously TA conducted enumeration. If we select this path, it decreases amount of events to 662. Then, we can find the answer by reviewing and Googling functions in *form_data* field.

SQL function *updatexml* appeared to be in the most events on the first page, and it is the answer. 
![Pasted image 20250308170103.png](/img/user/Pasted%20image%2020250308170103.png)

What was the value of the cookie that Kevin's browser transmitted to the malicious URL as part of an XSS attack? Answer guidance: All digits. Not the cookie name or symbols like an equal sign.

	index="botsv2" kevin sourcetype="stream:http"
	<script>"

Answer: 1502408189

AND

What brewertalk.com username was maliciously created by a spear phishing attack?

Answer: kiagerfield

![Pasted image 20250309193857.png](/img/user/Pasted%20image%2020250309193857.png)

#### 300 series questions

Mallory's critical PowerPoint presentation on her MacBook gets encrypted by ransomware on August 18. What is the name of this file after it was encrypted?