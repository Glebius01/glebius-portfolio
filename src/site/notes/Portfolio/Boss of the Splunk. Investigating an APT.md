---
{"dg-publish":true,"permalink":"/portfolio/boss-of-the-splunk-investigating-an-apt/"}
---

#### Finding the IP Scanning Your Web Server

1. Determining the sourcetypes to search provides a nice starting point for nearly every search created. Identify sourcetypes associated with the website: `index=botsv1 imreallynotbatman.com | stats count by sourcetype` 

2.  Find all source address. Note that we are running this search with the time picker set to All time. If we are doing an investigation in our production environment, it is ideal from a performance and volume of data perspective to focus on a smaller time frame, but for the purpose of this investigation with a small data set we are going to leave the time set to All time: `index=botsv1 imreallynotbatman.com | stats count by src | eventstats sum(count) as perc | eval percentage=round(count*100/perc,2) | fields - perc | sort - count`

3. Since we are investigating potential IP scanning we should select *stream:http data* to filter out unrelated IPs. We can achieve this simply by adding `sourcetype="stream:http"`  to the previous query. One of the IPs has 94.4% of logs, which invokes our interest. We can validate the answer by examining *suricata logs*, namely the *signature* field.

#### Identifying The Web Vulnerability Scanner

1. There is acunetix_wvs_security test among the first entries in the search. Googling shows that this is automatic vulnerability scanner for web applications by Invicti. `index=botsv1 imreallynotbatman.com sourcetype="stream:http" src=40.80.148.42 | stats count by http_user_agent`

#### Determining Which Web Server is the Target
1. `index="botsv1" sourcetype="stream:http" src_ip=40.80.148.42` and investigating top 10 URI field values. This query can be modified by adding `status=200` to show only successful loads, `stats count by uri` to see what value are most frequently seen. `sort - count` to display the most frequent first.

#### Identifying Where a Brute Force Attack Originated
1. First we need to narrow our search, we can do it by taking into account: the target IP, brute force attacks usually push some information to the server using 'POST' http method request, form_data field may contain username and password key fields. Having made changes, we can get such query: `index=botsv1 sourcetype=stream:http dest="192.168.250.70" http_method=POST form_data=*username*passwd* | stats count by src  

	Side note - The form_data field contains information being passed from the client browser to the web server. If we search the form_data, we can use wildcards to look for values that contain the strings “username" and "passwd” within the field. This could be a very expensive search done at scale which is why it is important to set the index= and the time picker to narrow the amount of data to be searched.

#### Identifying the First Password Attempted in a Brute Force Attack
2. `index=botsv1 sourcetype="stream:http" dest="192.168.250.70" http_method=POST form_data=*username*passwd* | stats count by _time, form_data | sort _time asc | head 10`. 
3. The password itself can be extracted using `| rex field=form_data "passwd=(?<userpassword>\w+)"`. Alternative to sort asc - reverse, and to stats count is table.
### Identifying the Password Used To Gain Access
4. `index=botsv1 sourcetype="stream:http" dest="192.168.250.70" http_method=POST form_data=*username*passwd* dest_headers!="*Connection: close*"  | rex field=form_data "passwd=(?<userpassword>\w+)" | table dest_headers, userpassword, src`
   
5. Another way to do it, is to stats count all the used passwords and sort them -- the password which has been used twice, was most likely successful. Please note **value(src)** which is used to search for more than 1 value in the field.

	`index=botsv1 sourcetype="stream:http" dest="192.168.250.70" http_method=POST form_data=*username*passwd*` 
	`| rex field=form_data "passwd=(?<userpassword>\w+)"` 
	`| stats count values(src) by userpassword`
	`| sort - count`
### Determining The Elapsed Time Between Events
`index=botsv1 sourcetype=stream:http`
`| rex field=form_data "passwd=(?<userpassword>\w+)"` 
`| search userpassword=batman` 
`| transaction userpassword` 
`| table duration`

### Identifying the Executable Uploaded
Starting with stream:http, we know the destination is the web server and we know its IP address. If we add the string `"*.exe"` to our search, we can narrow our search and then look into the part_filename{} field and see 2 filenames referenced; one exe and one php file. Note that we don't yet know the field name hrtr, but Splunk's full text search capabilities will find the file extension regardless of what field it is in.

Each logs have their own values in the fields, for example dest=imreallynotbatman and dest_ip=192.168.250.70, thus AND/OR statements, and parenthesis might be required.

To identify initially we can use:

`index=botsv1 sourcetype=stream:http dest="192.168.250.70" *.exe`

`index=botsv1 sourcetype=suricata dest_ip=192.168.250.70 .exe`

`index=botsv1 sourcetype=suricata dest_ip="192.168.250.70" http.http_method=POST .exe`

### Determining the Hash of the Uploaded File

Use Sysmon logs as they provide information about hashes. Filter out by event description to see only process execution/creation, then filter by command line to ensure that exactly 3791.exe is run.

`index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="3791.exe" | rex field=Hashes "MD5=(?<MD5_hash>\w+)" | stats values(MD5_hash)`

### Identifying the File that Defaced Our Web Server

We can look at the connections to external IP addresses originating from our server. If there are any, it is already unusual. Then we can analyse each of these connection and pivot into URL fields to get more details. 

`index=botsv1 src=192.168.250.70 sourcetype=suricata`

### Identifying the FQDN of the System that Defaced The Web Server

Find the malicious file and check URL field. Additionally, we can confirm findings by investigating other source types with the malicious file. Alternatively, utilise DNS logs and targeted IP to see. 

`index=botsv1 "/poisonivy-is-coming-for-you-batman.jpeg"` 

