# XDR_Investigations  -  June 2025 release
If you would like to demonstrate XDR actual Threat Hunting capabilities, this is for you!
This windows batch file will create a security event that can be used to investigate a specific SANS reported threat

Scenario:
Cisco XDR has a browser plug in that can parse observables from a html page, deliberate immediate dispositions and run a one-click investigation to see if any owned assets have made a connection. This can show how fast XDR detects and what an XDR Investigation looks like when there is a positive hit.

Prior to the demo:
Run this file on a Windows OS from admin command line (it will pause at the end to see results)
This batch file will:
1) Elevate privileges without prompt
2) Make a directory called c:\test
3) copy powershell to that directory
4) start browser session to a benign location within the research
5) attempts a http web-request to download a non-existing malicious file from a blocked IP
6) attempts to invoke mimikatz from a non-existent github repository
7) cleans itself up by removing the C:\test directory
8) optionally removing the security logs


Demo:
Install the XDR Ribbon plug-in into your browser
Naviage to the latest research on this threat
    Use SANS:  https://isc.sans.edu/diary/vBulletin+Exploits+CVE202548827+CVE202548828/32006
Launch the XDR Ribbon browser plug-in
Locate: "Find Observables on Page" button and scrape the page of observables
Select all of the observables and run an investigation

If the batch file was previously ran, you will see a connection from the host you ran the file on along with any other integrated associations. You can pivot on the host and see the full incident.

For issues or questions, contact Darryl Hicks:  darhicks@cisco.com
