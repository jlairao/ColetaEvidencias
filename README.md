# ColetaEvidencias
List of evidences for Windows Servers activation

Script developed in Powershell to collect evidence in text mode to attach to the SCoAD questionnaire.

The Script collects information about:

Hotfix installed
System Information (systeminfo)
Security Policy (SecPol)

How to use this script

1 - Find a Windows Server that meets the following minimum requirements:

- Windows Server 2008 R2 or higher.

- Powershell Version 4 or higher.

2 - Create the C:\IBM_Support\PS directory.

3 - Copy the Coleta-Evidencias.ps1 file script to the previously created directory.

4 - Open Powershell ISE as Administrator and open the file C:\IBM_Support\PS\Coleta-Evidencias.ps1.

5 - Create and populate the SERVERS.TXT file with the host name of the servers you want to collect information from. (Do not use this script to collect information from the server where the script is running!).

6 - Execute the script .\Coleta-Evidencias.ps1.

7 - The result will be a .ZIP file in the format HOSTNAME-Evidences-Intel.ZIP saved in the directory C: \IBM_Support\PS.

8 - Important: The user account must have an administrator profile (domain) to collect information on the servers remotely.
