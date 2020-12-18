# Datto RMM :: FireEye Red Team Countermeasure Scanner
Build 23, 18th December 2020, (C) Copyright Datto, Inc.

## BACKSTORY

On the 8th of December, a group of security auditors and consultants within FireEye's internal "Red Team" were hacked by a sophisticated state actor. In the attack, tools used by Red Team to test vulnerabilities in systems being audited were exfiltrated.
Following the news of the hack, FireEye decided to release countermeasures to the public to help detect whether stolen Red Team code has been used by malicious actors to leverage attacks on their devices. 

Using FireEye's countermeasures, Datto is making available a script which scans a system for executables showing signatures associated with Red Team's code.

Presence of an infected file does not necessarily imply a successful attack; if a device is properly patched, Red Team's tools are of limited effectiveness. FireEye have provided a list of CVEs to patch against in order to guarantee protection against their exploits.
The list is: https://github.com/fireeye/red_team_tool_countermeasures/blob/master/CVEs_red_team_tools.md

## TECHNICAL INFORMATION

This script was originally developed for use with the Datto RMM product. It has been released for other RMM vendors to distribute to their partners via their own script distribution methods.

It uses the YARA scanning tool by VirusTotal alongside a YARA definition set from FireEye to scan executable files on Windows systems for signs of code known to FireEye to belong to their Red Team toolset.
It is written in and compatible with PowerShell versions 2.0 onward (Windows 7 ships with PowerShell 2.0).
**YARA Requires the Microsoft Visual C++ Redistributable.** The script uses either the 32- or 64-bit build according to the capabilities of the system, so install the 64-bit redistributable on 64-bit systems.

The files "yara32.exe", "yara64.exe" and "all-yara.yar" must be attached to the script. They are invoked from the same directory as the location of the script file.
The file "buildXX.ps1", where XX is a number, is the script in question.

The script expects an environmental variable to be mapped at $env:usrScanScope. This variable should have a value of 1 to 4, (ideally) with the partner able to select which option. "1" only scans executables running in memory at execution time. "2" scans executables present on the Home Drive (usually C:\); "3" scans executables on all fixed and removable drives. "4" scans executables on ALL accessible drives.

Option 1 should conclude within ten minutes. Expect options 2-4 to take upwards of an hour depending on the amount of data present.

If you edit this script, please preserve the credits for Datto RMM and the author (seagull).

## OUTPUT

The script can produce up to two files, both in the same relative directory as the script file. 
The first, **log.txt**, details every file that has been scanned along with any errors encountered during the scanning process. This is always produced.
The second, **detections.txt**, is only made if a detection is recognised.

The script will exit with code 1 in two scenarios:
1) The VC++ Redistributable wasn't located on the device. Note that 64-bit devices will use the 64-bit binary which requires the 64-bit redistributable.
2) A detection has been found. The text "! DETECTION:" will appear in the logfile; the 'detections.txt' file noted above will also be created.

## CHANGELOG

* Build 1-15: ProCo builds produced to demonstrate basic functionality. Not made available for public download.
* Build 20: 16th Dec. Initial build.
* Build 22: 17th Dec. Fixed an issue where the Visual C++ redistributable would not be correctly checked for.
* Build 23: 18th Dec. Added functionality to log detections to separate detections.txt file. Nothing else has changed; results from build 22 are still valid.

## CREDITS

This script was written by seagull for Datto RMM. The Component was written for the Datto RMM ComStore.
YARA is a project by VirusTotal. The "yara-COPYING.txt" file is included at their request. GitHub: https://github.com/VirusTotal/yara/
The YARA definitions were released by FireEye. GitHub: https://github.com/fireeye/red_team_tool_countermeasures

Datto RMM: https://www.datto.com/rmm