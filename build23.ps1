<#fireEye red team vuln scanner :: build 23/seagull (Datto RMM) :: user variables: usrScanScope
provided for other RMMs for the good of the community :: preserve all seagull and Datto RMM credits#>

#scanning function

function doScan {
    param ([parameter(mandatory=$false,ValueFromPipeline=$true)]$list)
    process {
        #catch both type-1 and alternative use-cases
        if ($env:usrScanScope -eq 1) {$file=$list.Path} else {$file=$list.FullName}

        #add it to the logfile, with a pause for handling
        try {
            Add-Content "log.txt" -Value $file -ErrorAction Stop
        } catch {
            Start-Sleep -Seconds 1
            Add-Content "log.txt" -Value $file -ErrorAction SilentlyContinue
        }

        #scan it
        clear-variable yaResult -ErrorAction SilentlyContinue
        $yaResult=cmd /c "yara$varch.exe `"all-yara.yar`" `"$file`" -s"
        if ($yaResult) {
            #sound an alarm
            write-host "====================================================="
            $script:varDetection=1
            write-host "! DETECTION:"
            write-host $yaResult
            #write to a file
            if (!(test-path "detections.txt" -ErrorAction SilentlyContinue)) {set-content -path "detections.txt" -Value "! FILES DETECTED !"}
            Add-Content "detections.txt" -Value $yaResult
        }
    }
}

write-host "FireEye Red Team Countermeasures (by Datto)"
write-host "====================================================="

[string]$varch=[intPtr]::Size*8
$script:varDetection=0

#check to make sure yara will run on the host device
cmd /c "yara$varch.exe -v >nul 2>&1"
$varExit=$LASTEXITCODE
if ($varExit -ne 0) {
    write-host "! ERROR: YARA was unable to run on this device."
    write-host "  The Visual C++ Redistributable is required in order to use YARA."
    if ($env:CS_CC_HOST) {
        write-host "  An installer Component is available from the ComStore."
    }
    exit 1
}

#make a logfile

% {$host.ui.WriteErrorLine("Output may be truncated; results are stored in $PWD\log.txt.")}
% {$host.ui.WriteErrorLine("=====================================================")}
set-content -Path "log.txt" -Force -Value "Files scanned:"
Add-Content "log.txt" -Value "====================================================="

#check the files are there

if (!(test-path yara32.exe -ErrorAction SilentlyContinue) -or !(test-path yara64.exe -ErrorAction SilentlyContinue) -or !(test-path all-yara.yar -ErrorAction SilentlyContinue)) {
    write-host "! ERROR: YARA binary files were not found attached to Component."
    write-host "  Execution cannot continue."
    exit 1
}

#input variable "usrScanScope": 1: memory / 2: home drive / 3: all fixed/remov drives / 4: all accessible drives

if ($env:usrScanScope -eq 2) {
    write-host "- Scan scope: All EXEs present on home drive (Intensive)."
    get-childitem -Path $env:HOMEDRIVE\* -Force -Recurse -include *.exe -ErrorAction SilentlyContinue | select FullName | ? {$_.FullName} | doScan
} elseif ($env:usrScanScope -eq 3) {
    write-host "- Scan scope: All EXEs present on ALL fixed or removable drives (Very intensive)."
    Get-WmiObject -Class Win32_logicaldisk | ? {$_.DriveType -eq 2 -or $_.DriveType -eq 3} | ? {$_.FreeSpace} | % {
        get-childitem -Path "$($_.DeviceID)\*" -Force -Recurse -include *.exe -ErrorAction SilentlyContinue | select FullName | ? {$_.FullName} | doScan
    }
} elseif ($env:usrScanScope -eq 4) {
    write-host "- Scan scope: All EXEs present on ALL drives of all types (Most intensive)."
    Get-WmiObject -Class Win32_logicaldisk | ? {$_.FreeSpace} | % {
        get-childitem -Path "$($_.DeviceID)\*" -Force -Recurse -include *.exe -ErrorAction SilentlyContinue | select FullName | ? {$_.FullName} | doScan
    }
} else {
    write-host "- Scan scope: All EXEs running in memory (Default)."
    get-process | select -unique | select Path | ? {$_.Path} | doScan
}

if ($script:varDetection -eq 1) {
    write-host "====================================================="
    write-host "! Files containing FireEye exploit code have been found on the system."
    write-host "  These files are noted above and locally on the device as detections.txt."
} else {
    write-host "- No files matching FireEye exploit code were found on the system."
}

#close out

write-host "- Scan completed."
write-host "  A list of all scanned files has been written to the StdErr stream."

write-host "- Ensure devices are up-to-date with the CVE mitigation list:"
write-host '  https://github.com/fireeye/red_team_tool_countermeasures/blob/master/CVEs_red_team_tools.md'

get-content log.txt | % {$host.ui.WriteErrorLine($_)}

exit $script:varDetection