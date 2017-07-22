################################################################
# Get SCCM views from the SCCM MS-SQL database
################################################################

$scriptPath = $PSScriptRoot

Set-Location -Path $scriptPath -PassThru

# Initialize logging

. "$scriptPath\ps_logger.ps1"

Write-Log( @"
=== Extracting SCCM Views from SCCM database ==============
"@
	) -logfile sccmlog

# Get some temporary file names
$tmp_file1 = [System.IO.Path]::GetRandomFileName()
$tmp_file2 = [System.IO.Path]::GetRandomFileName()
Write-Log "Temporary file names: $tmp_file1  $tmp_file2" -logfile sccmlog

# Extract the needed views

Write-Log "& $scriptPath\sccm_dump_view.ps1 `"v_GS_ADD_REMOVE_PROGRAMS_64`"" -logfile sccmlog

Write-Log "=== Starting to dump SCCM views" -logfile sccmlog

Invoke-Expression "& $scriptPath\sccm_dump_view.ps1 `"v_GS_ADD_REMOVE_PROGRAMS_64`""

Invoke-Expression "& $scriptPath\sccm_dump_view.ps1 `"v_GS_ADD_REMOVE_PROGRAMS`""

Invoke-Expression "& $scriptPath\sccm_dump_view.ps1 `"v_R_System`""

Write-Log "=== Finished dumping SCCM views. Renaming files" -logfile sccmlog


# Rename the two software inventory files

ren v_GS_ADD_REMOVE_PROGRAMS_64.csv $tmp_file1
ren v_GS_ADD_REMOVE_PROGRAMS.csv $tmp_file2

# Remove Microsoft-related data

Write-Log "=== Removing MS data from extracted views" -logfile sccmlog

sls -Notmatch -Pattern "\|\""microsoft" -Path $tmp_file1 |
	ForEach-Object {$_.Line} |
	Out-File "v_GS_ADD_REMOVE_PROGRAMS_64.csv"

Write-Log "=== Removing MS data from extracted views - continuing" -logfile sccmlog

sls -Notmatch -Pattern "\|\""microsoft" -Path $tmp_file2 |
	ForEach-Object {$_.Line} |
	Out-File "v_GS_ADD_REMOVE_PROGRAMS.csv"

Write-Log "=== Extraction terminated" -logfile sccmlog

Write-Log "=== Dump AD exclusion groups" -logfile sccmlog

Invoke-Expression "& $scriptPath\ad_groups.ps1"
Write-Log "=== Copy files to linux srv for further processing"

Invoke-Expression "& $scriptPath\sccm_scp.ps1"

Write-Log "=== Move CSV files to target directory" -logfile sccmlog

Move-Item -Path $scriptPath\*.csv -Destination $scriptPath\csv -force

dir $scriptPath\csv


Write-Log "=== eliminate temporary files to save space" -logfile sccmlog

rm $tmp_file1 -force -erroraction 'silentlycontinue'
rm $tmp_file2 -force -erroraction 'silentlycontinue'

dir
