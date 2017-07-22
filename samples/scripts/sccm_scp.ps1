################################################################
# Copy extracted files to linux server for processing
################################################################

$scriptPath = $PSScriptRoot

Set-Location -Path $scriptPath -PassThru

# Initialize logging

. "$scriptPath\ps_logger.ps1"

Write-Log "=== Delete old files if any on linux host" -logfile sccmlog

ssh -o "StrictHostKeyChecking no" -i <my_ssh_key> sccm_uid@<my_floating_ip> 'rm /var/deploy/csv/v_*csv && rm /var/deploy/csv/ps*csv'

Write-Log "=== Copy new extracted data to linux host" -logfile sccmlog

scp -B -o "StrictHostKeyChecking no" -i $scriptPath/keys/sshkey_win_161107 *csv sccm_uid@10.130.64.196:/var/deploy/csv

ssh -o "StrictHostKeyChecking no" -i $scriptPath/keys/sshkey_win_161107 sccm_uid@10.130.64.196 'chmod 664 /var/deploy/csv/v_*csv && chmod 664 /var/deploy/csv/ps*csv'

Write-Log "=== Copy to linux host completed" -logfile sccmlog

