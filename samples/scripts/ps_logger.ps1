################################################################
# Powershell simplistic logging function
# cf http://stackoverflow.com/questions/7834656/create-log-file-in-powershell
################################################################

Function Write-Log {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]
    $Message,

    [Parameter(Mandatory=$False)]
    [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
    [String]
    $Level = "INFO",

    [Parameter(Mandatory=$False)]
    [string]
    $logfile
    )

    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp $Level $Message"
    If($logfile) {
        Add-Content $logfile -Value $Line
    }
    Else {
        Write-Output $Line
    }
}
