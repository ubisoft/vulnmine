################################################################
# Dump a "view" from SCCM MS-SQL database
################################################################

# Input parameters
param(
		[Parameter(Position=1)]
		[string]$myview="",
		[switch]$h
		)

$scriptPath = $PSScriptRoot

Set-Location -Path $scriptPath -PassThru

# Initialize logging

. "$scriptPath\ps_logger.ps1"

Write-Log " " -logfile sccmlog

if ($h -or !$myview.CompareTo("")) {
	Write-Log( @"
	Usage:
		myview	View to dump to csv file with header column names
"@
	) -logfile sccmlog
exit
}
Else {
	Write-Log( @"
	Processing view: $myview
"@
	) -logfile sccmlog
}


# Global variables

$BCP_EXPORT_SERVER = "<my_production_sccm_server>"
$BCP_EXPORT_DB = "<my_production_sccm_database>"
$tmp_table1 = [System.IO.Path]::GetTempFileName()
$tmp_table2 = [System.IO.Path]::GetTempFileName()


# Remember current working directory
$mydir = Convert-Path .

# setup some convenience variables to keep each line shorter
$path = [System.IO.Path]::Combine($mydir,"$myview.csv")
$mode = [System.IO.FileMode]::Create
$access = [System.IO.FileAccess]::Write
$sharing = [IO.FileShare]::Read

# create the FileStream and StreamWriter objects
try {
    $fs = New-Object IO.FileStream($path, $mode, $access, $sharing)
    }
catch {
    # let's get some more information about the error
    Write-Log $_  -logfile sccmlog
    $_.GetType().FullName              # the type of $_ is 'System.Management.Automation.ErrorRecord'
    $_.Exception
    $_.Exception.GetType().FullName    # the exception type name is 'System.IO.FileNotFoundException'
    $_.Exception.Message               # the exception message
    throw "*** Error opening file ***"
    }
$sw = New-Object System.IO.StreamWriter($fs,
            [System.Text.Encoding]::Unicode)

# Find the column names for the view being exported as a CSV file

#Invoke-Expression "bcp `"DECLARE @colnames VARCHAR(max);SELECT @colnames = COALESCE(@colnames + ',', '') + name from $BCP_EXPORT_DB.sys.columns where object_id = OBJECT_ID('dbo.$myview'); select @colnames;`"  queryout $tmp_table1 -w -T -S $BCP_EXPORT_SERVER"

Invoke-Expression "bcp `"DECLARE @colnames VARCHAR(max);SELECT @colnames = COALESCE(@colnames + ',', '') + column_name from $BCP_EXPORT_DB.INFORMATION_SCHEMA.columns where TABLE_NAME = '$myview'; select @colnames;`"  queryout $tmp_table1 -w -T -S $BCP_EXPORT_SERVER"


# All the fields need to be quoted. This is because of some data in SCCM.
# Idem output needs to be unicode. Some chinese characters in data.
# Idem separator "|" since SCCM has distinguished names with embedded commas

# Here we quote all the field names

$line = Get-Content "$tmp_table1"
$tokens = $line.split(",")
$quotedline = 'x'
foreach ($token in $tokens) {
	If ($quotedline.CompareTo('x')) {
		$quotedline = "$quotedline`"|`"$token"
		}
	Else {
		$quotedline = "`"$token"
		}
	}

# Add on the last '"' at the end
$quotedline = "$quotedline`""

# and then write out the finished header line of quoted column names
$sw.WriteLine($quotedline)


# Now dump the view into a temporary CSV file
# Add "most" of the quoting / separators that are needed

# We build a SELECT dynamically in order to ensure that columns are dumped in the same order as in the CSV Header line
Invoke-Expression "bcp `"SELECT $line FROM $BCP_EXPORT_DB.dbo.$myview`" queryout $tmp_table2 -w -t'\`"|\`"' -T -S $BCP_EXPORT_SERVER"


# Read the temporary file
# Add beginning / ending quotes (which are missing in the bcp raw output)
# Get rid of the pesky NUL characters as well
# Concatenate all this to the output csv file


foreach ($line in [System.IO.File]::ReadLines($tmp_table2)) {
    $line = "`"$line`""-replace("`0","")
    # $line = "`"$line`""
    $sw.WriteLine($line)
    }

# Get rid of the temporary work file and close the output file

$sw.Dispose()
$fs.Dispose()
rm $tmp_table1 -force -erroraction 'silentlycontinue'
rm $tmp_table2 -force -erroraction 'silentlycontinue'




