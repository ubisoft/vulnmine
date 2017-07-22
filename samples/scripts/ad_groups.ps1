######
#	Dump a key AD group relevant for the SCCM analysis / stats
######

Import-Module ActiveDirectory

Get-ADGroupMember -Identity "CN=<my_super_duper_AD_group>,OU=Software,OU=SCCM,DC=mycorp,DC=com" -Recursive | 	Export-Csv -Path "my_super_duper_AD_group.csv" -Encoding Unicode


######
#	Dump AD user data
######


# Get-ADUser -Filter 'Name -like "Tom Somebody"' -Properties "AccountExpirationDate", `

Get-ADUser -Filter * -Properties "AccountExpirationDate", `
"accountExpires", `
"AccountLockoutTime", `
"AccountNotDelegated", `
"AllowReversiblePasswordEncryption", `
"c", `
"CannotChangePassword", `
"CanonicalName", `
"City", `
"CN", `
"co", `
"Company", `
"Country", `
"countryCode", `
"Created", `
"createTimeStamp", `
"Department", `
"Description", `
"directReports", `
"DisplayName", `
"DistinguishedName", `
"Division", `
"EmailAddress", `
"EmployeeID", `
"EmployeeNumber", `
"employeeType", `
"Enabled", `
"extensionAttribute2", `
"extensionAttribute3", `
"extensionAttribute4", `
"extensionAttribute5", `
"extensionAttribute9", `
"Fax", `
"GivenName", `
"HomeDirectory", `
"HomedirRequired", `
"HomeDrive", `
"homeMDB", `
"HomePage", `
"HomePhone", `
"Initials", `
"l", `
"LastBadPasswordAttempt", `
"lastLogon", `
"LastLogonDate", `
"lastLogonTimestamp", `
"legacyExchangeDN", `
"LockedOut", `
"lockoutTime", `
"logonCount", `
"LogonWorkstations", `
"mail", `
"mailNickname", `
"managedObjects", `
"Manager", `
"mDBUseDefaults", `
"mobile", `
"MobilePhone", `
"Modified", `
"modifyTimeStamp", `
"Name", `
"Office", `
"OfficePhone", `
"OtherName", `
"PasswordExpired", `
"PasswordLastSet", `
"PasswordNeverExpires", `
"PasswordNotRequired", `
"physicalDeliveryOfficeName", `
"POBox", `
"PostalCode", `
"PrimaryGroup", `
"primaryGroupID", `
"ProtectedFromAccidentalDeletion", `
"proxyAddresses", `
"pwdLastSet", `
"SamAccountName", `
"ScriptPath", `
"SID", `
"SmartcardLogonRequired", `
"sn", `
"st", `
"State", `
"StreetAddress", `
"Surname", `
"telephoneNumber", `
"Title", `
"userAccountControl", `
"UserPrincipalName", `
"uSNChanged", `
"uSNCreated", `
"whenChanged", `
"whenCreated" `
| Export-Csv `
-Path ps-users-ad.csv -Encoding UTF8 -NoTypeInformation
