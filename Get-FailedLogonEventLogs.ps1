param(
	$UserName
)

function global:Get-DomainController {       
	[CmdletBinding()]            
	Param (
		[String]$Domain,
		[Switch]$CurrentForest 
	)#End Param

	Begin {            			   
	}#Begin          
	Process {
		if ($CurrentForest -or $Domain) {
			try{
				$Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()    
			}
			catch {
				"Cannot connect to current forest."
			}
			if ($Domain) {
				# User specified domain OR Match
				$Forest.domains | Where-Object {$_.Name -eq $Domain} | 
					ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name}
			}
			else {
				# All domains in forest
				$Forest.domains | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name}
			}
		}
		else {
			# Current domain only
			[system.directoryservices.activedirectory.domain]::GetCurrentDomain() |
				ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name}
		}

	}#Process
	End
	{
	}#End
}

$DomainControllers = Get-DomainController

Function Get-AccountEvents
{
	param(
		[string[]]$ServerList,
		[string]$UserName
	)
	
	# Workflows: https://technet.microsoft.com/en-us/library/JJ574194.aspx
	
	ForEach ( $server in $serverList ) {
		if ( test-connection $server -quiet ) {
			Write-Verbose "Checking $server"
			
			# Instance IDs in Event Log
			# 		https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4771
			# 4625: An account failed to log on
			# 4738: A user account was changed
			# 4740: A user account was locked out
			# 4767: A user account was unlocked
			# 4771: Kerberos pre-authentication failed
			# 4776: The domain controller attempted to validate the credentials for an account
			$InstanceIDs = @(4625,4771,4738,4767,4776,4740)
			$Events = Get-EventLog -Logname Security -After (Get-Date).Date -message "*$UserName*" -Computername $server -InstanceID $InstanceIDs -newest 10 # -PSCredential $Credentials
			
			# $StartTime = (Get-Date).Date
			# $StartTimeMiliseconds = New-TimeSpan $StartTime | Select-Object -ExpandProperty TotalMilliseconds
			# $xpathfilter = [string]::Format("*/System[EventID=4625 or EventID=4771 or EventID=4738 or EventID=4767 or EventID=4776 or EventID=4740] and */System/TimeCreated[timediff(@SystemTime) <= {0}] and EventData[Data[@Name='TargetUserName']='{1}']]" , $StartTimeMiliseconds,$UserName)
			# $Events = Get-WinEvent -PSComputerName $server -LogName "Security" -FilterXPath $xpathfilter
			
		} else {
			Write-Verbose "Could not communicate to $server"
		}
		
		ForEach ( $event in $Events ) {
			$EventMessage = $event.Message
			switch ( [int]($event.InstanceID) ) {
				4625 {
					$SourceAccountInfo = ($EventMessage -Split("Target Account:"))[0]
					$SourceAccountInfo = $SourceAccountInfo -Split("`n") | ? { $_ -match "Account Name" }
					$SourceAccount = $SourceAccountInfo.Split(":")[1].Trim()
					# $retEvent.SourceAccount = $SourceAccount #($event.Message -Split("Target Account:"))[0].Split("`n") | ? { $_ -match "Account Name" } | % { $_.Split(":")[1].Trim()  }
					
					$TargetAccountInfo = ($EventMessage -Split("Target Account:"))[1]
					$TargetAccountInfo = $TargetAccountInfo -Split("`n") | ? { $_ -match "Account Name" }
					$TargetAccount = $TargetAccountInfo.Split(":")[1].Trim()
					# $retEvent.Account = $TargetAccount # ($EventMessage -Split("Target Account:"))[1].Split("`n") | ? { $_ -match "Account Name" } | % { $_.Split(":")[1].Trim() }
					
					$SourceLine =  $EventMessage -Split("`n") | ? { $_ -match "Source Workstation" }
					$Source = $SourceLine.Split(":")[1].Trim()
					# $retEvent.Source = $Source # $EventMessage.Split("`n") | ? { $_ -match "Source Workstation" } | % { $_.Split(":")[1].Trim() }
					
					$ChangedAttrs = $EventMessage -Split("Changed Attributes:")[1]
					$ChangedAttrs = $ChangedAttrs -Split("Additional Information:").Trim().Split("`n",[System.StringSplitOptions]::RemoveEmptyEntries)
					$ChangedAttrs = $ChangedAttrs | ? { $_ -Split(":")[1].Trim() -ne "-" }
					$Message = $event.Message -Split("`n")[0]
					$Message = "$Message`nChanged Attributes:`n"
					$Message = "$Message `n$ChangedAttrs"
					# $retEvent.Message = $Message
					$retEvent = New-Object -type PSObject -Prop @{
						Computer = $server
						EventID = $event.EventID
						Time = $event.TimeGenerated
						SourceAccount = $SourceAccount
						Account = $TargetAccount
						Source = $Source
						Message = $Message
					}
				}
				4738 {
				
					$retEvent = New-Object -type PSObject -Prop @{
						Computer = $server
						EventID = $event.EventID
						Time = $event.TimeGenerated
						SourceAccount = ""
						Account = ""
						Source = ""
						Message = $event.Message
					}
				}
				4740 {
					
					$retEvent = New-Object -type PSObject -Prop @{
						Computer = $server
						EventID = $event.EventID
						Time = $event.TimeGenerated
						SourceAccount = ""
						Account = ""
						Source = ""
						Message = $event.Message
					}
				}
				4767 {
					
					$retEvent = New-Object -type PSObject -Prop @{
						Computer = $server
						EventID = $event.EventID
						Time = $event.TimeGenerated
						SourceAccount = ""
						Account = ""
						Source = ""
						Message = $event.Message
					}
				}
				4771 {
					
					$retEvent = New-Object -type PSObject -Prop @{
						Computer = $server
						EventID = $event.EventID
						Time = $event.TimeGenerated
						SourceAccount = ""
						Account = ""
						Source = ""
						Message = $event.Message
					}
				}
				4776 {
					if ( $_.EntryType -eq "SuccessAudit" ) {
						
					} else {
						# Event ID 680
						# 0xC000006A	An incorrect password was supplied.
						# 0xC000006F	The account is not allowed to log on at this time.
						# 0xC0000064	The account does not exist.
						# 0xC0000070	The account is not allowed to log on from this computer.
						# 0xC0000071	The password has expired.
						# 0xC0000072	The account is disabled.
						$Account = $EventMessage -Split("`n") | ? { $_ -match "Logon Account" } | % { $_.Split(":")[1].Trim() }
						$Source = $EventMessage -Split("`n") | ? { $_ -match "Source Workstation" } | % { $_.Split(":")[1].Trim() }
						$Message = $EventMessage -Split("`n")[0]
						
						$retEvent = New-Object -type PSObject -Prop @{
							Computer = $server
							EventID = $event.EventID
							Time = $event.TimeGenerated
							SourceAccount = $SourceAccount
							Account = $TargetAccount
							Source = $Source
							Message = $Message
						}
					}
				}
			}
			Write-Output $retEvent
		}
	}
}


$Events = Get-AccountEvents -ServerList $DomainControllers -UserName $UserName -Verbose
$Events
