## get connection status 
$connectionstatus = Get-WmiObject win32_networkadapter -Filter "netconnectionid = 'Ethernet 4'" | select netconnectionstatus -ExpandProperty netconnectionstatus| Out-String

## if the connection status is 7 or 4 then disable the nic and renable it. 

if ($connectionstatus -eq 7 or $connectionstatus -eq 4){
	Disable-NetAdapter -Name "Ethernet 4" -Confirm:$false
	Start-Sleep -s 5
	Enable-NetAdapter -Name "Ethernet 4" -Confirm:$false
}else{
	exit
	
}