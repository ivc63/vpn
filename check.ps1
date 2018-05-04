function Test-Port{   
<#     
.SYNOPSIS     
    Tests port on computer.   
     
.DESCRIPTION   
    Tests port on computer.  
      
.PARAMETER computer   
    Name of server to test the port connection on. 
       
.PARAMETER port   
    Port to test  
        
.PARAMETER tcp   
    Use tcp port  
       
.PARAMETER udp   
    Use udp port   
      
.PARAMETER UDPTimeOut  
    Sets a timeout for UDP port query. (In milliseconds, Default is 1000)   
       
.PARAMETER TCPTimeOut  
    Sets a timeout for TCP port query. (In milliseconds, Default is 1000) 
                  
.NOTES     
    Name: Test-Port.ps1   
    Author: Boe Prox   
    DateCreated: 18Aug2010    
    List of Ports: http://www.iana.org/assignments/port-numbers   
       
    To Do:   
        Add capability to run background jobs for each host to shorten the time to scan.          
.LINK     
    https://boeprox.wordpress.org  
      
.EXAMPLE     
    Test-Port -computer 'server' -port 80   
    Checks port 80 on server 'server' to see if it is listening   
     
.EXAMPLE     
    'server' | Test-Port -port 80   
    Checks port 80 on server 'server' to see if it is listening  
       
.EXAMPLE     
    Test-Port -computer @("server1","server2") -port 80   
    Checks port 80 on server1 and server2 to see if it is listening   
     
.EXAMPLE 
    Test-Port -comp dc1 -port 17 -udp -UDPtimeout 10000 
     
    Server   : dc1 
    Port     : 17 
    TypePort : UDP 
    Open     : True 
    Notes    : "My spelling is Wobbly.  It's good spelling but it Wobbles, and the letters 
            get in the wrong places." A. A. Milne (1882-1958) 
     
    Description 
    ----------- 
    Queries port 17 (qotd) on the UDP port and returns whether port is open or not 
        
.EXAMPLE     
    @("server1","server2") | Test-Port -port 80   
    Checks port 80 on server1 and server2 to see if it is listening   
       
.EXAMPLE     
    (Get-Content hosts.txt) | Test-Port -port 80   
    Checks port 80 on servers in host file to see if it is listening  
      
.EXAMPLE     
    Test-Port -computer (Get-Content hosts.txt) -port 80   
    Checks port 80 on servers in host file to see if it is listening  
         
.EXAMPLE     
    Test-Port -computer (Get-Content hosts.txt) -port @(1..59)   
    Checks a range of ports from 1-59 on all servers in the hosts.txt file       
             
#>    
[cmdletbinding(   
    DefaultParameterSetName = '',   
    ConfirmImpact = 'low'   
)]   
    Param(   
        [Parameter(   
            Mandatory = $True,   
            Position = 0,   
            ParameterSetName = '',   
            ValueFromPipeline = $True)]   
            [array]$computer,   
        [Parameter(   
            Position = 1,   
            Mandatory = $True,   
            ParameterSetName = '')]   
            [array]$port,   
        [Parameter(   
            Mandatory = $False,   
            ParameterSetName = '')]   
            [int]$TCPtimeout=1000,   
        [Parameter(   
            Mandatory = $False,   
            ParameterSetName = '')]   
            [int]$UDPtimeout=1000,              
        [Parameter(   
            Mandatory = $False,   
            ParameterSetName = '')]   
            [switch]$TCP,   
        [Parameter(   
            Mandatory = $False,   
            ParameterSetName = '')]   
            [switch]$UDP                                     
        )   
    Begin {   
        If (!$tcp -AND !$udp) {$tcp = $True}   
        #Typically you never do this, but in this case I felt it was for the benefit of the function   
        #as any errors will be noted in the output of the report           
        $ErrorActionPreference = "SilentlyContinue"   
        $report = @()   
    }   
    Process {      
        ForEach ($c in $computer) {   
            ForEach ($p in $port) {   
                If ($tcp) {     
                    #Create temporary holder    
                    $temp = "" | Select Server, Port, TypePort, Open, Notes   
                    #Create object for connecting to port on computer   
                    $tcpobject = new-Object system.Net.Sockets.TcpClient   
                    #Connect to remote machine's port                 
                    $connect = $tcpobject.BeginConnect($c,$p,$null,$null)   
                    #Configure a timeout before quitting   
                    $wait = $connect.AsyncWaitHandle.WaitOne($TCPtimeout,$false)   
                    #If timeout   
                    If(!$wait) {   
                        #Close connection   
                        $tcpobject.Close()   
                        Write-Verbose "Connection Timeout"   
                        #Build report   
                        $temp.Server = $c   
                        $temp.Port = $p   
                        $temp.TypePort = "TCP"   
                        $temp.Open = "False"   
                        $temp.Notes = "Connection to Port Timed Out"   
                    } Else {   
                        $error.Clear()   
                        $tcpobject.EndConnect($connect) | out-Null   
                        #If error   
                        If($error[0]){   
                            #Begin making error more readable in report   
                            [string]$string = ($error[0].exception).message   
                            $message = (($string.split(":")[1]).replace('"',"")).TrimStart()   
                            $failed = $true   
                        }   
                        #Close connection       
                        $tcpobject.Close()   
                        #If unable to query port to due failure   
                        If($failed){   
                            #Build report   
                            $temp.Server = $c   
                            $temp.Port = $p   
                            $temp.TypePort = "TCP"   
                            $temp.Open = "False"   
                            $temp.Notes = "$message"   
                        } Else{   
                            #Build report   
                            $temp.Server = $c   
                            $temp.Port = $p   
                            $temp.TypePort = "TCP"   
                            $temp.Open = "True"     
                            $temp.Notes = ""   
                        }   
                    }      
                    #Reset failed value   
                    $failed = $Null       
                    #Merge temp array with report               
                    $report += $temp   
                }       
                If ($udp) {   
                    #Create temporary holder    
                    $temp = "" | Select Server, Port, TypePort, Open, Notes                                      
                    #Create object for connecting to port on computer   
                    $udpobject = new-Object system.Net.Sockets.Udpclient 
                    #Set a timeout on receiving message  
                    $udpobject.client.ReceiveTimeout = $UDPTimeout  
                    #Connect to remote machine's port                 
                    Write-Verbose "Making UDP connection to remote server"  
                    $udpobject.Connect("$c",$p)  
                    #Sends a message to the host to which you have connected.  
                    Write-Verbose "Sending message to remote host"  
                    $a = new-object system.text.asciiencoding  
                    $byte = $a.GetBytes("$(Get-Date)")  
                    [void]$udpobject.Send($byte,$byte.length)  
                    #IPEndPoint object will allow us to read datagrams sent from any source.   
                    Write-Verbose "Creating remote endpoint"  
                    $remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any,0)  
                    Try {  
                        #Blocks until a message returns on this socket from a remote host.  
                        Write-Verbose "Waiting for message return"  
                        $receivebytes = $udpobject.Receive([ref]$remoteendpoint)  
                        [string]$returndata = $a.GetString($receivebytes) 
                        If ($returndata) { 
                           Write-Verbose "Connection Successful"   
                            #Build report   
                            $temp.Server = $c   
                            $temp.Port = $p   
                            $temp.TypePort = "UDP"   
                            $temp.Open = "True"   
                            $temp.Notes = $returndata    
                            $udpobject.close()    
                        }                        
                    } Catch {  
                        If ($Error[0].ToString() -match "\bRespond after a period of time\b") {  
                            #Close connection   
                            $udpobject.Close()   
                            #Make sure that the host is online and not a false positive that it is open  
                            If (Test-Connection -comp $c -count 1 -quiet) {  
                                Write-Verbose "Connection Open"   
                                #Build report   
                                $temp.Server = $c   
                                $temp.Port = $p   
                                $temp.TypePort = "UDP"   
                                $temp.Open = "True"   
                                $temp.Notes = ""  
                            } Else {  
                                <#  
                                It is possible that the host is not online or that the host is online,   
                                but ICMP is blocked by a firewall and this port is actually open.  
                                #>  
                                Write-Verbose "Host maybe unavailable"   
                                #Build report   
                                $temp.Server = $c   
                                $temp.Port = $p   
                                $temp.TypePort = "UDP"   
                                $temp.Open = "False"   
                                $temp.Notes = "Unable to verify if port is open or if host is unavailable."                                  
                            }                          
                        } ElseIf ($Error[0].ToString() -match "forcibly closed by the remote host" ) {  
                            #Close connection   
                            $udpobject.Close()   
                            Write-Verbose "Connection Timeout"   
                            #Build report   
                            $temp.Server = $c   
                            $temp.Port = $p   
                            $temp.TypePort = "UDP"   
                            $temp.Open = "False"   
                            $temp.Notes = "Connection to Port Timed Out"                          
                        } Else {                       
                            $udpobject.close()  
                        }  
                    }      
                    #Merge temp array with report               
                    $report += $temp   
                }                                   
            }   
        }                   
    }   
    End {   
        #Generate Report   
        $report  
    } 
}
###ОПРЕДЕЛЕНИЕ ПЕРЕМЕННЫХ
$ntp_srv = "0.ru.pool.ntp.org"
"Введите ip-адрес туннеля для проверки связи"
$tunnel_srv_ip = Read-Host
"Введите TCP-порт туннеля или нажмите Enter для icmp-проверки"
$tunnel_srv_port = Read-Host


"Пожалуйста подождите..."
###СЛУЖБА БРАНДМАУЭРА
$fw_service = Get-Service mpssvc
$fw_service_load = Get-WmiObject Win32_Service -Filter "name = 'mpssvc'" | select StartMode

###ДОПОЛНИТЕЛЬНОЕ ПО
$avp_soft = Get-Process |  where {$_.ProcessName -eq 'avp'}
$crypto_soft = Get-Process |  where {$_.ProcessName -eq 'PKIMonitor'}

###ПРОВЕРКА ВРЕМЕНИ
$date_local = (Get-Date).ToString('dd MMMM yyyyг.')
$time_local = (Get-Date).ToString('HH:mm')
$timezone_local = [TimeZoneInfo]::Local.DisplayName | %{ $_.Split(" ")[0]; }
$time_local_sync = (get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\W32Time\Parameters).Type

$time_ntp_tmp = w32tm /stripchart /computer:$ntp_srv /samples:3
[string]$time_ntp = $time_ntp_tmp[5]
$ntp_srv_status=$time_ntp.IndexOf("d:")
if ($ntp_srv_status -ne "-1")
{
$time_ntp = $time_ntp.Split(":")[4]
$time_ntp = $time_ntp.Split(".")[0]
[int]$time_ntp = $time_ntp.Substring(1.)
}
else {[int]$time_ntp = -1}

###ПРОВЕРКА IE

$IE_settings = Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
$IE_Proxy = $IE_settings.DefaultConnectionSettings[8]

###ПРОВЕРКА VPN
[string]$vpn_path = Get-Process | where {$_.ProcessName -eq 'monitor'} | Get-ChildItem

if ($vpn_path)
{
$vpn_path = $vpn_path -replace "\\Monitor.exe"
[string]$vpn_settings = Get-Content "$vpn_path\APN*.TXT" | select-string "0000 S S "
$vpn_srv_name = $vpn_settings.Substring(9,51)
$vpn_srv_name = $vpn_srv_name -replace "  "
$vpn_srv_id = $vpn_settings.Substring(60,9)
$vpn_srv_id2 = $vpn_settings.Substring(74,12)
[string]$ip_coord_vipnet = Get-Content "$vpn_path\fireaddr.doc" | Select-String -Pattern $vpn_srv_id |%{($_ -split "[ ]")[1]}
$vpn_srv_connect = Test-Connection $ip_coord_vipnet -count 2 -quiet -ErrorAction SilentlyContinue
}

###ПРОВЕРКА НАЛИЧИЯ ТУННЕЛЯ
$vpn_srv_tunnel1 = Get-Content "$vpn_path\ipliradr.do$" | Select-String -Pattern $vpn_srv_id2 | Select-String -Pattern " S:" | Select-String -NotMatch "-" |%{($_ -split "[ S:]")[4]}
$vpn_srv_tunnel2 = Get-Content "$vpn_path\ipliradr.do$" | Select-String -Pattern $vpn_srv_id2 | Select-String -Pattern " S:" | Select-String -Pattern "-" |%{($_ -split "[ S:]")[4]}
[string]$tunnel_srv_check1 = $vpn_srv_tunnel1 | Select-String -Pattern $tunnel_srv_ip
foreach ($temp in $vpn_srv_tunnel2)
{
$x= $temp.Split("-")[0]
$y= $temp.Split("-")[1]
[int]$a1= $x.Split(".")[0]
[int]$b1= $x.Split(".")[1]
[int]$c1= $x.Split(".")[2]
[int]$d1= $x.Split(".")[3]
[int]$a2= $y.Split(".")[0]
[int]$b2= $y.Split(".")[1]
[int]$c2= $y.Split(".")[2]
[int]$d2= $y.Split(".")[3]

$ip1= ($a1*16777216)+($b1*65536)+($c1*256)+($d1)
$ip2= ($a2*16777216)+($b2*65536)+($c2*256)+($d2)
if ($ip1 -le "184034057" -and $ip2 -ge "184034057"){$tunnel_srv_check2= $tunnel_srv_ip }
}
if ($tunnel_srv_check1 -eq "$tunnel_srv_ip" -or $tunnel_srv_check2 -eq "$tunnel_srv_ip") {$tunnel_srv_check= "$tunnel_srv_ip"}

###ПРОВЕРКА ТУННЕЛЯ
if ($tunnel_srv_check -eq "$tunnel_srv_ip" -and $vpn_srv_connect -eq "True")
    {
        $tunnel_srv_connect= Test-Port -computer $tunnel_srv_ip -port $tunnel_srv_port   
    }
###ВЫВОД РЕЗУЛЬТАТОВ
Write-Host "ПРОВЕРКА ВРЕМЕНИ И ДАТЫ" -BackgroundColor White -ForegroundColor black
"Дата        : " + $date_local
"Время       : " + $time_local
"Часовой пояс: " + $timezone_local
if ($time_ntp -lt "60") {Write-Host "Время на компьютере соответствует серверу $ntp_srv" -BackgroundColor Green -ForegroundColor Black}
if ($time_ntp -ge "60" -and $time_ntp -lt "3600") {Write-Host "Время на компьютере отличается от сервера $ntp_srv в пределах одного часа" -BackgroundColor Yellow -ForegroundColor Black}
if ($time_ntp -ge "3600" -and $time_ntp -lt "86400") {Write-Host "Время на компьютере отличается от сервера $ntp_srv более чем на один час" -BackgroundColor Red -ForegroundColor Black}
if ($time_ntp -ge "86400") {Write-Host "Дата на компьютере оличается от сервера $ntp_srv" -BackgroundColor Red -ForegroundColor Black}
if ($time_ntp -eq "-1") { Write-Host "Сервер времени $ntp_srv недоступен, проверьте дату и время вручную" -BackgroundColor Yellow -ForegroundColor Black}
if ($timezone_local -eq "(UTC+03:00)") {Write-Host "Часовой пояс установлен правильно" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "Часовой пояс установлен неправильно" -BackgroundColor Red -ForegroundColor Black}
if ($time_local_sync -eq "NoSync") {Write-Host "Синхронизация времени выключена" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "Синхронизация времени включена" -BackgroundColor Green -ForegroundColor Black}
""

Write-Host "ПРОВЕРКА БРАНДМАУЭРА" -BackgroundColor White -ForegroundColor black
if ($fw_service.Status -eq "Stopped") {Write-Host "Служба брандмауэра выключена" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "Служба брандмауэра включена" -BackgroundColor Red -ForegroundColor Black}
if ($fw_service_load.StartMode -eq "Disable") {Write-Host "Тип запуска службы брандмауэра - ОТКЛЮЧЕНО" -BackgroundColor Green -ForegroundColor Black} 
if ($fw_service_load.StartMode -eq "Manual") {Write-Host "Тип запуска службы брандмауэра - ВРУЧНУЮ" -BackgroundColor Yellow -ForegroundColor Black} else {Write-Host "Тип запуска службы брандмауэра - АВТО" -BackgroundColor Red -ForegroundColor Black}
""

Write-Host "ПРОВЕРКА ДОПОЛНИТЕЛЬНОГО ПО" -BackgroundColor White -ForegroundColor black
if ($avp_soft) {Write-Host "Антивирус Касперского установлен" -BackgroundColor Yellow -ForegroundColor black} else {Write-Host "Антивирус Касперского не установлен" -BackgroundColor Green -ForegroundColor black}
if ($crypto_soft) {Write-Host "СКЗИ КриптоПро установлено" -BackgroundColor Yellow -ForegroundColor black} else {Write-Host "СКЗИ КриптоПро не установлено" -BackgroundColor Green -ForegroundColor black}
""

Write-Host "ПРОВЕРКА ДОСТУПНОСТИ КООРДИНАТОРА" -BackgroundColor White -ForegroundColor black
if (!$vpn_path) {Write-Host "ПО ViPNet Client не установлено или не запущено" -BackgroundColor Red -ForegroundColor Black}
else
{
if ($vpn_srv_connect -eq "True") {Write-Host "Координатор" $vpn_srv_name $vpn_srv_ip "доступен" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "Координатор" $vpn_srv_name $vpn_srv_ip "недоступен" -BackgroundColor Red -ForegroundColor Black}
}
""

Write-Host "ПРОВЕРКА НАЛИЧИЯ ТУННЕЛЯ" -BackgroundColor White -ForegroundColor black
if (!$vpn_path) {Write-Host "Не удалось обнаружить запущенное или установленное ПО ViPNet Client" -BackgroundColor Red -ForegroundColor Black}
else
{
if ($tunnel_srv_check1 -eq "$tunnel_srv_ip" -or $tunnel_srv_check2 -eq "$tunnel_srv_ip") {Write-Host "Туннель " $tunnel_srv_ip "прописан" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "Туннель" $tunnel_srv_ip "отсутствует" -BackgroundColor Red -ForegroundColor Black}
}
""

Write-Host "ПРОВЕРКА НАСТРОЕК БРАУЗЕРА" -BackgroundColor White -ForegroundColor black
if ($IE_Proxy -eq "1") {Write-Host "Прокси-сервер в IE отключен" -BackgroundColor Green -ForegroundColor Black}
if ($IE_Proxy -eq "3") {Write-Host "Прокси-сервер в IE включен" -BackgroundColor Red -ForegroundColor Black}
if ($IE_Proxy -eq "5" -or $IE_Proxy -eq "9") {Write-Host "Автоопределение прокси-сервера в IE включено" -BackgroundColor Yellow -ForegroundColor Black}
if ($IE_Proxy -ne "1" -and $IE_Proxy -ne "3" -and $IE_Proxy -ne "5" -and $IE_Proxy -ne "9") {Write-Host "Настройки IE определить не удалось :(" -BackgroundColor Yellow -ForegroundColor Black}
""

Write-Host "ПРОВЕРКА СОДЕНИНЕНИЯ С ТУННЕЛЕМ" -BackgroundColor White -ForegroundColor black
if ($tunnel_srv_connect.Open -eq "True") {Write-Host "Туннель" $tunnel_srv_ip ":" $tunnel_srv_port "доступен" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "Туннель" $tunnel_srv_ip ":" $tunnel_srv_port "недоступен" -BackgroundColor Red -ForegroundColor Black}
