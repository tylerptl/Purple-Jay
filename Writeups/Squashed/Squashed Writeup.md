# Overview
Squashed is a linux machine running an outdated service that leaks data and doesnt enforce authentication. Access to this service can be leveraged to upload malicious code to the victim to carry out remote code execution. Upon successful persistence to the victim, insecure file permissions & privileges can be exploited to impersonate more privileged users eventually resulting in root access.

## Recommended tools
- [feroxbuster](https://github.com/epi052/feroxbuster) : any directory buster will do (gobuster, dirb, dirbuster, etc.)
- nmap: A network scanner installed by default on kali. Can be used to identify running service, gather information on hosts, fingerprint services, and much more.
- metasploit: An exploit framework installed by default on kali. Can be used to enumerate, scan, and exploit targets.

## OWASP Threats
- [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [A06:2021 – Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)


# Initial Enumeration
```nmap
PORT      STATE SERVICE  REASON  VERSION
22/tcp    open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp    open  http     syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Built Better
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp   open  rpcbind  syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      35894/udp   mountd
|   100005  1,2,3      44295/tcp   mountd
|   100005  1,2,3      45929/tcp6  mountd
|   100005  1,2,3      47995/udp6  mountd
|   100021  1,3,4      34387/tcp   nlockmgr
|   100021  1,3,4      37278/udp   nlockmgr
|   100021  1,3,4      44467/tcp6  nlockmgr
|   100021  1,3,4      48263/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  syn-ack 3 (RPC #100227)
34387/tcp open  nlockmgr syn-ack 1-4 (RPC #100021)
35005/tcp open  mountd   syn-ack 1-3 (RPC #100005)
37997/tcp open  mountd   syn-ack 1-3 (RPC #100005)
44295/tcp open  mountd   syn-ack 1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

- Basic nmap enumeration reveals SSH (22), HTTP (80), RPC (111), and NFS (2049) all running on default ports. Other open ports appear to link back to RPC.

# Initial Exploitation


## Enumerating Apache
- Navigating to the apache web server reveals a pretty standard website with no interesting code in the source content (CTRL+U), nor any hidden directories discovered with `feroxbuster`
- ![[Pasted image 20230222150213.png]]
- ![[Pasted image 20230223094443.png]]
- Given the lack of quick wins, or unique directories, move on to the next service.
- **Tip:** At this point you could hit the server with `nikto` to detect any vulnerabilities/misconfigurations, but it wont return anything of use. It is the de-facto web server vulnerability scanner, but its scope its often so broad that no meaningful data is returned - far better to use more precise tools for a given environment even if that means using more. 

## Enumerating NFS
- Through the nmap scan, we also know that a Network File System (NFS) is running on the default port. We have two easy ways of detecting shares hosted by the NFS that can be mounted.
	- `showmount -e $IP`
	- Or using metasploit (which also has many other submodules that could be used for further enum)
		- For the `auxiliary/scanner/nfs/nfsmount ` module shown below, we only need to set the IP - all other options are not required.
	- ![[Pasted image 20230223093752.png]]
- This reveals two directories that we can mount. 
	- `/home/ross`
	- `/var/www/html`
	- **Note:** Both return an asterisk next to them indicating they are globally ascessible. Further, NFS v2 (which this is) has no means of authentication/authorization. There are more modern releases of NFS which offer some degree of authentication, but generally speaking its a fairly insecure means of file transfer.
- To mount a remote directory on our host, we can use `sudo mount -t nfs $IP:/home/ross /mnt/ross -o nolock` - mimic this command for the apache directory as well.
	- This reads "mount a NFS type share from the victim AT the directory of `/home/ross` on my local directory of `/mnt/ross` -o nolock"
- ![[Pasted image 20230223092341.png]]
- With both shares mounted, take a look at the content of each. You'll first notice that we dont have enough permission to view the apache share and that its restricted to a user with an id of `2017` who is a member of the `www-data` group. 
	- The content of the apache share is fairly standard webserver directories - it also lines up with what our directory searching returned earlier. Its safe to assume at this point that this directory is the source of the apache server. 
- ![[Pasted image 20230223094156.png]]
- The content of the `ross` share looks to be a standard linux user home director. Nothing of real interest yet aside from a Keepass password DB. This would be a high value target for a threat actor, but for now its a rabbit hole. Attempts to crack the DB file fail when using `keepasstojohn` due to an unsupported version. This should be revisited if other exploits fail.
- ![[Pasted image 20230223164759.png]]

# NFS Initial Foothold
- At this point we've got a couple key factors that can be strung together for an initial foothold.
	- We know there are two accessible NFS shares - one for the home directory of the user `ross`, and one protected directory for the `apache` server. The apache server is accessible only to a user with the `uid` of `2017`, and a member of the `www-data` group
	- We cant write to the `ross` share, but we can write to the `apache` share, and writing to the mount will write to the share on the victim as well. This means if we can upload executable code to the share, we could possibly trigger it on the server.

## Writing Remotely Executable Code
- Our goal right now is to get connectivity to the host by having the server execute code that we have pushed to the `apache` share from our local mount. Since this is a linux server its safe to assume our best bets for executing code will use perl, python, php, or bash since these are either installed by default, or commonly added to linux hosts.
	- Start by creating the new `squash` user, and give them the appropriate `uid` and group membership.
		- ![[Pasted image 20230223165950.png]]
		- `sudo adduser squash`
		- `sudo usermod -u 2017 squash`
		- `sudo usermod -g www-data squash`
	- Now we need to pull down a reverse shell that will call back to our kali machine. We can get one from [pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), or just use this [php shell](https://github.com/pentestmonkey/php-reverse-shell).
	- To get this to work, we will need the server executing the code (the lab machine) to connect back to a local kali listener - as such we need to edit the code with our kali IP and listening port.
	- ![[Pasted image 20230223165423.png]]
	- Save this php shell, and then switch to the new squashed user.
	- ![[Pasted image 20230223165838.png]]
	- Stand up a `netcat` listener on kali using `nc -lvnp 8080` or whatever port you used
		- ![[Pasted image 20230223171540.png]]
		- **Tip:** `rlwrap` is not necessary and just provides QoL features
	- We now are successfully connected to the victim. To refresh the connection, simply kill the shell with CTRL+C, stand up the `netcat` listener again, and send the curl command to the reverse shell script.


## Enumerating the Ross share
- Since the foothold was established via NFS, lets quickly check the `/etc/exports` file which [controls file exports to remote hosts](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/5/html/deployment_guide/s1-nfs-server-config-exports)
- ![[Pasted image 20230223172007.png]]
- For the `apache` share, we see that is has:
	- **rw**: read-write
	- **sync**: Reply to requests only after the changes have been committed to stable storage
	- **root_squash**: Map requests from uid/gid 0 to the anonymous uid/gid. By default, NFS enables this flag which automatically downgrades a `root` user to the `nfsnobody` user. In a sense, all `root` owned files then become `nfsnobody` owned files. With this downgrade, NFS also essentially prevents the uploading of programs with the [setuid](Map requests from uid/gid 0 to the anonymous uid/gid) bit set. 
- The `ross` share is the same except without the `RW` flag. Had all NFS shares implemented the more stringent `all_squash`, then this exploit would not have been possible as it takes it a step further and downgrades all users, rather than root, which would have prevented code execution.
	- **all_squash**: Map all uids and gids to the anonymous user. Useful for NFS-exported public FTP directories, news spool directories, etc.
	- [Manual for exports](https://linux.die.net/man/5/exports)
- It was previously impossible to read or write ross's home directory - which checks out since the share didnt implement the `rw` flag. Try duplicating the procedure for the `2017` user for ross.
	- First, get the uid/gid info for `ross` on the victim host.
	- ![[Pasted image 20230223175109.png]]
	- On Kali:
		- `sudo useradd ross`
		- `sudo usermod -u 1001 ross`
		- `sudo usermod -g 1001 ross`
- Switch to the new `ross` user on kali and begin looking through the share.
	- `sudo su ross`
- Looking at the root of the share, there are some atypical files belonging to the `ftpuser` user and `ftpgroup` group
- ![[Pasted image 20230223175339.png]]
- [Cursory](https://askubuntu.com/questions/300682/what-is-the-xauthority-file) google searches for these files indicate they are generated for X11 sessions.
	- **Note:** When hardening linux hosts in accordance w/DISA guidance, its recommended X11forwarding to be disabled unless it supports a documented use-case. 
- Be lazy and first print out all the files in ross' home dir with `cat .*` 
- ![[Pasted image 20230224073317.png]]

# Escalation to Root

- Looking at the `.Xauthority` file in particular reveals some text regarding a cookie. Its very garbled though as this is bytes rather than just plain text. After some snooping it looks like this file is used to [authenticate users to an X server](https://superuser.com/questions/1482471/xorg-x11-how-to-provide-cookie-based-access-to-x-server-using-xauth) to remotely view a GUI session.
	- This is ross's way into the server, and the goal now is to steal this so we can authenticate a session. Heres the plan:
		- Copy the content of the remote file in the share (`/mnt/squashed_ross` which is `/home/ross` on the victim) to a file on the victim through the `alex` shell which was opened earlier.
		- base64 encode the file to allow for proper copying with `cat .Xauth* | base64`
		- ![[Pasted image 20230224074232.png]]
		- ![[Pasted image 20230224075045.png]]
		- `echo "your b64 string" | base64 -d > /tmp/.Xauthority`
		- Export the `XAUTHORITY` environment variable to point to the hijacked credential in `/tmp/.Xauthority` - and we have successfully impersonated ross.
- Now that we have stolen the credential, we need to escalate our privileges. Lets use this cred to connect to the display - but first see what is being displayed with the [w](https://man7.org/linux/man-pages/man1/w.1.html) command.
	- ![[Pasted image 20230224075626.png]]
	- We now know ross is authed and is vieweing the `:0` gnome session - lets screenshot the window that X is displaying, save it, host a webserver, and transfer back to kali.
		- `xwd -root -screen -silent -display :0 > /tmp/squashed.xwd` - [docs](https://linux.die.net/man/1/xwd)
		- Host a webserver `python3 -m http.server 80` in the directory storing the screenshot - theres a few ways to transfer, but if the victim has python/python3 installed (confirmed with `which python3`) this is very easy.
		- On kali, pull down this file with `curl http://VICTIM_IP/FILE_NAME`
	- Now that the image is back on kali, we cant open it in a `.xwd` format. Since its obviously a screenshot, convert it to a png/jpg with `convert FILE_NAME.xwd squashed.png`. This will reveal credentials for the `root` user. 