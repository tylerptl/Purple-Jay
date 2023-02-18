# 2023 Hackthebox CTF Training
This repo is best viewed in [Obsidian.md](https://obsidian.md/). Once installed, open this repo as an Obsidian Vault.
## Goal
This training is meant to provide you a basic technical understanding of how to exploit common threats found in the [OWASP Top Ten](https://owasp.org/www-project-top-ten/) by providing you with 4 separate standalone vulnerable machines from Hackthebox. Each machine will have unique exploit killchains that you will need to carry out in order to fully compromise the box - this is determined by having root (linux) or system authority (windows) access to the machine. With this access, you will need to access the content of two 'flags' (text files containing a unique hash) found on the machines - one low privilege flag, and one requiring total compromise. 

Note: This is a gamified environment where the end goal is to gain unrestricted access to the machines - this should be not be considered indiciative of what an attack may look like in real life, as these labs do not take into consideration stealth, persistence, lateral movement, or other high-value vectors.


## Getting Started

## Setting up a kali vm
On your windows PC, perform the following:
- Download and install [VMWare Workstation Player]([VMware Workstation Player | VMware](https://www.vmware.com/products/workstation-player.html))
- Download the [Kali VMWare image]([Get Kali | Kali Linux](https://www.kali.org/get-kali/#kali-virtual-machines))
- ![](/Assets/Pasted%20image%2020230216112529.png)
- To install, follow the instructions found in the docs linked at the [bottom of the download]([Import Pre-Made Kali VMware VM | Kali Linux Documentation](https://www.kali.org/docs/virtualization/import-premade-vmware/))
- Once installed, start the VM and connect as the user `kali` with a password of `kali` (default credentials)
	- You can change these if you want, but for the sake of the CTF this isnt required.
- Once connected, open the terminal in the top left corner of your screen and type `sudo apt update && sudo apt full-upgrade -y`
	- You may be prompted to allow install, or restart a service - in all cases, accept.
- With this done, your kali VM is fully up to date and ready to use.

### Getting setup on Hackthebox

After receiving your login information for [Hackthebox](https://app.hackthebox.com), navigate to the labs home page and click lab access at the top right. You'll need to download your VPN pack to gain access to the lab infrastructure.

- Select **Machines**
- For **VPN Access** choose `US-VIP+`
- For **VPN Server** choose `US VIP+ 1`
- For **Protocol** choose `UDP 1337`
- Download ![[Pasted image 20230216111212.png]]
- Its recommended that you create a specific folder to store all CTF related artifacts including this `.ovpn` file.
	- Ex. In a kali terminal type `mkdir ~/Documents/ctf` and use that directory to store your scripts, findings, notes, etc.
- 
