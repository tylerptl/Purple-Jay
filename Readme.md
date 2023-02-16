# 2023 Hackthebox CTF Training
This repo is best viewed in [Obsidian.md](https://obsidian.md/). Once installed, open this repo as an Obsidian Vault.
## Goal
This training is meant to provide you a basic technical understanding of how to exploit common threats found in the [OWASP Top Ten](https://owasp.org/www-project-top-ten/) by providing you with 4 separate standalone vulnerable machines from Hackthebox. Each machine will have unique exploit killchains that you will need to carry out in order to fully compromise the box - this is determined by having root (linux) or system authority (windows) access to the machine. With this access, you will need to access the content of two 'flags' (text files containing a unique hash) found on the machines - one low privilege flag, and one requiring total compromise. 

Note: This is a gamified environment where the end goal is to gain unrestricted access to the machines - this should be not be considered indiciative of what an attack may look like in real life, as these labs do not take into consideration stealth, persistence, lateral movement, or other high-value vectors.


## Getting Started

### Getting setup on Hackthebox

You will receive an email with a gift card that you can redeem on [Hackthebox](https://app.hackthebox.com) - instructions on how to redeem and create your account should be delivered in the same email.

Once you have your account made, navigate back to to the [labs home page]([Hack The Box :: Dashboard](https://app.hackthebox.com/home)) and click lab access at the top right. You'll need to download your VPN pack to gain access to the lab infrastructure.
- Select **Machines**
- For **VPN Access** choose `US-VIP+`
- For **VPN Server** choose `US VIP+ 1`
- For **Protocol** choose `UDP 1337`
- Download ![[Pasted image 20230216111212.png]]

## Setting up a kali vm

- Download and install [VMWare Workstation Player]([VMware Workstation Player | VMware](https://www.vmware.com/products/workstation-player.html))
- Download the [Kali VMWare image]([Get Kali | Kali Linux](https://www.kali.org/get-kali/#kali-virtual-machines))
- ![[Pasted image 20230216112529.png]]
- 