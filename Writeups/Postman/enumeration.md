## redis-cli


## Feroxbuster
```bash
feroxbuster --url http://$IP -d 2 -T 2                                                                     

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher π€                 ver: 2.7.1
ββββββββββββββββββββββββββββ¬ββββββββββββββββββββββ
 π―  Target Url            β http://10.129.2.1
 π  Threads               β 50
 π  Wordlist              β /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 π  Status Codes          β [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 π₯  Timeout (secs)        β 2
 π¦‘  User-Agent            β feroxbuster/2.7.1
 π  Config File           β /etc/feroxbuster/ferox-config.toml
 π  HTTP methods          β [GET]
 π  Recursion Depth       β 2
 π  New Version Available β https://github.com/epi052/feroxbuster/releases/latest
ββββββββββββββββββββββββββββ΄ββββββββββββββββββββββ
 π  Press [ENTER] to use the Scan Management Menuβ’
ββββββββββββββββββββββββββββββββββββββββββββββββββ
200      GET       91l      253w     3844c http://10.129.2.1/
301      GET        9l       28w      309c http://10.129.2.1/images => http://10.129.2.1/images/
301      GET        9l       28w      306c http://10.129.2.1/css => http://10.129.2.1/css/
301      GET        9l       28w      309c http://10.129.2.1/upload => http://10.129.2.1/upload/
301      GET        9l       28w      305c http://10.129.2.1/js => http://10.129.2.1/js/
301      GET        9l       28w      308c http://10.129.2.1/fonts => http://10.129.2.1/fonts/
403      GET       11l       32w      298c http://10.129.2.1/server-status
[####################] - 1m    210000/210000  0s      found:7       errors:147    
[####################] - 1m     30000/30000   453/s   http://10.129.2.1 
[####################] - 1m     30000/30000   453/s   http://10.129.2.1/ 
[####################] - 0s     30000/30000   0/s     http://10.129.2.1/images => Directory listing (add -e to scan)
[####################] - 0s     30000/30000   0/s     http://10.129.2.1/css => Directory listing (add -e to scan)
[####################] - 0s     30000/30000   0/s     http://10.129.2.1/upload => Directory listing (add -e to scan)
[####################] - 0s     30000/30000   0/s     http://10.129.2.1/js => Directory listing (add -e to scan)
[####################] - 2s     30000/30000   0/s     http://10.129.2.1/fonts => Directory listing (add -e to scan)

```