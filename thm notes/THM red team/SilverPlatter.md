
┌──(kali㉿kali)-[~/THM/SilverPlatter]
└─$ nmap -A -T4 -p- 10.64.132.140 -oN initial.nmap
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-30 14:15 EST
Nmap scan report for 10.64.132.140
Host is up (0.021s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 52:de:d7:9f:92:59:d8:aa:7c:36:e3:df:14:fb:cd:9c (ECDSA)
|_  256 7f:08:13:13:fe:44:70:fe:30:e2:d5:57:48:d9:eb:05 (ED25519)
80/tcp   open  http       nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Hack Smarter Security
8080/tcp open  http-proxy
|_http-title: Error
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Sun, 30 Nov 2025 19:15:43 GMT
|     <html><head><title>Error</title></head><body>404 - Not Found</body></html>
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SMBProgNeg, SSLSessionReq, Socks5, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|_    Connection: close
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.95%I=7%D=11/30%Time=692C97DF%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\
SF:r\nContent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Sun,
SF:\x2030\x20Nov\x202025\x2019:15:43\x20GMT\r\n\r\n<html><head><title>Erro
SF:r</title></head><body>404\x20-\x20Not\x20Found</body></html>")%r(HTTPOp
SF:tions,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\r\nC
SF:ontent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Sun,\x20
SF:30\x20Nov\x202025\x2019:15:43\x20GMT\r\n\r\n<html><head><title>Error</t
SF:itle></head><body>404\x20-\x20Not\x20Found</body></html>")%r(RTSPReques
SF:t,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nCon
SF:nection:\x20close\r\n\r\n")%r(FourOhFourRequest,C9,"HTTP/1\.1\x20404\x2
SF:0Not\x20Found\r\nConnection:\x20close\r\nContent-Length:\x2074\r\nConte
SF:nt-Type:\x20text/html\r\nDate:\x20Sun,\x2030\x20Nov\x202025\x2019:15:43
SF:\x20GMT\r\n\r\n<html><head><title>Error</title></head><body>404\x20-\x2
SF:0Not\x20Found</body></html>")%r(Socks5,42,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Gene
SF:ricLines,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200
SF:\r\nConnection:\x20close\r\n\r\n")%r(Help,42,"HTTP/1\.1\x20400\x20Bad\x
SF:20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(S
SF:SLSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\
SF:x200\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,42,"HTTP/
SF:1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x2
SF:0close\r\n\r\n")%r(TLSSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Kerberos,4
SF:2,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnec
SF:tion:\x20close\r\n\r\n")%r(SMBProgNeg,42,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(LPDSt
SF:ring,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\n
SF:Connection:\x20close\r\n\r\n")%r(LDAPSearchReq,42,"HTTP/1\.1\x20400\x20
SF:Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n"
SF:);
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   17.96 ms 192.168.128.1
2   ...
3   18.03 ms 10.64.132.140



┌──(kali㉿kali)-[~/THM/SilverPlatter]
└─$ gobuster dir -u 10.64.132.140 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .html,.txt,.js,.php,.json,.yaml,.xml
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.64.132.140
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              txt,js,php,json,yaml,xml,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 14124]
/images               (Status: 301) [Size: 178] [--> http://10.64.132.140/images/]
/assets               (Status: 301) [Size: 178] [--> http://10.64.132.140/assets/]
/README.txt           (Status: 200) [Size: 771]
/LICENSE.txt          (Status: 200) [Size: 17128]

┌──(kali㉿kali)-[~/THM/SilverPlatter]
└─$ gobuster dir -u http://10.64.132.140:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .html,.txt,.js,.php,.json,.yaml,.xml
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.64.132.140:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              txt,js,php,json,yaml,xml,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/website              (Status: 302) [Size: 0] [--> http://10.64.132.140:8080/website/]
/console              (Status: 302) [Size: 0] [--> /noredirect.html]
