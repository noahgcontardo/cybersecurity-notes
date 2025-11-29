┌──(kali㉿kali)-[~/THM/AgentSudo]
└─$ nmap -A -T4 -p- 10.64.132.105 -oN initial.nmap                 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-29 12:22 EST
Nmap scan report for 10.64.132.105
Host is up (0.023s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=11/29%OT=21%CT=1%CU=35057%PV=Y%DS=3%DC=T%G=Y%TM=692B2C
OS:18%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=108%TI=Z%CI=I%II=I%TS=A)SE
OS:Q(SP=102%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS=A)SEQ(SP=103%GCD=1%ISR=106%TI=Z
OS:%CI=I%II=I%TS=A)SEQ(SP=107%GCD=1%ISR=10B%TI=Z%CI=I%II=I%TS=A)SEQ(SP=FC%G
OS:CD=1%ISR=109%TI=Z%CI=I%II=I%TS=A)OPS(O1=M578ST11NW7%O2=M578ST11NW7%O3=M5
OS:78NNT11NW7%O4=M578ST11NW7%O5=M578ST11NW7%O6=M578ST11)WIN(W1=68DF%W2=68DF
OS:%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M578NNSNW7%C
OS:C=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%
OS:T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD
OS:=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S
OS:=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK
OS:=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 3 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   22.76 ms 192.168.128.1
2   ...
3   22.89 ms 10.64.132.105

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.66 seconds

┌──(kali㉿kali)-[~/THM/AgentSudo]
└─$ gobuster dir -u 10.64.132.105 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .json,.js,.html,.txt,.php,.yaml,.xml  
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.64.132.105
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              txt,php,yaml,xml,json,js,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 218]

--lame result