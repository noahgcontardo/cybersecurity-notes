
root@ip-10-201-119-38:~# nmap -A -T4 -p- 10.201.10.115 -oN initial.nmap
Starting Nmap 7.80 ( https://nmap.org ) at 2025-10-11 21:42 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.201.10.115
Host is up (0.00016s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://cloudsite.thm/
4369/tcp  open  epmd    Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    rabbit: 25672
25672/tcp open  unknown
MAC Address: 16:FF:F0:73:23:99 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=10/11%OT=22%CT=1%CU=38602%PV=Y%DS=1%DC=D%G=Y%M=16FFF0%
OS:TM=68EAC1BE%P=x86_64-pc-linux-gnu)SEQ(SP=FD%GCD=1%ISR=10B%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11N
OS:W7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F
OS:4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T
OS:=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.16 ms 10.201.10.115

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 157.47 seconds
root@ip-10-201-119-38:~# 



root@ip-10-201-121-143:~# gobuster dir -u http://cloudsite.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .mb, .json, .php, .txt, .js, .html, yaml, .xml -b 404

Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cloudsite.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              mb,
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.                    (Status: 200) [Size: 18451]
/assets               (Status: 301) [Size: 315] [--> http://cloudsite.thm/assets/]
/server-status        (Status: 403) [Size: 278]



root@ip-10-201-119-38:~# nmap -p 4369 --script epmd-info 10.201.10.115
Starting Nmap 7.80 ( https://nmap.org ) at 2025-10-11 21:51 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for cloudsite.thm (10.201.10.115)
Host is up (0.00011s latency).

PORT     STATE SERVICE
4369/tcp open  epmd
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    rabbit: 25672
MAC Address: 16:FF:F0:73:23:99 (Unknown)

i got this to work need to copy nmap scan over later because i need to leave
 epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    rabbit: 25672
noticed from nmap scan epmd port has name of ctf in one of the nodes

after looking up a guide on enumerating this service I found this

ot@ip-10-201-119-38:~# echo -n -e "\x00\x01\x6e" | nc -vn 10.201.10.115 4369
Connection to 10.201.10.115 4369 port [tcp/*] succeeded!
name rabbit at port 25672



https://angelica.gitbook.io/hacktricks/network-services-pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd

so now we have a node name rabbit and we now know the unknown service open port 25672 matters

going to setup my erlang to see what I can do with it as no metasploit modules seem to automatically give me the cookie or mention that in particular

https://github.com/sadshade/erlang-otp-rce/blob/main/erlang-otp-rce.py

made account with user bob@bob.bob passwd bob

![[Pasted image 20251014115847.png]]shows /dashboard/inactive

![[Pasted image 20251014121141.png]]

![[Pasted image 20251014122013.png]]


POST /api/upload HTTP/1.1
Host: storage.cloudsite.thm
Content-Length: 663
Accept-Language: en-GB,en;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywrqOiKKsp46b6J6O
Accept: */*
Origin: http://storage.cloudsite.thm
Referer: http://storage.cloudsite.thm/dashboard/active
Accept-Encoding: gzip, deflate, br
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImpvZUBqb2Uuam9lIiwic3Vic2NyaXB0aW9uIjoiYWN0aXZlIiwiaWF0IjoxNzYwNDYzNDUxLCJleHAiOjE3NjA0NjcwNTF9.0rk4MgFlNkfnAjgM83ArGgV3CfGBTdzaunis1uj6CYE
Connection: keep-alive

------WebKitFormBoundarywrqOiKKsp46b6J6O
Content-Disposition: form-data; name="file"; filename="initial.nmap"
Content-Type: application/octet-stream


I signed into the account Joe off burpsuite to grab the JWT token from the response. Seeing it is running express api 
![[Pasted image 20251014133243.png]]

