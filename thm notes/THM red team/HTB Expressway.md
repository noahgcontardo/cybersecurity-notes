┌──(kali㉿kali)-[~/HTB/enu]
└─$ sudo nmap -A -T4 -p- 10.10.11.87 -oN expressway.initial.nmap
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-01 18:12 EDT
Nmap scan report for 10.10.11.87
Host is up (0.011s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

-somehow I doubt this machine is just running an SSH daemon