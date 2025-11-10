root@ip-10-201-83-78:~# nmap -sCV -T4 10.201.97.31 -oN initial.nmap

Host is up (0.028s latency).
Not shown: 988 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-09 16:21:35Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: SOUPEDECODE
|   NetBIOS_Domain_Name: SOUPEDECODE
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: SOUPEDECODE.LOCAL
|   DNS_Computer_Name: DC01.SOUPEDECODE.LOCAL
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-09T16:23:50+00:00
| ssl-cert: Subject: commonName=DC01.SOUPEDECODE.LOCAL
| Not valid before: 2025-06-17T21:35:42
|_Not valid after:  2025-12-17T21:35:42

enum4linux -a 10.201.103.90

had a lame output

root@ip-10-201-48-39:~# nxc smb 10.201.103.90 -u '' -p '' --shares
SMB         10.201.103.90   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.201.103.90   445    DC01             [-] SOUPEDECODE.LOCAL\: STATUS_ACCESS_DENIED 
SMB         10.201.103.90   445    DC01             [-] Error enumerating shares: Error occurs while reading from remote(104)

ldapsearch -x -H ldap://DC01.SOUPEDECODE.LOCAL -s base -b "" "objectclass=*"

did spit out base info

rootDomainNamingContext: DC=SOUPEDECODE,DC=LOCAL
ldapServiceName: SOUPEDECODE.LOCAL:dc01$@SOUPEDECODE.LOCAL
isGlobalCatalogReady: TRUE
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: DIGEST-MD5

ldapsearch -x -H ldap://DC01.SOUPEDECODE.LOCAL -s base -b "SOUPEDECODE" "objectclass=*"
ldapsearch -x -H ldap://DC01.SOUPEDECODE.LOCAL -s base -b "LOCAL" "objectclass=*"

but plugging in base info got us nothing because of not allowing anonymous LDAP bindings

root@ip-10-201-48-39:~# nxc smb 10.201.122.170 -u '' -p '' --shares

got nothing

root@ip-10-201-48-39:~# nxc smb 10.201.122.170 -u ' ' -p '' --shares
SMB         10.201.122.170  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.201.122.170  445    DC01             [+] SOUPEDECODE.LOCAL\ : (Guest)
SMB         10.201.122.170  445    DC01             [*] Enumerated shares
SMB         10.201.122.170  445    DC01             Share           Permissions     Remark
SMB         10.201.122.170  445    DC01             -----           -----------     ------
SMB         10.201.122.170  445    DC01             ADMIN$                          Remote Admin
SMB         10.201.122.170  445    DC01             backup                          
SMB         10.201.122.170  445    DC01             C$                              Default share
SMB         10.201.122.170  445    DC01             IPC$            READ            Remote IPC
SMB         10.201.122.170  445    DC01             NETLOGON                        Logon server share 
SMB         10.201.122.170  445    DC01             SYSVOL                          Logon server share 
SMB         10.201.122.170  445    DC01             Users  