FTP:
TCP21 control channel to establish and manage connection
TCP20 for data transfer only

active mode FTP: cllient establishes connection as described via 21 

if a firewall protects the client passive mode is extremely useful as the server announces a port and the client can establish the data channel gratuitously. That way the client's firewall can't block the connection like it can in active mode.


FTP status codes:
https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes

FTP commands:
https://hackviser.com/tactics/pentesting/services/ftp

ftp <target-ip> <target-port>  
  
#target port is optional

lftp X.X.X.X

ftp://username:password@X.X.X.X

gobuster dir -u ftp://<target-ip> -w <wordlist-path>

hydra uses the web URL format for FTP

hydra [-L users.txt or -l user_name] [-P pass.txt or -p password] -f [-S port] ftp://X.X.X.X

FTP bounce scan (-b flag for nmap to bounce off ftp server masking the source can be enumerated by seeing if the FTP server doesn't restrict the PORT command)

nmap -b <FTP_server>:<port> <target_network>


1. `Find an FTP` server that doesn't restrict the `PORT` command.
2. Connect to the FTP server.

```
ftp X.X.X.X
```

3. Use the `PORT` command to redirect data to the target.

```
quote PORT target_IP,port
```

4. Initiate a file transfer or command that sends data to the target.

```
get filename
```

As part of your enumeration efforts it is helpful to check for /etc/vsftpd.conf perms to see if you can read the config as well as /ftp/users

settings to lookout for:

anonymous_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
no_anon_password=YES
anon_root=/home/username/ftp
write_enable=YES

anonymous login can be done by using the username anonymous

this can be checked with 

ftp> status


-----------------------------------

TFTP like ftp is in cleartext and runs on p69 NICE. Also runs on UDP 

FROM CPTS

|**Commands**|**Description**|
|---|---|
|`connect`|Sets the remote host, and optionally the port, for file transfers.|
|`get`|Transfers a file or set of files from the remote host to the local host.|
|`put`|Transfers a file or set of files from the local host onto the remote host.|
|`quit`|Exits tftp.|
|`status`|Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on.|
|`verbose`|Turns verbose mode, which displays additional information during file transfer, on or off.|
TFTP still has the read write perms of the FS however there is no login the way FTP has

