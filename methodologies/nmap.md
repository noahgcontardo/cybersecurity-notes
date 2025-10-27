ls /usr/share/nmap/scripts | grep -i http

grep -iR "vuln" /usr/share/nmap/scripts

run multiple scripts:

sudo nmap -sV --script=ftp-enum,ftp-brute 10.10.15.216



on some machines especially windows you may need to ARP ping to or do an ICMP-less ping to discover it

--arp-request for arp and -Pn for pingless, no ICMP

|   |   |   |
|---|---|---|
|-PR|nmap 192.168.1.1-1/24 -PR|ARP discovery on local network|
occasionally you also may have to disable DNS res or just UDP scan certain services

|-n|nmap 192.168.1.1 -n|Never do DNS resolution|

or -sU for UDP scan (take longer than TCP as apparently it takes a while to confirm no message is sent back as UDP scans assume ports may be open if they do not reply)