sudo grep -R --line-number "LD_PRELOAD" /etc /usr /var 2>/dev/null

Rip out LD preloads assigned to user

sudo -l 

display current sudo level access 

find / -type f -perm 4000 2>/dev/null

rip out files with SUID set