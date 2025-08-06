# External-Enumeration

## Table of contents

##### ➤ Enumeration

* [1. Port Scanning](#port-scanning)
* [2. Fuzzing](#Automated-enumeration)
* [3. Vulnerability scan](#Automated-enumeration)
* [4. Online enumeration tools](#Automated-enumeration)

##### ➤ Ports (detailed view)

* [Port 21](#port-21)
* [Port 22](#port-22)
* [Port 23](#port-23)
* [Port 25](#port-25)
* [Port 80](#port-80)
* [Port 88](#port-88)
* [Port 110](#port-110)
* [Port 111](#port-111)
* [Port 139, 445](#port-139-445)
* [Port 143](#port-143)
* [Port 161, 162, 10161, 1016 (udp)](#port-161-162-10161-10162-udp)
* [Port 389](#port-389)
* [Port 587](#port-587)
* [Port 1433](#port-1433)
* [Port 2375](#port-2375)
* [Port 3389](#port-3389)
* [Port 5672](#port-5672)
* [Port 5985](#port-5985,-5986)
* [Port 11211](#port-11211)
* [Port 15672](#port-15672)


# 
# ⭕ Enumeration 

## 🔻Port scanning

##### ➤ Nmap

**Note:** If nmap is not executed with root access rights, it is required to used -sT parameter rather than -sS, otherwise all ports will be appear filtered.

###### • Detect active host
```
 nmap -sn -T4 10.0.0.0/24 -oN active-hosts
```

###### • Silent mode
```
nmap -sS -sV -vv -Pn -p<PORT> <IP>
```

###### • Agressive mode
```
nmap -T4 -sS -A -p- <IP>

nmap -T4 -sS -sC -p- -Pn <IP>

nmap -T4 -sC -sV -p- --min-rate=1000 <IP>
```

###### • UDP Scan
```
nmap -T4 -sUV <IP>

nmap -T4 -A -sUV --top-ports 1000 -Pn <IP>
```

###### • List the nmap script
```
ls -l /usr/share/nmap/scripts/smb*
```

##### ➤ Masscan
```
masscan -p21,22,443,8000-8100 10.0.0.0/24
```


## 🔻Fuzzing

##### ➤ Knockpy - Subdomain fuzzing
```
knockpy domain.com -w /usr/share/wordlists/list --silent csv -o /path/to/new/folder

usage: knockpy [-h] [-v] [--no-local] [--no-remote] [--no-scan] [--no-http] 
               [--no-http-code CODE [CODE ...]] [--dns DNS] [-w WORDLIST] 
               [-o FOLDER] [-t SEC] [-th NUM] [--silent [{False,json,json-pretty,csv}]]
               domain
```

##### ➤ Dirb
```
dirb http://10.0.0.1/abc/ /usr/share/wordlists/dirb/big.txt  
```

##### ➤ Gobuster

###### Extension list
```
.html,.php,.asp,.aspx,.htm,.xml,.json,.jsp,.pl,.ini,.bak,.bck.
```

###### Bruteforce
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

##### ➤ Feroxbuster
```
feroxbuster -u http://10.0.0.1 -w /usr/share/seclists/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt  --threads 30 -C 404,403
OR
feroxbuster -u http://mydomain.com -w /usr/share/seclists/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt  --threads 30 -C 404,403
```

####  ➤ Fuzzing
```
gobuster fuzz -u http://10.0.0.1/user/FUZZ/condig -w /usr/share/wordlists/dirb/common.txt -e -t 20
```

####  ➤  Fuzzing Virtual Host
```
ffuf -u http://mywebsite.com -w /usr/share/seclists/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt -H 'Host: FUZZ.mywebsite.com' -fs 15949
```

## 🔻Vulnerability scanner

##### ➤ Nikto
```
nikto -host=http://example.com
```

##### ➤ Automatic Searchsploit analysis through Nmap results
```
nmap -T4 -sC -sV -p- --min-rate=1000 10.0.0.1 -oX output.xml
searchsploit --nmap output.xml 
```

## 🔻Online enumeration tools
```
https://dnsdumpster.com/
https://search.censys.io/
https://crt.sh/
https://archive.org/
https://www.robtex.com/
```

# 
# ⭕ Ports (detailled view)

## 🔻Port 21
#### ➤ Vuln detection using nmap
```
nmap -p 21 -sV -sC --script="ftp-vuln-*, ftp-anon" 10.0.0.1-254
```

#### ➤ Bruteforcing
```
#Hydra - Password spraying
hydra -s 21 -t 4 -L username.lst -p password01! 10.0.0.1 ftp

#Hydra - Bruteforce specific user
hydra -s 21 -t 4 -l admin -P /usr/share/wordlists/rockyou.txt 10.0.0.1 ftp

#Hydra - Bruteforce common login:passord
hydra -s 21 -C /home/kali/wordlists/legion/ftp-betterdefaultpasslist.txt -u -f 10.0.0.1 ftp

#Medusa
medusa -h 10.10.10.10 -u user -P passwords.txt -M ftp 
```

#### ➤ Basic Connection and FTP commands
```
➤ Connection
ftp 10.0.0.1 21

➤ Upload a file (from the folder where the shell has been started)
binary
put <filename>

➤ Download a file (to the folder where the shell has been started)
binary
get <filename>

ex:
get test.zip
get "Access Control.zip"
```

#### ➤ Common Errors
```
➤ 229 Entering Extended Passive Mode (|||26826|)
```
![image](https://github.com/Kiosec/External-Enumeration/assets/100965892/87976e59-04e6-41e9-bc23-c9d0f71b7d4f)


## 🔻Port 22
#### ➤ Hydra - Bruteforcing
```
#Hydra - Bruteforce specific user
hydra -s 22 -v -t 4 -l root -P /usr/share/wordlists/rockyou.txt 10.0.0.1 ssh

#Hydra - Password spraying
hydra -L user.txt -p password01! 10.0.0.1 ssh

#Hydra - Full bruteforce
hydra -L user.txt -P rockyou.txt 10.10.219.212 ssh
```

#### ➤ SSH connection
```
ssh lexis@10.0.0.1
ssh lexis@10.0.0.1 -oKexAlgorithms=+diffie-hellman-group1-sha1
```

#### ➤ SSH connection error
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

#### ➤ SSH connection using id_rsa private key
```
chmod 600 id_rsa
ssh -i id_rsa kiosec@10.0.0.1
```

## 🔻Port 23
Authentication login page can be take a moment to appears (1min)

```
#From Kali linux
Kiosec@cyberlab:/home/kali>#telnet 10.10.0.1
Trying 10.10.0.1...
Connected to 10.10.0.1.
Escape character is '^]'.

Welcome to Microsoft Telnet Service 

login: security
login:security 
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>
```

## 🔻Port 25

#### Documentation

| Command   | Description |
|-----------|-------------|
| `HELO`    | Used to initiate an SMTP conversation with an email server. The command is followed by an IP address or a domain name (e.g., `HELO 10.1.2.14`). |
| `EHLO`    | Used to initiate a conversation with an Extended SMTP (ESMTP) server. Works the same way as `HELO`, but for ESMTP. |
| `STARTTLS`| Used to start a secure TLS (Transport Layer Security) connection to an email server. |
| `RCPT`    | Used to specify the recipient's email address. |
| `DATA`    | Used to initiate the transfer of the email message content. |
| `RSET`    | Used to reset (cancel) the current email transaction. |
| `MAIL`    | Used to specify the sender's email address. |
| `QUIT`    | Used to close the connection with the server. |
| `HELP`    | Used to display a help menu (if available). |
| `AUTH`    | Used to authenticate a client to the email server. |
| `VRFY`    | Used to verify whether a user's email mailbox exists. |
| `EXPN`    | Used to request or expand a mailing list on the remote server. |


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

## 🔻Port 80
```
wpscan --url http://10.0.0.1/ --passwords /usr/share/wordlists/rockyou.txt --usernames admin --api-token {token-api}
```

## 🔻Port 88
```
Service : kerberos-sec  Microsoft Windows Kerberos

# Install kerbrute : https://github.com/ropnop/kerbrute/releases
# Think to add the domain to the /etc/host -> echo '@IP @domain' >> /etc/hosts (example echo '10.0.0.1 cyberlab.local' >> /etc/hosts)
# Enumerate the user
root@kali:~# kerbrute userenum -d <domain_name> --dc <dns_domain_name> userlist.txt -t 100

Important note : Once a list of user founded, try to obtain the TGT ticket (ASREPPROASTING through GetNPusers.py)

# Password Spraying
root@kali:~# ./kerbrute_linux_amd64 passwordspray -d <domain_name> domain-users.txt Password123
```


## 🔻Port 110
## 🔻Port 111
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

```
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.0.0.1
```

## 🔻Port 139, 445
#### Basic enumeration
```
enum4linux -A 10.0.0.1
enum4linux 10.0.0.1 -u anonymous
```

#### List nmap scripts - Detection vuln port 445,139
```

nmap -p 445,139 -Pn --script smb-protocols.nse 10.0.0.1
nmap -v -p 139,445 --script=smb-os-discovery 10.0.0.1

nmap -v -p 139,445 --script=smb* 10.0.0.1

nmap -p 445,139 -Pn --script=smb-vuln-*.nse 10.0.0.1 // Do not return all vuln because some script needs specific args
nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 10.0.0.1
nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 10.0.0.1

#Enumerate the shares
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.0.0.1

```

#### Connection attempt
```
smbclient -L \\10.0.0.1
smbclient -L 10.0.0.1 -U anonymous
smbclient -L 10.0.0.1 --options='client min protocol=NT1'

smbclient \\\\10.10.155.41\\<share_name>
```

#### SMBClient - download everything for what we have permission
```
#Be careful to access a folder that you are minumum a read only permission. (check with smbmap before)
#In the example below, HR is a folder with read only permission
root@ip-10-10-148-27:~# smbclient \\\\10.10.155.41\\HR
WARNING: The "syslog" option is deprecated
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Fri Mar 12 02:11:49 2021
  ..                                 DR        0  Fri Mar 12 02:11:49 2021
  Administrator                       D        0  Thu Mar 11 21:55:48 2021
  All Users                         DHS        0  Sat Sep 15 08:28:48 2018
  atlbitbucket                        D        0  Thu Mar 11 22:53:06 2021
<...>
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \Administrator\*
STATUS_STOPPED_ON_SYMLINK listing \All Users\*
STATUS_STOPPED_ON_SYMLINK listing \*
smb: \All Users\> 
```

#### SMBmap List the rights on the folders / recursif mode
```
smbmap -H 10.0.0.1

➤ Reculsive enumeration
smbmap -H 10.0.0.1 -r

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

#### Download a share folder
```
#Example with the folder named anonymous
smbget -R smb://10.0.0.1/anonymous

#Example with a specific file
smbget -r smb://10.0.0.1/folder/file
press enter
```

#### Mount a share folder
```
mount -t cifs //10.0.0.1/share /mnt/share
mount -t cifs -o "username=user,password=password" //10.0.0.1/share /mnt/share
```

#### User enumeration using SID

Lookupsid is a tool that allows you to enumerate user and group Security Identifiers (SIDs) on a Windows system. Each user and group account in Windows has a unique SID, and by obtaining these SIDs, you can gather valuable information about the system's user accounts, aiding in understanding the network's structure and potential security risks. The tool uses the SMB (Server Message Block) protocol, which is commonly used for Windows networking, to facilitate communication.

```
#Command : python lookupsid.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP>
impacket-lookupsid 'mywindows.htb/guest'@mywindows.htb -no-pass
Impacket v0.13.0.dev0+20250130.104306.0f4b866 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at cicada.htb
[*] StringBinding ncacn_np:cicada.htb[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-917908876-1423158569-3159038727
498: MYWINDOWS\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: MYWINDOWS\Administrator (SidTypeUser)
501: MYWINDOWS\Guest (SidTypeUser)
...
1109: MYWINDOWS\Dev Support (SidTypeGroup)
1601: MYWINDOWS\Totoro (SidTypeUser)
1601: MYWINDOWS\Kiosec (SidTypeUser)
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


## 🔻Port 143


## 🔻Port 161, 162, 10161, 10162 (udp)

#### SMNP enumeration
```
# Using snmpbulkwalk
$ snmpbulkwalk -c public -v2c 10.0.0.1 .

# using snmp-chek (Prefered to detect dedicated tools running)
#Example :
kali@kali:~$ snmp-check 10.0.0.1
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.0.0.1 using SNMPv1 and community 'public'
[...]                             
  3765                  runnable              clamd                 /usr/local/sbin/clamd                      
  3767                  runnable              clamav-milter         /usr/local/sbin/clamav-milter  --black-hole-mode -l -o -q /var/run/clamav/clamav-milter.ctl
  3776                  runnable              inetd                 /usr/sbin/inetd
```


```


## 🔻Port 389

#### User enumeration using LDAP PING
Explanation : https://blog.netwrix.com/2022/12/13/using-ldap-ping-to-enumerate-active-directory-users/
Github : https://github.com/lkarlslund/ldapnomnom
```
┌─[✗]─[root@htb-tuswhlsdcc]─[/home/kiosec/Documents]
└──╼ #./ldapnomnom-linux-x64 --input xato-net-10-million-usernames.txt --server test.com --maxservers 32 --parallel 16
 __    ____  _____ _____                             
|  |  |    \|  _  |  _  |___ ___ _____ ___ ___ _____ 
|  |__|  |  |     |   __|   | . |     |   | . |     |
|_____|____/|__|__|__|  |_|_|___|_|_|_|_|_|___|_|_|_|
prerelease

IN  SPACE  NO  ONE  CAN  HEAR  YOU  NOM  NOM  USERNAMES

guest
administrator
```

#### User enumeration using Null Session
```
nxc smb 10.129.219.77 -u '' -p '' --users
```

#### Without user account
```
➤ Anonymous connection attempt (-x). With the example test.com : DOMAIN = test and DOMAIN2 = com
ldapsearch -h 10.129.136.235 -p 389 -x -b "dc=htb,dc=local"   
ldapsearch -H ldap://machine.htb:389/ -x -s base -b '' "(objectClass=*)" "*" +

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


## 🔻Port 587
## 🔻Port 1433
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



## 🔻Port 2375

Default docker port

#### Nmap 
```
nmap -sV -p 2375 10.0.0.1
```

#### Detect version 
```
curl http://10.0.0.1:2375/version

{
  "Platform": {
    "Name": "Docker Engine - Community"
  },
  "Components": [
    {
      "Name": "Engine",
      "Version": "20.10.20",
      "Details": {
        "ApiVersion": "1.41",
        "Arch": "amd64",
        "BuildTime": "2022-10-18T18:18:12.000000000+00:00",
        "Experimental": "false",
        "GitCommit": "03df974",
        "GoVersion": "go1.18.7",
        "KernelVersion": "5.15.0-1022-aws",
        "MinAPIVersion": "1.12",
        "Os": "linux"
      }]
}
```

#### Exploit
```
# To test if we can run commands, we'll list the containers on the target
docker -H tcp://10.0.0.1:2375 ps
```


## 🔻Port 3389

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

## 🔻Port 5672 - AMQP

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

## 🔻Port 5985, 5986

Details : https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm

#### ➤ Brute force 
```
#Brute force
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt

#Check a pair of credentials (Password) and execute a command
crackmapexec winrm <IP> -d <Domain Name> -u <username> -p <password> -x "whoami"

# Check a pair of credentials (Hash) and execute a PS command
crackmapexec winrm <IP> -d <Domain Name> -u <username> -H <HASH> -X '$PSVersionTable'
```

#### ➤ login remotely over WinRM (using TGT ticket as example)

https://github.com/Hackplayers/evil-winrm

```
ruby evil-winrm.rb -i <IP> -u <USERNAME> -p <PASSWORD>
OR
gem evil-winrm
evil-winrm -i <IP> -u <USERNAME> -p <PASSWORD>

ex:
evil-winrm -i 10.0.0.1 -u svc-securiry --password 'mystr0ngpasssword!'

```

## 🔻Port 11211 - Memcache

#### ➤ Nmap enumeration
```
nmap -n -sV --script memcached-info -p 11211 10.0.0.1
```

#### ➤ Manual enumeration
```
echo "version" | nc -vn -w 1 <IP> 11211      #Get version
echo "stats" | nc -vn -w 1 <IP> 11211        #Get status
echo "stats slabs" | nc -vn -w 1 <IP> 11211  #Get slabs
echo "stats items" | nc -vn -w 1 <IP> 11211  #Get items of slabs with info
echo "stats cachedump <number> 0" | nc -vn -w 1 <IP> 11211  #Get key names (the 0 is for unlimited output size)
echo "get <item_name>" | nc -vn -w 1 <IP> 11211  #Get saved info
```

#### ➤ Extraction data script
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

## 🔻Port 15672 - RabbitMQ
```
The default credentials are guest:guest
```
