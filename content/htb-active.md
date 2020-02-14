Title: Active - Hack the Box
Date: 2018-12-08
Modified: 2020-02-05
Category: ctf
Tags: ctf, hack the box, oscp prep
Slug: htb-active
Authors: Riley
Summary: Guide to Active from Hack the Box, featuring a Kerberoast attack.

## Description

Active is a Windows Server 2008 R2 Active Directory Domain Controller.  The attack path features a well-loved attack, Kerberoast.

Active is assigned IP 10.10.10.100.

## Reconnaissance

We start every box by identifying the target and running a port scan against it.

#### Nmap (minus some extra Windows stuff)
```bash
# nmap -v -sC -sV -oA nmap/active 10.10.10.100

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7600 (1DB04001) (Windows Server 2008 R2)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7600 (1DB04001)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2018-07-29 17:35:32Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)

Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2, cpe:/o:microsoft:windows

Host script results:
| nbstat: NetBIOS name: DC, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:11:3f (VMware)
| Names:
|   DC<00>               Flags: <unique><active>
|   ACTIVE<00>           Flags: <group><active>
|   ACTIVE<1c>           Flags: <group><active>
|   DC<20>               Flags: <unique><active>
|_  ACTIVE<1b>           Flags: <unique><active>
```

Active appears to be a Windows 2008 R2 Active Directory Domain Controller for the ACTIVE.HTB domain. Since this is a Windows computer, we should see if any shares are available to us from a null session.

## Getting User

One of the first things to check on any Windows server is SMB null sessions.  For this, we can use `smbmap`.

#### SMBMap
![smbmap-shares](images\ctf\htb\active\smbmap-shares.jpg)

Active does allow null sessions to connect to the Replication share. Enumerating further:

![smbmap-groups](images\ctf\htb\active\smbmap-groups.jpg)

According to [adsecurity](https://adsecurity.org/?p=2288), Groups.xml is a file that is distributed via Group Policy that can (among other things) create local users, set scheduled tasks, and change the local Administrator password. It may have very useful information.

It is possible to download the file using smbmap by setting the `--download` flag followed by the full path to the file, in this case `Replication\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml`.

After downloading the file, we can view the contents (which I have formatted for easy reading):

#### Groups.xml
```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
    <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
        <Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>
    </User>
</Groups>
```

Based on the Groups and User tags, this is modifying or distributing an account named __active.htb\SVC_TGS__, which is clearly a domain joined user. Under _Properties_, the `cpassword` tag holds a password encrypted by an AES-256 private key.

This would be a problem, if [Microsoft hadn't released the 32-byte key](https://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be.aspx) sometime before 2012.

Kali comes with the `gpp-decrypt` utility, which is built specifically for this task. Running it on the encrypted password reveals the user account's password in plaintext.

![v](images\ctf\htb\active\gpp-decrypt.jpg)

So the password for SVC_TGS is __GPPStillStandingStrong2k18__. To test the credentials, we can run any utility that authenticates against AD, such as Impacket's `GetADUsers.py` script.

#### GetADUsers.py
![GetADUsers](images\ctf\htb\active\GetADUsers.jpg)

The credentials we have are valid, and Administrator appears to be the only account to target at the moment. We can attempt to run `psexec.py` (also Impacket) on the target to get a shell, but the account doesn't appear to have write access to any shares.

#### psexec.py (no shell)
![psexec-user](images\ctf\htb\active\psexec-user.jpg)

What we can do is access the __Users__ share and read from the user's home directory and get the user flag in `Users\SVC_TGS\Desktop`.

![user-flag](images\ctf\htb\active\user-flag.jpg)

## Getting Administrator

While searching for methods to escalate our privileges, it's likely that we would run Impacket's `GetUserSPNs.py`.

![GetUserSPNs](images\ctf\htb\active\GetUserSPNs.jpg)

It appears that a CIFS service is running on the Administrator account. We may be able to perform a [Kerberoast attack](https://attack.mitre.org/techniques/T1208/) on the service and gain access to the Administrator account.

There are plenty of excellent guides on what Kerberoasting is and how it works, so I will [provide](https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf) [some](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/) [resources](https://pentestlab.blog/2018/06/12/kerberoast/) and keep my own explanation brief.

Since the Administrator account is running a service (CIFS) on the machine, it has a SPN set on the account. Since we possess the ability to obtain a valid Kerberos TGT ticket, we may request a Kerberos TGS service ticket for any SPN from any domain controller we can authenticate to. Parts of the TGS we obtain will be encrypted with the password hash of the service account (in this case Administrator), meaning that we can brute force the credentials offline without ever knowing the actual password hash of the account.

## Sunday Dinner, aka How I Kerberoasted Your Domain and You're Gonna Like It

To perform the attack from a non-domain joined computer, the easiest method is to use `GetUserSPNs.py` to view any <s>beef roasts</s> SPNs we fancy (repeat image for continuity purposes).

![Kerberoast-stage1](images\ctf\htb\active\Kerberoast-stage1.jpg)

If there are SPN's we like the looks of (such as that CIFS service on the Administrator account), we simply add the `-request` flag and execute again:

![Kerberoast-stage2](images\ctf\htb\active\Kerberoast-stage2.jpg)

Finally, take your silver ticket and throw it into your <s>oven</s> password cracker of choice. I use hashcat.

![Kerberoast-stage3](images\ctf\htb\active\Kerberoast-stage3.jpg)

Now that we have the Administrator account password, we can use `psexec.py` to execute commands and obtain a shell on the target system.

![roasted](images\ctf\htb\active\roasted.jpg)

This concludes the guide of Active from Hack the Box.