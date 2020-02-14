Title: ChangeMe - Hack the Box
Date: 2020-02-06
Modified: 2020-02-06
Category: ctf
Tags: ctf, hack the box, oscp prep
Slug: changeme
Authors: Riley
Summary: ChangeMe

## Description

[Description of box and general attack path]

[box] is assigned IP 10.10.10.xxx.

## Reconnaissance

We begin by initiating an Nmap scan.

#### Nmap (minus some extra Windows stuff)
[nmap command and results here]
```
```

## Getting User

One of the first things to check on any Windows server is SMB null sessions.  For this, we can use `smbmap`.

#### Tool1
![Image or code block of output]()

#### interesting-file.xml
```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
    <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
        <Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>
    </User>
</Groups>
```

#### tool2.py
![out2]()

## Getting Administrator / Root

## Other interesting stage