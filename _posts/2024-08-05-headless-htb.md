---
layout: article
title: "Headless - HackTheBox Writeup"
date: "2024-05-08"
image: "/assets/img/headless/homepage.png"
tags: []
---

Description...

We port scan the machine.

<div class="article-code">
{% highlight sh %}
jeanp@~$ nmap -sV -sC 10.10.11.8
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-08 17:34 EDT
Nmap scan report for 10.10.11.8
Host is up (0.055s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Wed, 08 May 2024 21:34:26 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
...
{% endhighlight %}
</div>

We can't SSH into the machine without a password so let's check port 5000 first. The nmap returns a GET HTTP request so let's take a look at the website.



<div class="article-image">
  <img src="/assets/img/headless/homepage.png">
  <p>home page</p>
</div>

We are welcomed with a countdown, and if we click on the button we are taken to a form.

<div class="article-image">
  <img src="/assets/img/headless/supportform.png">
  <p>/support</p>
</div>

If we post data through the form, nothing interesting happens, we just get the same form back.

Let's use dirb now to see what else we can find.

<div class="article-code">
{% highlight sh %}
jeanp@~$ dirb http://10.10.11.8:5000/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed May  8 18:24:38 2024
URL_BASE: http://10.10.11.8:5000/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.11.8:5000/ ----
+ http://10.10.11.8:5000/dashboard (CODE:500|SIZE:265)                                        
+ http://10.10.11.8:5000/support (CODE:200|SIZE:2363)                                         
                                                                                              
-----------------
END_TIME: Wed May  8 18:33:59 2024
DOWNLOADED: 4612 - FOUND: 2
{% endhighlight %}
</div>

We get a 200 for /dashboard

<div class="article-image">
  <img src="/assets/img/headless/unauthorized.png">
  <p>/support</p>
</div>












