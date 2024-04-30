---
layout: article
title:  "ProxyAsAService - HackTheBox Writeup"
date: "2024-04-29"
---

By looking at the name of the challenge and glancing over the code, we can assume we will have to exploit faulty configurations in some proxy to get our flag.

<div class="article-image">
  <img src="/assets/img/proxyasaservice/homepage.png">
  <p>home screen</p>
</div>

Clicking on either one of the buttons will take us to the legitimate Reddit website, so if we can't really go further than this using the UI, we might have to rely on exploiting the proxy using only the URL box. Strangely, the URL has a url parameter appended to it, `?url=/r/cats`. If we try deleting this, we get a JSON response with a 404 error.

<div class="article-image">
  <img src="/assets/img/proxyasaservice/404error.png">
  <p>/r/cats/</p>
</div>

It's time to look at some code to understand what's happening. Luckily there aren't many files.

<div class="article-code">
  {% highlight python %}
from application.app import app
  
app.run(host='0.0.0.0', port=1337)
  {% endhighlight %}
  <p>run.py</p>
</div>

Now we know the application is running on port 1337 inside the server's local network. The server's router is receiving requests on a random port, like port 32817 in this case, and then forwarding the requests to the application hosted with port 1337 on local.

Let's open the `application` folder and check some files inside.

<div class="article-code">
{% highlight python %}
from flask import Flask, jsonify
from application.blueprints.routes import proxy_api, debug

app = Flask(__name__)
app.config.from_object('application.config.Config')

app.register_blueprint(proxy_api, url_prefix='/')
app.register_blueprint(debug, url_prefix='/debug')

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not Found'}), 404

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Not Allowed'}), 403

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad Request'}), 400
{% endhighlight %}
<p>app.py</p>
</div>

This file registers the blueprints `proxy_api` and `debug` with a prefix of `/debug`. Also, we can now notice why navigating to `http://83.136.255.150:32817/r/cats` returned us a JSON with `error: "Not Found"` - all the errors are handled through this file.

Let's check what code is responsible for displaying our flag.

<div class='article-code'>
{% highlight python %}
@debug.route('/environment', methods=['GET'])
@is_from_localhost
def debug_environment():
    environment_info = {
        'Environment variables': dict(os.environ),
        'Request headers': dict(request.headers)
    }

    return jsonify(environment_info)
{% endhighlight %}
    <p>routes.py</p>
</div>


`debug_environment()` returns the environment variables in JSON.

<div class="article-image">
  <img src="/assets/img/proxyasaservice/notallowed.png">
  <p>/debug/environment/</p>
</div>

We can't directly navigate to the route because this function is decorated with `@is_from_localhost`.

<div class='article-code'>
{% highlight python %}
def is_from_localhost(func):
    @functools.wraps(func)
    def check_ip(*args, **kwargs):
        if request.remote_addr != '127.0.0.1':
            return abort(403)
        return func(*args, **kwargs)
    return check_ip
{% endhighlight %}
    <p>util.py</p>
</div>

`def is_from_localhost(func):` takes a function as a parameter, which in this case is `debug_environment()` since the decorator was declared inside this function.

To understand these calls a little better, here's a more intuitive snippet of code:

<div class='article-code'>
{% highlight python %}
def dogs(func):
    print("I love dogs!") # Print
    func() # Call cats(), which will print too

@dogs # Execute dogs() and pass cats() as the func param
def cats():
    print("I love cats!")
{% endhighlight %}
</div>

<div class='article-code'>
{% highlight sh %}
└─$ python test.py

I love dogs!
I love cats!
{% endhighlight %}
</div>

`cats()` is able to run its code because the decorator calls `dogs()` and it takes `cats()` as the `func` parameter.

`is_from_localhost(func)` checks if the Remote_Addr header from the request is coming from localhost. This is a bad idea because if there's a proxy in your local network, then the condition `if request.remote_addr != '127.0.0.1':` becomes obsolete. Let's explain this with a diagram:

<div class="article-image">
  <img src="/assets/img/proxyasaservice/diagram.png">
</div>

The query to the `/debug/environment` route doesn't go through the proxy, so in the request headers, the `Remote_Addr` is still our client IP. Thus, once our request goes through the condition `if request.remote_addr != '127.0.0.1':`, we get a 403 error. 

Let's now show what happens when you instead use the proxy.

<div class="article-image">
  <img src="/assets/img/proxyasaservice/diagram2.png">
</div>

This is why using the `Remote_Addr` header instead of `X-Forwarded-For` to know where the request came from when you have a proxy in your local network is a bad idea.

If the user is able to send their request through the proxy, they will easily bypass the security check `if request.remote_addr != '127.0.0.1':`. In fact, this is something that happened in real life with StackOverflow's website early development: [Anatomy of an Attack: How I Hacked StackOverflow][StackOverflow].

Okay, so now we know we have to use the proxy function to make it do a request to `/debug/environment` for us.

<div class='article-code'>
{% highlight python %}
@proxy_api.route('/', methods=['GET', 'POST'])
def proxy():
    url = request.args.get('url')

    if not url:
        cat_meme_subreddits = [
            '/r/cats/',
            '/r/catpictures',
            '/r/catvideos/'
        ]

        random_subreddit = random.choice(cat_meme_subreddits)

        return redirect(url_for('.proxy', url=random_subreddit))
    
    target_url = f'http://{SITE_NAME}{url}'
    response, headers = proxy_req(target_url)

    return Response(response.content, response.status_code, headers.items())
{% endhighlight %}
<p>routes.py</p>
</div>

But here we stumble upon two problems...

The first one is, the `target_url` is hardcoded with `reddit.com` as the domain, so if we send a request to `http://94.237.62.195:45170/?url=/debug/environment`, the target url will be converted into `http://reddit.com/debug/environment`, which is not the host we want to reach.

<div class='article-code'>
{% highlight python %}
RESTRICTED_URLS = ['localhost', '127.', '192.168.', '10.', '172.']

def is_safe_url(url):
    for restricted_url in RESTRICTED_URLS:
        if restricted_url in url:
            return False
    return True
{% endhighlight %}
</div>

<div class='article-code'>
{% highlight python %}
def proxy_req(url):    
    method = request.method
    headers =  {
        key: value for key, value in request.headers if key.lower() in ['x-csrf-token', 'cookie', 'referer']
    }
    data = request.get_data()

    response = requests.request(
        method,
        url,
        headers=headers,
        data=data,
        verify=False
    )

    if not is_safe_url(url) or not is_safe_url(response.url):
        return abort(403)
    
    return response, headers
{% endhighlight %}
<p>util.py</p>
</div>

The second problem is the proxy function is calling `is_safe_url(url)` to check if our url param contains any localhost strings. This fix is easy enough - we just have to use `0.0.0.0` instead of any of the restricted URLs `['localhost', '127.', '192.168.', '10.', '172.']`.

I spent hours trying to figure out how to make a request to the host I wanted with a hardcoded url in the way, until I stumbled upon this documentation: [Access using credentials in the URL][Firefox].

In short, you can avoid login prompts by using an encoded URL:

`https://username:password@www.example.com/`

<div class="article-image">
  <img src="/assets/img/proxyasaservice/authentication.png">
</div>

The website doesn't have any login functionality, but this syntax allows us to ignore the `reddit.com` domain and instead call ours after the @ symbol.

Let's try it out. We must remember to call the application by its local port, not the public one, so we append `:1337` at the end of the IP as specified in the `run.py` file.

<div class="article-image">
  <img src="/assets/img/proxyasaservice/flag.png">
<p>http://94.237.62.195:45170/?url=@0.0.0.0:1337/debug/environment</p>
</div>

The application successfully returns a response showing all the environment variables, including the flag.


[Firefox]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication#access_using_credentials_in_the_url

[StackOverflow]: https://blog.ircmaxell.com/2012/11/anatomy-of-attack-how-i-hacked.html




































































