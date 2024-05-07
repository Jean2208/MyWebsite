---
layout: article
title:  "Insomnia - HackTheBox Writeup"
date: "2024-04-27"
image: "/assets/img/insomnia/homescreen.png"
---

Insomnia is a PHP website challenge in HackTheBox that features a vulnerability in the login functionality, allowing us to bypass password checks for the administrator user.

When opening up the website, we can see that it has both Login and Register functionality.

<div class="article-image">
  <img src="/assets/img/insomnia/homescreen.png">
  <p>home screen</p>
</div>

After signing up and logging in, we are greeted with the following screen.

<div class="article-image">
  <img src="/assets/img/insomnia/greeted.png">
  <p>/index.php/profile</p>
</div>

Now, let's take a look at some code. 

<div class="article-code">
  {% highlight sh %}
sqlite3 /var/www/html/Insomnia/database/insomnia.db <<'EOF'
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);
INSERT INTO users (username, password) VALUES ('administrator', LOWER(hex(randomblob(16))));
EOF

# Create JWT secret key
echo "JWT_SECRET='$(openssl rand -hex 32)'" >> /var/www/html/Insomnia/.env
  {% endhighlight %}
  <p>entrypoint.sh</p>
</div>

The code creates a .db file with a `users` table and inserts an `administrator` username alongside a random password. We might have to steal the password of the administrator to get our flag.

At first glance, this password is not really bruteforceable. It's a 16 random byte string, which if we wanted to bruteforce, would take us up to 16^32 combinations to crack. 16 being all possible characters (a-f) and (0-9), and 32 being the length of the string since every byte is made up of 2 characters, so 16 * 2 = 32.

The same goes for the JWT Secret generated and stored in the environment table.

Let's check the `Controllers` folder, since this folder handles all the backend logic in websites.

<div class="article-code">
  {% highlight php %}
class ProfileController extends BaseController
{
    public function index()
    {
        $token = (string) $_COOKIE["token"] ?? null;
        $flag = file_get_contents(APPPATH . "/../flag.txt");
        if (isset($token)) {
            $key = (string) getenv("JWT_SECRET");
            $jwt_decode = JWT::decode($token, new Key($key, "HS256"));
            $username = $jwt_decode->username;
            if ($username == "administrator") {
                return view("ProfilePage", [
                    "username" => $username,
                    "content" => $flag,
                ]);
            } else {
                $content = "Haven't seen you for a while";
                return view("ProfilePage", [
                    "username" => $username,
                    "content" => $content,
                ]);
            }
        }
    }
}
  {% endhighlight %}
  <p>ProfileController.php</p>
</div>

Here we find some important information: `$flag = file_get_contents(APPPATH . "/../flag.txt")`. The contents of the flag are stored in a `$flag` variable, which is later passed to the view under one condition: `if ($username == "administrator")`. Otherwise, the user will get the default message "Haven't seen you for a while". Here's the relevant part of the code in the profile view:

<div class="article-code">
  {% highlight php %}
<div class="home__container">
    <div class="home__title">
        Welcome back <?= $username ?>
    </div>
    <div class="home__desc">
        <?= $content ?>
    </div>
</div>
  {% endhighlight %}
  <p>ProfilePage.php</p>
</div>

By this point, we know that exploiting the app using the JWT Secret is not really possible since it's using a random private key to decode its contents. So let's switch our attention to the login logic.

<div class="article-code">
  {% highlight php %}
public function login()
{
    $db = db_connect();
    $json_data = request()->getJSON(true);
    if (!count($json_data) == 2) {
        return $this->respond("Please provide username and password", 404);
    }
    $query = $db->table("users")->getWhere($json_data, 1, 0);
    $result = $query->getRowArray();
    if (!$result) {
        return $this->respond("User not found", 404);
  {% endhighlight %}
  <p>UserController.php</p>
</div>

Here I spent some time trying to figure out what was wrong with this code. I was curious about this `getWhere($json_data, 1, 0)` function, as I didn't know what the second and third parameters meant. So I relied on AI for some quick info and got the following:

- The 1 parameter specifies that only one row should be retrieved (limit is set to 1).
- The 0 parameter indicates that no rows should be skipped (offset is set to 0).

With these parameters, the SQL command turns out to be `SELECT * FROM users WHERE username = 'admin' AND password = 'pass123' LIMIT 1 OFFSET 0;`

Not too interesting, but at the end of the response, it mentioned this function is vulnerable to SQL injections. This definitely caught my attention, so I decided to test it out.

<div class="article-image">
  <img src="/assets/img/insomnia/sqlinjection.png">
  <p>BurpSuite</p>
</div>

Unfortunately, this did not work. I got stuck for a while, until I decided to take a look at this `if (!count($json_data) == 2)` condition again. It just didn't seem right every time I would look at it.

Turns out this condition is not correct. Let's break it down:

`count($json_data)`: gives you the count of elements in the JSON body.

`!count($json_data)`: negates the outpout of count.

Let's test this inside a PHP script to see how it behaves.

<div class="article-code">
  {% highlight php %}
<?php

var_dump(!0); // if (true == 2)
var_dump(!1); // if (false == 2)
var_dump(!5); // if (false == 2)
  {% endhighlight %}
</div>

<div class="article-code">
  {% highlight sh %}
└─$ php test.php

bool(true)
bool(false)
bool(false)
  {% endhighlight %}
</div>

So if we try sending 0 elements in the JSON body, the if condition will run, and the return statement will hit.

But if we try sending more than 0 elements, the if condition will never run, and the return statement will never hit. Hence, if the return statement never hits, the rest of the code executes, and the `getWhere()` function will check for a matching user in the `users` table with whatever info we pass in the JSON. And this info can be only the username, no password included.

<div class="article-image">
  <img src="/assets/img/insomnia/adminlogin.png">
  <p>BurpSuite</p>
</div>


Login for administrator using only the username is successful, and the flag is displayed on the website.

<div class="article-image">
  <img src="/assets/img/insomnia/flag.png">
  <p>/index.php/profile</p>
</div>




























