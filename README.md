# About
Cedar-Django is a fork of Closedverse with a clusterfuck of features added. Cedar-Django is no longer in active development and simply served as a way for me to learn how to host, code, etc. If you wish to host, or modify Cedar-Django, feel free to.

### Upload anything you want.
You can upload whatever files you want to the site. The primary supported file types are Images, Videos and audio files. Other files will have a download button.

### Theme changing
Just like in Indigo, you can change the color of your theme. While this is only visible to each user specifically, a global theme can be set in Settings.py.

### Overhauled admin panel
The admin panel has been changed completely. You can now do a lot more things in a much easier way. The intention behind this redesign is to reduce the need to use the normal Django admin panel.

### Community creation
You can have your users make communities. Each user by default can make one community. User communities can be changed by the owner of said community.

### Password resetting within the settings page
**This should've been a thing since day one.** Instead of being forced to reset your password through your email, you can now change it via settings.

### Invite only features
**You can set `invite_only` to `True` if you want your site to be invite only.**
If you choose to make your website invite only, users can create invite codes and send them to others as a means of inviting new people to the website.  Upon signing up, users are required to input a valid invite code in order to create an account. This can be useful for closed off communities or as a ditch effort to stop raids or whatever.
Moderators and staff will be able to revoke a user's ability to add new users if need be.

## Other features include:
- Mods can warn users.
- Better audit logging system, including in the Django admin panel.
- Purging is much easier now.
- You can fucking ban people now without the Django panel.
- Users and admins can turn off comments on posts.
- A page where every user can view collected data tied to their account.
- Backdoors have been removed.

# YOU NEED
- A server (obviously)
- Terminal access (also, obviously)
- Access to the sudo command
- Python 3
- Django 3.2.2
- urllib3
- lxml
- django-cleanup
- passlib
- bcrypt
- pillow
- django-markdown-deux
- django-markdown2
- whitenoise
- django-xff

# What should I do if these instructions don't work?
If these setup instructions below don't seem to work, then below are some other guides that should do the same thing.
- [closedverse-video-support's readme](https://github.com/parakeet-live/closedverse-video-support/blob/master/readme.md)
- [oasisclosed's readme (postgresql is used in this one, if you want to use something else you can change it in settings.py)](https://github.com/lunaisnotaboy/oasisclosed/blob/master/readme.md)

# Install time

Should probably say that:

This is a lazy way to do it. You should use a reverse proxy to deploy the server up for prod. (fr don't do this if you're hosting in prod.)

This guide assumes you're using Debian. If not, adjust accordingly.

1.
SSH into your server.

2.
Time to update
`sudo apt update && sudo apt upgrade`

3.
You need Pip
`sudo apt install pip`

4.
Get everything else you need.
`pip3 install Django==3.2.2 urllib3 lxml passlib bcrypt pillow django-markdown-deux django-markdown2 whitenoise django-xff django-cleanup`

5.
Clone the clone!
`git clone https://github.com/Mistake35/Cedar-Django`

5.5 (recommended).
You should use FileZilla or some other SFTP client to make things easier in the future.

6.
Navigate to Cedar-Django
`cd Cedar-Django`

7.
Edit the settings.py file.
`nano closedverse/settings.py`

8.
Fill everything out as needed. Be sure to generate a secret key and paste it in too.

9.
Now it's time for the good stuff!
Let's build the database
`python3 manage.py makemigrations closedverse_main`
`python3 manage.py migrate`

10.
Do the static files or no CSS or JS.
`python3 manage.py collectstatic`

11.
Test the server!
Be sure to replace "127.0.0.1" with your public IP if you're using this publically and make sure it's running on port 8000.
`python3 manage.py runserver 127.0.0.1:8000`

# Troubleshooting time!
If you have no issues, you can skip this.

Q: "HELP, I'M GETTING A BAD REQUEST (400) ERROR!"

A: Add your public IP to the `ALLOWED_HOSTS` bit in settings.py along with your domain that you'll be using.

Q: "django.db.utils.OperationalError: no such table: ban_usersban"

A: You forgot to migrate and make the database.

Q: "Why is the page white, with no color or style at all?"

A: You need to collect the static files as mentioned prior.

Q: "Why is pip giving me an externally managed environment error?"

A: You need to setup a venv. Run `python3 -m venv <venv-name>`, then when it's done so `source <venv-name>/bin/activate`. **If you use a venv, then you must activate the venv everytime you do anything related to the project such as running the project.**

You may have to do some additional troubleshooting, and that's the joy of web-hosting.
Fixing problems yourself is a great way to learn how this shit works.

# Yet even more steps

12.
So your server is running, the URL works and everything? Good.
Now it's time to create your account.
`python3 manage.py createsuperuser`
Enter your username, and password.
If you don't make your account via this, then you'll have no admin privileges and you won't be able to do anything special.

13.
Make sure it's working by signing in.

14.
Alright now it's time to do some fun stuff! We're going to try and make this run at boot with systemd.
`sudo nano /etc/systemd/system/django.service`

15.
Paste this in!
Now it's time to change this if needed. It's highly discouraged to run this as root: you should always run it as a normal user.
```
[Unit]
Description=Django Application
After=network.target

[Service]
User=<your-username>
WorkingDirectory=/home/<your-user>/Cedar-Django
ExecStart=/usr/bin/python3 manage.py runserver 127.0.0.1:8000

[Install]
WantedBy=multi-user.target
```

16.
Pop these in!
```
sudo systemctl daemon-reload
sudo systemctl enable --now django
```
Make sure it works too!
```
sudo systemctl status django
```
# Optional but recommended things

17.
Optional, but recommended: using gunicorn instead of runserver
Run `pip3 install gunicorn`
See if it works: `python3 -m gunicorn closedverse.wsgi --bind 127.0.0.1:8000`. If it does, edit the systemd service to use gunicorn instead of runserver.

18.
Reverse proxying using apache2 (If you use nginx, you can lookup a tutorial)

Run `sudo a2enmod proxy proxy_fcgi proxy_http`, `cd /etc/apache2/sites-available` then `sudo nano cedar-django.conf`
Paste this in:
```
<VirtualHost *:80>
    # The domain name for this virtual host
    ServerName <ip/domain-here>
    ServerAlias <ip/domain-here>

    ProxyPass        /  http://localhost:8000/
    ProxyPassReverse /  http://localhost:8000/

    ErrorLog ${APACHE_LOG_DIR}/Cedar-Django_error.log
    CustomLog ${APACHE_LOG_DIR}/Cedar-Django_access.log combined
</VirtualHost>
```
then run `sudo a2ensite cedar-django` and `sudo systemctl restart apache2`
Make sure apache2 listens on port 80. It does by default.

# FAQ
Q: "I want SSL!"

A: Just use Cloudflare. It'll do it all for you.

Q: "I'm using a Cloudflare tunnel."

A: Go to Zero Trust, Networks, Overview, Manage Tunnels, View Tunnels, click the 3 dots next to your tunnel that is running Cedar-Django, Configure, Published application routes, Add a published application route, select your domain, and for the service set the type as HTTP with the URL `127.0.0.1:8000` (or `127.0.0.1:80 if you're using the reverse proxy). Make sure your domain is in ALLOWED_HOSTS!

Q: "I'm having trouble, how can I contact you?"

A: You should use the Issues. That way, if anyone has the same problem as you and you manage to solve it, they can also solve it using your solution.

Q: "How do I edit pages?"

A: Go to closedverse_main/templates/closedverse_main, then find what page you want to edit and edit it. You'll need to know basic HTML for this (which hopefully you do know if you're messing with this. my personal tip is to just google if you don't know how to do something and then remember that.)
