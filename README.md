# About
Cedar-Django is a fork of Closedverse with custom features added to it.

### Theme changing
Just like in Indigo, you can change the color of your theme. While this is only visible to each user specifically, a global theme can be set in Settings.py.

### Overhauled admin panel
The admin panel has been changed completely. You can now do a lot more things in a much easier way. The intention behind this redesign is to reduce the need to use the normal Django admin panel.

### Community creation
You can have your users make communities. Each user by default can make one community. User communities can be changed by the owner of said community.

### Password resetting within the settings page
**This should've been a thing since day one.** Instead of being forced to reset your password through your email, you can now change it via settings.

### Invite only features
**You can set `invite_only` to `True` if you want your site to be invite only** If you choose to make your website invite only, users can create invite codes and send them to others as a means of inviting new people to the website.  Upon signing up, users are required to input a valid invite code in order to create an account. This can be useful for closed off communities or as a ditch effort to stop raids or whatever.
Moderators and staff will be able to revoke a user's ability to add new users if need be.

### Announcements appear on the side of the main page.
If you have an announcement community, each post will appear there.

`welcomemsgs` are visible on the front page when you aren't signed in.

## Other features include:
- Mods can warn users.
- Better audit logging system.
- Purging is much easier now.
- You can fucking ban people now without the Django panel.
- Users and admins can turn off comments on posts.
- Each and every ban is an IP ban automatically.
- A page where every user can view collected data tied to their account.

# YOU NEED
- A server (obviously)
- Terminal access (also, obviously)
- Access to the sudo command
- Python 3
- Django 3.2.2
- urllib3
- lxml
- passlib
- bcrypt
- pillow
- django-markdown-deux
- django-markdown2
- whitenoise
- django-xff

# Install time

Should probably say that this is a lazy way to do it. You should use a reverse proxy to deploy the server up for prod.

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
`pip3 install Django==3.2.2 urllib3 lxml passlib bcrypt pillow django-markdown-deux django-markdown2 whitenoise django-xff`

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
Be sure to replace "IP-HERE" with your public IP and make sure it's running on port 80.
`python3 manage.py runserver IP-HERE:80`

# Troubleshooting time!
Q: "HELP, I'M GETTING A BAD REQUEST (400) ERROR!"
A: Add your public IP to the `ALLOWED_HOSTS` bit in settings.py along with your domain that you'll be using.

Q: "django.db.utils.OperationalError: no such table: ban_usersban"
A: You forgot to migrate and make the database.

Q: "Why is the page white, with no color or style at all?"
A: You need to collect the static files as mentioned prior.

You may have to do some additional troubleshooting, and that's the joy of web-hosting.
Fixing problems yourself is a great way to learn how this shit works.

# Yet even more steps

12.
So your server is running, the URL works and everything? Good.
Now it's time to create your account.
`python3 manage.py createsuperuser`
Enter your username, and password.

13.
Make sure it's working by signing in.

14.
Alright now it's time to do some fun stuff! We're going to try and make this run at boot with systemd.
`sudo nano /etc/systemd/system/django.service`

15.
Paste this in!
Now it's time to change this if needed.
```
[Unit]
Description=Django Application
After=network.target

[Service]
User=root
WorkingDirectory=/root/Cedar-Django
ExecStart=/usr/bin/python3 manage.py runserver IP-HERE:80

[Install]
WantedBy=multi-user.target
```

16.
Pop these in!
```
sudo systemctl daemon-reload
sudo systemctl enable django
sudo systemctl start django
```
Make sure it works too!
```
sudo systemctl status django
```
