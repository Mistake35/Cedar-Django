Readme thing

# YOU NEED
- Cloudflare
- A server (obviously)
- Terminal access (also obviously)
- Python 3

1.
SSH into your server.

2.
Time to update
$ sudo apt update && sudo apt upgrade

3.
You need Pip
$ sudo apt install pip

4.
Get everything else you need.
$ pip3 install Django==3.2.2 urllib3 lxml passlib bcrypt pillow django-markdown-deux django-markdown2 whitenoise django-colorfield django-admin-interface

5.
Clone the clone!
git clone https://github.com/Mistake35/Cedar-Django

5.5 (recommended).
You should use Filezilla or some other SFTP client to make things easier in the future.

6.
navigate to Cedar-Django
$ cd Cedar-Django

7.
Edit the settings.py file.
$ nano closedverse/settings.py

8.
Fill everything out as needed. Be sure to generate a secret key and paste it in too.

9.
Now it's time for the good stuff! 
Let's build the database
$ python3 manage.py migrate

10.
Do the static files or no CSS or JS.
$ python3 manage.py collectstatic

11.
Test the server!
Be sure to replace "IP-HERE" with your public IP and make sure it's running on port 80.
$ python3 manage.py runserver IP-HERE:80

# Troubleshooting time!
Q: "HELP I'M GETTING A BAD REQUEST (400) ERROR!"
A: Add your public IP to the ALLOWED_HOSTS bit in settings.py along with your domain that you'll be using.

Q: "django.db.utils.OperationalError: no such table: ban_usersban"
A: You forgot to migrate and make the database.

Q: "Why is the page white with no color or style at all?"
A: You need to collect the static files as mentioned prior.

Q: "KeyError: HTTP_CF_CONNECTING_IP"
A: Cloudflare is needed for this shit to work properly.

You may have to do some additional troubleshooting, and that's the joy of web-hosting.
Fixing problems yourself is a great way to learn how this shit works. 

# Yet even more steps

12.
So your server is running, the URL works and everything? Good.
Now it's time to create your account.
$ python3 manage.py createsuperuser
Enter your username, and password.

13.
Make sure its working by signing in.

14.
Alright now it's time to do some fun stuff! We're going to try and make this run at boot with systemd.
$ sudo nano /etc/systemd/system/django.service

15.
Paste this in!
Now it's time to change this if needed.
'''
[Unit]
Description=Django Application
After=network.target

[Service]
User=root
WorkingDirectory=/root/Cedar-Django
ExecStart=/usr/bin/python3 manage.py runserver IP-HERE:80

[Install]
WantedBy=multi-user.target
'''

16.
Pop these in!
$ sudo systemctl daemon-reload
$ sudo systemctl enable django
$ sudo systemctl start django
Make sure it works too!
$ sudo systemctl status django

17.
The final stretch! 
Set up your server with Cloudflare. You need a domain name, and you need patience as this can take some time to take effect.
If you do this final step right, Cedar should be working fine, and it should have HTTPS working too!
