from lxml import html
# Todo: move all requests to using requests instead of urllib3
import urllib.request, urllib.error
import requests
from lxml import etree
from random import choice
import json
import time
import os.path
from PIL import Image, ExifTags, ImageFile
from datetime import datetime
from binascii import crc32
from math import floor
from hashlib import md5, sha1
import io
from uuid import uuid4
import imghdr
import base64
from closedverse import settings
import re
from os import remove, rename

def HumanTime(date, full=False):
    now = time.time()
    time_difference = now - date
    time_units = {86400: 'day', 3600: 'hour', 60: 'minute'}
    if time_difference >= 259200 or full:
        return datetime.fromtimestamp(date).strftime('%m/%d/%Y %I:%M %p')
    elif time_difference <= 59:
        return 'Less than a minute ago'
    else:
        for unit, unit_name in time_units.items():
            if time_difference < unit:
                continue
            else:
                number_of_units = floor(time_difference / unit)
                if number_of_units > 1:
                    unit_name += 's'
                return f'{number_of_units} {unit_name} ago'

def get_mii(id):
	# Using AccountWS
	dmca = {
		'X-Nintendo-Client-ID': 'a2efa818a34fa16b8afbc8a74eba3eda',
		'X-Nintendo-Client-Secret': 'c91cdb5658bd4954ade78533a339cf9a',
	}
	# TODO: Make this, the gravatar request, and reCAPTCHA request escape (or plainly use) URL params
	nnid = requests.get('https://accountws.nintendo.net/v1/api/admin/mapped_ids?input_type=user_id&output_type=pid&input=' + id, headers=dmca)
	nnid_dec = etree.fromstring(nnid.content)
	del(nnid)
	pid = nnid_dec[0][1].text
	if not pid:
		return False
	del(nnid_dec)
	mii = requests.get('https://accountws.nintendo.net/v1/api/miis?pids=' + pid, headers=dmca)
	try:
		mii_dec = etree.fromstring(mii.content)
	# Can't be fucked to put individual exceptions to catch here
	except:
		return False
	del(mii)
	try:
		miihash = mii_dec[0][2][0][0].text.split('.net/')[1].split('_')[0]
	except IndexError:
		miihash = None
	screenname = mii_dec[0][3].text
	nnid = mii_dec[0][6].text
	del(mii_dec)
	
	# Also todo: Return the NNID based on what accountws returns, not the user's input!!!
	return [miihash, screenname, nnid]


def recaptcha_verify(request, key):
	if not request.POST.get('g-recaptcha-response'):
		return False
	re_request = urllib.request.urlopen('https://www.google.com/recaptcha/api/siteverify?secret={0}&response={1}'.format(key, request.POST['g-recaptcha-response']))
	jsond = json.loads(re_request.read().decode())
	if not jsond['success']:
		return False
	return True

ImageFile.LOAD_TRUNCATED_IMAGES = True
# This image upload code is fucked now thanks to pillow. I gotta go through it and refine it.
def image_upload(img, stream=False, drawing=False):
	# Decode the image
	decodedimg = img.read() if stream else base64.b64decode(img)
	# Open the image
	im = Image.open(io.BytesIO(decodedimg))
	# Check for EXIF data and rotate the image if necessary
	if hasattr(im, '_getexif'):
		orientation = 0x0112
		exif = im._getexif()
		if exif is not None:
			orientation = exif.get(orientation)
			rotations = {
				3: Image.ROTATE_180,
				6: Image.ROTATE_270,
				8: Image.ROTATE_90
			}
			if orientation in rotations:
				im = im.transpose(rotations[orientation])
	# Resize the image
	im.thumbnail((800, 800))
	# Check the aspect ratio if this is a drawing
	if drawing and ((im.size[0] / im.size[1]) < 0.30):
		return 1
	# Generate a hash of the image
	imhash = sha1(im.tobytes()).hexdigest()
	# Set the file format and location
	target = 'webp'
	floc = imhash + '.' + target
	# Save the file if it doesn't already exist
	if not os.path.exists(settings.MEDIA_ROOT + floc):
		im.save(settings.MEDIA_ROOT + floc, target, quality=80, method=6)
	# Return the URL of the file
	return settings.MEDIA_URL + floc

# Todo: Put this into post/comment delete thingy method
def image_rm(image_url):
	if settings.image_delete_opt:
		if settings.MEDIA_URL in image_url:
			sysfile = image_url.split(settings.MEDIA_URL)[1]
			sysloc = settings.MEDIA_ROOT + sysfile
			if settings.image_delete_opt > 1:
				try:
					remove(sysloc)
				except:
					return False
				else:
					return True
			# The RM'd directory to move it to
			rmloc = sysloc.replace(settings.MEDIA_ROOT, settings.MEDIA_ROOT + 'rm/')
			try:
				rename(sysloc, rmloc)
			except:
				return False
			else:
				return True
		else:
			return False

def get_gravatar(email):
	try:
		page = urllib.request.urlopen('https://gravatar.com/avatar/'+ md5(email.encode('utf-8').lower()).hexdigest() +'?d=404&s=128')
	except:
		return False
	return page.geturl()

def filterchars(str=""):
	# If string is blank, None, any other object, etc, make it whitespace so it's detected by isspace.
	if not str:
		str = " "
	# Forbid chars in this list, currently: Right-left override, largest Unicode character.
	# Now restricting everything in https://www.reddit.com/r/Unicode/comments/5qa7e7/widestlongest_unicode_characters_list/
	forbid = ["\u202e", "\ufdfd", "\u01c4", "\u0601", "\u2031", "\u0bb9", "\u0bf8", "\u0bf5", "\ua9c4", "\u102a", "\ua9c5", "\u2e3b", "\ud808", "\ude19", "\ud809", "\udc2b", "\ud808", "\udf04", "\ud808", "\ude1f", "\ud808", "\udf7c", "\ud808", "\udc4e", "\ud808", "\udc31", "\ud808", "\udf27", "\ud808", "\udd43", "\ud808", "\ude13", "\ud808", "\udf59", "\ud808", "\ude8e", "\ud808", "\udd21", "\ud808", "\udd4c", "\ud808", "\udc4f", "\ud808", "\udc30", "\ud809", "\udc2a", "\ud809", "\udc29", "\ud808", "\ude19", "\ud809", "\udc2b"]
	for char in forbid:
		if char in str:
			str = str.replace(char, " ")
	if str.isspace():
		try:
			girls = json.load(open(settings.BASE_DIR + '/girls.json'))
		except:
			girls = ['None']
		return choice(girls)
	return str

# Check IP for proxy.
def iphub(addr):
	if settings.iphub_key and not '192.168' in addr:
		get = requests.get('http://v2.api.iphub.info/ip/' + addr, headers={'X-Key': settings.iphub_key})
		if get.json()['block'] == 1:
			return True
		else:
			return False

# NNID blacklist check
def nnid_blacked(nnid):
	blacklist = json.load(open(settings.nnid_forbiddens))
	# The NNID server omits dashes and dots from NNIDs, gotta make sure nobody gets through this
	nnid = nnid.lower().replace('-', '').replace('.', '')
	if nnid in blacklist:
		return True
	return False
