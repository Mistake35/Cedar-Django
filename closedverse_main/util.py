import urllib.request, urllib.error
# requests is only used for get_mii which is not being used currently
#import requests
from lxml import etree
import json
import time
import os.path
from PIL import Image, ImageFile #, ExifTags,
from datetime import datetime
from math import floor
from hashlib import md5, sha1
import io
import base64
from closedverse import settings
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

# the current source as of now uses AJAX to get mii data
def get_mii(id):
	# Using AccountWS
	dmca = {
		'X-Nintendo-Client-ID': 'a2efa818a34fa16b8afbc8a74eba3eda',
		'X-Nintendo-Client-Secret': 'c91cdb5658bd4954ade78533a339cf9a',
	}
	
	# Perform the first request to get pid
	url_pid = 'https://accountws.nintendo.net/v1/api/admin/mapped_ids?input_type=user_id&output_type=pid&input=' + id
	request_pid = urllib.request.Request(url_pid, headers=dmca)
	with urllib.request.urlopen(request_pid) as nnid_response:
		nnid_content = nnid_response.read()
	nnid_dec = etree.fromstring(nnid_content)
	pid = nnid_dec[0][1].text
	if not pid:
		return False
	
	# Perform the second request to get mii information
	url_mii = 'https://accountws.nintendo.net/v1/api/miis?pids=' + pid
	request_mii = urllib.request.Request(url_mii, headers=dmca)
	with urllib.request.urlopen(request_mii) as mii_response:
		mii_content = mii_response.read()
	try:
		mii_dec = etree.fromstring(mii_content)
	except:
		return False
	
	try:
		miihash = mii_dec[0][2][0][0].text.split('.net/')[1].split('_')[0]
	except IndexError:
		miihash = None
	screenname = mii_dec[0][3].text
	nnid = mii_dec[0][6].text
	
	return [miihash, screenname, nnid]

def recaptcha_verify(request, key):
	if not request.POST.get('g-recaptcha-response'):
		return False
	re_request = urllib.request.urlopen('https://www.google.com/recaptcha/api/siteverify?secret={0}&response={1}'.format(key, request.POST['g-recaptcha-response']))
	jsond = json.loads(re_request.read().decode())
	if not jsond['success']:
		return False
	return True

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
		return 'None'
	return str
	
""" Not using getipintel anymore
def getipintel(addr):
	# My router's IP prefix is 192.168.1.*, so this works in debug
	if settings.ipintel_email and not '192.168' in addr:
		try:
			site = urllib.request.urlopen('https://check.getipintel.net/check.php?ip={0}&contact={1}&flags=f'
			.format(addr, settings.ipintel_email))
		except:
			return 0
		return float(site.read().decode())
	else:
		return 0
"""

# not ideal, switch this to use a real cache when caching for everything else is implemented (never?)
iphub_cache = dict()

# Now using iphub
def iphub(addr, want_asn=False):
	# hack to exclude my private network at the time (security flaw?)
	if settings.IPHUB_KEY and not '192.168' in addr:
		if addr in iphub_cache:
			get_r = iphub_cache[addr]
			#print('getting ip ' + addr + ' from cache 😌')
		else:
			#print('GETTING IP ' + addr + ' FROM IPHUB😤😤😤😤😤😤')
			req = urllib.request.Request('http://v2.api.iphub.info/ip/' + addr, headers={'X-Key': settings.IPHUB_KEY})
			response = urllib.request.urlopen(req)
			data = response.read().decode()
			get_r = json.loads(data)
			iphub_cache[addr] = get_r
		if want_asn:
			return get_r.get('asn', '0')
		if get_r.get('block', 0) == 1:
			return True
		# should just return falsey when returning nothing anyway?
		#else:
		#	return False
