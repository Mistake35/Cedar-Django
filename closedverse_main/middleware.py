from django.http import HttpResponseForbidden
from closedverse import settings
from django.shortcuts import redirect
from django.contrib.auth import logout
from .models import Ban
from django.utils import timezone
from re import compile

# Taken from https://python-programming.com/recipes/django-require-authentication-pages/
if settings.FORCE_LOGIN:
	EXEMPT_URLS = [compile(settings.LOGIN_URL.lstrip('/'))]
	if hasattr(settings, 'LOGIN_EXEMPT_URLS'):
		EXEMPT_URLS += [compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]

class CheckForBanMiddleware:
	def __init__(self, get_response):
		self.get_response = get_response

	def __call__(self, request):
		response = self.get_response(request)
		return response

	def process_view(self, request, view_func, view_args, view_kwargs):
		if not request.user.is_authenticated:
			return None
		# Get one active ban that is not expired for the user
		active_user_ban = Ban.objects.filter(
			to=request.user,
			active=True,
			expiry_date__gte=timezone.now()
		).first()
		if active_user_ban:		   
			return HttpResponseForbidden('You are banned from this site. Reason: ' + active_user_ban.reason)
		# Get one active ban that is not expired for the IP address
		ip_address = request.META.get('REMOTE_ADDR')
		active_ip_ban = Ban.objects.filter(
			ip_address=ip_address,
			active=True,
			expiry_date__gte=timezone.now(),
		).first()
		if active_ip_ban:
			return HttpResponseForbidden('Your IP address is banned from this site. Reason: ' + active_ip_ban.reason)
		return None

class ClosedMiddleware(object):
	def __init__(self, get_response):
		self.get_response = get_response

	def __call__(self, request):
		# Force logins if it's set
		if settings.FORCE_LOGIN and not request.user.is_authenticated:
			if not any(m.match(request.path_info.lstrip('/')) for m in EXEMPT_URLS):
				if request.headers.get('x-requested-with') == 'XMLHttpRequest':
					return HttpResponseForbidden("Login is required")
				return redirect(settings.LOGIN_REDIRECT_URL)
		# Fix this ; put something in settings signifying if the server supports HTTPS or not
		#if not request.is_secure() and (not settings.DEBUG) and settings.CLOSEDVERSE_PROD:
			# Let's try to redirect to HTTPS for non-Nintendo stuff.
		"""
		if not request.META.get('HTTP_USER_AGENT'):
			return HttpResponseForbidden("You need a user agent.", content_type='text/plain')
		if settings.CLOSEDVERSE_PROD not request.is_secure() and not 'Nintendo' in request.META['HTTP_USER_AGENT']:
			return redirect('https://{0}{1}'.format(request.get_host(), request.get_full_path()))
		"""
		if request.user.is_authenticated:
			"""
			if not request.user.is_active():
				if request.user.warned_reason:
					ban_msg = request.user.warned_reason
				else:
					ban_msg = 'You are banned.'
				return HttpResponseForbidden(ban_msg)
			"""
			# can just forbid post requests for the time being (but leav our funny logout message :3)
			if not request.user.is_active() and request.method != 'GET' and request.get_full_path() != '/logout/':
				return HttpResponseForbidden()
		response = self.get_response(request)
		if request.user.is_authenticated:
			# for reverse proxy
			response['X-Username'] = request.user.username

		return response
