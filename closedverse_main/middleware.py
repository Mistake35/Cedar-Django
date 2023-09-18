from django.http import HttpResponseForbidden
from closedverse import settings
from django.shortcuts import redirect, render
from .models import Ban
from django.utils import timezone
from re import compile

# Taken from https://python-programming.com/recipes/django-require-authentication-pages/
if settings.FORCE_LOGIN:
	EXEMPT_URLS = [compile(settings.LOGIN_URL.lstrip('/'))]
	if hasattr(settings, 'LOGIN_EXEMPT_URLS'):
		EXEMPT_URLS += [compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]

def get_client_ip(request):
	try:
		x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
		if x_forwarded_for and ',' not in x_forwarded_for:
			ip = x_forwarded_for.split(',')[0]
		else:
			ip = request.META.get('REMOTE_ADDR')

		# for Cloudflare
		ip = request.META.get('HTTP_CF_CONNECTING_IP', ip)

	except Exception:
		ip = request.META.get('REMOTE_ADDR')

	return ip


class ProxyMiddleware:
	def __init__(self, get_response):
		self.get_response = get_response

	def __call__(self, request):
		request.META['REMOTE_ADDR'] = get_client_ip(request)
		response = self.get_response(request)
		return response

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
			expiry_date__gte=timezone.now()).first()
		if active_user_ban:
			context = {'ban': active_user_ban}
			return render(request, 'ban.html', context)
		# Get one active ban that is not expired for the IP address
		ip_address = request.META.get('REMOTE_ADDR')
		active_ip_ban = Ban.objects.filter(
		ip_address=ip_address,
		active=True,
		expiry_date__gte=timezone.now(),).first()
		if active_ip_ban:
			context = {'ban': active_ip_ban}
			return render(request, 'ban.html', context)
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
		response = self.get_response(request)
		if request.user.is_authenticated:
			# for reverse proxy
			response['X-Username'] = request.user.username

		return response
