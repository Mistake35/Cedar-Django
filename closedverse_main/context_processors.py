from closedverse import settings
if not hasattr(settings, 'brand_name'):
	# use default app name by default as brand name
	from closedverse_main import apps
	brand_name = apps.ClosedverseMainConfig.verbose_name
else:
	brand_name = settings.brand_name

# variable for this and name are here for imports
brand_logo = settings.STATIC_URL + 'img/menu-logo.svg'

# the name of the function is merely what's imported into settings.py
def brand_name_universal(request):
	# this returns what's actually newly available to the template
	# so the name of the key actually dictates what you put in the tmpl
	return {"brand_name": brand_name, "brand_logo": brand_logo}
