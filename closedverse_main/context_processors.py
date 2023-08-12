try:
	from closedverse.settings import brand_name
except ImportError:
	# use default app name by default as brand name
	from closedverse_main import apps
	brand_name = apps.ClosedverseMainConfig.verbose_name

# the name of the function is merely what's imported into settings.py
def brand_name_universal(request):
	# this returns what's actually newly available to the template
	# so the name of the key actually dictates what you put in the tmpl
	return {"brand_name": brand_name}
