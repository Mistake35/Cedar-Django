"""closedverse URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path, re_path
from django.views.static import serve

#from closedverse_main import urls
from closedverse.settings import STATIC_URL

# determine static root for admin app
#admin_root = admin.__file__.replace('__init__.py', 'static/admin')
# Set internal server error handler
handler500 = 'closedverse_main.views.server_err'
urlpatterns = [
    path('admin/', admin.site.urls),
    # edit - the below snippet and admin_root variable are only for if you don't want to use whitenoise
    # translation: i made all of this before realizing whitenoise could serve it lmao

    # serve static for admin, in production? since admin is the only app now
    # accomodations might be needed for other apps (e.g silk?)
    # also the slice is meant to normalize e.g static_url being '/s/' to just 's/', etc. (is this necessary? prob not)
    #re_path(r'^'+STATIC_URL[1:]+'admin/(?P<path>.*)$', serve, {'document_root': admin_root}),

    # URLs for Closedverse
    path('', include('closedverse_main.urls'))
]
