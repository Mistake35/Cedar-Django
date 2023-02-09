"""closedverse URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include

from django.contrib import admin
from .settings import INSTALLED_APPS, MEDIA_ROOT, MEDIA_URL
from django.conf.urls.static import static
handler500 = 'closedverse_main.views.server_err'
urlpatterns = [
    url(r'^admin/', admin.site.urls),
	url(r'^', include('closedverse_main.urls'))
]

if 'silk' in INSTALLED_APPS:
	urlpatterns += [url(r'^silk/', include('silk.urls', namespace='silk'))]

urlpatterns += static(MEDIA_URL, document_root=MEDIA_ROOT)
