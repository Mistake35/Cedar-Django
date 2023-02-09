from django.shortcuts import render
from closedverse_main.models import User
from django.conf import settings

in_maintenance = False

class MaintenanceManagement():
    """Maintenance Management"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        current_url = request.path_info
        SURL = settings.STATIC_URL
        
        if(in_maintenance):
            if SURL in current_url:
                return response
            else:
                return render(request, 'mv.html')
        else:
            return response
        '''
            try:
                if SURL in current_url:
                    return response
                elif not(User.is_staff(request.user)):
	                return render(request, 'mv.html')
                else:
                    return response
            except:
                return render(request, 'mv.html')
        else:
            return response
'''