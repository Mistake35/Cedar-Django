from django.shortcuts import render
from django.http import HttpResponseForbidden
from .models import UsersBan

class BanManagement():
    """Users Management"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if(UsersBan.objects.all().filter(ban=True, user_id=request.user.id)):
            return HttpResponseForbidden('Commit suicide')
        elif request.user.is_authenticated:
            if not request.user.is_active():
                return HttpResponseForbidden(request.user.warned_reason)
            else:
                return response
        else:
            return response
