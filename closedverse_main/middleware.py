from django.http import HttpResponseForbidden, HttpResponseBadRequest
from closedverse import settings
from django.shortcuts import render
from django.shortcuts import redirect
from django.contrib.auth import logout
from re import compile

class ClosedMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.user.is_authenticated:
            if not request.user.profile():
                return HttpResponseForbidden('So, Somehow your profile is completely gone. Your account itself still exists, but your profile does not. Please contact an admin, and ask them to make a profile for you. If you are unable to contact someone, you should make a new account.')
            else:
                return response
                '''
        for keyword in ['24.61.157.95', ]:
            if keyword in request.META['HTTP_CF_CONNECTING_IP']:
                return redirect('https://file.garden/Xbo5elapeDSxWf1x/adam.mp4')

        for keyword in ['PlayStation', 'Switch', '3DS', ]:
            if keyword in request.META['HTTP_USER_AGENT']:
                return HttpResponseForbidden('Error code 403')
        '''
        else:
            return response

# Taken from https://python-programming.com/recipes/django-require-authentication-pages/
'''
class ClosedMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Force logins if it's set
        if settings.force_login and not request.user.is_authenticated:
            if not any(m.match(request.path_info.lstrip('/')) for m in EXEMPT_URLS):
                if request.is_ajax():
                    return HttpResponseForbidden("Login is required")
                return redirect(settings.LOGIN_REDIRECT_URL)
        # Fix this ; put something in settings signifying if the server supports HTTPS or not
        if not request.is_secure() and (not settings.DEBUG) and settings.PROD:
            # Let's try to redirect to HTTPS for non-Nintendo stuff.
            if not request.META.get('HTTP_USER_AGENT'):
                return HttpResponseForbidden("You need a user agent.", content_type='text/plain')
            if not request.is_secure() and not 'Nintendo' in request.META['HTTP_USER_AGENT']:
                return redirect('https://{0}{1}'.format(request.get_host(), request.get_full_path()))
        if request.user.is_authenticated:
            # User active; this doesn't work at the moment due to Postgres not being able to change bools to ints
            if request.user.is_active() == 0:
                return HttpResponseForbidden()
            elif request.user.is_active() == 2:
                return redirect(settings.inactive_redirect)
            
            if not request.user.is_active:
                return HttpResponseForbidden()
            # If there isn't a request.session
            if not request.session.get('passwd'):
                request.session['passwd'] = request.user.password
            else:
                if request.session['passwd'] != request.user.password:
                    logout(request)
        response = self.get_response(request)

        return response
        '''
        
"""
return HttpResponseForbidden("You're one sick fuck. I would never suggest removing an Inkling girl's clothes and licking her tiny body all over, nibbling her neck and kissing her adorable little nipples. Only a heartless monster would think about her cute girlish mouth and tongue wrapped around a thick cock slick with her saliva, pumping in and out of her mouth until it erupts, the cum more than her little throat can swallow. The idea of thick viscous semen overflowing, dribbling down her chin over her flat chest, her tiny hands scooping it all up and watching her suck it off her fingertips is just horrible. You're all a bunch of sick perverts, thinking of spreading her smooth slender thighs, cock poised at the entrance to her pure, tight, virginal pussy, and thrusting in deep as a whimper escapes her lips which are slippery with cum, while her small body shudders from having her cherry taken in one quick stroke. I am disgusted at how you'd get even more excited as you lean over her, listening to her quickening breath, her girlish moans and gasps while you hasten your strokes, her sweet pants warm and moist on your face and her flat chest, shiny with a sheen of fresh sweat, rising and falling rapidly to meet yours. It is truly nasty how you'd run your hands all over her tiny body while you violate her, feeling her nipples hardening against your tongue as you lick her chest, her neck and her armpits, savoring the scent of her skin and sweat while she trembles from the stimulation and as she reaches her climax, hearing her cry out softly as she has her first orgasm while that cock is buried impossibly deep inside her, pulsing violently as an intense amount of hot cum spurts forth and floods through her freshly-deflowered pussy for the first time, filling her womb only to spill out of her with a sickening squelch. And as you lie atop her flushed body, she murmurs breathlessly, \"You came so much inside of me,\" then her fingers dig into your back as she feels your cock hardening inside again.", content_type='text/plain')"""
