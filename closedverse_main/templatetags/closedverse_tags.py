from django import template
from closedverse_main.util import HumanTime
from closedverse_main.models import mii_domain
from closedverse import settings

register = template.Library()

@register.simple_tag
def avatar(user, feeling=0):
	return user.do_avatar(feeling)
@register.simple_tag
def invite_only(request):
    if settings.invite_only:
        return True
    else:
        return False
@register.simple_tag
def color_theme(request):
    if request.user.is_authenticated and request.user.theme:
        theme = request.user.theme.strip("#")
    elif settings.site_wide_theme_hex:
        theme = settings.site_wide_theme_hex.strip("#")
    else:
        theme = None
    return theme
@register.simple_tag
def miionly(mh):
	if not mh:
		return settings.STATIC_URL + 'img/anonymous-mii.png'
	else:
		return '{1}{0}_normal_face.png'.format(mh, mii_domain)
@register.simple_tag
def time(stamp, full=False):
	return HumanTime(stamp.timestamp(), full) or "Less than a minute ago"
@register.simple_tag
def user_class(user):
	return user.get_class()[0]
@register.simple_tag
def user_level(user):
	return user.get_class()[1]
@register.inclusion_tag('closedverse_main/elements/user-icon-container.html')
def user_icon_container(user, feeling=0, status=False):
	return {
	'uclass': user_class(user),
	'user': user,
	'status': status,
	'url': avatar(user, feeling),
	}
@register.inclusion_tag('closedverse_main/elements/no-content.html')
def nocontent(text='', style=''):
	return {
        'text': text,
        'style': style,
    }
@register.simple_tag
def empathy_txt(feeling=0, has=False):
	if has:
		return 'Unyeah'
	return {
	0: 'Yeah!',
	1: 'Yeah!',
	2: 'Yeah♥',
	3: 'Yeah!?',
	4: 'Yeah...',
	5: 'Yeah...',
	38: 'Nyeah~',
	2012: 'olv.portal.miitoo.',
#	4: 'yeah...',
#	5: 'yeah...',
#	38: 'something something balls',
#    39: 'lol i lied',
#	69: 'Adam is gay.',
#    70: 'I am a faggot!',
#    71: 'Juice',
#    72: 'Commit Suicide',
#    73: 'Fresh!',
	}.get(feeling, 'Yeah!')
	# olv.portal.miitoo is going to be the only easter egg in this thing ever
@register.inclusion_tag('closedverse_main/elements/p_username.html')
def p_username(user):
	return {
		'user': user,
	}
@register.inclusion_tag('closedverse_main/elements/empathy-content.html')
def empathy_content(yeahs, request, has_yeah=False):
	for yeah in yeahs:
		if yeah.post:
			yeah.feeling = yeah.post.feeling
		else:
			yeah.feeling = yeah.comment.feeling
	return {
		'yeahs': yeahs,
		'myself': request.user,
		'has_yeah': has_yeah,
	}
@register.inclusion_tag('closedverse_main/elements/names.html')
def print_names(names):
	return {
		'nameallmn': len(names) - 4,
		'names': names,
	}
@register.inclusion_tag('closedverse_main/elements/loading-spinner.html')
def loading_spinner():
	return {
		
	}
