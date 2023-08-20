from django import forms
from .models import *
from django.core.exceptions import ValidationError

# I do want to move each and every form over to here. Not only will this trivialize making new forms, this will also make it more secure or something.
class CommunitySettingForm(forms.ModelForm):
	community_name = forms.CharField(max_length=64,required=True)
	community_description = forms.CharField(max_length = 2200,required=False)
	community_platform = forms.IntegerField(max_value = 7, min_value = 0, required = True)
	force_login = forms.BooleanField(required = False)
	community_icon = forms.ImageField(required = False)
	community_banner = forms.ImageField(required = False)
	class Meta:
		model = Community
		fields = (
			'community_name', 
			'community_description', 
			'community_platform', 
			'force_login',
			'community_icon',
			'community_banner'
		)

class PurgeForm(forms.Form):
	purge_posts = forms.BooleanField(required=False, label='Purge all posts', help_text='Purge all posts from this user.')
	purge_comments = forms.BooleanField(required=False, label='Purge all comments', help_text='Purge all comments from this user.')
	restore_all = forms.BooleanField(required=False, label='Restore purged content', help_text='Restore everything that was purged, this will not apply to posts deleted manually.')

class UserForm(forms.ModelForm):
	username = forms.CharField(max_length = 64, required = True, help_text = 'Usernames are used when signing in, so be sure to let this user know if you change this.')
	c_tokens = forms.IntegerField(min_value = 0, max_value = 100, required = False, help_text = 'The remaining C-Tokens this user has.')
	has_mh = forms.BooleanField(required = False, label='Use Mii', help_text='Don\'t fuck with this please.')
	avatar = forms.CharField(required = False, help_text = 'If \"Use Mii\" is turned on, The Mii ID should reside here, otherwise any good old URL will do.')

	class Meta:
		model = User
		fields = ['username', 'nickname', 'role', 'c_tokens', 'hide_online', 'active', 'can_invite', 'warned', 'has_mh', 'avatar', 'warned_reason']

	def clean_username(self):
		username = self.cleaned_data.get('username')
		if not re.compile(r'^[A-Za-z0-9-._]{1,32}$').match(username) or not re.compile(r'[A-Za-z0-9]').match(username):
			raise forms.ValidationError("The username contains invalid characters.")
		return username


class ProfileForm(forms.ModelForm):
	# applying classes is super weird.
	comment = forms.CharField(required=False, widget=forms.Textarea(attrs={'class': 'textarea'}))
	let_freedom = forms.BooleanField(required=False, label='Let this user upload images?', help_text='If you disable this, This user will not be able to post images, videos or make a new account.')
	class Meta:
		model = Profile
		fields = ['comment', 'country', 'whatareyou', 'weblink', 'external', 'let_freedom', 'limit_post', 'cannot_edit', 'pronoun_is', 'id_visibility', 'let_friendrequest', 'yeahs_visibility', 'comments_visibility']