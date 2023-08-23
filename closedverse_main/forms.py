from django import forms
from .models import *
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.timezone import timedelta
from closedverse import settings

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
		
class Settomgs_Change_Password(forms.Form):
	Old_Password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'auth-input', 'placeholder': 'Old Password'}))
	New_Password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'auth-input', 'placeholder': 'New Password'}))
	Confirm_Password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'auth-input', 'placeholder': 'Confirm Password'}))
	
	def clean(self):
		cleaned_data = super().clean()
		old = cleaned_data.get('Old_Password')
		new = cleaned_data.get('New_Password')
		confirm = cleaned_data.get('Confirm_Password')
		if not old or not new or not confirm:
			raise forms.ValidationError('Please fill out all the fields.')
		if old == new:
			raise forms.ValidationError('The old password and new password can\'t be the same.')
		if new != confirm:
			raise forms.ValidationError('Passwords do not match.')
		try:
			validate_password(new)
		except forms.ValidationError as error:
			raise forms.ValidationError("your password fucking sucks!")
		return cleaned_data
class PurgeForm(forms.Form):
	purge_posts = forms.BooleanField(required=False, label='Purge all posts', help_text='Purge all posts from this user.')
	purge_comments = forms.BooleanField(required=False, label='Purge all comments', help_text='Purge all comments from this user.')
	restore_all = forms.BooleanField(required=False, label='Restore purged content', help_text='Restore everything that was purged, this will not apply to posts deleted manually.')

class LoginForm(forms.Form):
	username = forms.CharField(max_length=255, widget=forms.TextInput(attrs={'class': 'auth-input', 'placeholder': 'Username'}))
	password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'auth-input', 'placeholder': 'Password'}))

	def clean(self):
		cleaned_data = super(LoginForm, self).clean()
		username = cleaned_data.get('username')
		password = cleaned_data.get('password')

		user = User.objects.authenticate(username=username, password=password)

		if user is None:
			raise forms.ValidationError("The user doesn't exist.")
		elif user[1] == False:
			raise forms.ValidationError("Invalid password.", code='invalid')
		elif user[1] == 2:
			raise forms.ValidationError("This account's password needs to be reset. Contact an admin or reset by email.", code='required_reset')
		elif not user[0].is_active():
			raise forms.ValidationError("This account was disabled.", code='disabled')
		return cleaned_data

class User_tools_Form(forms.ModelForm):
	username = forms.CharField(max_length = 64, required = True, help_text = 'Usernames are used when signing in, so be sure to let this user know if you change this.')
	has_mh = forms.BooleanField(required = False, label='Use Mii', help_text='Turn this on to use Mii Hashes instead of normal profile pictures.')
	avatar = forms.CharField(required = False, help_text = 'If \"Use Mii\" is turned on, The Mii Hash should reside here, otherwise any good old URL will do.')

	class Meta:
		model = User
		fields = ['username', 'nickname', 'role', 'c_tokens', 'hide_online', 'active', 'can_invite', 'has_mh', 'avatar']

	def clean_username(self):
		username = self.cleaned_data.get('username')
		if not re.compile(r'^[A-Za-z0-9-._]{1,32}$').match(username) or not re.compile(r'[A-Za-z0-9]').match(username):
			raise forms.ValidationError("The username contains invalid characters.")
		return username

class Profile_tools_Form(forms.ModelForm):
	# applying classes is super weird.
	comment = forms.CharField(required=False, widget=forms.Textarea(attrs={'class': 'textarea'}))
	let_freedom = forms.BooleanField(required=False, label='Let this user upload images?', help_text='If you disable this, This user will not be able to post images, videos or make a new account.')
	class Meta:
		model = Profile
		fields = ['comment', 'country', 'whatareyou', 'weblink', 'external', 'let_freedom', 'limit_post', 'cannot_edit']

class Give_warning_form(forms.ModelForm):
	reason = forms.CharField(required=True, widget=forms.Textarea(attrs={'class': 'textarea'}))
	# Super simple, does not need to be it's own form but whatever.
	class Meta:
		model = Warning
		fields = ['reason']

class Give_Ban_Form(forms.ModelForm):
	BAN_OPTIONS = [
	(1, '1 Day'),
	(2, '2 Days'),
	(3, '3 Days'),
	(7, '1 Week'),
	(14, '2 Weeks'),
	(30, '1 Month'),
	(60, '2 Months'),
	(365, '1 Year'),
	(None, 'Forever'),
	]
	# In the future we can add options for IP bans and shit.
	reason = forms.CharField(required=True, widget=forms.Textarea(attrs={'class': 'textarea'}))
	expiry_date = forms.ChoiceField(required=False, choices=BAN_OPTIONS, initial=1)

	def clean_expiry_date(self):
		expiry_choice = self.cleaned_data['expiry_date']
		if expiry_choice:
			return timezone.now() + timedelta(days=int(expiry_choice))
		else:
			return timezone.now() + timedelta(days=365.25*100) # same exact thing done in indigo.
	class Meta:
		model = Ban
		fields = ['reason', 'expiry_date']