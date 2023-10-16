from django import forms
import uuid
from PIL import Image
import io
from .models import *
from django.core.files.base import ContentFile
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.timezone import timedelta
from django.core.validators import URLValidator
from closedverse import settings
from django.core.validators import EmailValidator

def compress_and_resize_content(image, icon=False):
	try:
		im = Image.open(image)
		im = im.convert('RGB')

		if icon == True:
			width, height = im.size
			min_dimension = min(width, height)
			left = (width - min_dimension) / 2
			top = (height - min_dimension) / 2
			right = (width + min_dimension) / 2
			bottom = (height + min_dimension) / 2
			im = im.crop((left, top, right, bottom))
			im.thumbnail((100, 100))
		else:
			im.thumbnail((1200, 1200))

		output = io.BytesIO()
		# no more webp
		im.save(output, format='JPEG', quality=85)
		output.seek(0)
		random_name = f"{uuid.uuid4()}.jpg"
		return ContentFile(output.read(), name=random_name)
	except:
		return image

class message_form(forms.ModelForm):
	body = forms.CharField(max_length=2200, required=True)
	file = forms.FileField(required=False)
	feeling_id = forms.IntegerField(required=False)

	def clean_file(self):
		file = self.cleaned_data.get('file')
		max_size = settings.max_file_size
		if file:
			if file.size > max_size:
				raise ValidationError(f'File size is too large. ({max_size / 1024 /1024 }MB max)')
			if file.content_type.startswith('image'):
				return compress_and_resize_content(image=file)
			return file
	
	class Meta:
		model = Message
		fields = (
			'body', 
			'file', 
			'feeling_id',
		)

class comment_form(forms.ModelForm):
	body = forms.CharField(max_length=2200, required=True)
	file = forms.FileField(required=False)
	feeling_id = forms.IntegerField(required=False)
	is_spoiler = forms.BooleanField(required=False)

	def clean_file(self):
		file = self.cleaned_data.get('file')
		max_size = settings.max_file_size
		if file:
			if file.size > max_size:
				raise ValidationError(f'File size is too large. ({max_size / 1024 /1024 }MB max)')
			if file.content_type.startswith('image'):
				return compress_and_resize_content(image=file)
			return file

	class Meta:
		model = Comment
		fields = (
			'body', 
			'file', 
			'feeling_id',
			'is_spoiler',
		)

class post_form(forms.ModelForm):
	body = forms.CharField(max_length=2200, required=True)
	url = forms.URLField(required=False)
	file = forms.FileField(required=False)
	feeling_id = forms.IntegerField(required=False)
	is_spoiler = forms.BooleanField(required=False)

	def clean_file(self):
		file = self.cleaned_data.get('file')
		max_size = settings.max_file_size
		if file:
			if file.size > max_size:
				raise ValidationError(f'File size is too large. ({max_size / 1024 /1024 }MB max)')
			if file.content_type.startswith('image'):
				return compress_and_resize_content(image=file)
			return file

	def clean_url(self):
		url = self.cleaned_data.get('url')
		if url:
			try:
				URLValidator()(value=url)
			except ValidationError:
				raise ValidationError("Uh-oh, that URL wasn't valid.")
		return url

	class Meta:
		model = Post
		fields = (
			'body', 
			'url', 
			'file', 
			'feeling_id',
			'is_spoiler',
		)

class edit_community(forms.ModelForm):
	description	 = forms.CharField(max_length = 2200,required=False, widget=forms.Textarea(attrs={'class': 'textarea'}))
		
	def __init__(self, *args, **kwargs):
		super(edit_community, self).__init__(*args, **kwargs)
		# Store the initial values of the image fields
		self.initial_ico = self.instance.ico
		self.initial_banner = self.instance.banner

	def clean_ico(self):
		ico = self.cleaned_data.get('ico')
		max_size = settings.max_file_size
		# Check if the image has changed
		if ico and ico != self.initial_ico:
			if ico.size > max_size:
				raise ValidationError(f'File size is too large. ({max_size / 1024 /1024 }MB max)')
			return compress_and_resize_content(image=ico, icon=True)
		return ico

	def clean_banner(self):    
		banner = self.cleaned_data.get('banner')
		max_size = settings.max_file_size
		# Check if the image has changed
		if banner and banner != self.initial_banner:
			if banner.size > max_size:
				raise ValidationError(f'File size is too large. ({max_size / 1024 /1024 }MB max)')
			return compress_and_resize_content(image=banner)
		return banner

	class Meta:
		model = Community
		fields = (
			'name', 
			'description', 
			'platform', 
			'require_auth',
			'ico',
			'banner',
		)
		
class set_password(forms.Form):
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
class purge_user(forms.Form):
	purge_posts = forms.BooleanField(required=False, label='Purge all posts', help_text='Purge all posts from this user.')
	purge_comments = forms.BooleanField(required=False, label='Purge all comments', help_text='Purge all comments from this user.')
	restore_all = forms.BooleanField(required=False, label='Restore purged content', help_text='Restore everything that was purged, this will not apply to posts deleted manually.')

class sign_in(forms.Form):
	username = forms.CharField(max_length=255, widget=forms.TextInput(attrs={'class': 'auth-input', 'placeholder': 'Username / Email'}))
	password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'auth-input', 'placeholder': 'Password'}))

	def clean(self):
		cleaned_data = super(sign_in, self).clean()
		username = cleaned_data.get('username')
		password = cleaned_data.get('password')

		user = User.objects.authenticate(username=username, password=password)

		if user is None:
			raise forms.ValidationError("The user doesn't exist.")
		elif user[1] == False:
			raise forms.ValidationError("Invalid password.", code='invalid')
		elif user[1] == 2:
			raise forms.ValidationError("This account's password needs to be reset. Contact an admin or reset by email.", code='required_reset')
		elif not user[0].is_active:
			raise forms.ValidationError("This account was disabled.", code='disabled')
		# Check for active user ban
		active_user_ban = Ban.objects.filter(to=user[0], active=True, expiry_date__gte=timezone.now()).first()
		if active_user_ban:
			raise forms.ValidationError("This account has been banned until {}. Reason: {}".format(active_user_ban.expiry_date, active_user_ban.reason), code='banned')
		self.user = user
		return cleaned_data

class manage_user(forms.ModelForm):
	username = forms.CharField(max_length = 64, required = True, help_text = 'Usernames are used when signing in, so be sure to let this user know if you change this.')
	has_mh = forms.BooleanField(required = False, label='Use Mii', help_text='Turn this on to use Mii Hashes instead of normal profile pictures.')
	avatar = forms.CharField(required = False, help_text = 'If \"Use Mii\" is turned on, The Mii Hash should reside here, otherwise any good old URL will do.')

	class Meta:
		model = User
		fields = ['username', 'nickname', 'role', 'c_tokens', 'hide_online', 'can_invite', 'has_mh', 'avatar']

	def clean_username(self):
		username = self.cleaned_data.get('username')
		if not re.compile(r'^[A-Za-z0-9-._]{1,32}$').match(username) or not re.compile(r'[A-Za-z0-9]').match(username):
			raise forms.ValidationError("The username contains invalid characters.")
		return username

class manage_profile(forms.ModelForm):
	# applying classes is super weird.
	comment = forms.CharField(required=False, widget=forms.Textarea(attrs={'class': 'textarea'}))
	let_freedom = forms.BooleanField(required=False, label='Let this user upload images?', help_text='If you disable this, This user will not be able to post images, videos or make a new account.')
	class Meta:
		model = Profile
		fields = ['comment', 'country', 'whatareyou', 'weblink', 'external', 'let_freedom', 'limit_post', 'cannot_edit']

class give_warning(forms.ModelForm):
	reason = forms.CharField(required=True, widget=forms.Textarea(attrs={'class': 'textarea'}))
	# Super simple, does not need to be it's own form but whatever.
	class Meta:
		model = Warning
		fields = ['reason']

class give_ban(forms.ModelForm):
	BAN_OPTIONS = [
	(1, '1 Day'),
	(2, '2 Days'),
	(3, '3 Days'),
	(7, '1 Week'),
	(14, '2 Weeks'),
	(21, '3 Weeks'),
	(30, '1 Month'),
	(60, '2 Months'),
	(90, '3 Months'),
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
		
class edit_ban(forms.ModelForm):
	reason = forms.CharField(required=True, widget=forms.Textarea(attrs={'class': 'textarea'}))
	expiry_date = forms.DateTimeField(widget=forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'DateTimeInput'}, format='%Y-%m-%dT%H:%M'))
	active = forms.BooleanField(required=False)
	class Meta:
		model = Ban
		fields = ['reason', 'expiry_date', 'active']

class profile_settings_page(forms.Form):
	# This form is an absolute clusterfuck.
	screen_name = forms.CharField(max_length=32, required=True)
	pronouns = forms.CharField(max_length=16, required=False)
	profile_comment = forms.CharField(max_length=2200, required=False)
	country = forms.CharField(max_length=64, required=False)
	email = forms.CharField(max_length=255, required=False)
	website = forms.CharField(max_length=255, required=False)
	external = forms.CharField(max_length=255, required=False)
	whatareyou = forms.CharField(max_length=255, required=False)
	color = forms.CharField(max_length=7, required=False)
	id_visibility = forms.IntegerField(max_value=2, min_value=0)
	let_friendrequest = forms.IntegerField(max_value=2, min_value=0)
	yeahs_visibility = forms.IntegerField(max_value=2, min_value=0)
	comments_visibility = forms.IntegerField(max_value=2, min_value=0)
	theme = forms.CharField(max_length=7, required=False)
	reset_theme = forms.BooleanField(required=False)

	'''PFP stuff'''
	avatar = forms.IntegerField(max_value=3, min_value=0, required=False)
	origin_id = forms.CharField(max_length=16, min_length=6, required=False)
	mh = forms.CharField(max_length=16, required=False)
	file= forms.ImageField(required=False)

	def clean_email(self):
		email = self.cleaned_data.get('email')
		validator = EmailValidator()
		if email:
			try:
				validator(email)
			except ValidationError:
				raise forms.ValidationError("Invalid email.")
			return email
		return None
	
	def is_color_acceptable(self, hex_color):
		hex_color = hex_color.lstrip('#')
		r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
		r /= 255.0
		g /= 255.0
		b /= 255.0
		luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b

		# Define thresholds
		too_dark_threshold = 0.2
		too_bright_threshold = 0.8

		if luminance < too_dark_threshold:
			return False
		elif luminance > too_bright_threshold:
			return False
		else:
			return True
		
	def get_gravatar(self, email):
		try:
			page = urllib.request.urlopen('https://gravatar.com/avatar/'+ md5(email.encode('utf-8').lower()).hexdigest() +'?d=404&s=128')
		except:
			return False
		return page.geturl()

	# what an abomination
	def save(self, user, commit=True):
		profile = user.profile()

		user.nickname = self.cleaned_data['screen_name']
		user.email = self.cleaned_data['email']
		
		if not self.cleaned_data.get('origin_id'):
			profile.origin_info = None
			profile.origin_id = None

		avatar_option = self.cleaned_data.get('avatar')
		match avatar_option:
			# will add case 3 later who gives a shit
			case 2:
				if self.cleaned_data.get('file'):
					user.avatar_upload = compress_and_resize_content(image=self.cleaned_data.get('file'), icon=True)
					user.avatar_type = 0
			case 1:
				user.avatar_input = util.get_gravatar(user.email) or None
				user.avatar_type = 1
			case 0:
				if not self.cleaned_data.get('origin_id'):
					user.avatar_type = 0
					user.avatar_input = None
				else:
					if self.cleaned_data.get('mh'):
						user.avatar_type = 2
						user.avatar_input = self.cleaned_data.get('mh')
						profile.origin_id = self.cleaned_data.get('origin_id')
						profile.origin_info = json.dumps([self.cleaned_data.get('mh'), 'if you see this then something is wrong', self.cleaned_data['origin_id']])

		# Setting the username color
		color = self.cleaned_data.get('color')
		if color:
			try:
				validate_color(color)
			except ValidationError:
				user.color = None
			else:
				if self.is_color_acceptable(color):
					user.color = color
				else:
					user.color = None

		# Setting the theme
		theme = self.cleaned_data.get('theme')
		if theme:
			reset_theme = self.cleaned_data.get('reset_theme')
			try:
				validate_color(theme)
			except ValidationError:
				user.theme = None
			else:
				if reset_theme:
					user.theme = None
					pass
				if self.is_color_acceptable(theme):
					user.theme = theme
				else:
					user.theme = None

		profile.comment = self.cleaned_data['profile_comment']
		profile.pronoun_is = self.cleaned_data['pronouns']
		profile.country = self.cleaned_data['country']
		profile.weblink = self.cleaned_data['website']
		profile.external = self.cleaned_data['external']
		profile.whatareyou = self.cleaned_data['whatareyou']
		profile.id_visibility = self.cleaned_data['id_visibility']
		profile.let_friendrequest = self.cleaned_data['let_friendrequest']
		profile.yeahs_visibility = self.cleaned_data['yeahs_visibility']
		profile.comments_visibility = self.cleaned_data['comments_visibility']
		if commit:
			user.save()
			profile.save()
