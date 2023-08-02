from django.contrib import admin
#from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group
from django.forms import ModelForm, PasswordInput
from closedverse_main import models
from closedverse import settings

from . import models

# Override admin login page
from closedverse_main.views import login_page
admin.autodiscover()
admin.site.login = login_page

"""
class UserForm(ModelForm):
	class Meta:
		model = models.User
		fields = '__all__'
		widgets = {
			'password': PasswordInput(),
		}
"""
@admin.action(description='Hide selected items')
def Hide_Memo(modeladmin, request, queryset):
	queryset.update(show = False)
@admin.action(description='Show selected items')
def Show_Memo(modeladmin, request, queryset):
	queryset.update(show = True)
@admin.action(description='Hide selected items')
def Hide_content(modeladmin, request, queryset):
	queryset.update(is_rm = True)
@admin.action(description='Show selected items')
def Show_content(modeladmin, request, queryset):
	queryset.update(is_rm = False)
@admin.action(description='Feature selected communities')
def Feature_community(modeladmin, request, queryset):
	queryset.update(is_feature = True)
@admin.action(description='Unfeature selected communities')
def Unfeature_community(modeladmin, request, queryset):
	queryset.update(is_feature = False)
@admin.action(description='Force login')
def force_login(modeladmin, request, queryset):
	queryset.update(require_auth = True)
@admin.action(description='Unforce login')
def unforce_login(modeladmin, request, queryset):
	queryset.update(require_auth = False)
@admin.action(description='Disable user')
def Disable_user(modeladmin, request, queryset):
	queryset.update(active = False)

class UserAdmin(admin.ModelAdmin):
	search_fields = ('id', 'unique_id', 'username', 'nickname', 'email', )
	list_display = ('id', 'username', 'nickname', 'warned', 'level', 'staff', 'active', )
	exclude = ('addr', 'signup_addr', 'password', )
	actions = [Disable_user]
	#exclude = ('staff', )
	# Not yet
	#form = UserForm
class ProfileAdmin(admin.ModelAdmin):
	search_fields = ('id', 'unique_id', 'origin_id', )
	raw_id_fields = ('user', 'favorite', )
	list_display = ('id', 'user', 'comment', 'let_freedom', )

class ComplaintAdmin(admin.ModelAdmin):
	search_fields = ('id', 'unique_id', 'body', )
	raw_id_fields = ('creator', )
class ConversationAdmin(admin.ModelAdmin):
	search_fields = ('id', 'unique_id', )
	raw_id_fields = ('source', 'target', )

class PostAdmin(admin.ModelAdmin):
	raw_id_fields = ('creator', 'poll', )
	search_fields = ('id', 'unique_id', 'body', 'creator__username', )
	list_display = ('id', 'creator', 'body', 'is_rm', )
	actions = [Hide_content, Show_content]
	def get_queryset(self, request):
		return models.Post.real.get_queryset()

class CommentAdmin(admin.ModelAdmin):
	raw_id_fields = ('creator', 'original_post', )
	search_fields = ('id', 'unique_id', 'body', 'creator__username', )
	list_display = ('id', 'creator', 'body', 'original_post', 'is_rm', )
	actions = [Hide_content, Show_content]
	def get_queryset(self, request):
		return models.Comment.real.get_queryset()

class CommunityAdmin(admin.ModelAdmin):
	raw_id_fields = ('creator', )
	list_display = ('id', 'name', 'description', 'type', 'creator', 'is_rm', 'is_feature', 'require_auth')
	search_fields = ('id', 'unique_id', 'name', 'description', )
	actions = [Hide_content, Show_content, Feature_community, Unfeature_community, force_login, unforce_login]
	def get_queryset(self, request):
		return models.Community.real.get_queryset()

class MessageAdmin(admin.ModelAdmin):
	raw_id_fields = ('creator', 'conversation', )
	search_fields = ('id', 'unique_id', 'body', 'creator__username', )
	list_display = ('id', 'creator', 'conversation', 'body', )
	actions = [Hide_content, Show_content]
	def get_queryset(self, request):
		return models.Message.real.get_queryset()

class NotificationAdmin(admin.ModelAdmin):
		raw_id_fields = ('to', 'source', 'context_post', 'context_comment', )
		search_fields = ('unique_id', )
		list_display = ('id', 'to', 'source', 'context_post', 'context_comment', )

class AuditAdmin(admin.ModelAdmin):
		raw_id_fields = ('by', 'user', 'post', 'comment', 'reversed_by', )
		search_fields = ('by__username', 'user__username', )

class AdsAdmin(admin.ModelAdmin):
		raw_id_fileds = ('id', 'created', 'url', 'imageurl')
		
class InvitesAdmin(admin.ModelAdmin):
		raw_id_fileds = ('id', 'created', 'creator')

class WelcomemsgAdmin(admin.ModelAdmin):
		raw_id_fileds = ('id', 'created', 'message', )
		list_display = ('Title', 'message', 'show', 'order', 'created', )
		actions = [Hide_Memo, Show_Memo]

class YeahAdmin(admin.ModelAdmin):
		raw_id_fields = ('by', 'post', 'comment', )
		list_display = ('by', 'post', 'comment', )
		search_fields = ('by__username', 'post__body', 'comment__body', )
		
class HistoryAdmin(admin.ModelAdmin):
		raw_id_fields = ('user',)
		list_display = ('id', 'user')

#class BlockAdmin(admin.ModelAdmin)

admin.site.unregister(Group)

admin.site.register(models.User, UserAdmin)
admin.site.register(models.Profile, ProfileAdmin)
admin.site.register(models.Community, CommunityAdmin)
admin.site.register(models.Complaint, ComplaintAdmin)
admin.site.register(models.Message, MessageAdmin)
admin.site.register(models.Conversation, ConversationAdmin)
admin.site.register(models.Notification, NotificationAdmin)
admin.site.register(models.UserBlock)
admin.site.register(models.AuditLog, AuditAdmin)
admin.site.register(models.ProfileHistory, HistoryAdmin)


admin.site.register(models.Post, PostAdmin)
admin.site.register(models.Comment, CommentAdmin)
admin.site.register(models.Ads, AdsAdmin)
admin.site.register(models.welcomemsg, WelcomemsgAdmin)
admin.site.register(models.Yeah, YeahAdmin)
admin.site.register(models.Follow)
admin.site.register(models.FriendRequest)
admin.site.register(models.Friendship, ConversationAdmin)
admin.site.register(models.Invites, InvitesAdmin)
admin.site.register(models.Poll)
admin.site.register(models.PollVote)
