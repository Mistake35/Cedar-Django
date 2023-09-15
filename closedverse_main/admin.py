from django.apps import apps
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import AdminPasswordChangeForm
from django.contrib.auth.models import Group, Permission
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.conf import settings

from . import models

@admin.action(description='Void selected Invites', permissions=["change"])
def Void_invite(modeladmin, request, queryset):
	queryset.update(void = True)
@admin.action(description='Restore selected Invites', permissions=["change"])
def Restore_invite(modeladmin, request, queryset):
	queryset.update(void = False, used = False)
@admin.action(description='Hide selected items', permissions=["change"])
def Hide_content(modeladmin, request, queryset):
	queryset.update(is_rm = True)
@admin.action(description='Show selected items', permissions=["change"])
def Show_content(modeladmin, request, queryset):
	queryset.update(is_rm = False)
@admin.action(description='Disable comments', permissions=["change"])
def Disable_comments(modeladmin, request, queryset):
	queryset.update(lock_comments = 2)
@admin.action(description='Enable comments', permissions=["change"])
def Enable_comments(modeladmin, request, queryset):
	queryset.update(lock_comments = 0)
@admin.action(description='Feature selected communities', permissions=["change"])
def Feature_community(modeladmin, request, queryset):
	queryset.update(is_feature = True)
@admin.action(description='Unfeature selected communities', permissions=["change"])
def Unfeature_community(modeladmin, request, queryset):
	queryset.update(is_feature = False)
@admin.action(description='Force login', permissions=["change"])
def force_login(modeladmin, request, queryset):
	queryset.update(require_auth = True)
@admin.action(description='Unforce login', permissions=["change"])
def unforce_login(modeladmin, request, queryset):
	queryset.update(require_auth = False)
@admin.action(description='Disable user', permissions=["change"])
def Disable_user(modeladmin, request, queryset):
	queryset.update(is_active = False)
@admin.action(description='Enable user', permissions=["change"])
def Enable_user(modeladmin, request, queryset):
	queryset.update(is_active = True)

@admin.action(description='Demote user', permissions=["change"])
def Demote_user(modeladmin, request, queryset):
	queryset.update(is_superuser = False)
	queryset.update(is_staff = False)
	queryset.update(level = 0)

class UserAdmin(BaseUserAdmin):
	search_fields = ('id', 'username', 'nickname', 'email', 'addr', 'signup_addr')
	list_display = ('id', 'username', 'nickname', 'level', 'is_active', 'is_staff', 'is_superuser')
	actions = [Disable_user, Enable_user, Demote_user]
	raw_id_fields = ('role', )
	readonly_fields = ('last_login', 'created', )
	fieldsets = (
		(None, {'fields': ('nickname', 'username', 'password')}),
		('Personal info', {'fields': ('email', ('addr', 'signup_addr'))}),
		('Cosmetic', {'fields': (('role', 'avatar', 'has_mh'), 'color', 'theme', 'bg_url',)}),
		('Data', {'fields': ('last_login', 'created', 'hide_online')}),
		('Permissions', {'fields': (('is_active', 'is_staff', 'is_superuser', 'can_invite'), 'level', 'c_tokens', 'groups', 'user_permissions')}),
	)

	# yes this is stupid...
	def get_queryset(self, request):
		# Filter the list of users displayed based on the current user's level and superuser status.
		qs = super().get_queryset(request)
		if request.user.is_superuser:
			return qs
		return qs.filter(level__lt=request.user.level)

	def has_change_permission(self, request, obj=None):
		if not obj:
			return super().has_change_permission(request, obj)
		# Superusers can edit anyone
		if request.user.is_superuser:
			return True
		# Users cannot edit superusers or users with a higher level than themselves
		if obj.is_superuser or obj.level >= request.user.level:
			return False
		return super().has_change_permission(request, obj)
	
	def has_delete_permission(self, request, obj=None):
		if not obj:
			return super().has_delete_permission(request, obj)
		# Superusers can delete anyone
		if request.user.is_superuser:
			return True
		# Users cannot delete superusers or users with a higher level than themselves
		if obj.is_superuser or obj.level >= request.user.level:
			return False
		return super().has_delete_permission(request, obj)
	
	def get_readonly_fields(self, request, obj=None):
		# Get the default readonly fields
		readonly_fields = super().get_readonly_fields(request, obj)

		# If the user is not a superuser, add the fields to the readonly list
		if not request.user.is_superuser:
			readonly_fields += ('level', 'is_staff', 'is_superuser', 'groups', 'user_permissions', 'password')
		return readonly_fields
	
class ProfileAdmin(admin.ModelAdmin):
	search_fields = ('id', 'user__username__icontains', 'comment', 'origin_id',)
	raw_id_fields = ('user', 'favorite',)
	list_display = ('id', 'user', 'comment', 'let_freedom',)

class InvitesAdmin(admin.ModelAdmin):
	search_fields = ('creator__username', 'used_by__username', 'code', )
	raw_id_fields = ('creator', 'used_by', )
	list_display = ('creator', 'used_by', 'code', 'used', 'void', )
	actions = [Void_invite, Restore_invite]

class ComplaintAdmin(admin.ModelAdmin):
	search_fields = ('id', 'body', )
	raw_id_fields = ('creator', )

class ConversationAdmin(admin.ModelAdmin):
	search_fields = ('id', )
	raw_id_fields = ('source', 'target', )

class PostAdmin(admin.ModelAdmin):
	raw_id_fields = ('creator', 'poll', )
	search_fields = ('id', 'body', 'creator__username', )
	list_display = ('id', 'creator', 'body', 'is_rm', )
	actions = [Hide_content, Show_content, Disable_comments, Enable_comments]
	def get_queryset(self, request):
		return models.Post.real.get_queryset()

class CommentAdmin(admin.ModelAdmin):
	raw_id_fields = ('creator', 'original_post', )
	search_fields = ('id', 'body', 'creator__username', )
	list_display = ('id', 'creator', 'body', 'original_post', 'is_rm', )
	actions = [Hide_content, Show_content]
	def get_queryset(self, request):
		return models.Comment.real.get_queryset()

class CommunityAdmin(admin.ModelAdmin):
	raw_id_fields = ('creator', )
	list_display = ('id', 'name', 'description', 'type', 'creator', 'popularity', 'is_rm', 'is_feature', 'require_auth')
	search_fields = ('id', 'name', 'description', )
	actions = [Hide_content, Show_content, Feature_community, Unfeature_community, force_login, unforce_login]
	def get_queryset(self, request):
		return models.Community.real.get_queryset()

class MessageAdmin(admin.ModelAdmin):
	raw_id_fields = ('creator', 'conversation', )
	search_fields = ('id', 'body', 'creator__username', )
	list_display = ('id', 'creator', 'conversation', 'body', )
	actions = [Hide_content, Show_content]
	def get_queryset(self, request):
		return models.Message.real.get_queryset()

class NotificationAdmin(admin.ModelAdmin):
	raw_id_fields = ('to', 'source', 'context_post', 'context_comment',)
	search_fields = ('to__username', 'source__username', 'context_post__body', 'context_comment__body',)
	list_display = ('id', 'to', 'source', 'context_post', 'context_comment',)

class AuditAdmin(admin.ModelAdmin):
	raw_id_fields = ('by', 'user', 'post', 'comment', 'community', 'reversed_by', )
	search_fields = ('by__username', 'user__username', 'post__body', 'comment__body', 'community__name', )

class AdsAdmin(admin.ModelAdmin):
	raw_id_fileds = ('id', 'created', 'url', 'imageurl')

class YeahAdmin(admin.ModelAdmin):
	raw_id_fields = ('by', 'post', 'comment', )
	list_display = ('by', 'post', 'comment', )
	search_fields = ('by__username', 'post__body', 'comment__body', )
		
class HistoryAdmin(admin.ModelAdmin):
	raw_id_fields = ('user',)
	list_display = ('id', 'user')

class RoleAdmin(admin.ModelAdmin):
	exclude = ('is_static', )

class BanAdmin(admin.ModelAdmin):
	raw_id_fields = ('to', 'by')
	list_display = ('by', 'to', 'reason', 'expiry_date', 'active')

	def save_model(self, request, obj, form, change):
		# Set the 'by' field to the currently logged-in user
		obj.by = request.user

		# Check if the user being banned is a superuser or has a higher level than the user issuing the ban
		if obj.to.is_superuser or obj.to.level > request.user.level:
			messages.error(request, "You cannot ban a superuser or a user with a higher level.")
			return

		super().save_model(request, obj, form, change)

	def response_add(self, request, obj, post_url_continue=None):
		# If there was an error, redirect back to the 'add' page
		if messages.get_messages(request):
			return HttpResponseRedirect(request.path)
		return super().response_add(request, obj, post_url_continue)

class LoginAdmin(admin.ModelAdmin):
	raw_id_fields = ('user',)
	list_display = ('user', 'addr', 'user_agent', )
	search_fields = ('user__username', 'addr', 'user_agent', )

admin.site.register(models.Role, RoleAdmin)
admin.site.register(models.User, UserAdmin)
admin.site.register(models.Profile, ProfileAdmin)
admin.site.register(models.Invites, InvitesAdmin)
admin.site.register(models.Community, CommunityAdmin)
admin.site.register(models.Complaint, ComplaintAdmin)
admin.site.register(models.Message, MessageAdmin)
admin.site.register(models.Conversation, ConversationAdmin)
admin.site.register(models.Notification, NotificationAdmin)
admin.site.register(models.LoginAttempt, LoginAdmin)
admin.site.register(models.UserBlock)
admin.site.register(models.AuditLog, AuditAdmin)
admin.site.register(models.ProfileHistory, HistoryAdmin)

admin.site.register(models.Yeah)
admin.site.register(models.Follow)
admin.site.register(models.FriendRequest)
admin.site.register(models.Post, PostAdmin)
admin.site.register(models.Comment, CommentAdmin)
admin.site.register(models.Ads, AdsAdmin)
admin.site.register(models.Ban, BanAdmin)
admin.site.register(models.Warning)

# This will show fucking everything, just don't give other people perms to see content types, sessions, and all that shit.
# This is so the superuser, owner of the site can see everything.
app_models = apps.get_models()
for model in app_models:
    try:
        admin.site.register(model)
    except admin.sites.AlreadyRegistered:
        pass