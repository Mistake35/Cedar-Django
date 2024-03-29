from django import template
register = template.Library()

@register.inclusion_tag('closedverse_main/elements/community_sidebar.html')
def community_sidebar(community, request):
	return {
		'community': community,
		'can_edit': community.can_edit_community(request.user),
		'Community_block': community.Community_block(request),
		'request': request,
	}
@register.inclusion_tag('closedverse_main/elements/community_post.html')
def community_post(post, type=0):
	return {
	'post': post,
	'type': type,
	}

@register.inclusion_tag('closedverse_main/elements/post-list.html')
def post_list(posts, next_offset=None, type=0, nf_text='', time=None):
	text = {
	0: "This community doesn't have any posts yet.",
	}.get(type, nf_text)
	return {
		'posts': posts,
		'nf': text,
		'next': next_offset,
		'time': time,
	}
@register.inclusion_tag('closedverse_main/elements/post-form.html')
def post_form(user, community):
	return {
		'user': user,
		'community': community,
	}
@register.inclusion_tag('closedverse_main/elements/post-comment.html')
def post_comment(comment):
	return {
		'comment': comment,
	}
@register.inclusion_tag('closedverse_main/elements/post_comments.html')
def post_comments(comments):
	return {
		'comments': comments,
	}
@register.inclusion_tag('closedverse_main/elements/feeling-selector.html')
def feeling_selector(val=0):
	return {
		'val': val,
	}
@register.inclusion_tag('closedverse_main/elements/comment-form.html')
def comment_form(post, user=None):
	return {
		'post': post,
		'user': user,
	}
@register.inclusion_tag('closedverse_main/elements/memo-drawboard.html')
def memo_drawboard():
	return {
		
	}
@register.inclusion_tag('closedverse_main/elements/file-button.html')
def file_button():
	return {
		
	}
@register.inclusion_tag('closedverse_main/elements/community_page_elem.html')
def community_page_element(communities, text='General Communities', feature=False, url_name=''):
	return {
		'communities': communities,
		'title': text,
		'feature': feature,
		'url_name': url_name,
	}
