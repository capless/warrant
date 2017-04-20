from django.conf.urls import url
from django.contrib.auth import views as auth_views
from .views import ProfileView,UpdateProfileView,MySubsriptions,\
    AdminListUsers,AdminSubscriptions

urlpatterns = (
    url(r'^login/$', auth_views.login, {'template_name': 'warrant/login.html'}, name='login'),
    url(r'^logout/$', auth_views.logout, {'template_name': 'warrant/logout.html'}, name='logout'),
    url(r'^profile/$', ProfileView.as_view(),name='profile'),
    url(r'^profile/update/$', UpdateProfileView.as_view(),name='update-profile'),
    url(r'^profile/subscriptions/$', MySubsriptions.as_view(),name='subscriptions'),
    url(r'^admin/cognito-users/$', AdminListUsers.as_view(),name='admin-cognito-users'),
    url(r'^admin/cognito-users/(?P<username>[-\w]+)$', AdminSubscriptions.as_view(),name='admin-cognito-user')
)