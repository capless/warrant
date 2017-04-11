from django.conf.urls import url
from django.contrib.auth import views as auth_views
from .views import UserView

urlpatterns = [
    url(r'^login/$', auth_views.login, {'template_name': 'warrant/login.html'}, name='login'),
    url(r'^logout/$', auth_views.logout, {'template_name': 'warrant/logout.html'}, name='logout'),
    url(r'^user_info/$', UserView.as_view(), name='user_view')
]