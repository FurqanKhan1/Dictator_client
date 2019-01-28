#!python
# log/urls.py
from django.conf.urls import url #,patterns,url
from . import views

# We are adding a URL called /home
urlpatterns = [
    url(r'^$', views.home, name='home'),
	url(r'^password/$', views.change_password.as_view(), name='change_password'),
	url(r'^reset_password_confirm/(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/$',
            views.PasswordResetConfirmView.as_view(), name='reset_password_confirm'),
    url(r'^reset_password',
            views.ResetPasswordRequestView.as_view())
]
