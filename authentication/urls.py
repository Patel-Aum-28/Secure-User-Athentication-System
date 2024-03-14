from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('signup', views.signup, name='signup'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
    path('signin', views.signin, name='signin'),
    path('signout', views.signout, name='signout'),
    path('password_reset', views.password_reset_request, name='password_reset'),
    path('reset/<uidb64>/<token>', views.password_reset_confirm, name='password_reset_confirm'),
    path('verify_otp', views.verify_otp, name='verify_otp'),
    path('resend_otp', views.resend_otp, name='resend_otp'),
]
