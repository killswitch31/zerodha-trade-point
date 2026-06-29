"""
Definition of urls for zerodha_trade_point.
"""

from datetime import datetime
from django.urls import path
from django.contrib import admin
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.auth.decorators import login_not_required
from app import forms, views


urlpatterns = [
    path('', views.home, name='home'),
    path('contact/', views.contact, name='contact'),
    path('about/', views.about, name='about'),
    path('configurezkauth/', views.configurezkauth, name='configurezkauth'),
    path('kite/callback/', views.kite_callback, name='kite_callback'),
    path('trade/', views.trade, name='trade'),
    path('trade/place/', views.trade_place, name='trade_place'),
    path('trade/modify/', views.trade_modify, name='trade_modify'),
    path('trade/cancel/', views.trade_cancel, name='trade_cancel'),
    path('trade/instruments/', views.instruments_search, name='instruments_search'),
    path('trade/instruments-all/', views.instruments_all, name='instruments_all'),
    path('trade/quote/', views.quote, name='quote'),
    path('deleteuser/', views.deleteuser, name='deleteuser'),
    path('managezkusers/', views.managezkusers, name='managezkusers'),
    path('token-statuses/', views.token_statuses, name='token_statuses'),
    path('login/',
         login_not_required(LoginView.as_view
         (
             template_name='app/login.html',
             authentication_form=forms.BootstrapAuthenticationForm,
             extra_context=
             {
                 'title': 'Log in',
                 'year' : datetime.now().year,
             }
         )),
         name='login'),
    path('logout/', LogoutView.as_view(next_page='/'), name='logout'),
    path('admin/', admin.site.urls),
]
