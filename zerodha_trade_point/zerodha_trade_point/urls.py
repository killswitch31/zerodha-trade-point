"""
Definition of urls for zerodha_trade_point.
"""

from datetime import datetime
from django.urls import path # type: ignore
from django.contrib import admin # type: ignore
from django.contrib.auth.views import LoginView, LogoutView # type: ignore
from app import forms, views


urlpatterns = [
    path('', views.home, name='home'),
    path('configurezkauth/', views.configurezkauth, name='configurezkauth'),
    path('kite/callback/', views.kite_callback, name='kite_callback'),
    path('trade/', views.trade, name='trade'),
    path('trade/refresh/', views.trade_refresh_data, name='trade_refresh_data'),
    path('trade/place/', views.trade_place, name='trade_place'),
    path('trade/modify/', views.trade_modify, name='trade_modify'),
    path('trade/cancel/', views.trade_cancel, name='trade_cancel'),
    path('trade/convert/', views.trade_convert_position, name='trade_convert_position'),
    path('trade/instruments/', views.instruments_search, name='instruments_search'),
    path('trade/instruments-all/', views.instruments_all, name='instruments_all'),
    path('trade/quote/', views.quote, name='quote'),
    path('deletezkuser/', views.deletezkuser, name='deletezkuser'),
    path('managezkusers/', views.managezkusers, name='managezkusers'),
    path('token-statuses/', views.token_statuses, name='token_statuses'),
    path('login/',
         LoginView.as_view(
             template_name='app/login.html',
             authentication_form=forms.BootstrapAuthenticationForm,
             extra_context={
                 'title': 'Log in',
                 'year': datetime.now().year,
             }
         ),
         name='login'),
    path('logout/', LogoutView.as_view(next_page='/login/'), name='logout'),
    path('admin/', admin.site.urls),
]
