# core/urls.py
from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

app_name = 'core'

urlpatterns = [
    path("", views.home, name="home"),
    path("signup/", views.signup, name="signup"),
    path("login/", views.login_view, name="login"),
    path("logout/", auth_views.LogoutView.as_view(next_page="core:home"), name="logout"),
    path("resultados/", views.resultados, name="resultados"),
    path("historico/", views.historico, name="historico"),
    path("contato/", views.contato, name="contato"),
]