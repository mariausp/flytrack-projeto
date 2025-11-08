from django.urls import path
from . import views

app_name = "core"

urlpatterns = [
    path("", views.home, name="home"),
    path("signup/", views.signup, name="signup"),
    path("login/", views.login_view, name="login"),
    path("resultados/", views.resultados, name="resultados"),
    path("historico/", views.historico, name="historico"),
    path("contato/", views.contato, name="contato"),
]
