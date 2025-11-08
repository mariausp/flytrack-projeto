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
    path("senha/esqueci/", views.forgot_password, name="password_reset"),
    path("senha/enviado/", views.reset_password_done, name="password_reset_done"),
    path("senha/redefinir/<uidb64>/<token>/", views.reset_password_confirm, name="password_reset_confirm"),
    path("senha/concluida/", views.reset_password_complete, name="password_reset_complete"),
    path("post-login/", views.post_login, name="post_login"),
    path("painel/", views.admin_home, name="admin_home"),

]
