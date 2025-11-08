from django.urls import path
from . import views
from django.contrib.auth.views import LogoutView

app_name = "core"

urlpatterns = [
    # Páginas públicas
    path("", views.home, name="home"),
    path("resultados/", views.resultados, name="resultados"),
    path("historico/", views.historico, name="historico"),
    path("contato/", views.contato, name="contato"),

    # Autenticação
    path("signup/", views.signup, name="signup"),
    path("login/", views.login_view, name="login"),
    path('logout/', LogoutView.as_view(next_page='login'), name='logout'),

    # Esqueci minha senha (custom)
    path("senha/esqueci/", views.forgot_password, name="password_reset"),
    path("senha/enviado/", views.reset_password_done, name="password_reset_done"),
    path("senha/redefinir/<uidb64>/<token>/", views.reset_password_confirm, name="password_reset_confirm"),
    path("senha/concluida/", views.reset_password_complete, name="password_reset_complete"),

    # Pós-login (decide admin x home)
    path("post-login/", views.post_login, name="post_login"),

    # Painel administrativo interno (não é o /admin/ do Django)
    path("painel/", views.admin_home, name="admin_home"),

    # Rotas do painel (ajuste quando tiver views específicas)
    path("painel/voo/cadastrar/", views.admin_home, name="voo_cadastrar"),  # provisório
]
