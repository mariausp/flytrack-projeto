from django.urls import path
from django.contrib.auth.views import LogoutView

from . import views, api

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
    path("painel/passageiros/", views.admin_passageiros, name="admin_passageiros"),
    path("painel/voos/", views.admin_voos, name="admin_voos"),
    path("painel/passagens/", views.admin_passagens, name="admin_passagens"),
    path("painel/pagamentos/", views.admin_pagamentos, name="admin_pagamentos"),
    path("painel/checkin/", views.admin_checkin, name="admin_checkin"),
    path("painel/produtos/", views.admin_produtos, name="admin_produtos"),
    path("painel/configuracoes/", views.admin_configuracoes, name="admin_configuracoes"),

    # Rotas do painel (ajuste quando tiver views específicas)
    path("painel/voo/cadastrar/", views.admin_home, name="voo_cadastrar"),  # provisório

    # API pública autenticada (consumida via JavaScript)
    path("api/voos/", api.busca_voos, name="api_busca_voos"),
]
