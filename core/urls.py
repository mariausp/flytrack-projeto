from django.urls import path, reverse_lazy
from django.contrib.auth.views import LogoutView
from django.contrib.auth import views as auth_views

from . import views, api
from .forms import CustomPasswordResetForm

app_name = "core"

urlpatterns = [
    # Páginas públicas
    path("", views.home, name="home"),
    path("resultados/", views.resultados, name="resultados"),
    path("resultados/resumo/", views.resumo_compra, name="resumo_compra"),
    path("historico/", views.historico, name="historico"),
    path("contato/", views.contato, name="contato"),

    # Autenticação
    path("signup/", views.signup, name="signup"),
    path("login/", views.login_view, name="login"),
    path(
        "logout/",
        LogoutView.as_view(next_page="core:login"),  # usa o nome com namespace
        name="logout",
    ),

    # Esqueci minha senha (usando as views prontas do Django)
    path(
        "senha/esqueci/",
        auth_views.PasswordResetView.as_view(
            template_name="password_reset.html",
            form_class=CustomPasswordResetForm,  # só deixa passar e-mail cadastrado
            email_template_name="password_reset_email.html",
            subject_template_name="password_reset_subject.txt",
            success_url=reverse_lazy("core:password_reset_done"),
        ),
        name="password_reset",
    ),
    path(
        "senha/enviado/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="password_reset_done.html",
        ),
        name="password_reset_done",
    ),
    path(
        "senha/redefinir/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(
            template_name="password_reset_confirm.html",
            success_url=reverse_lazy("core:password_reset_complete"),
        ),
        name="password_reset_confirm",
    ),
    path(
        "senha/concluida/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="password_reset_complete.html",
        ),
        name="password_reset_complete",
    ),

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

    # Seleção de assentos (pós-resultados)
    path("resultados/assentos/", views.selecionar_assento, name="selecionar_assento"),
    path("checkout/pagamento/", views.pagamento, name="pagamento"),
    path("checkout/confirmacao/", views.confirmacao, name="confirmacao"),

    # API pública autenticada (consumida via JavaScript)
    path("api/voos/", api.busca_voos, name="api_busca_voos"),
]
