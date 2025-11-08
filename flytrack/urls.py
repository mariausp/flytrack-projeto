# flytrack/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # 1) Suas rotas do app (inclui /login/ -> core.views.login_view)
    path("", include(("core.urls", "core"), namespace="core")),

    # 2) Rotas de auth padrão do Django em /accounts/ (reset de senha, change password, etc.)
    path("accounts/", include("django.contrib.auth.urls")),

    # 3) Admin do Django
    path("admin/", admin.site.urls),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
