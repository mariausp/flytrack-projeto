# flytrack/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from core import views as core_views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('admin/', admin.site.urls),

    # Auth “padrão” do Django em /accounts/ (login, logout, reset, change password etc.)
    path('accounts/', include('django.contrib.auth.urls')),

    # Atalho “bonito” para login usando teu template (templates/login.html)
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),

    # Cadastro (novo)
    path('signup/', core_views.signup, name='signup'),

    # Rotas do app principal
    path('', include('core.urls', namespace='core')),

    path("logout/", auth_views.LogoutView.as_view(next_page="core:home"), name="logout"),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
