
# core/admin.py
from django.contrib import admin
from .models import Profile
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from .models import User
from .models import Ticket

@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    # Campos extras no detalhe do usuário
    fieldsets = DjangoUserAdmin.fieldsets + (
        ("Informações extras", {"fields": ("cpf", "birth_date")}),
    )

    # Campos extras no formulário de criação pelo admin
    add_fieldsets = DjangoUserAdmin.add_fieldsets + (
        (None, {
            "classes": ("wide",),
            "fields": ("username", "email", "password1", "password2", "cpf", "birth_date"),
        }),
    )

    list_display = ("username", "email", "first_name", "last_name", "cpf", "birth_date", "is_staff")
    search_fields = ("username", "email", "first_name", "last_name", "cpf")

@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ("codigo","user","origem","destino","partida","status","preco")
    search_fields = ("codigo","origem","destino","user__username","user__email")
    list_filter = ("status",)

@admin.register(Voo)
class VooAdmin(admin.ModelAdmin):

    list_display = ("codigo", "origem", "destino", "partida", "preco", "criado_em")
    search_fields = ("codigo", "origem", "destino")
    list_filter = ("origem", "destino", "partida")
    ordering = ("-criado_em",)
