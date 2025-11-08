from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser


# --- MODELO DE USUÁRIO PERSONALIZADO ---
class User(AbstractUser):
    cpf = models.CharField("CPF", max_length=11, blank=True, null=True, unique=True)
    birth_date = models.DateField("Data de nascimento", blank=True, null=True)

    def __str__(self):
        return self.get_full_name() or self.username


# --- PERFIL ASSOCIADO AO USUÁRIO ---
class Profile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,  # <- referência ao User customizado
        on_delete=models.CASCADE,
        related_name="profile"
    )

    birth_date = models.DateField(verbose_name="Data de nascimento", blank=True, null=True)
    cpf = models.CharField(max_length=11, unique=True)

    def __str__(self):
        return f"Perfil de {self.user.username}"
