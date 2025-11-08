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

class PasswordResetToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="password_reset_tokens")
    token_hash = models.CharField(max_length=64, unique=True)  # sha256 hex
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    request_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "token_hash"]),
            models.Index(fields=["expires_at"]),
        ]

    def __str__(self):
        return f"PasswordResetToken(user={self.user_id}, used={bool(self.used_at)})"
