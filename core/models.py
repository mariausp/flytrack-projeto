# core/models.py
from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator

class PortalMeta(models.Model):
    class Meta:
        managed = False
        default_permissions = ()
        permissions = [
            ("access_admin_portal", "Pode acessar o portal administrativo do site"),
        ]


# ------------------ USUÁRIO CUSTOM ------------------
cpf_validator = RegexValidator(
    regex=r"^\d{11}$",
    message="Informe 11 dígitos numéricos para o CPF."
)

class User(AbstractUser):
    cpf = models.CharField(
        "CPF",
        max_length=11,
        blank=True,
        null=True,
        unique=True,
        validators=[cpf_validator],
        help_text="Somente 11 dígitos (sem pontos/traços)."
    )
    birth_date = models.DateField("Data de nascimento", blank=True, null=True)

    def __str__(self):
        return self.get_full_name() or self.username


# ------------------ PROFILE (EXTRAS DO USUÁRIO) ------------------
# Se você não tem campos extras, pode até remover a tabela Profile por enquanto.
class Profile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile"
    )
    # Coloque AQUI apenas campos que NÃO existem no User.
    # Ex.: foto, preferências, etc. Evite repetir cpf/birth_date.
    avatar_url = models.URLField(blank=True, null=True)

    def __str__(self):
        return f"Perfil de {self.user.username}"


# ------------------ RESET DE SENHA (TOKEN) ------------------
class PasswordResetToken(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="password_reset_tokens"
    )
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

class Ticket(models.Model):
    STATUS_CHOICES = [
        ("PAGO", "Pago"),
        ("CANCELADO", "Cancelado"),
        ("PENDENTE", "Pendente"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="tickets",
    )
    codigo = models.CharField("Localizador", max_length=20)
    origem = models.CharField(max_length=64)
    destino = models.CharField(max_length=64)
    partida = models.DateTimeField("Data/hora de partida")
    chegada = models.DateTimeField("Data/hora de chegada", null=True, blank=True)
    preco = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="PAGO")
    criado_em = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-partida", "-id"]
        indexes = [
            models.Index(fields=["user", "partida"]),
            models.Index(fields=["codigo"]),
        ]

    def __str__(self):
        return f"{self.codigo} — {self.origem}→{self.destino}"
