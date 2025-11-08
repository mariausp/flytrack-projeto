# core/views.py
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail, EmailMessage, BadHeaderError
from django.conf import settings
from django.http import HttpResponse
from .forms import SignupForm
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
import hashlib, secrets, datetime
from base64 import urlsafe_b64encode, urlsafe_b64decode
from django.utils import timezone
from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import Http404
from .forms import ForgotPasswordForm, ResetPasswordForm
from .models import PasswordResetToken
import textwrap

User = get_user_model()

def home(request):
    return render(request, 'home.html')

def resultados(request):
    return render(request, 'resultados.html')

def historico(request):
    return render(request, 'historico.html')

def contato(request):
    context = {"errors": {}, "data": {}}
    if request.method == "POST":
        nome = request.POST.get("nome", "").strip()
        email = request.POST.get("email", "").strip()
        assunto = request.POST.get("assunto", "").strip()
        mensagem = request.POST.get("mensagem", "").strip()

        context["data"] = {"nome": nome, "email": email, "assunto": assunto, "mensagem": mensagem}

        if not nome:
            context["errors"]["nome"] = "Informe seu nome."
        if not email:
            context["errors"]["email"] = "Informe seu e-mail."
        else:
            try:
                validate_email(email)
            except ValidationError:
                context["errors"]["email"] = "E-mail inválido."
        if not assunto:
            context["errors"]["assunto"] = "Informe um assunto."
        if not mensagem or len(mensagem) < 10:
            context["errors"]["mensagem"] = "Escreva uma mensagem (mínimo 10 caracteres)."

        if not context["errors"]:
            try:
                corpo_admin = textwrap.dedent(f"""
                Nova mensagem de contato no FlyTrack:

                Nome: {nome}
                E-mail: {email}
                Assunto: {assunto}

                Mensagem:
                {mensagem}
                """)
                EmailMessage(
                    subject=f"[FlyTrack] Contato: {assunto}",
                    body=corpo_admin,
                    from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
                    to=[getattr(settings, "CONTACT_TO_EMAIL", settings.EMAIL_HOST_USER)],
                    reply_to=[email] if email else None,
                ).send(fail_silently=False)

                # resposta opcional ao usuário
                send_mail(
                    subject="Recebemos sua mensagem — FlyTrack",
                    message=textwrap.dedent(f"Olá, {nome}!\n\nRecebemos sua mensagem e responderemos em breve.\n\nAssunto: {assunto}\n\n— Equipe FlyTrack"),
                    from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
                    recipient_list=[email],
                    fail_silently=True,
                )

                context["success"] = True
                context["data"] = {}
            except BadHeaderError:
                context["errors"]["assunto"] = "Assunto inválido."
            except Exception:
                # era: context["errors"]["__all__"] = ...
                context["errors"]["global"] = "Não foi possível enviar sua mensagem agora. Tente novamente mais tarde."

    return render(request, 'contato.html', context)

def signup(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, "Conta criada com sucesso. Você já está logada.")
            # auto login após cadastro
            login(request, user)
            return redirect("core:home")  # ajuste para a rota que preferir
        else:
            # form.errors vai para template
            pass
    else:
        form = SignupForm()
    return render(request, "registration/signup.html", {"form": form})

def login_view(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f"Olá {user.get_full_name() or user.username} — você entrou.")
                return redirect("core:post_login")
            else:
                messages.error(request, "Usuário ou senha inválidos.")
        else:
            messages.error(request, "Usuário ou senha inválidos.")
    else:
        form = AuthenticationForm()
    return render(request, "registration/login.html", {"form": form})

def logout_view(request):
    logout(request)
    messages.info(request, "Você saiu da conta.")
    return redirect("core:home")

@login_required
def post_login(request):
    """
    Decide pra onde mandar após login:
    - Se for staff (admin), vai para o painel
    - Caso contrário, vai para a home normal
    """
    if request.user.is_staff:
        return redirect("core:admin_home")
    return redirect("core:home")

@staff_member_required
def admin_home(request):
    # Renderize um template específico do painel (crie core/templates/admin_home.html)
    return render(request, "admin_home.html")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def forgot_password(request):
    """
    GET: mostra formulário de e-mail.
    POST: (sempre) mostra página de 'enviado', independentemente de o e-mail existir (anti-enumeração).
    """
    if request.method == "POST":
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            try:
                user = User.objects.get(email__iexact=email)
            except User.DoesNotExist:
                # Não revela existência
                return redirect("core:password_reset_done")

            # Apaga tokens antigos expirados (higiene)
            PasswordResetToken.objects.filter(user=user, used_at__isnull=True, expires_at__lt=timezone.now()).delete()

            # Gera token aleatório + salva hash
            raw_token = secrets.token_urlsafe(32)
            token_hash = _hash_token(raw_token)
            expires = timezone.now() + datetime.timedelta(hours=2)  # expira em 2h (ajuste se quiser)

            PasswordResetToken.objects.create(
                user=user,
                token_hash=token_hash,
                expires_at=expires,
                request_ip=(request.META.get("REMOTE_ADDR") or None),
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
            )

            # monta link: uid + token
            uidb64 = urlsafe_b64encode(str(user.pk).encode()).decode()
            reset_url = request.build_absolute_uri(
                reverse("core:password_reset_confirm", args=[uidb64, raw_token])
            )

            # envia e-mail (simples)
            subject = "Redefinição de senha — Fly Track"
            body = (
                "Olá,\n\n"
                "Recebemos uma solicitação para redefinir a sua senha no Fly Track.\n"
                f"Use o link abaixo (válido por 2 horas):\n\n{reset_url}\n\n"
                "Se você não solicitou, ignore este e-mail.\n\n"
                "— Equipe Fly Track"
            )
            try:
                send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)
            except BadHeaderError:
                pass  # não expõe erro aqui

            return redirect("core:password_reset_done")
    else:
        form = ForgotPasswordForm()

    return render(request, "password_reset.html", {"form": form})

def reset_password_confirm(request, uidb64: str, token: str):
    """
    Valida token (hash + expiração + não usado) e permite setar nova senha.
    Token é uso único: ao salvar, marca como usado e invalida os demais tokens ativos do usuário.
    """
    # decodifica uid
    try:
        uid = int(urlsafe_b64decode(uidb64.encode()).decode())
    except Exception:
        raise Http404("Link inválido")

    try:
        user = User.objects.get(pk=uid)
    except User.DoesNotExist:
        raise Http404("Usuário não encontrado")

    token_hash = _hash_token(token)
    try:
        prt = PasswordResetToken.objects.get(user=user, token_hash=token_hash, used_at__isnull=True)
    except PasswordResetToken.DoesNotExist:
        raise Http404("Link inválido ou já utilizado")

    if timezone.now() > prt.expires_at:
        messages.error(request, "Este link expirou. Solicite uma nova redefinição.")
        return redirect("core:password_reset")

    if request.method == "POST":
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            new_password = form.cleaned_data["new_password"]
            user.set_password(new_password)
            user.save()

            # marca usado e invalida outros tokens do usuário
            prt.used_at = timezone.now()
            prt.save(update_fields=["used_at"])
            PasswordResetToken.objects.filter(user=user, used_at__isnull=True).update(used_at=timezone.now())

            return redirect("core:password_reset_complete")
    else:
        form = ResetPasswordForm()

    return render(request, "password_reset_confirm.html", {"form": form, "user": user})

def reset_password_done(request):
    return render(request, "password_reset_done.html")

def reset_password_complete(request):
    return render(request, "password_reset_complete.html")
